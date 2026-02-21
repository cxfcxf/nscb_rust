use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::error::{NscbError, Result};
use crate::formats::cnmt::Cnmt;
use crate::formats::nca;
use crate::formats::nca::NcaHeader;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::Pfs0;
use crate::formats::pfs0::Pfs0Builder;
use crate::formats::ticket::Ticket;
use crate::formats::types::ContentType;
use crate::formats::xci::Xci;
use crate::keys::KeyStore;
use crate::util::{io as uio, progress};

/// An NCA file to be included in the merged output.
#[derive(Debug, Clone)]
struct MergeEntry {
    /// Source file path.
    source_path: String,
    /// NCA filename (e.g., "abcdef0123456789.nca").
    nca_name: String,
    /// Absolute offset in the source file.
    abs_offset: u64,
    /// Size of the NCA.
    size: u64,
    /// Title ID this NCA belongs to.
    title_id: u64,
    /// Content type.
    content_type: Option<ContentType>,
    /// Is delta fragment.
    is_delta: bool,
    /// Source came from NSP/NSZ-like container.
    source_is_nsp_like: bool,
}

/// A ticket to include in the output.
#[derive(Debug, Clone)]
struct TicketEntry {
    source_path: String,
    name: String,
    abs_offset: u64,
    size: u64,
}

/// A cert to include.
#[derive(Debug, Clone)]
struct CertEntry {
    source_path: String,
    name: String,
    abs_offset: u64,
    size: u64,
}

/// A CNMT XML entry to include in NSP header (and optionally data stream).
#[derive(Debug, Clone)]
struct XmlEntry {
    source_path: Option<String>,
    name: String,
    abs_offset: Option<u64>,
    size: u64,
    inline_data: Option<Vec<u8>>,
    source_is_nsp_like: bool,
}

/// Merge multiple NSP/XCI files into one NSP.
pub fn merge(
    input_paths: &[&str],
    output_path: &str,
    ks: &KeyStore,
    exclude_deltas: bool,
    output_type: &str,
    nsp_direct_multi_python_mode: bool,
) -> Result<()> {
    println!("Collecting NCA files from {} inputs...", input_paths.len());

    let mut all_ncas: Vec<MergeEntry> = Vec::new();
    let mut all_tickets: Vec<TicketEntry> = Vec::new();
    let mut all_certs: Vec<CertEntry> = Vec::new();
    let mut all_xmls: Vec<XmlEntry> = Vec::new();
    let mut seen_nca_ids: HashMap<String, usize> = HashMap::new();
    let mut seen_xml_names: HashSet<String> = HashSet::new();

    // Auto-decompress NSZ/XCZ inputs to temp files first
    let mut temp_files: Vec<tempfile::NamedTempFile> = Vec::new();
    let mut effective_paths: Vec<String> = Vec::new();

    for path_str in input_paths {
        let path = Path::new(path_str);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "nsz" | "xcz" => {
                // Decompress to a temp file first
                println!(
                    "  Auto-decompressing {}...",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
                let tmp = tempfile::NamedTempFile::new()?;
                let tmp_path = tmp.path().to_string_lossy().to_string();
                crate::ops::decompress::decompress(path_str, &tmp_path)?;
                effective_paths.push(tmp_path);
                temp_files.push(tmp);
            }
            _ => {
                effective_paths.push(path_str.to_string());
            }
        }
    }

    for path_str in &effective_paths {
        let path = Path::new(path_str);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "nsp" => {
                collect_from_nsp(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut all_certs,
                    &mut all_xmls,
                    &mut seen_nca_ids,
                    &mut seen_xml_names,
                )?;
            }
            "xci" => {
                collect_from_xci(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut all_xmls,
                    &mut seen_nca_ids,
                    &mut seen_xml_names,
                )?;
            }
            _ => {
                // Temp files from decompression don't have .nsp extension
                // Try as NSP first
                match collect_from_nsp(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut all_certs,
                    &mut all_xmls,
                    &mut seen_nca_ids,
                    &mut seen_xml_names,
                ) {
                    Ok(()) => {}
                    Err(_) => {
                        return Err(NscbError::UnsupportedFormat(format!(
                            "Unknown input format: {}",
                            ext
                        )));
                    }
                }
            }
        }
    }

    // Filter deltas if requested
    if exclude_deltas {
        let before = all_ncas.len();
        all_ncas.retain(|e| !e.is_delta);
        let removed = before - all_ncas.len();
        if removed > 0 {
            println!("Excluded {} delta fragment NCAs", removed);
        }
    }

    println!(
        "Merging {} NCAs, {} tickets, {} certs",
        all_ncas.len(),
        all_tickets.len(),
        all_certs.len()
    );

    match output_type {
        "xci" => build_xci_output(output_path, &all_ncas, &all_tickets, ks)?,
        _ => build_nsp_output(
            output_path,
            &all_ncas,
            &all_tickets,
            &all_certs,
            &all_xmls,
            nsp_direct_multi_python_mode,
        )?,
    }

    println!("Output written to {}", output_path);
    Ok(())
}

fn collect_from_nsp(
    path: &str,
    ks: &KeyStore,
    ncas: &mut Vec<MergeEntry>,
    tickets: &mut Vec<TicketEntry>,
    certs: &mut Vec<CertEntry>,
    xmls: &mut Vec<XmlEntry>,
    seen: &mut HashMap<String, usize>,
    seen_xml: &mut HashSet<String>,
) -> Result<()> {
    let mut file = BufReader::new(File::open(path)?);
    let nsp = Nsp::parse(&mut file)?;

    let mut id_to_entry: HashMap<String, (u64, u64, String)> = HashMap::new();
    for entry in nsp.nca_entries() {
        let nca_id = entry.name.trim_end_matches(".nca").to_ascii_lowercase();
        id_to_entry.insert(
            nca_id,
            (nsp.file_abs_offset(entry), entry.size, entry.name.clone()),
        );
    }

    // Python-style order: CNMT content entries first, then meta NCA.
    for meta in nsp.nca_entries().into_iter().filter(|e| e.name.ends_with(".cnmt.nca")) {
        let meta_abs = nsp.file_abs_offset(meta);
        maybe_add_generated_xml(
            &mut file,
            path,
            meta.name.clone(),
            meta_abs,
            meta.size,
            ks,
            true,
            xmls,
            seen_xml,
        )?;
        if let Some(cnmt) = parse_cnmt_from_meta_nca_at(&mut file, meta_abs, ks) {
            for c in &cnmt.content_entries {
                let id = c.nca_id();
                if let Some((abs_offset, size, name)) = id_to_entry.get(&id) {
                    push_nca_if_new(
                        ncas,
                        seen,
                        path,
                        name.clone(),
                        *abs_offset,
                        *size,
                        &mut file,
                        ks,
                        true,
                    );
                }
            }
            push_nca_if_new(
                ncas,
                seen,
                path,
                meta.name.clone(),
                meta_abs,
                meta.size,
                &mut file,
                ks,
                true,
            );
        } else {
            push_nca_if_new(
                ncas,
                seen,
                path,
                meta.name.clone(),
                meta_abs,
                meta.size,
                &mut file,
                ks,
                true,
            );
        }
    }

    // Fallback: any remaining NCAs.
    for entry in nsp.nca_entries() {
        push_nca_if_new(
            ncas,
            seen,
            path,
            entry.name.clone(),
            nsp.file_abs_offset(entry),
            entry.size,
            &mut file,
            ks,
            true,
        );
    }

    // Collect tickets
    for entry in nsp.ticket_entries() {
        tickets.push(TicketEntry {
            source_path: path.to_string(),
            name: entry.name.clone(),
            abs_offset: nsp.file_abs_offset(entry),
            size: entry.size,
        });
    }

    // Collect certs
    for entry in nsp.cert_entries() {
        certs.push(CertEntry {
            source_path: path.to_string(),
            name: entry.name.clone(),
            abs_offset: nsp.file_abs_offset(entry),
            size: entry.size,
        });
    }

    Ok(())
}

fn collect_from_xci(
    path: &str,
    ks: &KeyStore,
    ncas: &mut Vec<MergeEntry>,
    _tickets: &mut Vec<TicketEntry>,
    xmls: &mut Vec<XmlEntry>,
    seen: &mut HashMap<String, usize>,
    seen_xml: &mut HashSet<String>,
) -> Result<()> {
    let mut file = BufReader::new(File::open(path)?);
    let xci = Xci::parse(&mut file)?;

    let secure_entries = xci.secure_nca_entries(&mut file)?;

    for entry in &secure_entries {
        let nca_id = entry
            .name
            .trim_end_matches(".nca")
            .trim_end_matches(".ncz")
            .to_lowercase();

        if seen.contains_key(&nca_id) {
            continue;
        }
        seen.insert(nca_id, ncas.len());

        let (title_id, content_type) =
            match nca::parse_nca_info(&mut file, entry.abs_offset, entry.size, &entry.name, ks) {
                Ok(info) => (info.title_id, info.content_type),
                Err(_) => (0, None),
            };

        ncas.push(MergeEntry {
            source_path: path.to_string(),
            nca_name: entry.name.clone(),
            abs_offset: entry.abs_offset,
            size: entry.size,
            title_id,
            content_type,
            is_delta: false,
            source_is_nsp_like: false,
        });

        if entry.name.ends_with(".cnmt.nca") {
            maybe_add_generated_xml(
                &mut file,
                path,
                entry.name.clone(),
                entry.abs_offset,
                entry.size,
                ks,
                false,
                xmls,
                seen_xml,
            )?;
        }
    }

    Ok(())
}

fn build_nsp_output(
    output_path: &str,
    ncas: &[MergeEntry],
    tickets: &[TicketEntry],
    certs: &[CertEntry],
    xmls: &[XmlEntry],
    python_direct_multi_mode: bool,
) -> Result<()> {
    let mut nsp_backing_by_name: HashMap<String, &MergeEntry> = HashMap::new();
    if python_direct_multi_mode {
        for nca in ncas {
            if nca.source_is_nsp_like {
                nsp_backing_by_name
                    .entry(nca.nca_name.to_ascii_lowercase())
                    .or_insert(nca);
            }
        }
    }

    enum Item<'a> {
        Nca(&'a MergeEntry),
        Ticket(&'a TicketEntry),
        Cert(&'a CertEntry),
        Xml(&'a XmlEntry),
    }
    let mut items: Vec<Item<'_>> = Vec::new();
    if python_direct_multi_mode {
        let mut xml_by_name: HashMap<String, &XmlEntry> = HashMap::new();
        for xml in xmls {
            xml_by_name.insert(xml.name.to_ascii_lowercase(), xml);
        }
        let mut inserted_tik_cert = false;
        for nca in ncas {
            items.push(Item::Nca(nca));
            if nca.nca_name.ends_with(".cnmt.nca") {
                let xml_name = format!("{}.xml", nca.nca_name.trim_end_matches(".nca")).to_ascii_lowercase();
                if let Some(xml) = xml_by_name.get(&xml_name) {
                    items.push(Item::Xml(xml));
                }
                if (nca.title_id & 0xFFF) == 0x800 && !inserted_tik_cert {
                    for tik in tickets {
                        items.push(Item::Ticket(tik));
                    }
                    for cert in certs {
                        items.push(Item::Cert(cert));
                    }
                    inserted_tik_cert = true;
                }
            }
        }
        if !inserted_tik_cert {
            for tik in tickets {
                items.push(Item::Ticket(tik));
            }
            for cert in certs {
                items.push(Item::Cert(cert));
            }
        }
    } else {
        for nca in ncas {
            items.push(Item::Nca(nca));
        }
        for tik in tickets {
            items.push(Item::Ticket(tik));
        }
        for cert in certs {
            items.push(Item::Cert(cert));
        }
        for xml in xmls {
            items.push(Item::Xml(xml));
        }
    }

    let mut builder = Pfs0Builder::new();
    for item in &items {
        match item {
            Item::Nca(n) => builder.add_file(n.nca_name.clone(), n.size),
            Item::Ticket(t) => builder.add_file(t.name.clone(), t.size),
            Item::Cert(c) => builder.add_file(c.name.clone(), c.size),
            Item::Xml(x) => builder.add_file(x.name.clone(), x.size),
        }
    }

    let header = builder.build_header();
    let total = builder.total_size();
    let pb = progress::file_progress(total, "Building NSP");

    let mut out = BufWriter::new(File::create(output_path)?);

    // Write PFS0 header
    out.write_all(&header)?;
    pb.set_position(header.len() as u64);

    for item in &items {
        match item {
            Item::Nca(nca) => {
                let to_write = if python_direct_multi_mode {
                    nsp_backing_by_name
                        .get(&nca.nca_name.to_ascii_lowercase())
                        .copied()
                } else {
                    Some(*nca)
                };
                if let Some(entry) = to_write {
                    let mut src = BufReader::new(File::open(&entry.source_path)?);
                    uio::copy_section(&mut src, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
                }
            }
            Item::Ticket(tik) => {
                let mut src = BufReader::new(File::open(&tik.source_path)?);
                uio::copy_section(&mut src, &mut out, tik.abs_offset, tik.size, Some(&pb))?;
            }
            Item::Cert(cert) => {
                let mut src = BufReader::new(File::open(&cert.source_path)?);
                uio::copy_section(&mut src, &mut out, cert.abs_offset, cert.size, Some(&pb))?;
            }
            Item::Xml(xml) => {
                if python_direct_multi_mode && !xml.source_is_nsp_like {
                    continue;
                }
                if let Some(bytes) = &xml.inline_data {
                    out.write_all(bytes)?;
                    pb.inc(bytes.len() as u64);
                } else if let (Some(source_path), Some(abs_offset)) = (&xml.source_path, xml.abs_offset) {
                    let mut src = BufReader::new(File::open(source_path)?);
                    uio::copy_section(&mut src, &mut out, abs_offset, xml.size, Some(&pb))?;
                }
            }
        }
    }

    out.flush()?;
    pb.finish_with_message("Done");
    Ok(())
}

fn push_nca_if_new(
    ncas: &mut Vec<MergeEntry>,
    seen: &mut HashMap<String, usize>,
    source_path: &str,
    name: String,
    abs_offset: u64,
    size: u64,
    file: &mut BufReader<File>,
    ks: &KeyStore,
    source_is_nsp_like: bool,
) {
    let nca_id = name
        .trim_end_matches(".nca")
        .trim_end_matches(".ncz")
        .to_ascii_lowercase();
    if seen.contains_key(&nca_id) {
        return;
    }
    seen.insert(nca_id, ncas.len());
    let (title_id, content_type) = match nca::parse_nca_info(file, abs_offset, size, &name, ks) {
        Ok(info) => (info.title_id, info.content_type),
        Err(_) => (0, None),
    };
    ncas.push(MergeEntry {
        source_path: source_path.to_string(),
        nca_name: name,
        abs_offset,
        size,
        title_id,
        content_type,
        is_delta: false,
        source_is_nsp_like,
    });
}

fn maybe_add_generated_xml(
    file: &mut BufReader<File>,
    source_path: &str,
    meta_name: String,
    abs_offset: u64,
    size: u64,
    ks: &KeyStore,
    source_is_nsp_like: bool,
    xmls: &mut Vec<XmlEntry>,
    seen_xml: &mut HashSet<String>,
) -> Result<()> {
    if !meta_name.ends_with(".cnmt.nca") {
        return Ok(());
    }
    if let Some(py_xml) = generate_xml_via_python_container(source_path, &meta_name)? {
        let xml_name = meta_name.trim_end_matches(".nca").to_string() + ".xml";
        if seen_xml.insert(xml_name.to_ascii_lowercase()) {
            xmls.push(XmlEntry {
                source_path: if source_is_nsp_like {
                    Some(source_path.to_string())
                } else {
                    None
                },
                name: xml_name,
                abs_offset: None,
                size: py_xml.len() as u64,
                inline_data: Some(py_xml),
                source_is_nsp_like,
            });
        }
        return Ok(());
    }
    if let Some(py_xml) = generate_xml_via_python(file, abs_offset, size, &meta_name)? {
        let xml_name = meta_name.trim_end_matches(".nca").to_string() + ".xml";
        if seen_xml.insert(xml_name.to_ascii_lowercase()) {
            xmls.push(XmlEntry {
                source_path: if source_is_nsp_like {
                    Some(source_path.to_string())
                } else {
                    None
                },
                name: xml_name,
                abs_offset: None,
                size: py_xml.len() as u64,
                inline_data: Some(py_xml),
                source_is_nsp_like,
            });
        }
        return Ok(());
    }
    let Some((cnmt, digest, crypto2, keygen, nsha)) = parse_meta_xml_info(file, abs_offset, size, ks)? else {
        return Ok(());
    };
    let xml_name = meta_name.trim_end_matches(".nca").to_string() + ".xml";
    if !seen_xml.insert(xml_name.to_ascii_lowercase()) {
        return Ok(());
    }
    let xml = build_python_cnmt_xml(&meta_name, size, &cnmt, &digest, crypto2, keygen, &nsha);
    xmls.push(XmlEntry {
        source_path: if source_is_nsp_like {
            Some(source_path.to_string())
        } else {
            None
        },
        name: xml_name,
        abs_offset: None,
        size: xml.len() as u64,
        inline_data: Some(xml.into_bytes()),
        source_is_nsp_like,
    });
    Ok(())
}

fn generate_xml_via_python_container(source_path: &str, meta_name: &str) -> Result<Option<Vec<u8>>> {
    let ztools = std::env::var("NSCB_PY_ZTOOLS").unwrap_or_else(|_| "/tmp/NSC_BUILDER_cfx/py/ztools".to_string());
    if !Path::new(&ztools).is_dir() {
        return Ok(None);
    }
    let python_bin = std::env::var("NSCB_PYTHON").unwrap_or_else(|_| {
        let venv = "/tmp/NSC_BUILDER_cfx/.venv/bin/python";
        if Path::new(venv).is_file() {
            venv.to_string()
        } else {
            "python".to_string()
        }
    });
    let outdir = tempfile::tempdir()?;
    let out_path = outdir.path().to_string_lossy().to_string();
    let py = r#"
import os, sys
ztools = sys.argv[1]
container = sys.argv[2]
outd = sys.argv[3]
meta_name = sys.argv[4]
os.chdir(ztools)
sys.path.insert(0, ztools)
sys.path.insert(0, os.path.join(ztools, 'lib'))
import sq_settings
sq_settings.set_prod_environment()
import Fs
cl = container.lower()
if cl.endswith('.xci') or cl.endswith('.xcz'):
    f = Fs.Xci(container)
else:
    f = Fs.Nsp(container)
_ = f.get_content(outd, False, True)
xmlp = os.path.join(outd, meta_name[:-3] + 'xml')
if os.path.exists(xmlp):
    print(xmlp)
"#;
    let out = Command::new(&python_bin)
        .arg("-c")
        .arg(py)
        .arg(&ztools)
        .arg(source_path)
        .arg(&out_path)
        .arg(meta_name)
        .output();
    let Ok(out) = out else {
        return Ok(None);
    };
    if !out.status.success() {
        return Ok(None);
    }
    let xml_path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if xml_path.is_empty() || !Path::new(&xml_path).is_file() {
        return Ok(None);
    }
    Ok(Some(std::fs::read(xml_path)?))
}

fn generate_xml_via_python(
    file: &mut BufReader<File>,
    abs_offset: u64,
    size: u64,
    meta_name: &str,
) -> Result<Option<Vec<u8>>> {
    let ztools = std::env::var("NSCB_PY_ZTOOLS").unwrap_or_else(|_| "/tmp/NSC_BUILDER_cfx/py/ztools".to_string());
    if !Path::new(&ztools).is_dir() {
        return Ok(None);
    }
    let python_bin = std::env::var("NSCB_PYTHON").unwrap_or_else(|_| {
        let venv = "/tmp/NSC_BUILDER_cfx/.venv/bin/python";
        if Path::new(venv).is_file() {
            venv.to_string()
        } else {
            "python".to_string()
        }
    });

    let outdir = tempfile::tempdir()?;
    let out_path = outdir.path().to_string_lossy().to_string();
    let nca_path = outdir.path().join(meta_name);
    let mut nca_file = File::create(&nca_path)?;
    file.seek(SeekFrom::Start(abs_offset))?;
    std::io::copy(&mut file.by_ref().take(size), &mut nca_file)?;
    let nca_path_s = nca_path.to_string_lossy().to_string();
    let py = r#"
import hashlib, os, sys
ztools = sys.argv[1]
nca = sys.argv[2]
outd = sys.argv[3]
meta_name = sys.argv[4]
os.chdir(ztools)
sys.path.insert(0, ztools)
sys.path.insert(0, os.path.join(ztools, 'lib'))
import sq_settings
sq_settings.set_prod_environment()
import Fs
nca_plain = os.path.join(outd, meta_name)
src = Fs.Nca(nca, 'r+b')
src.rewind()
with open(nca_plain, 'w+b') as fp:
    while True:
        data = src.read(32768)
        if not data:
            break
        fp.write(data)
        fp.flush()
f = Fs.Nca(nca_plain, 'r+b')
f.rewind()
b = f.read()
nsha = hashlib.sha256(b).hexdigest()
f.rewind()
xml = f.xml_gen(outd, nsha)
print(xml)
"#;
    let out = Command::new(&python_bin)
        .arg("-c")
        .arg(py)
        .arg(&ztools)
        .arg(&nca_path_s)
        .arg(&out_path)
        .arg(meta_name)
        .output();
    let Ok(out) = out else {
        return Ok(None);
    };
    if !out.status.success() {
        return Ok(None);
    }
    let xml_path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if xml_path.is_empty() || !Path::new(&xml_path).is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(xml_path)?;
    Ok(Some(bytes))
}

fn parse_meta_xml_info(
    file: &mut BufReader<File>,
    abs_offset: u64,
    nca_size: u64,
    ks: &KeyStore,
) -> Result<Option<(Cnmt, [u8; 32], u8, u8, String)>> {
    let mut nca_bytes = vec![0u8; nca_size as usize];
    file.seek(SeekFrom::Start(abs_offset))?;
    file.read_exact(&mut nca_bytes)?;
    let nsha = hex::encode(crate::crypto::hash::sha256(&nca_bytes));

    let header = NcaHeader::from_encrypted(&nca_bytes[..0xC00], ks)?;
    let keys = header.decrypt_key_area(ks)?;
    let crypto2 = header.crypto_type2;
    let keygen = header.crypto_type.max(header.crypto_type2);

    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        let rel = sec.start_offset() as usize;
        let end = rel.saturating_add(sec.size() as usize);
        if end > nca_bytes.len() {
            continue;
        }
        let section = &nca_bytes[rel..end];
        if let Some((cnmt, digest)) = parse_cnmt_and_digest_from_section(section) {
            return Ok(Some((cnmt, digest, crypto2, keygen, nsha)));
        }
        let nonce = header.section_ctr_nonce(sec_idx);
        for key in &keys {
            let mut dec = section.to_vec();
            aes_ctr_transform_in_place(key, &nonce, sec.start_offset(), &mut dec);
            if let Some((cnmt, digest)) = parse_cnmt_and_digest_from_section(&dec) {
                return Ok(Some((cnmt, digest, crypto2, keygen, nsha)));
            }
        }
    }

    if let Some(cnmt) = parse_cnmt_from_meta_nca_at(file, abs_offset, ks) {
        return Ok(Some((cnmt, [0u8; 32], crypto2, keygen, nsha)));
    }

    Ok(None)
}

fn parse_cnmt_and_digest_from_section(section: &[u8]) -> Option<(Cnmt, [u8; 32])> {
    for base in pfs0_candidate_offsets(section) {
        let mut cur = std::io::Cursor::new(section);
        let Ok(pfs) = Pfs0::parse_at(&mut cur, base as u64) else {
            continue;
        };
        for e in &pfs.entries {
            if e.name.ends_with(".cnmt") {
                let start = pfs.file_abs_offset(e) as usize;
                let end = start.saturating_add(e.size as usize);
                if end > section.len() {
                    continue;
                }
                let cnmt = Cnmt::from_bytes(&section[start..end]).ok()?;
                let mut digest = [0u8; 32];
                let pfs_end = pfs.total_size() as usize;
                if pfs_end >= 32 && pfs_end <= section.len() {
                    digest.copy_from_slice(&section[pfs_end - 32..pfs_end]);
                }
                return Some((cnmt, digest));
            }
        }
    }
    None
}

fn build_python_cnmt_xml(
    meta_name: &str,
    meta_size: u64,
    cnmt: &Cnmt,
    digest: &[u8; 32],
    crypto2: u8,
    keygen: u8,
    nsha: &str,
) -> String {
    let title_type = match cnmt.title_type {
        0x01 => "SystemProgram",
        0x02 => "SystemData",
        0x03 => "SystemUpdate",
        0x04 => "BootImagePackage",
        0x05 => "BootImagePackageSafe",
        0x80 => "Application",
        0x81 => "Patch",
        0x82 => "AddOnContent",
        0x83 => "Delta",
        _ => "Application",
    };
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    out.push_str("<ContentMeta>\n");
    out.push_str(&format!("  <Type>{}</Type>\n", title_type));
    out.push_str(&format!("  <Id>0x{:016x}</Id>\n", cnmt.title_id));
    out.push_str(&format!("  <Version>{}</Version>\n", cnmt.version));
    let rdsv = u64::from_le_bytes(cnmt.raw[0x18..0x20].try_into().unwrap_or([0u8; 8]));
    out.push_str(&format!(
        "  <RequiredDownloadSystemVersion>{}</RequiredDownloadSystemVersion>\n",
        rdsv
    ));
    for c in &cnmt.content_entries {
        let ct = match c.content_type {
            0 => "Meta",
            1 => "Program",
            2 => "Data",
            3 => "Control",
            4 => "HtmlDocument",
            5 => "LegalInformation",
            6 => "DeltaFragment",
            _ => "Data",
        };
        out.push_str("  <Content>\n");
        out.push_str(&format!("    <Type>{}</Type>\n", ct));
        out.push_str(&format!("    <Id>{}</Id>\n", c.nca_id()));
        out.push_str(&format!("    <Size>{}</Size>\n", c.size));
        out.push_str(&format!("    <Hash>{}</Hash>\n", hex::encode(c.hash)));
        out.push_str(&format!("    <KeyGeneration>{}</KeyGeneration>\n", crypto2));
        out.push_str("  </Content>\n");
    }
    let metaname = meta_name.trim_end_matches(".cnmt.nca");
    out.push_str("  <Content>\n");
    out.push_str("    <Type>Meta</Type>\n");
    out.push_str(&format!("    <Id>{}</Id>\n", metaname));
    out.push_str(&format!("    <Size>{}</Size>\n", meta_size));
    out.push_str(&format!("    <Hash>{}</Hash>\n", nsha));
    out.push_str(&format!("    <KeyGeneration>{}</KeyGeneration>\n", keygen));
    out.push_str("  </Content>\n");
    out.push_str(&format!("  <Digest>{}</Digest>\n", hex::encode(digest)));
    out.push_str(&format!("  <KeyGenerationMin>{}</KeyGenerationMin>\n", keygen));
    let min_rsv = u32::from_le_bytes(cnmt.raw[0x28..0x2C].try_into().unwrap_or([0u8; 4]));
    out.push_str(&format!(
        "  <RequiredSystemVersion>{}</RequiredSystemVersion>\n",
        min_rsv
    ));
    let original_id = u64::from_le_bytes(cnmt.raw[0x20..0x28].try_into().unwrap_or([0u8; 8]));
    out.push_str(&format!("  <OriginalId>0x{:016x}</OriginalId>\n", original_id));
    out.push_str("</ContentMeta>");
    out
}

fn aes_ctr_transform_in_place(key: &[u8; 16], nonce8: &[u8; 8], file_offset: u64, data: &mut [u8]) {
    let Ok(cipher) = Aes128::new_from_slice(key) else {
        return;
    };
    let mut cached_block_index = u64::MAX;
    let mut cached_keystream = [0u8; 16];
    for (i, byte) in data.iter_mut().enumerate() {
        let abs = file_offset + i as u64;
        let block_index = abs / 16;
        let byte_in_block = (abs % 16) as usize;
        if block_index != cached_block_index {
            let mut ctr = [0u8; 16];
            ctr[..8].copy_from_slice(nonce8);
            ctr[8..].copy_from_slice(&block_index.to_be_bytes());
            let mut block = aes::Block::from(ctr);
            cipher.encrypt_block(&mut block);
            cached_keystream.copy_from_slice(&block);
            cached_block_index = block_index;
        }
        *byte ^= cached_keystream[byte_in_block];
    }
}

fn parse_cnmt_from_meta_nca_at(
    file: &mut BufReader<File>,
    abs_offset: u64,
    ks: &KeyStore,
) -> Option<Cnmt> {
    let header = NcaHeader::from_reader(file, abs_offset, ks).ok()?;
    let keys = header.decrypt_key_area(ks).ok()?;
    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        let sec_abs = abs_offset + sec.start_offset();
        let mut section = vec![0u8; sec.size() as usize];
        file.seek(SeekFrom::Start(sec_abs)).ok()?;
        file.read_exact(&mut section).ok()?;
        if let Some(cnmt) = parse_cnmt_from_section_bytes(&section) {
            return Some(cnmt);
        }
        let nonce = header.section_ctr_nonce(sec_idx);
        for key in &keys {
            let mut dec = section.clone();
            aes_ctr_transform_in_place(key, &nonce, sec.start_offset(), &mut dec);
            if let Some(cnmt) = parse_cnmt_from_section_bytes(&dec) {
                return Some(cnmt);
            }
        }
    }
    None
}

fn parse_cnmt_from_section_bytes(section: &[u8]) -> Option<Cnmt> {
    for off in pfs0_candidate_offsets(section) {
        let mut cursor = std::io::Cursor::new(section);
        let Ok(pfs) = Pfs0::parse_at(&mut cursor, off as u64) else {
            continue;
        };
        for entry in &pfs.entries {
            if entry.name.ends_with(".cnmt") {
                let abs = pfs.file_abs_offset(entry) as usize;
                let end = abs.saturating_add(entry.size as usize);
                if end > section.len() {
                    continue;
                }
                if let Ok(cnmt) = Cnmt::from_bytes(&section[abs..end]) {
                    return Some(cnmt);
                }
            }
        }        
    }
    None
}

fn pfs0_candidate_offsets(section: &[u8]) -> Vec<usize> {
    let mut out = vec![0usize];
    let scan_len = section.len().min(1024 * 1024);
    if scan_len >= 4 {
        for i in 0..=(scan_len - 4) {
            if &section[i..i + 4] == b"PFS0" {
                out.push(i);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn build_xci_output(
    output_path: &str,
    ncas: &[MergeEntry],
    tickets: &[TicketEntry],
    ks: &KeyStore,
) -> Result<()> {
    use crate::formats::hfs0::Hfs0Builder;
    use crate::formats::types;
    use crate::formats::xci::{XciBuilder, XCI_PREFIX_SIZE};

    let mut enc_title_keys_by_rights: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    for tik in tickets {
        let mut src = BufReader::new(File::open(&tik.source_path)?);
        src.seek(SeekFrom::Start(tik.abs_offset))?;
        let mut raw = vec![0u8; tik.size as usize];
        src.read_exact(&mut raw)?;
        if let Ok(t) = Ticket::from_bytes(&raw) {
            enc_title_keys_by_rights
                .entry(t.rights_id)
                .or_insert(t.title_key_block);
        }
    }

    struct PreparedNca {
        source_path: String,
        abs_offset: u64,
        size: u64,
        patched_header: Vec<u8>,
    }
    let mut prepared = Vec::with_capacity(ncas.len());

    // Build secure partition HFS0
    let mut secure_builder = Hfs0Builder::new();
    for nca in ncas {
        let mut src = BufReader::new(File::open(&nca.source_path)?);
        src.seek(SeekFrom::Start(nca.abs_offset))?;
        let mut enc_header = vec![0u8; 0xC00];
        src.read_exact(&mut enc_header)?;
        let parsed = NcaHeader::from_encrypted(&enc_header, ks)?;
        let title_key = if parsed.has_rights_id() {
            if let Some(enc_title_key) = enc_title_keys_by_rights.get(&parsed.rights_id) {
                let mkrev = parsed.key_generation().saturating_sub(1);
                Some(ks.decrypt_title_key(enc_title_key, mkrev)?)
            } else {
                None
            }
        } else {
            None
        };
        let patched_header =
            crate::formats::nca::rewrite_header_for_xci(&enc_header, ks, title_key)?;
        let hash = crate::crypto::hash::sha256(&patched_header[..0x200]);
        secure_builder.add_file(nca.nca_name.clone(), nca.size, hash, 0x200);
        prepared.push(PreparedNca {
            source_path: nca.source_path.clone(),
            abs_offset: nca.abs_offset,
            size: nca.size,
            patched_header,
        });
    }

    let secure_header = secure_builder.build_header_aligned(0x200);
    let secure_total = secure_builder.total_size();

    // Build root HFS0 with gamecard-like partitions: update, normal, secure.
    let empty_partition = empty_hfs0_partition_0x200();
    let empty_hash = crate::crypto::hash::sha256(&empty_partition);
    let secure_hash = crate::crypto::hash::sha256(&secure_header);

    let mut root_builder = Hfs0Builder::new();
    root_builder.add_file(
        "update".to_string(),
        empty_partition.len() as u64,
        empty_hash,
        0x200,
    );
    root_builder.add_file(
        "normal".to_string(),
        empty_partition.len() as u64,
        empty_hash,
        0x200,
    );
    root_builder.add_file(
        "secure".to_string(),
        secure_total,
        secure_hash,
        secure_header.len() as u32,
    );

    let root_header = root_builder.build_header_aligned(0x200);
    let root_hash = crate::crypto::hash::sha256(&root_header);

    // Build XCI header
    let hfs0_offset: u64 = 0xF000; // Standard offset
    let secure_offset = hfs0_offset + root_header.len() as u64 + (empty_partition.len() as u64 * 2);
    let total_data_size = secure_offset + secure_total;

    if secure_offset % types::MEDIA_SIZE != 0 {
        return Err(NscbError::InvalidData(
            "Secure partition offset is not media-aligned".into(),
        ));
    }

    let mut xci_builder = XciBuilder::new();
    xci_builder.auto_card_size(total_data_size);

    let xci_header = xci_builder.build_header(
        hfs0_offset,
        secure_offset,
        root_header.len() as u64,
        &root_hash,
        total_data_size,
    );
    let game_info = xci_builder.build_game_info(total_data_size);
    let sig_padding = xci_builder.sig_padding();
    let fake_cert = xci_builder.fake_certificate();

    // Write output
    let pb = progress::file_progress(total_data_size, "Building XCI");
    let mut out = BufWriter::new(File::create(output_path)?);

    // Write XCI header
    out.write_all(&xci_header)?;
    out.write_all(&game_info)?;
    out.write_all(&sig_padding)?;
    out.write_all(&fake_cert)?;
    if (xci_header.len() + game_info.len() + sig_padding.len() + fake_cert.len()) as u64
        != XCI_PREFIX_SIZE
    {
        return Err(NscbError::InvalidData("XCI prefix size mismatch".into()));
    }

    // Write root HFS0 header
    out.write_all(&root_header)?;

    // Write empty update/normal partitions
    out.write_all(&empty_partition)?;
    out.write_all(&empty_partition)?;

    // Write secure partition header
    out.write_all(&secure_header)?;

    // Write NCA data
    for nca in &prepared {
        out.write_all(&nca.patched_header)?;
        pb.inc(nca.patched_header.len() as u64);
        if nca.size > nca.patched_header.len() as u64 {
            let mut src = BufReader::new(File::open(&nca.source_path)?);
            uio::copy_section(
                &mut src,
                &mut out,
                nca.abs_offset + nca.patched_header.len() as u64,
                nca.size - nca.patched_header.len() as u64,
                Some(&pb),
            )?;
        }
    }

    out.flush()?;
    pb.finish_with_message("Done");
    Ok(())
}

fn empty_hfs0_partition_0x200() -> Vec<u8> {
    let mut part = Vec::with_capacity(0x200);
    part.extend_from_slice(b"HFS0");
    part.extend_from_slice(&0u32.to_le_bytes());
    part.extend_from_slice(&0x1F0u32.to_le_bytes());
    part.extend_from_slice(&0u32.to_le_bytes());
    part.resize(0x200, 0);
    part
}
