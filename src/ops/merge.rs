use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

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
use crate::ops::split::{group_nsp_entries, group_xci_entries, TitleGroup};
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
    /// Source container was originally compressed (NSZ/XCZ), matching squirrel.py NCZ path quirks.
    source_was_compressed: bool,
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

#[derive(Debug)]
struct EffectiveInput {
    path: String,
    source_was_compressed: bool,
    container_hint: ContainerHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedContent {
    input_index: usize,
    version: u32,
}

#[derive(Debug, Clone, Copy)]
enum ContainerHint {
    NspLike,
    XciLike,
}

fn effective_direct_multi_rsv_cap(rsvcap: Option<u32>, keypatch: Option<u8>) -> Option<u32> {
    let mut effective = rsvcap?;
    if let Some(new_keygen) = keypatch {
        let min_rsv = crate::formats::types::get_min_rsv(new_keygen, effective);
        if min_rsv > effective {
            effective = min_rsv;
        }
    }
    Some(effective)
}

/// Merge multiple NSP/XCI files into one NSP.
pub fn merge(
    input_paths: &[&str],
    output_path: &str,
    ks: &KeyStore,
    exclude_deltas: bool,
    output_type: &str,
    nsp_direct_multi_python_mode: bool,
    rsvcap: Option<u32>,
    keypatch: Option<u8>,
    print_version: bool,
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
    let mut effective_inputs: Vec<EffectiveInput> = Vec::new();

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
                effective_inputs.push(EffectiveInput {
                    path: tmp_path,
                    source_was_compressed: true,
                    container_hint: if ext == "xcz" {
                        ContainerHint::XciLike
                    } else {
                        ContainerHint::NspLike
                    },
                });
                temp_files.push(tmp);
            }
            _ => {
                effective_inputs.push(EffectiveInput {
                    path: path_str.to_string(),
                    source_was_compressed: false,
                    container_hint: match ext.as_str() {
                        "xci" => ContainerHint::XciLike,
                        _ => ContainerHint::NspLike,
                    },
                });
            }
        }
    }

    let selected_content_names = select_python_direct_multi_content(&effective_inputs, ks)?;

    for input in &effective_inputs {
        let selected_names = selected_content_names
            .get(input.path.as_str())
            .cloned()
            .unwrap_or_default();
        let path_str = input.path.as_str();
        let source_was_compressed = input.source_was_compressed;
        let path = Path::new(path_str);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match (ext.as_str(), input.container_hint) {
            ("nsp", _) | ("", ContainerHint::NspLike) => {
                collect_from_nsp(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut all_certs,
                    &mut all_xmls,
                    &mut seen_nca_ids,
                    &mut seen_xml_names,
                    rsvcap,
                    keypatch,
                    source_was_compressed,
                    print_version,
                    &selected_names,
                )?;
            }
            ("xci", _) | ("", ContainerHint::XciLike) => {
                collect_from_xci(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut all_xmls,
                    &mut seen_nca_ids,
                    &mut seen_xml_names,
                    rsvcap,
                    keypatch,
                    source_was_compressed,
                    print_version,
                    &selected_names,
                )?;
            }
            _ => {
                return Err(NscbError::UnsupportedFormat(format!(
                    "Unknown input format: {}",
                    ext
                )));
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
        "xci" => build_xci_output(
            output_path,
            &all_ncas,
            &all_tickets,
            ks,
            rsvcap,
            keypatch,
            print_version,
        )?,
        _ => build_nsp_output(
            output_path,
            &all_ncas,
            &all_tickets,
            &all_certs,
            &all_xmls,
            nsp_direct_multi_python_mode,
            ks,
            rsvcap,
            keypatch,
            print_version,
        )?,
    }

    println!("Output written to {}", output_path);
    Ok(())
}

fn select_python_direct_multi_content(
    effective_inputs: &[EffectiveInput],
    ks: &KeyStore,
) -> Result<HashMap<String, HashSet<String>>> {
    let mut groups_by_input: Vec<Vec<TitleGroup>> = Vec::with_capacity(effective_inputs.len());

    for input in effective_inputs {
        let groups = inspect_input_groups(input, ks)?;
        groups_by_input.push(groups);
    }

    let best_by_title = pick_best_title_groups(&groups_by_input);
    let mut selected_names_by_input: HashMap<String, HashSet<String>> = HashMap::new();
    for (input_index, groups) in groups_by_input.into_iter().enumerate() {
        let selected = groups
            .into_iter()
            .filter(|group| {
                best_by_title
                    .get(&group.title_id)
                    .is_some_and(|picked| picked.input_index == input_index)
            })
            .flat_map(|group| group.entries.into_iter().map(|entry| entry.name))
            .collect::<HashSet<_>>();
        selected_names_by_input.insert(effective_inputs[input_index].path.clone(), selected);
    }

    Ok(selected_names_by_input)
}

fn pick_best_title_groups(groups_by_input: &[Vec<TitleGroup>]) -> HashMap<u64, SelectedContent> {
    let mut best_by_title: HashMap<u64, SelectedContent> = HashMap::new();
    for (input_index, groups) in groups_by_input.iter().enumerate() {
        for group in groups {
            let version = group.version.unwrap_or(0);
            match best_by_title.get(&group.title_id) {
                Some(current) if current.version >= version => {}
                _ => {
                    best_by_title.insert(
                        group.title_id,
                        SelectedContent {
                            input_index,
                            version,
                        },
                    );
                }
            }
        }
    }
    best_by_title
}

fn inspect_input_groups(input: &EffectiveInput, ks: &KeyStore) -> Result<Vec<TitleGroup>> {
    let mut file = BufReader::new(File::open(&input.path)?);
    match input.container_hint {
        ContainerHint::NspLike => {
            let nsp = Nsp::parse(&mut file)?;
            group_nsp_entries(&nsp, &mut file, &input.path, ks)
        }
        ContainerHint::XciLike => {
            let xci = Xci::parse(&mut file)?;
            group_xci_entries(&xci, &mut file, &input.path, ks)
        }
    }
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
    rsvcap: Option<u32>,
    keypatch: Option<u8>,
    source_was_compressed: bool,
    print_version: bool,
    selected_names: &HashSet<String>,
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
        if !selected_names.contains(&meta.name) {
            continue;
        }
        let meta_abs = nsp.file_abs_offset(meta);
        maybe_add_generated_xml(
            &mut file,
            meta.name.clone(),
            meta_abs,
            meta.size,
            ks,
            true,
            xmls,
            seen_xml,
            rsvcap,
            keypatch,
            print_version,
        )?;
        if let Some(cnmt) = parse_cnmt_from_meta_nca_at(&mut file, meta_abs, ks) {
            for c in &cnmt.content_entries {
                let id = c.nca_id();
                if let Some((abs_offset, size, name)) = id_to_entry.get(&id) {
                    if !selected_names.contains(name) {
                        continue;
                    }
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
                        source_was_compressed,
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
                source_was_compressed,
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
                source_was_compressed,
            );
        }
    }

    // Fallback: any remaining NCAs.
    for entry in nsp.nca_entries() {
        if !selected_names.contains(&entry.name) {
            continue;
        }
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
            source_was_compressed,
        );
    }

    // Collect tickets
    for entry in nsp.ticket_entries() {
        if !selected_names.contains(&entry.name) {
            continue;
        }
        tickets.push(TicketEntry {
            source_path: path.to_string(),
            name: entry.name.clone(),
            abs_offset: nsp.file_abs_offset(entry),
            size: entry.size,
        });
    }

    // Collect certs
    for entry in nsp.cert_entries() {
        if !selected_names.contains(&entry.name) {
            continue;
        }
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
    rsvcap: Option<u32>,
    keypatch: Option<u8>,
    source_was_compressed: bool,
    print_version: bool,
    selected_names: &HashSet<String>,
) -> Result<()> {
    let mut file = BufReader::new(File::open(path)?);
    let xci = Xci::parse(&mut file)?;

    let secure_entries = xci.secure_nca_entries(&mut file)?;

    for entry in &secure_entries {
        if !selected_names.contains(&entry.name) {
            continue;
        }
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
            source_was_compressed,
        });

        if entry.name.ends_with(".cnmt.nca") {
            let _ = maybe_add_generated_xml(
                &mut file,
                entry.name.clone(),
                entry.abs_offset,
                entry.size,
                ks,
                false,
                xmls,
                seen_xml,
                rsvcap,
                keypatch,
                print_version,
            );
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
    ks: &KeyStore,
    rsvcap: Option<u32>,
    keypatch: Option<u8>,
    print_version: bool,
) -> Result<()> {
    let effective_rsvcap = effective_direct_multi_rsv_cap(rsvcap, keypatch);
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
                        .or(Some(*nca))
                } else {
                    Some(*nca)
                };
                if let Some(entry) = to_write {
                    let src_file = File::open(&entry.source_path).map_err(|e| {
                        NscbError::Io(std::io::Error::new(
                            e.kind(),
                            format!(
                                "failed to open NCA source '{}' for '{}': {}",
                                entry.source_path, entry.nca_name, e
                            ),
                        ))
                    })?;
                    let mut src = BufReader::new(src_file);
                    if effective_rsvcap.is_some() || keypatch.is_some() {
                        src.seek(SeekFrom::Start(entry.abs_offset))?;
                        let mut nca_bytes = vec![0u8; entry.size as usize];
                        src.read_exact(&mut nca_bytes)?;
                        if let Some(cap) = effective_rsvcap {
                            if entry.nca_name.ends_with(".cnmt.nca") {
                                if let Some((patched, before, after)) =
                                    crate::formats::nca::patch_meta_nca_with_rsvcap(
                                        &nca_bytes,
                                        ks,
                                        cap,
                                        keypatch,
                                    )?
                                {
                                    if print_version {
                                        println!("CNMT {} RSV {} -> {}", entry.nca_name, before, after);
                                    }
                                    nca_bytes = patched;
                                }
                            }
                        }
                        if let Some(new_keygen) = keypatch {
                            let parsed = NcaHeader::from_encrypted(&nca_bytes[..0xC00], ks)?;
                            if new_keygen < parsed.crypto_type2 {
                                let patched_header = crate::formats::nca::rewrite_header_with_keygen(
                                    &nca_bytes[..0xC00],
                                    ks,
                                    new_keygen,
                                    false,
                                )?;
                                if print_version {
                                    println!(
                                        "NCA {} keygen {} -> {}",
                                        entry.nca_name,
                                        parsed.crypto_type2,
                                        new_keygen
                                    );
                                }
                                nca_bytes[..0xC00].copy_from_slice(&patched_header);
                            }
                        }
                        out.write_all(&nca_bytes)?;
                        pb.inc(nca_bytes.len() as u64);
                    } else {
                        uio::copy_section(&mut src, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
                    }
                }
            }
            Item::Ticket(tik) => {
                let src_file = File::open(&tik.source_path).map_err(|e| {
                    NscbError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to open ticket source '{}': {}", tik.source_path, e),
                    ))
                })?;
                let mut src = BufReader::new(src_file);
                uio::copy_section(&mut src, &mut out, tik.abs_offset, tik.size, Some(&pb))?;
            }
            Item::Cert(cert) => {
                let src_file = File::open(&cert.source_path).map_err(|e| {
                    NscbError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to open cert source '{}': {}", cert.source_path, e),
                    ))
                })?;
                let mut src = BufReader::new(src_file);
                uio::copy_section(&mut src, &mut out, cert.abs_offset, cert.size, Some(&pb))?;
            }
            Item::Xml(xml) => {
                if let Some(bytes) = &xml.inline_data {
                    out.write_all(bytes)?;
                    pb.inc(bytes.len() as u64);
                } else if let (Some(source_path), Some(abs_offset)) = (&xml.source_path, xml.abs_offset) {
                    let src_file = File::open(source_path).map_err(|e| {
                        NscbError::Io(std::io::Error::new(
                            e.kind(),
                            format!("failed to open xml source '{}': {}", source_path, e),
                        ))
                    })?;
                    let mut src = BufReader::new(src_file);
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
    source_was_compressed: bool,
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
        source_was_compressed,
    });
}

fn maybe_add_generated_xml(
    file: &mut BufReader<File>,
    meta_name: String,
    abs_offset: u64,
    size: u64,
    ks: &KeyStore,
    source_is_nsp_like: bool,
    xmls: &mut Vec<XmlEntry>,
    seen_xml: &mut HashSet<String>,
    rsvcap: Option<u32>,
    keypatch: Option<u8>,
    _print_version: bool,
) -> Result<()> {
    if !meta_name.ends_with(".cnmt.nca") {
        return Ok(());
    }
    let Some((cnmt, digest, crypto2, keygen, nsha)) = parse_meta_xml_info(file, abs_offset, size, ks)? else {
        return Ok(());
    };
    let xml_name = meta_name.trim_end_matches(".nca").to_string() + ".xml";
    if !seen_xml.insert(xml_name.to_ascii_lowercase()) {
        return Ok(());
    }
    let mut cnmt = cnmt;
    if let Some(cap) = effective_direct_multi_rsv_cap(rsvcap, keypatch) {
        let before = cnmt.required_system_version;
        let keygen_u8 = keypatch.unwrap_or(keygen);
        let after = crate::formats::types::apply_patcher_meta_rsv(keygen_u8, before, cap);
        cnmt.patch_required_system_version(after);
    }
    let xml = build_python_cnmt_xml(&meta_name, size, &cnmt, &digest, crypto2, keygen, &nsha);
    xmls.push(XmlEntry {
        source_path: None,
        name: xml_name,
        abs_offset: None,
        size: xml.len() as u64,
        inline_data: Some(xml.into_bytes()),
        source_is_nsp_like,
    });
    Ok(())
}

pub(crate) fn generate_meta_xml_bytes(
    file: &mut BufReader<File>,
    meta_name: &str,
    abs_offset: u64,
    size: u64,
    ks: &KeyStore,
    rsvcap: Option<u32>,
    keypatch: Option<u8>,
    meta_hash_override: Option<&str>,
) -> Result<Option<(String, Vec<u8>)>> {
    if !meta_name.ends_with(".cnmt.nca") {
        return Ok(None);
    }
    let Some((cnmt, digest, crypto2, keygen, nsha)) = parse_meta_xml_info(file, abs_offset, size, ks)? else {
        return Ok(None);
    };
    let xml_name = meta_name.trim_end_matches(".nca").to_string() + ".xml";
    let mut cnmt = cnmt;
    if let Some(cap) = effective_direct_multi_rsv_cap(rsvcap, keypatch) {
        let before = cnmt.required_system_version;
        let keygen_u8 = keypatch.unwrap_or(keygen);
        let after = crate::formats::types::apply_patcher_meta_rsv(keygen_u8, before, cap);
        cnmt.patch_required_system_version(after);
    }
    let meta_hash = meta_hash_override.unwrap_or(&nsha);
    let xml = build_python_cnmt_xml(meta_name, size, &cnmt, &digest, crypto2, keygen, meta_hash);
    Ok(Some((xml_name, xml.into_bytes())))
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

    let header = NcaHeader::from_encrypted(&nca_bytes[..0xC00], ks)?;
    let keys = header.decrypt_key_area(ks)?;
    let crypto2 = header.crypto_type2;
    let keygen = header.python_patcher_key_generation();
    // Match squirrel.py's direct-multi xml path, which hashes from the NCA stream cursor
    // after the embedded PFS0 is opened. For meta NCAs this lands at `pfs0_abs + 0x30`.
    let nsha_start = (0xC00u64 + header.htable_offset() + header.pfs0_offset() + 0x30)
        .min(nca_bytes.len() as u64) as usize;
    let nsha = hex::encode(crate::crypto::hash::sha256(&nca_bytes[nsha_start..]));
    let xml_digest = python_xml_digest(&nca_bytes, &header, &keys).unwrap_or([0u8; 32]);

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
            let digest = if xml_digest != [0u8; 32] { xml_digest } else { digest };
            return Ok(Some((cnmt, digest, crypto2, keygen, nsha)));
        }
        let nonce = header.section_ctr_nonce(sec_idx);
        for key in &keys {
            let mut dec = section.to_vec();
            aes_ctr_transform_in_place(key, &nonce, sec.start_offset(), &mut dec);
            if let Some((cnmt, digest)) = parse_cnmt_and_digest_from_section(&dec) {
                let digest = if xml_digest != [0u8; 32] { xml_digest } else { digest };
                return Ok(Some((cnmt, digest, crypto2, keygen, nsha)));
            }
        }
    }

    if let Some(cnmt) = parse_cnmt_from_meta_nca_at(file, abs_offset, ks) {
        return Ok(Some((cnmt, xml_digest, crypto2, keygen, nsha)));
    }

    Ok(None)
}

fn python_xml_digest(
    encrypted_nca: &[u8],
    header: &NcaHeader,
    section_keys: &[[u8; 16]; 4],
) -> Option<[u8; 32]> {
    let pfs0_abs = 0xC00u64
        .checked_add(header.htable_offset())?
        .checked_add(header.pfs0_offset())?;
    let digest_abs = pfs0_abs.checked_add(header.pfs0_size())?.checked_sub(0x20)?;

    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        let sec_start = sec.start_offset();
        let sec_end = sec.end_offset();
        if !(sec_start <= digest_abs && digest_abs + 0x20 <= sec_end) {
            continue;
        }
        let sec_start_usize = sec_start as usize;
        let sec_end_usize = sec_end as usize;
        if sec_end_usize > encrypted_nca.len() {
            continue;
        }
        let rel = (digest_abs - sec_start) as usize;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&encrypted_nca[sec_start_usize + rel..sec_start_usize + rel + 0x20]);
        if header.section_crypto_type(sec_idx) != 0 {
            let key = section_keys[2];
            let counter = header.section_crypto_counter(sec_idx);
            aes_ctr_transform_with_counter_in_place(&key, &counter, digest_abs, &mut digest);
        }
        return Some(digest);
    }
    None
}

fn aes_ctr_transform_with_counter_in_place(
    key: &[u8; 16],
    counter16: &[u8; 16],
    file_offset: u64,
    data: &mut [u8],
) {
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
            let mut ctr = *counter16;
            ctr[8..].copy_from_slice(&block_index.to_be_bytes());
            let mut block = aes::Block::from(ctr);
            cipher.encrypt_block(&mut block);
            cached_keystream.copy_from_slice(&block);
            cached_block_index = block_index;
        }
        *byte ^= cached_keystream[byte_in_block];
    }
}

#[cfg(test)]
mod tests {
    use super::{pick_best_title_groups, SelectedContent};
    use crate::formats::types::TitleType;
    use crate::ops::split::{GroupedEntry, TitleGroup};
    use std::collections::HashMap;

    fn fake_group(title_id: u64, version: u32, title_type: Option<TitleType>) -> TitleGroup {
        TitleGroup {
            title_id,
            version: Some(version),
            title_type,
            game_name: "test".to_string(),
            entries: vec![GroupedEntry {
                name: format!("{title_id:016x}.nca"),
                abs_offset: 0,
                size: 1,
            }],
        }
    }

    #[test]
    fn direct_multi_keeps_highest_version_per_title_id() {
        let groups = vec![
            vec![fake_group(0x0100_0000_0000_0800, 262_144, Some(TitleType::Patch))],
            vec![fake_group(0x0100_0000_0000_0800, 327_680, Some(TitleType::Patch))],
        ];
        let picked = pick_best_title_groups(&groups);
        let expected = HashMap::from([(
            0x0100_0000_0000_0800,
            SelectedContent {
                input_index: 1,
                version: 327_680,
            },
        )]);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked.get(&0x0100_0000_0000_0800).map(|s| s.input_index), Some(1));
        assert_eq!(picked.get(&0x0100_0000_0000_0800).map(|s| s.version), Some(327_680));
        assert_eq!(picked, expected);
    }

    #[test]
    fn direct_multi_keeps_first_when_versions_tie() {
        let groups = vec![
            vec![fake_group(0x0100_0000_0000_0800, 327_680, Some(TitleType::Patch))],
            vec![fake_group(0x0100_0000_0000_0800, 327_680, Some(TitleType::Patch))],
        ];
        let picked = pick_best_title_groups(&groups);
        assert_eq!(picked.get(&0x0100_0000_0000_0800).map(|s| s.input_index), Some(0));
        assert_eq!(picked.get(&0x0100_0000_0000_0800).map(|s| s.version), Some(327_680));
    }
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
    out.push_str(&format!(
        "  <RequiredSystemVersion>{}</RequiredSystemVersion>\n",
        cnmt.required_system_version
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
    rsvcap: Option<u32>,
    keypatch: Option<u8>,
    print_version: bool,
) -> Result<()> {
    let effective_rsvcap = effective_direct_multi_rsv_cap(rsvcap, keypatch);
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
    let mut source_headers_by_path: HashMap<String, Vec<NcaHeader>> = HashMap::new();

    for nca in ncas {
        if !nca.source_is_nsp_like && effective_rsvcap.is_none() && keypatch.is_none() {
            continue;
        }
        let mut src = BufReader::new(File::open(&nca.source_path).map_err(|e| {
            NscbError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to open source '{}' while preparing XCI headers for '{}': {}",
                    nca.source_path, nca.nca_name, e
                ),
            ))
        })?);
        src.seek(SeekFrom::Start(nca.abs_offset))?;
        let mut enc_header = vec![0u8; 0xC00];
        src.read_exact(&mut enc_header)?;
        source_headers_by_path
            .entry(nca.source_path.clone())
            .or_default()
            .push(NcaHeader::from_encrypted(&enc_header, ks).map_err(|e| {
                NscbError::InvalidData(format!(
                    "failed to parse NCA header for '{}' from '{}' at offset {}: {}",
                    nca.nca_name, nca.source_path, nca.abs_offset, e
                ))
            })?);
    }
    let source_is_cartridge: HashMap<String, bool> = source_headers_by_path
        .iter()
        .map(|(path, headers)| {
            let has_program = headers
                .iter()
                .any(|header| header.content_type_enum() == Some(crate::formats::types::ContentType::Program));
            (
                path.clone(),
                has_program && crate::formats::nca::python_xci_is_cartridge(headers, ks),
            )
        })
        .collect();

    // Build secure partition HFS0
    let mut secure_builder = Hfs0Builder::new();
    for nca in ncas {
        let mut src = BufReader::new(File::open(&nca.source_path).map_err(|e| {
            NscbError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to open source '{}' while building XCI for '{}': {}",
                    nca.source_path, nca.nca_name, e
                ),
            ))
        })?);
        src.seek(SeekFrom::Start(nca.abs_offset))?;
        let mut enc_header = vec![0u8; 0xC00];
        src.read_exact(&mut enc_header)?;
        if !nca.source_is_nsp_like && effective_rsvcap.is_none() && keypatch.is_none() {
            let hash = crate::crypto::hash::sha256(&enc_header[..0x200]);
            secure_builder.add_file(nca.nca_name.clone(), nca.size, hash, 0x200);
            prepared.push(PreparedNca {
                source_path: nca.source_path.clone(),
                abs_offset: nca.abs_offset,
                size: nca.size,
                patched_header: enc_header,
            });
            continue;
        }
        let parsed = NcaHeader::from_encrypted(&enc_header, ks).map_err(|e| {
            NscbError::InvalidData(format!(
                "failed to parse XCI build header for '{}' from '{}' at offset {}: {}",
                nca.nca_name, nca.source_path, nca.abs_offset, e
            ))
        })?;
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
        let gc_flag = crate::formats::nca::python_xci_gamecard_flag(
            &parsed,
            ks,
            *source_is_cartridge.get(&nca.source_path).unwrap_or(&false),
        );
        let mut final_nca: Option<Vec<u8>> = None;
        let mut patched_header =
            crate::formats::nca::rewrite_header_for_xci(&enc_header, ks, title_key, gc_flag)?;
        if let Some(cap) = effective_rsvcap {
            if nca.nca_name.ends_with(".cnmt.nca") {
                src.seek(SeekFrom::Start(nca.abs_offset))?;
                let mut full_nca = vec![0u8; nca.size as usize];
                src.read_exact(&mut full_nca)?;
                if let Some((patched, before, after)) =
                    crate::formats::nca::patch_meta_nca_with_rsvcap(&full_nca, ks, cap, keypatch)?
                {
                    if print_version {
                        println!("CNMT {} RSV {} -> {}", nca.nca_name, before, after);
                    }
                    patched_header = patched[..0xC00].to_vec();
                    final_nca = Some(patched);
                }
            }
        }
        if let Some(new_keygen) = keypatch {
            if new_keygen < parsed.crypto_type2 {
                patched_header = crate::formats::nca::rewrite_header_with_keygen(
                    &patched_header,
                    ks,
                    new_keygen,
                    true,
                )?;
                if print_version {
                    println!(
                        "NCA {} keygen {} -> {}",
                        nca.nca_name,
                        parsed.crypto_type2,
                        new_keygen
                    );
                }
            }
        }
        if let Some(bytes) = &mut final_nca {
            bytes[..0xC00].copy_from_slice(&patched_header);
        }
        let hash = crate::crypto::hash::sha256(&patched_header[..0x200]);
        secure_builder.add_file(nca.nca_name.clone(), nca.size, hash, 0x200);
        prepared.push(PreparedNca {
            source_path: nca.source_path.clone(),
            abs_offset: nca.abs_offset,
            size: nca.size,
            patched_header: final_nca.unwrap_or(patched_header),
        });
    }

    let secure_header = secure_builder.build_header_aligned(0x200);
    let secure_payload_total =
        secure_header.len() as u64 + prepared.iter().map(|n| n.size).sum::<u64>();
    let secure_total = crate::util::align::align_up(secure_payload_total, types::MEDIA_SIZE);

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

    if secure_total > secure_payload_total {
        let pad_len = (secure_total - secure_payload_total) as usize;
        out.write_all(&vec![0u8; pad_len])?;
        pb.inc(pad_len as u64);
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
