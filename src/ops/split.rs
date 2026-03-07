use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use regex::Regex;

use crate::crypto::aes_xts::NintendoXts;
use crate::error::{NscbError, Result};
use crate::formats::cnmt::Cnmt;
use crate::formats::nca;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::{Pfs0, Pfs0Entry};
use crate::formats::types::TitleType;
use crate::formats::xci::Xci;
use crate::keys::KeyStore;
use crate::util::{io as uio, progress};

#[derive(Clone, Debug)]
pub(crate) struct GroupedEntry {
    pub name: String,
    pub abs_offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct TitleGroup {
    pub title_id: u64,
    pub version: Option<u32>,
    pub title_type: Option<TitleType>,
    pub game_name: String,
    pub entries: Vec<GroupedEntry>,
}

/// Split a multi-title NSP/XCI into separate NSP files by base title ID.
pub fn split(input_path: &str, output_dir: &str, ks: &KeyStore) -> Result<()> {
    let path = Path::new(input_path);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    std::fs::create_dir_all(output_dir)?;

    match ext.as_str() {
        "nsp" | "nsz" => split_nsp(input_path, output_dir, ks),
        "xci" | "xcz" => split_xci(input_path, output_dir, ks),
        _ => Err(NscbError::UnsupportedFormat(format!(
            "Cannot split: {}",
            ext
        ))),
    }
}

fn split_nsp(input_path: &str, output_dir: &str, ks: &KeyStore) -> Result<()> {
    let mut file = BufReader::new(File::open(input_path)?);
    let nsp = Nsp::parse(&mut file)?;
    let groups = group_nsp_entries(&nsp, &mut file, input_path, ks)?;
    println!("Found {} title groups", groups.len());

    for group in &groups {
        let output_name = split_output_folder_name(
            group.title_id,
            group.version,
            group.title_type,
            &group.game_name,
        );
        let output_path = Path::new(output_dir).join(&output_name);
        std::fs::create_dir_all(&output_path)?;
        println!("Extracting {} ({} files)", output_name, group.entries.len());
        let total: u64 = group.entries.iter().map(|e| e.size).sum();
        let pb = progress::file_progress(total, &format!("Extracting {}", output_name));

        for entry in &group.entries {
            let out_file = output_path.join(&entry.name);
            let mut out = BufWriter::new(File::create(out_file)?);
            uio::copy_section(&mut file, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
            out.flush()?;
        }

        pb.finish_with_message("Done");
    }

    println!(
        "Split complete: {} folders written to {}",
        groups.len(),
        output_dir
    );
    Ok(())
}

fn nca_id_from_filename(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    for ext in [".nca", ".ncz"] {
        if let Some(stripped) = lower.strip_suffix(ext) {
            if stripped.len() == 32 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(stripped.to_string());
            }
        }
    }
    None
}

fn collect_title_ids_from_ticket_names(nsp: &Nsp) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for tik in nsp.ticket_entries() {
        let lower = tik.name.to_ascii_lowercase();
        if let Some(stem) = lower.strip_suffix(".tik") {
            if stem.len() == 32 && stem.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(tid) = u64::from_str_radix(&stem[..16], 16) {
                    out.insert(tid);
                }
            }
        }
    }
    out
}

#[derive(Clone, Debug)]
struct SplitGroupMeta {
    title_id: u64,
    version: u32,
    title_type: Option<TitleType>,
}

pub(crate) fn split_output_name(
    group_id: u64,
    version: Option<u32>,
    title_type: Option<TitleType>,
    base_name: &str,
) -> String {
    let tid = format!("{:016x}", group_id);
    match title_type {
        Some(TitleType::Patch) => {
            let v = version.unwrap_or(0);
            format!("{} [{}][v{}][UPD].nsp", base_name, tid, v)
        }
        Some(TitleType::AddOnContent) => {
            let v = version.unwrap_or(0);
            format!("{} [{}][v{}][DLC].nsp", base_name, tid, v)
        }
        Some(TitleType::Application) => format!("{} [{}] [v{}].nsp", base_name, tid, version.unwrap_or(0)),
        _ => {
            let is_update = (group_id & 0xFFF) == 0x800;
            let is_base = (group_id & 0xFFF) == 0x000;
            if is_update {
                let v = version.unwrap_or(0);
                format!("{} [{}][v{}][UPD].nsp", base_name, tid, v)
            } else if is_base {
                format!("{} [{}] [v{}].nsp", base_name, tid, version.unwrap_or(0))
            } else if let Some(v) = version {
                format!("{} [{}][v{}].nsp", base_name, tid, v)
            } else {
                format!("{}.nsp", tid)
            }
        }
    }
}

fn split_output_folder_name(
    group_id: u64,
    version: Option<u32>,
    title_type: Option<TitleType>,
    base_name: &str,
) -> String {
    split_output_name(group_id, version, title_type, base_name)
        .trim_end_matches(".nsp")
        .to_string()
}

fn infer_game_name_from_input(input_path: &str) -> String {
    let stem = Path::new(input_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("split")
        .to_string();

    // Remove trailing tag blocks like [..] and (..), then trim separators.
    let bracket_re = Regex::new(r"\s*\[[^\]]*\]").unwrap();
    let paren_re = Regex::new(r"\s*\([^)]*\)").unwrap();
    let mut s = bracket_re.replace_all(&stem, "").to_string();
    s = paren_re.replace_all(&s, "").to_string();
    let s = s
        .trim()
        .trim_matches(|c: char| c == '-' || c == '_' || c.is_whitespace());

    if s.is_empty() {
        "split".to_string()
    } else {
        s.to_string()
    }
}

fn infer_game_name_from_nsp<R: Read + Seek>(nsp: &Nsp, reader: &mut R, ks: &KeyStore) -> Option<String> {
    for entry in nsp.nca_entries() {
        let abs_offset = nsp.file_abs_offset(entry);
        if let Ok(info) = nca::parse_nca_info(reader, abs_offset, entry.size, &entry.name, ks) {
            if info.content_type == Some(crate::formats::types::ContentType::Control) {
                if let Some(name) = parse_nacp_title_from_control_nca(reader, abs_offset, ks) {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn infer_version_from_input(input_path: &str) -> Option<u32> {
    let stem = Path::new(input_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let re = Regex::new(r"\[v(\d+)\]").unwrap();
    let mut last: Option<u32> = None;
    for cap in re.captures_iter(stem) {
        if let Ok(v) = cap[1].parse::<u32>() {
            last = Some(v);
        }
    }
    last
}

fn split_xci(input_path: &str, output_dir: &str, ks: &KeyStore) -> Result<()> {
    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;
    let groups = group_xci_entries(&xci, &mut file, input_path, ks)?;
    println!("Found {} title groups in XCI", groups.len());

    for group in &groups {
        let output_name = split_output_folder_name(
            group.title_id,
            group.version,
            group.title_type,
            &group.game_name,
        );
        let output_path = Path::new(output_dir).join(&output_name);
        std::fs::create_dir_all(&output_path)?;
        println!("Extracting {} ({} files)", output_name, group.entries.len());
        let total: u64 = group.entries.iter().map(|e| e.size).sum();
        let pb = progress::file_progress(total, &format!("Extracting {}", output_name));

        for entry in &group.entries {
            let out_file = output_path.join(&entry.name);
            let mut out = BufWriter::new(File::create(out_file)?);
            uio::copy_section(&mut file, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
            out.flush()?;
        }
        pb.finish_with_message("Done");
    }

    Ok(())
}

fn infer_game_name_from_xci<R: Read + Seek>(
    secure_entries: &[crate::formats::xci::SecureNcaEntry],
    reader: &mut R,
    ks: &KeyStore,
) -> Option<String> {
    for entry in secure_entries {
        if let Ok(info) = nca::parse_nca_info(reader, entry.abs_offset, entry.size, &entry.name, ks) {
            if info.content_type == Some(crate::formats::types::ContentType::Control) {
                if let Some(name) = parse_nacp_title_from_control_nca(reader, entry.abs_offset, ks) {
                    return Some(name);
                }
            }
        }
    }
    None
}

pub(crate) fn group_nsp_entries<R: Read + Seek>(
    nsp: &Nsp,
    reader: &mut R,
    input_path: &str,
    ks: &KeyStore,
) -> Result<Vec<TitleGroup>> {
    let known_title_ids = collect_title_ids_from_ticket_names(nsp);
    let base_name =
        infer_game_name_from_nsp(nsp, reader, ks).unwrap_or_else(|| infer_game_name_from_input(input_path));
    let guessed_version = infer_version_from_input(input_path);
    let (groups, group_meta) = build_nsp_group_map(nsp, reader, ks, &known_title_ids);
    let mut result = groups
        .into_iter()
        .map(|(title_id, entries)| {
            let mut items = entries
                .into_iter()
                .map(|entry| GroupedEntry {
                    name: entry.name.clone(),
                    abs_offset: nsp.file_abs_offset(entry),
                    size: entry.size,
                })
                .collect::<Vec<_>>();
            let ticket_prefix = format!("{:016x}", title_id);
            for entry in nsp.ticket_entries() {
                if entry.name.to_ascii_lowercase().starts_with(&ticket_prefix) {
                    items.push(GroupedEntry {
                        name: entry.name.clone(),
                        abs_offset: nsp.file_abs_offset(entry),
                        size: entry.size,
                    });
                }
            }
            for entry in nsp.cert_entries() {
                items.push(GroupedEntry {
                    name: entry.name.clone(),
                    abs_offset: nsp.file_abs_offset(entry),
                    size: entry.size,
                });
            }
            TitleGroup {
                title_id,
                version: group_meta.get(&title_id).map(|meta| meta.version).or(guessed_version),
                title_type: group_meta.get(&title_id).and_then(|meta| meta.title_type),
                game_name: base_name.clone(),
                entries: items,
            }
        })
        .collect::<Vec<_>>();
    result.sort_by_key(|group| group.title_id);
    Ok(result)
}

pub(crate) fn group_xci_entries<R: Read + Seek>(
    xci: &Xci,
    reader: &mut R,
    input_path: &str,
    ks: &KeyStore,
) -> Result<Vec<TitleGroup>> {
    let secure_entries = xci.secure_nca_entries(reader)?;
    let base_name = infer_game_name_from_xci(&secure_entries, reader, ks)
        .unwrap_or_else(|| infer_game_name_from_input(input_path));
    let guessed_version = infer_version_from_input(input_path);
    let (groups, group_meta) = build_xci_group_map(&secure_entries, reader, ks);
    let mut result = groups
        .into_iter()
        .map(|(title_id, entries)| {
            let fallback = infer_meta_from_title_id(title_id, guessed_version);
            TitleGroup {
                title_id,
                version: group_meta
                    .get(&title_id)
                    .map(|meta| meta.version)
                    .or(fallback.map(|(version, _)| version)),
                title_type: group_meta
                    .get(&title_id)
                    .and_then(|meta| meta.title_type)
                    .or(fallback.and_then(|(_, title_type)| title_type)),
                game_name: base_name.clone(),
                entries: entries
                    .into_iter()
                    .map(|entry| GroupedEntry {
                        name: entry.name.clone(),
                        abs_offset: entry.abs_offset,
                        size: entry.size,
                    })
                    .collect(),
            }
        })
        .collect::<Vec<_>>();
    result.sort_by_key(|group| group.title_id);
    Ok(result)
}

fn infer_meta_from_title_id(title_id: u64, guessed_version: Option<u32>) -> Option<(u32, Option<TitleType>)> {
    let suffix = title_id & 0xFFF;
    if suffix == 0x800 {
        Some((guessed_version.unwrap_or(0), Some(TitleType::Patch)))
    } else if suffix == 0x000 {
        Some((0, Some(TitleType::Application)))
    } else {
        Some((0, Some(TitleType::AddOnContent)))
    }
}

fn build_nsp_group_map<'a, R: Read + Seek>(
    nsp: &'a Nsp,
    reader: &mut R,
    ks: &KeyStore,
    known_title_ids: &std::collections::HashSet<u64>,
) -> (HashMap<u64, Vec<&'a Pfs0Entry>>, HashMap<u64, SplitGroupMeta>) {
    let cnmt_ncas = nsp.cnmt_nca_entries(reader, ks);
    let mut cnmt_nca_map: HashMap<String, u64> = HashMap::new();
    let mut group_meta: HashMap<u64, SplitGroupMeta> = HashMap::new();
    for cnmt_info in &cnmt_ncas {
        if let Some(entry) = nsp.pfs0.find(&cnmt_info.filename) {
            let abs_offset = nsp.file_abs_offset(entry);
            if let Some(cnmt) = parse_cnmt_from_meta_nca(reader, abs_offset, ks) {
                let group_id = cnmt.title_id;
                group_meta.entry(group_id).or_insert(SplitGroupMeta {
                    title_id: cnmt.title_id,
                    version: cnmt.version,
                    title_type: cnmt.title_type_enum(),
                });
                if let Some(meta_nca_id) = nca_id_from_filename(&cnmt_info.filename) {
                    cnmt_nca_map.insert(meta_nca_id, group_id);
                }
                for nca_id in cnmt.nca_ids() {
                    cnmt_nca_map.insert(nca_id, group_id);
                }
            }
        }
    }

    let mut groups: HashMap<u64, Vec<&Pfs0Entry>> = HashMap::new();
    for entry in nsp.all_entries() {
        let nca_id = nca_id_from_filename(&entry.name).unwrap_or_else(|| entry.name.to_lowercase());
        if let Some(&base_id) = cnmt_nca_map.get(&nca_id) {
            groups.entry(base_id).or_default().push(entry);
        } else if entry.name.to_ascii_lowercase().ends_with(".nca")
            || entry.name.to_ascii_lowercase().ends_with(".ncz")
        {
            let abs_offset = nsp.file_abs_offset(entry);
            if let Ok(header) = crate::formats::nca::NcaHeader::from_reader(reader, abs_offset, ks) {
                let mut group_id = header.title_id;
                if header.has_rights_id() {
                    let rights_tid = u64::from_be_bytes(header.rights_id[..8].try_into().unwrap());
                    if known_title_ids.contains(&rights_tid) {
                        group_id = rights_tid;
                    }
                }
                groups.entry(group_id).or_default().push(entry);
            } else if let Ok(info) = nca::parse_nca_info(reader, abs_offset, entry.size, &entry.name, ks) {
                groups.entry(info.title_id).or_default().push(entry);
            }
        }
    }
    (groups, group_meta)
}

fn build_xci_group_map<'a, R: Read + Seek>(
    secure_entries: &'a [crate::formats::xci::SecureNcaEntry],
    reader: &mut R,
    ks: &KeyStore,
) -> (
    HashMap<u64, Vec<&'a crate::formats::xci::SecureNcaEntry>>,
    HashMap<u64, SplitGroupMeta>,
) {
    let mut cnmt_nca_map: HashMap<String, u64> = HashMap::new();
    let mut group_meta: HashMap<u64, SplitGroupMeta> = HashMap::new();
    for entry in secure_entries {
        if let Ok(info) = nca::parse_nca_info(reader, entry.abs_offset, entry.size, &entry.name, ks) {
            if info.content_type == Some(crate::formats::types::ContentType::Meta) {
                if let Some(cnmt) = parse_cnmt_from_meta_nca(reader, entry.abs_offset, ks) {
                    let group_id = cnmt.title_id;
                    group_meta.entry(group_id).or_insert(SplitGroupMeta {
                        title_id: cnmt.title_id,
                        version: cnmt.version,
                        title_type: cnmt.title_type_enum(),
                    });
                    if let Some(meta_nca_id) = nca_id_from_filename(&entry.name) {
                        cnmt_nca_map.insert(meta_nca_id, group_id);
                    }
                    for nca_id in cnmt.nca_ids() {
                        cnmt_nca_map.insert(nca_id, group_id);
                    }
                }
            }
        }
    }

    let mut groups: HashMap<u64, Vec<&crate::formats::xci::SecureNcaEntry>> = HashMap::new();
    if cnmt_nca_map.is_empty() {
        let mut meta_positions: Vec<(usize, u64)> = Vec::new();
        for (idx, entry) in secure_entries.iter().enumerate() {
            if entry.name.to_ascii_lowercase().ends_with(".cnmt.nca") {
                if let Ok(header) = crate::formats::nca::NcaHeader::from_reader(reader, entry.abs_offset, ks) {
                    meta_positions.push((idx, header.title_id));
                }
            }
        }
        if !meta_positions.is_empty() {
            if meta_positions.len() == 2 {
                let (m0, t0) = meta_positions[0];
                let (m1, t1) = meta_positions[1];
                let mut update_start = m1;
                for (idx, entry) in secure_entries.iter().enumerate().skip(m0 + 1).take(m1.saturating_sub(m0 + 1)) {
                    if let Ok(info) = nca::parse_nca_info(reader, entry.abs_offset, entry.size, &entry.name, ks) {
                        if info.content_type == Some(crate::formats::types::ContentType::Program) {
                            update_start = idx;
                            break;
                        }
                    }
                }
                for (idx, entry) in secure_entries.iter().enumerate() {
                    let group_id = if idx >= update_start { t1 } else { t0 };
                    groups.entry(group_id).or_default().push(entry);
                }
            } else {
                for (idx, entry) in secure_entries.iter().enumerate() {
                    let group_id = if entry.name.to_ascii_lowercase().ends_with(".cnmt.nca") {
                        crate::formats::nca::NcaHeader::from_reader(reader, entry.abs_offset, ks)
                            .map(|header| header.title_id)
                            .unwrap_or(meta_positions[0].1)
                    } else {
                        meta_positions
                            .iter()
                            .min_by_key(|(meta_idx, _)| idx.abs_diff(*meta_idx))
                            .map(|(_, tid)| *tid)
                            .unwrap_or(meta_positions[0].1)
                    };
                    groups.entry(group_id).or_default().push(entry);
                }
            }
        }
    } else {
        for entry in secure_entries {
            let nca_id = nca_id_from_filename(&entry.name).unwrap_or_else(|| entry.name.to_lowercase());
            if let Ok(header) = crate::formats::nca::NcaHeader::from_reader(reader, entry.abs_offset, ks) {
                if let Some(&group_id) = cnmt_nca_map.get(&nca_id) {
                    groups.entry(group_id).or_default().push(entry);
                    continue;
                }
                let mut group_id = header.title_id;
                if header.has_rights_id() {
                    let rights_tid = u64::from_be_bytes(header.rights_id[..8].try_into().unwrap());
                    if rights_tid != 0 {
                        group_id = rights_tid;
                    }
                }
                groups.entry(group_id).or_default().push(entry);
            } else if let Some(&group_id) = cnmt_nca_map.get(&nca_id) {
                groups.entry(group_id).or_default().push(entry);
            } else if let Ok(info) = nca::parse_nca_info(reader, entry.abs_offset, entry.size, &entry.name, ks) {
                groups.entry(info.title_id).or_default().push(entry);
            }
        }
    }
    (groups, group_meta)
}

pub(crate) fn parse_cnmt_from_meta_nca<R: Read + Seek>(
    reader: &mut R,
    nca_abs_offset: u64,
    ks: &KeyStore,
) -> Option<Cnmt> {
    let header = crate::formats::nca::NcaHeader::from_reader(reader, nca_abs_offset, ks).ok()?;
    let section_keys = header.decrypt_key_area(ks).ok();

    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        // Meta CNMT sections are tiny; skip absurdly large sections.
        if sec.size() > 64 * 1024 * 1024 {
            continue;
        }

        let sec_abs_offset = nca_abs_offset + sec.start_offset();
        let mut section_data = vec![0u8; sec.size() as usize];
        if reader.seek(SeekFrom::Start(sec_abs_offset)).is_err() {
            continue;
        }
        if reader.read_exact(&mut section_data).is_err() {
            continue;
        }

        // First try raw (already-plaintext section).
        if let Some(cnmt) = parse_cnmt_from_section_bytes(&section_data) {
            return Some(cnmt);
        }
        if let Some(cnmt) = parse_cnmt_from_section_bytes_allow_empty(&section_data) {
            return Some(cnmt);
        }

        // If raw failed, try CTR transform with each key-area slot.
        if let Some(keys) = &section_keys {
            let nonce = header.section_ctr_nonce(sec_idx);
            for key in keys {
                for &start in &[sec.start_offset(), 0u64] {
                    let mut dec_be = section_data.clone();
                    aes_ctr_transform_in_place(key, &nonce, start, true, &mut dec_be);
                    if let Some(cnmt) = parse_cnmt_from_section_bytes(&dec_be) {
                        return Some(cnmt);
                    }
                    if let Some(cnmt) = parse_cnmt_from_section_bytes_allow_empty(&dec_be) {
                        return Some(cnmt);
                    }

                    let mut dec_le = section_data.clone();
                    aes_ctr_transform_in_place(key, &nonce, start, false, &mut dec_le);
                    if let Some(cnmt) = parse_cnmt_from_section_bytes(&dec_le) {
                        return Some(cnmt);
                    }
                    if let Some(cnmt) = parse_cnmt_from_section_bytes_allow_empty(&dec_le) {
                        return Some(cnmt);
                    }
                }
            }

            // Some metadata sections are XTS-encrypted.
            if header.section_crypto_type(sec_idx) == 2 {
                let pairs = [(0usize, 1usize), (1, 0), (2, 3), (3, 2), (0, 2), (2, 0)];
                for (a, b) in pairs {
                    let mut xts_key = [0u8; 32];
                    xts_key[..16].copy_from_slice(&keys[a]);
                    xts_key[16..].copy_from_slice(&keys[b]);
                    let Ok(xts) = NintendoXts::new(&xts_key) else {
                        continue;
                    };
                    for &start_sector in &[(sec.start_offset() / 0x200), 0u64] {
                        for &le_sector in &[true, false] {
                            let mut dec = section_data.clone();
                            xts.decrypt_with_endian(start_sector, &mut dec, le_sector);
                            if let Some(cnmt) = parse_cnmt_from_section_bytes(&dec) {
                                return Some(cnmt);
                            }
                            if let Some(cnmt) = parse_cnmt_from_section_bytes_allow_empty(&dec) {
                                return Some(cnmt);
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: allow empty/edge CNMTs so meta NCAs still get grouped deterministically.
    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 || sec.size() > 64 * 1024 * 1024 {
            continue;
        }
        let sec_abs_offset = nca_abs_offset + sec.start_offset();
        let mut section_data = vec![0u8; sec.size() as usize];
        if reader.seek(SeekFrom::Start(sec_abs_offset)).is_err() {
            continue;
        }
        if reader.read_exact(&mut section_data).is_err() {
            continue;
        }
        if let Some(cnmt) = parse_cnmt_from_section_bytes_allow_empty(&section_data) {
            return Some(cnmt);
        }
    }

    None
}

pub(crate) fn parse_nacp_title_from_control_nca<R: Read + Seek>(
    reader: &mut R,
    nca_abs_offset: u64,
    ks: &KeyStore,
) -> Option<String> {
    let header = crate::formats::nca::NcaHeader::from_reader(reader, nca_abs_offset, ks).ok()?;
    let section_keys = header.decrypt_key_area(ks).ok();

    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        if sec.size() > 64 * 1024 * 1024 {
            continue;
        }

        let sec_abs_offset = nca_abs_offset + sec.start_offset();
        let mut section_data = vec![0u8; sec.size() as usize];
        if reader.seek(SeekFrom::Start(sec_abs_offset)).is_err() {
            continue;
        }
        if reader.read_exact(&mut section_data).is_err() {
            continue;
        }

        if let Some(title) = parse_nacp_title_from_section_bytes(&section_data) {
            return Some(title);
        }

        if let Some(keys) = &section_keys {
            let nonce = header.section_ctr_nonce(sec_idx);
            for key in keys {
                for &start in &[sec.start_offset(), 0u64] {
                    let mut dec_be = section_data.clone();
                    aes_ctr_transform_in_place(key, &nonce, start, true, &mut dec_be);
                    if let Some(title) = parse_nacp_title_from_section_bytes(&dec_be) {
                        return Some(title);
                    }

                    let mut dec_le = section_data.clone();
                    aes_ctr_transform_in_place(key, &nonce, start, false, &mut dec_le);
                    if let Some(title) = parse_nacp_title_from_section_bytes(&dec_le) {
                        return Some(title);
                    }
                }
            }

            if header.section_crypto_type(sec_idx) == 2 {
                let pairs = [(0usize, 1usize), (1, 0), (2, 3), (3, 2), (0, 2), (2, 0)];
                for (a, b) in pairs {
                    let mut xts_key = [0u8; 32];
                    xts_key[..16].copy_from_slice(&keys[a]);
                    xts_key[16..].copy_from_slice(&keys[b]);
                    let Ok(xts) = NintendoXts::new(&xts_key) else {
                        continue;
                    };
                    for &start_sector in &[(sec.start_offset() / 0x200), 0u64] {
                        for &le_sector in &[true, false] {
                            let mut dec = section_data.clone();
                            xts.decrypt_with_endian(start_sector, &mut dec, le_sector);
                            if let Some(title) = parse_nacp_title_from_section_bytes(&dec) {
                                return Some(title);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn parse_cnmt_from_section_bytes(section_data: &[u8]) -> Option<Cnmt> {
    for off in pfs0_candidate_offsets(section_data) {
        let mut cursor = Cursor::new(section_data);
        let Ok(pfs) = Pfs0::parse_at(&mut cursor, off as u64) else {
            continue;
        };
        for entry in &pfs.entries {
            if entry.name.ends_with(".cnmt") {
                let bytes = pfs.read_file(&mut cursor, &entry.name).ok()?;
                if let Ok(cnmt) = Cnmt::from_bytes(&bytes) {
                    // Filter out false-positive parses from undecrypted garbage.
                    let plausible_title = (cnmt.title_id >> 52) == 0x100;
                    if plausible_title && !cnmt.content_entries.is_empty() {
                        return Some(cnmt);
                    }
                }
            }
        }
    }
    None
}

fn parse_nacp_title_from_section_bytes(section_data: &[u8]) -> Option<String> {
    for off in pfs0_candidate_offsets(section_data) {
        let mut cursor = Cursor::new(section_data);
        let Ok(pfs) = Pfs0::parse_at(&mut cursor, off as u64) else {
            continue;
        };
        for entry in &pfs.entries {
            if entry.name.ends_with(".nacp") {
                let bytes = pfs.read_file(&mut cursor, &entry.name).ok()?;
                if let Ok(title) = crate::formats::nacp::parse_title(&bytes) {
                    return Some(title);
                }
            }
        }
    }
    crate::formats::nacp::parse_title_heuristic_scan(section_data)
}

fn parse_cnmt_from_section_bytes_allow_empty(section_data: &[u8]) -> Option<Cnmt> {
    for off in pfs0_candidate_offsets(section_data) {
        let mut cursor = Cursor::new(section_data);
        let Ok(pfs) = Pfs0::parse_at(&mut cursor, off as u64) else {
            continue;
        };
        for entry in &pfs.entries {
            if entry.name.ends_with(".cnmt") {
                let bytes = pfs.read_file(&mut cursor, &entry.name).ok()?;
                if let Ok(cnmt) = Cnmt::from_bytes(&bytes) {
                    return Some(cnmt);
                }
            }
        }
    }
    None
}

fn pfs0_candidate_offsets(section_data: &[u8]) -> Vec<usize> {
    let mut out = vec![0usize];
    let scan_len = section_data.len().min(1024 * 1024);
    if scan_len >= 4 {
        for i in 0..=(scan_len - 4) {
            if &section_data[i..i + 4] == b"PFS0" {
                out.push(i);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn aes_ctr_transform_in_place(
    key: &[u8; 16],
    nonce8: &[u8; 8],
    file_offset: u64,
    big_endian_counter: bool,
    data: &mut [u8],
) {
    let cipher = Aes128::new_from_slice(key);
    let Ok(cipher) = cipher else {
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
            if big_endian_counter {
                ctr[8..].copy_from_slice(&block_index.to_be_bytes());
            } else {
                ctr[8..].copy_from_slice(&block_index.to_le_bytes());
            }
            let mut block = aes::Block::from(ctr);
            cipher.encrypt_block(&mut block);
            cached_keystream.copy_from_slice(&block);
            cached_block_index = block_index;
        }
        *byte ^= cached_keystream[byte_in_block];
    }
}
