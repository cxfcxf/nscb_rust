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
    let known_title_ids = collect_title_ids_from_ticket_names(&nsp);
    let base_name = infer_game_name_from_input(input_path);
    let guessed_version = infer_version_from_input(input_path);

    // Get CNMT info to find which NCAs belong to which titles precisely.
    let cnmt_ncas = nsp.cnmt_nca_entries(&mut file, ks);

    // Map content NCA ID -> output group title ID (strict CNMT title_id grouping).
    let mut cnmt_nca_map: HashMap<String, u64> = HashMap::new();
    let mut group_meta: HashMap<u64, SplitGroupMeta> = HashMap::new();
    for cnmt_info in &cnmt_ncas {
        let entry = nsp.pfs0.find(&cnmt_info.filename);
        if let Some(entry) = entry {
            let abs_offset = nsp.file_abs_offset(entry);
            if let Some(cnmt) = parse_cnmt_from_meta_nca(&mut file, abs_offset, ks) {
                let group_id = cnmt.title_id;
                group_meta.entry(group_id).or_insert(SplitGroupMeta {
                    title_id: cnmt.title_id,
                    version: cnmt.version,
                    title_type: cnmt.title_type_enum(),
                });

                // The meta NCA itself should travel with its title group.
                if let Some(meta_nca_id) = nca_id_from_filename(&cnmt_info.filename) {
                    cnmt_nca_map.insert(meta_nca_id, group_id);
                }

                for nca_id in cnmt.nca_ids() {
                    cnmt_nca_map.insert(nca_id, group_id);
                }
            }
        }
    }

    // Build groups from CNMT data
    let mut groups: HashMap<u64, Vec<&Pfs0Entry>> = HashMap::new();

    for entry in nsp.all_entries() {
        let nca_id = nca_id_from_filename(&entry.name).unwrap_or_else(|| entry.name.to_lowercase());

        if let Some(&base_id) = cnmt_nca_map.get(&nca_id) {
            groups.entry(base_id).or_default().push(entry);
        } else if entry.name.to_ascii_lowercase().ends_with(".nca")
            || entry.name.to_ascii_lowercase().ends_with(".ncz")
        {
            // Fall back to NCA header grouping. Prefer rights-id-derived title ID
            // (matches ticket title IDs) when available.
            let abs_offset = nsp.file_abs_offset(entry);
            if let Ok(header) =
                crate::formats::nca::NcaHeader::from_reader(&mut file, abs_offset, ks)
            {
                let mut group_id = header.title_id;
                if header.has_rights_id() {
                    let rights_tid = u64::from_be_bytes(header.rights_id[..8].try_into().unwrap());
                    if known_title_ids.contains(&rights_tid) {
                        group_id = rights_tid;
                    }
                }
                groups.entry(group_id).or_default().push(entry);
            } else if let Ok(info) =
                nca::parse_nca_info(&mut file, abs_offset, entry.size, &entry.name, ks)
            {
                groups.entry(info.title_id).or_default().push(entry);
            }
        }
    }

    println!("Found {} title groups", groups.len());

    for (base_id, entries) in &groups {
        let output_name = split_output_folder_name(
            *base_id,
            group_meta.get(base_id),
            &base_name,
            guessed_version,
        );
        let output_path = Path::new(output_dir).join(&output_name);
        std::fs::create_dir_all(&output_path)?;
        println!("Extracting {} ({} NCAs)", output_name, entries.len());
        let total: u64 = entries.iter().map(|e| e.size).sum();
        let pb = progress::file_progress(total, &format!("Extracting {}", output_name));

        for entry in entries {
            let out_file = output_path.join(&entry.name);
            let mut out = BufWriter::new(File::create(out_file)?);
            let abs_offset = nsp.file_abs_offset(entry);
            uio::copy_section(&mut file, &mut out, abs_offset, entry.size, Some(&pb))?;
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

fn split_output_name(
    group_id: u64,
    meta: Option<&SplitGroupMeta>,
    base_name: &str,
    guessed_version: Option<u32>,
) -> String {
    let (title_id, version, title_type) = if let Some(m) = meta {
        (m.title_id, Some(m.version), m.title_type)
    } else {
        (group_id, None, None)
    };

    let tid = format!("{:016X}", title_id);
    match title_type {
        Some(TitleType::Patch) => {
            let v = version.unwrap_or(0);
            format!("{} [{}][v{}][UPD].nsp", base_name, tid, v)
        }
        Some(TitleType::AddOnContent) => {
            let v = version.unwrap_or(0);
            format!("{} [{}][v{}][DLC].nsp", base_name, tid, v)
        }
        Some(TitleType::Application) => format!("{} [{}].nsp", base_name, tid),
        _ => {
            let is_update = (title_id & 0xFFF) == 0x800;
            let is_base = (title_id & 0xFFF) == 0x000;
            if is_update {
                let v = version.or(guessed_version).unwrap_or(0);
                format!("{} [{}][v{}][UPD].nsp", base_name, tid, v)
            } else if is_base {
                format!("{} [{}].nsp", base_name, tid)
            } else if let Some(v) = version {
                format!("{} [{}][v{}].nsp", base_name, tid, v)
            } else {
                format!("{}.nsp", tid.to_lowercase())
            }
        }
    }
}

fn split_output_folder_name(
    group_id: u64,
    meta: Option<&SplitGroupMeta>,
    base_name: &str,
    guessed_version: Option<u32>,
) -> String {
    split_output_name(group_id, meta, base_name, guessed_version)
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
    // For XCI, extract NCAs from secure partition and split to NSP groups.
    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;
    let secure_entries = xci.secure_nca_entries(&mut file)?;
    let base_name = infer_game_name_from_input(input_path);
    let guessed_version = infer_version_from_input(input_path);

    // Build CNMT mapping: content NCA id -> title id.
    let mut cnmt_nca_map: HashMap<String, u64> = HashMap::new();
    let mut group_meta: HashMap<u64, SplitGroupMeta> = HashMap::new();

    for entry in &secure_entries {
        if let Ok(info) =
            nca::parse_nca_info(&mut file, entry.abs_offset, entry.size, &entry.name, ks)
        {
            if info.content_type == Some(crate::formats::types::ContentType::Meta) {
                if let Some(cnmt) = parse_cnmt_from_meta_nca(&mut file, entry.abs_offset, ks) {
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
        // Fallback when CNMT payload parsing fails: assign each non-meta NCA to the nearest
        // CNMT meta entry by file order. This mirrors Python splitter ordering on merged files.
        let mut meta_positions: Vec<(usize, u64)> = Vec::new();
        for (idx, entry) in secure_entries.iter().enumerate() {
            if entry.name.to_ascii_lowercase().ends_with(".cnmt.nca") {
                if let Ok(header) =
                    crate::formats::nca::NcaHeader::from_reader(&mut file, entry.abs_offset, ks)
                {
                    meta_positions.push((idx, header.title_id));
                }
            }
        }

        if !meta_positions.is_empty() {
            if meta_positions.len() == 2 {
                // Common merged base+update layout:
                // [base NCAs ... base.cnmt ... update NCAs ... update.cnmt]
                // Detect first Program NCA between metas as the handoff point to update.
                let (m0, t0) = meta_positions[0];
                let (m1, t1) = meta_positions[1];
                let mut update_start = m1;
                for (idx, entry) in secure_entries
                    .iter()
                    .enumerate()
                    .skip(m0 + 1)
                    .take(m1.saturating_sub(m0 + 1))
                {
                    if let Ok(info) = nca::parse_nca_info(
                        &mut file,
                        entry.abs_offset,
                        entry.size,
                        &entry.name,
                        ks,
                    ) {
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
                        crate::formats::nca::NcaHeader::from_reader(&mut file, entry.abs_offset, ks)
                            .map(|h| h.title_id)
                            .unwrap_or(meta_positions[0].1)
                    } else {
                        meta_positions
                            .iter()
                            .min_by_key(|(midx, _)| idx.abs_diff(*midx))
                            .map(|(_, tid)| *tid)
                            .unwrap_or(meta_positions[0].1)
                    };
                    groups.entry(group_id).or_default().push(entry);
                }
            }
        }
    } else {
        for entry in &secure_entries {
            let nca_id =
                nca_id_from_filename(&entry.name).unwrap_or_else(|| entry.name.to_lowercase());
            if let Ok(header) =
                crate::formats::nca::NcaHeader::from_reader(&mut file, entry.abs_offset, ks)
            {
                if let Some(&group_id) = cnmt_nca_map.get(&nca_id) {
                    groups.entry(group_id).or_default().push(entry);
                    continue;
                }

                // Prefer rights-id title for title-key NCAs; this distinguishes patch/update.
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
            } else if let Ok(info) =
                nca::parse_nca_info(&mut file, entry.abs_offset, entry.size, &entry.name, ks)
            {
                groups.entry(info.title_id).or_default().push(entry);
            }
        }
    }

    println!("Found {} title groups in XCI", groups.len());

    for (group_id, entries) in &groups {
        let output_name = split_output_folder_name(
            *group_id,
            group_meta.get(group_id),
            &base_name,
            guessed_version,
        );
        let output_path = Path::new(output_dir).join(&output_name);
        std::fs::create_dir_all(&output_path)?;
        println!("Extracting {} ({} NCAs)", output_name, entries.len());
        let total: u64 = entries.iter().map(|e| e.size).sum();
        let pb = progress::file_progress(total, &format!("Extracting {}", output_name));

        for entry in entries {
            let out_file = output_path.join(&entry.name);
            let mut out = BufWriter::new(File::create(out_file)?);
            uio::copy_section(&mut file, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
            out.flush()?;
        }
        pb.finish_with_message("Done");
    }

    Ok(())
}

fn parse_cnmt_from_meta_nca<R: Read + Seek>(
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

                    let mut dec_le = section_data.clone();
                    aes_ctr_transform_in_place(key, &nonce, start, false, &mut dec_le);
                    if let Some(cnmt) = parse_cnmt_from_section_bytes(&dec_le) {
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
