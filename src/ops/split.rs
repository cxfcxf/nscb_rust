use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use regex::Regex;

use crate::error::{NscbError, Result};
use crate::formats::cnmt::Cnmt;
use crate::formats::nca;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::{Pfs0Builder, Pfs0Entry};
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
            if let Ok(header) = crate::formats::nca::NcaHeader::from_reader(&mut file, abs_offset, ks) {
                // Find PFS0 section in the CNMT NCA
                for sec_idx in 0..4 {
                    let sec = &header.section_table[sec_idx];
                    if !sec.is_present() {
                        continue;
                    }
                    let sec_offset = abs_offset + sec.start_offset();
                    // Try to parse as PFS0 and read the .cnmt file within
                    if let Ok(pfs) = crate::formats::pfs0::Pfs0::parse_at(&mut file, sec_offset) {
                        for pfs_entry in &pfs.entries {
                            if pfs_entry.name.ends_with(".cnmt") {
                                if let Ok(cnmt_data) = pfs.read_file(&mut file, &pfs_entry.name) {
                                    if let Ok(cnmt) = Cnmt::from_bytes(&cnmt_data) {
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
                        }
                    }
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
            if let Ok(header) = crate::formats::nca::NcaHeader::from_reader(&mut file, abs_offset, ks) {
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

    // Also add tickets/certs to all groups (they're usually shared)
    let tik_entries: Vec<&Pfs0Entry> = nsp.ticket_entries();
    let cert_entries: Vec<&Pfs0Entry> = nsp.cert_entries();

    println!("Found {} title groups", groups.len());

    for (base_id, entries) in &groups {
        let output_name = split_output_name(*base_id, group_meta.get(base_id), &base_name, guessed_version);
        let output_path = Path::new(output_dir).join(&output_name);
        println!("Writing {} ({} files)", output_name, entries.len() + tik_entries.len() + cert_entries.len());

        let mut builder = Pfs0Builder::new();

        // Add NCAs for this group
        for entry in entries {
            builder.add_file(entry.name.clone(), entry.size);
        }
        // Add all tickets and certs to each split file
        for tik in &tik_entries {
            builder.add_file(tik.name.clone(), tik.size);
        }
        for cert in &cert_entries {
            builder.add_file(cert.name.clone(), cert.size);
        }

        let header = builder.build_header();
        let total = builder.total_size();
        let pb = progress::file_progress(total, &format!("Writing {}", output_name));
        let mut out =
            BufWriter::new(File::create(&output_path)?);

        out.write_all(&header)?;
        pb.set_position(header.len() as u64);

        for entry in entries {
            let abs_offset = nsp.file_abs_offset(entry);
            uio::copy_section(&mut file, &mut out, abs_offset, entry.size, Some(&pb))?;
        }
        for tik in &tik_entries {
            let abs_offset = nsp.file_abs_offset(tik);
            uio::copy_section(&mut file, &mut out, abs_offset, tik.size, Some(&pb))?;
        }
        for cert in &cert_entries {
            let abs_offset = nsp.file_abs_offset(cert);
            uio::copy_section(&mut file, &mut out, abs_offset, cert.size, Some(&pb))?;
        }

        out.flush()?;
        pb.finish_with_message("Done");
    }

    println!("Split complete: {} files written to {}", groups.len(), output_dir);
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
    let s = s.trim().trim_matches(|c: char| c == '-' || c == '_' || c.is_whitespace());

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
    // For XCI, extract NCAs from secure partition and group by title ID
    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;
    let secure_entries = xci.secure_nca_entries(&mut file)?;

    let mut groups: HashMap<u64, Vec<&crate::formats::xci::SecureNcaEntry>> = HashMap::new();

    for entry in &secure_entries {
        if let Ok(info) =
            nca::parse_nca_info(&mut file, entry.abs_offset, entry.size, &entry.name, ks)
        {
            let base_id = info.title_id & 0xFFFFFFFFFFFFE000;
            groups.entry(base_id).or_default().push(entry);
        }
    }

    println!("Found {} title groups in XCI", groups.len());

    for (base_id, entries) in &groups {
        let output_name = format!("{:016x}.nsp", base_id);
        let output_path = Path::new(output_dir).join(&output_name);
        println!("Writing {} ({} NCAs)", output_name, entries.len());

        let mut builder = Pfs0Builder::new();
        for entry in entries {
            builder.add_file(entry.name.clone(), entry.size);
        }

        let header = builder.build_header();
        let total = builder.total_size();
        let pb = progress::file_progress(total, &format!("Writing {}", output_name));
        let mut out =
            BufWriter::new(File::create(&output_path)?);

        out.write_all(&header)?;
        pb.set_position(header.len() as u64);

        for entry in entries {
            uio::copy_section(&mut file, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
        }

        out.flush()?;
        pb.finish_with_message("Done");
    }

    Ok(())
}
