use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{NscbError, Result};
use crate::formats::hfs0::Hfs0Builder;
use crate::formats::nca::NcaHeader;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::Pfs0Builder;
use crate::formats::ticket::Ticket;
use crate::formats::types;
use crate::formats::xci::{Xci, XciBuilder, XCI_PREFIX_SIZE};
use crate::keys::KeyStore;
use crate::ops::split::{group_nsp_entries, group_xci_entries, TitleGroup};
use crate::util::{io as uio, progress};

pub fn split_to_files(path: &str, output_dir: &str, output_type: &str, ks: &KeyStore) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;
    let ext = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "nsp" | "nsz" => {
            let mut file = BufReader::new(File::open(path)?);
            let nsp = Nsp::parse(&mut file)?;
            let groups = group_nsp_entries(&nsp, &mut file, path, ks)?;
            write_groups(path, output_dir, output_type, &groups, ks)
        }
        "xci" | "xcz" => {
            let mut file = BufReader::new(File::open(path)?);
            let xci = Xci::parse(&mut file)?;
            let groups = group_xci_entries(&xci, &mut file, path, ks)?;
            write_groups(path, output_dir, output_type, &groups, ks)
        }
        _ => Err(NscbError::UnsupportedFormat(format!(
            "Cannot dspl: {}",
            ext
        ))),
    }
}

fn write_groups(
    source_path: &str,
    output_dir: &str,
    output_type: &str,
    groups: &[TitleGroup],
    ks: &KeyStore,
) -> Result<()> {
    for group in groups {
        let output_name = python_dspl_output_name(group, output_type);
        let output_path = Path::new(output_dir).join(output_name);
        if should_emit_xci(group, output_type) {
            write_group_as_xci(source_path, &output_path, group, ks)?;
        } else {
            write_group_as_nsp(source_path, &output_path, group)?;
        }
    }
    Ok(())
}

fn should_emit_xci(group: &TitleGroup, output_type: &str) -> bool {
    output_type.eq_ignore_ascii_case("xci")
        && matches!(group.title_type, Some(crate::formats::types::TitleType::Application))
}

fn python_dspl_output_name(group: &TitleGroup, output_type: &str) -> String {
    let title = match group.title_type {
        Some(crate::formats::types::TitleType::AddOnContent) => "DLC".to_string(),
        _ => python_title_spacing(&group.game_name),
    };
    let ext = if should_emit_xci(group, output_type) { "xci" } else { "nsp" };
    format!(
        "{} [{:016x}] [v{}].{}",
        title,
        group.title_id,
        group.version.unwrap_or(0),
        ext
    )
}

fn python_title_spacing(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "-".to_string();
    }
    let has_non_ascii = trimmed.chars().any(|ch| !ch.is_ascii());
    let has_ascii_alpha = trimmed.chars().any(|ch| ch.is_ascii_alphabetic());
    if has_non_ascii && !has_ascii_alpha {
        let compact: Vec<char> = trimmed.chars().filter(|ch| !ch.is_whitespace()).collect();
        return compact
            .iter()
            .map(|ch| ch.to_string())
            .collect::<Vec<_>>()
            .join(" ");
    }
    trimmed.to_string()
}

fn write_group_as_nsp(source_path: &str, output_path: &Path, group: &TitleGroup) -> Result<()> {
    let mut builder = Pfs0Builder::new();
    for entry in &group.entries {
        builder.add_file(entry.name.clone(), entry.size);
    }

    let header = builder.build_header();
    let total = builder.total_size();
    let pb = progress::file_progress(total, &format!("Packing {}", output_path.display()));
    let mut out = BufWriter::new(File::create(output_path)?);
    let mut src = BufReader::new(File::open(source_path)?);

    out.write_all(&header)?;
    pb.set_position(header.len() as u64);

    for entry in &group.entries {
        uio::copy_section(&mut src, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
    }

    out.flush()?;
    pb.finish_with_message("Done");
    Ok(())
}

fn write_group_as_xci(
    source_path: &str,
    output_path: &Path,
    group: &TitleGroup,
    ks: &KeyStore,
) -> Result<()> {
    let mut src = BufReader::new(File::open(source_path)?);
    let mut enc_title_keys_by_rights: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    for entry in &group.entries {
        if !entry.name.ends_with(".tik") {
            continue;
        }
        src.seek(SeekFrom::Start(entry.abs_offset))?;
        let mut raw = vec![0u8; entry.size as usize];
        src.read_exact(&mut raw)?;
        if let Ok(ticket) = Ticket::from_bytes(&raw) {
            enc_title_keys_by_rights
                .entry(ticket.rights_id)
                .or_insert(ticket.title_key_block);
        }
    }

    struct PreparedNca {
        abs_offset: u64,
        size: u64,
        patched_header: Vec<u8>,
        name: String,
    }
    let mut prepared = Vec::new();
    let mut secure_builder = Hfs0Builder::new();
    for entry in &group.entries {
        if !entry.name.ends_with(".nca") && !entry.name.ends_with(".ncz") {
            continue;
        }
        src.seek(SeekFrom::Start(entry.abs_offset))?;
        let mut enc_header = vec![0u8; 0xC00];
        src.read_exact(&mut enc_header)?;
        let parsed = NcaHeader::from_encrypted(&enc_header, ks)?;
        let title_key = if parsed.has_rights_id() {
            if let Some(enc_title_key) = enc_title_keys_by_rights.get(&parsed.rights_id) {
                Some(ks.decrypt_title_key(enc_title_key, parsed.key_generation().saturating_sub(1))?)
            } else {
                None
            }
        } else {
            None
        };
        let patched_header = crate::formats::nca::rewrite_header_for_xci(&enc_header, ks, title_key)?;
        let hash = crate::crypto::hash::sha256(&patched_header[..0x200]);
        secure_builder.add_file(entry.name.clone(), entry.size, hash, 0x200);
        prepared.push(PreparedNca {
            abs_offset: entry.abs_offset,
            size: entry.size,
            patched_header,
            name: entry.name.clone(),
        });
    }

    let secure_header = secure_builder.build_header_aligned(0x200);
    let secure_total = secure_builder.total_size();
    let empty_partition = empty_hfs0_partition_0x200();
    let empty_hash = crate::crypto::hash::sha256(&empty_partition);
    let secure_hash = crate::crypto::hash::sha256(&secure_header);

    let mut root_builder = Hfs0Builder::new();
    root_builder.add_file("update".to_string(), empty_partition.len() as u64, empty_hash, 0x200);
    root_builder.add_file("normal".to_string(), empty_partition.len() as u64, empty_hash, 0x200);
    root_builder.add_file("secure".to_string(), secure_total, secure_hash, secure_header.len() as u32);

    let root_header = root_builder.build_header_aligned(0x200);
    let root_hash = crate::crypto::hash::sha256(&root_header);
    let hfs0_offset = 0xF000u64;
    let secure_offset = hfs0_offset + root_header.len() as u64 + (empty_partition.len() as u64 * 2);
    let total_size = secure_offset + secure_total;
    if secure_offset % types::MEDIA_SIZE != 0 {
        return Err(NscbError::InvalidData(
            "Secure partition offset is not media-aligned".into(),
        ));
    }

    let mut xci_builder = XciBuilder::new();
    xci_builder.auto_card_size(total_size);
    let xci_header = xci_builder.build_header(
        hfs0_offset,
        secure_offset,
        root_header.len() as u64,
        &root_hash,
        total_size,
    );
    let game_info = xci_builder.build_game_info(total_size);
    let sig_padding = xci_builder.sig_padding();
    let fake_cert = xci_builder.fake_certificate();

    let pb = progress::file_progress(total_size, &format!("Packing {}", output_path.display()));
    let mut out = BufWriter::new(File::create(output_path)?);
    out.write_all(&xci_header)?;
    out.write_all(&game_info)?;
    out.write_all(&sig_padding)?;
    out.write_all(&fake_cert)?;
    if (xci_header.len() + game_info.len() + sig_padding.len() + fake_cert.len()) as u64 != XCI_PREFIX_SIZE {
        return Err(NscbError::InvalidData("XCI prefix size mismatch".into()));
    }
    out.write_all(&root_header)?;
    out.write_all(&empty_partition)?;
    out.write_all(&empty_partition)?;
    out.write_all(&secure_header)?;

    for nca in &prepared {
        let _ = &nca.name;
        out.write_all(&nca.patched_header)?;
        pb.inc(nca.patched_header.len() as u64);
        if nca.size > nca.patched_header.len() as u64 {
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
