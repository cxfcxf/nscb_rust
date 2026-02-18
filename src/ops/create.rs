use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::error::{NscbError, Result};
use crate::formats::cnmt::Cnmt;
use crate::formats::pfs0::Pfs0;
use crate::keys::KeyStore;
use crate::util::{io as uio, progress};

/// Repack an input folder into a single NSP file.
///
/// This mirrors Python NSC_BUILDER `--create -ifo <folder>` behavior at a high level:
/// pack files from the folder root in deterministic NSP order.
pub fn create_from_folder(input_dir: &str, output_path: &str, ks: &KeyStore) -> Result<()> {
    let input = Path::new(input_dir);
    if !input.is_dir() {
        return Err(NscbError::InvalidData(format!(
            "Input folder not found: {}",
            input_dir
        )));
    }

    let files = collect_top_level_files(input)?;
    if files.is_empty() {
        return Err(NscbError::InvalidData(format!(
            "No files found in input folder: {}",
            input_dir
        )));
    }

    let ordered = build_pack_order(files, ks);
    if ordered.is_empty() {
        return Err(NscbError::InvalidData(format!(
            "No packable files found in input folder: {}",
            input_dir
        )));
    }

    let file_infos: Vec<(String, u64)> = ordered
        .iter()
        .map(|p| {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| NscbError::InvalidData("Invalid UTF-8 file name".into()))?
                .to_string();
            let size = p.metadata()?.len();
            Ok((name, size))
        })
        .collect::<Result<_>>()?;

    let header = build_python_style_pfs0_header(&file_infos);
    let total = header.len() as u64 + file_infos.iter().map(|(_, s)| *s).sum::<u64>();
    let pb = progress::file_progress(total, "Packing NSP");
    let mut out = BufWriter::new(File::create(output_path)?);

    out.write_all(&header)?;
    pb.set_position(header.len() as u64);

    for p in &ordered {
        let size = p.metadata()?.len();
        let mut src = File::open(p)?;
        uio::copy_with_progress(&mut src, &mut out, size, Some(&pb))?;
    }

    out.flush()?;
    pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}

fn collect_top_level_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            out.push(p);
        }
    }
    Ok(out)
}

fn build_pack_order(mut files: Vec<PathBuf>, ks: &KeyStore) -> Vec<PathBuf> {
    files.sort_by_key(|p| {
        p.file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default()
    });

    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // 1) CNMT-driven NCA order (matches python ncalist_bycnmt behavior).
    let mut id_to_file: Vec<(String, PathBuf)> = Vec::new();
    for p in &files {
        let name = lower_name(p);
        if name.ends_with(".nca") {
            if let Some(stem) = name.strip_suffix(".nca") {
                id_to_file.push((stem.to_string(), p.clone()));
            }
        } else if name.ends_with(".ncz") {
            if let Some(stem) = name.strip_suffix(".ncz") {
                id_to_file.push((stem.to_string(), p.clone()));
            }
        }
    }
    for p in &files {
        let name = lower_name(p);
        if name.ends_with(".cnmt.nca") {
            if let Some(cnmt) = parse_cnmt_from_meta_nca_file(p, ks) {
                for nca_id in cnmt.nca_ids() {
                    if let Some((_, fp)) = id_to_file.iter().find(|(id, _)| id == &nca_id) {
                        push_unique(&mut out, &mut seen, fp.clone());
                    }
                }
            }
        }
    }
    // Fallback when CNMT parsing fails: place non-meta NCAs first (largest-first),
    // then meta NCA, mirroring python create behavior on these split folders.
    if out.is_empty() {
        let mut non_meta: Vec<(u64, PathBuf)> = files
            .iter()
            .filter(|p| {
                let n = lower_name(p);
                n.ends_with(".nca") && !n.ends_with(".cnmt.nca")
            })
            .map(|p| (p.metadata().map(|m| m.len()).unwrap_or(0), p.clone()))
            .collect();
        non_meta.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| lower_name(&a.1).cmp(&lower_name(&b.1)))
        });
        for (_, p) in non_meta {
            push_unique(&mut out, &mut seen, p);
        }
    }
    // 2) Meta NCA(s)
    for p in &files {
        let name = lower_name(p);
        if name.ends_with(".cnmt.nca") {
            push_unique(&mut out, &mut seen, p.clone());
        }
    }
    // 3) .cnmt xml/plain
    for p in &files {
        let name = lower_name(p);
        if name.ends_with(".cnmt") || name.ends_with(".cnmt.xml") {
            push_unique(&mut out, &mut seen, p.clone());
        }
    }
    // 4) Images
    for p in &files {
        let name = lower_name(p);
        if name.ends_with(".jpg") || name.ends_with(".jpeg") || name.ends_with(".png") {
            push_unique(&mut out, &mut seen, p.clone());
        }
    }
    // 5) Tickets/certs
    for p in &files {
        let name = lower_name(p);
        if name.ends_with(".tik") || name.ends_with(".cert") {
            push_unique(&mut out, &mut seen, p.clone());
        }
    }
    // 6) Anything else
    for p in files {
        push_unique(&mut out, &mut seen, p);
    }

    out
}

fn lower_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn push_unique(out: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
    let key = path.to_string_lossy().to_string();
    if seen.insert(key) {
        out.push(path);
    }
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn build_python_style_pfs0_header(files: &[(String, u64)]) -> Vec<u8> {
    let mut string_table = Vec::new();
    let mut name_offsets = Vec::new();
    for (name, _) in files {
        name_offsets.push(string_table.len() as u32);
        string_table.extend_from_slice(name.as_bytes());
        string_table.push(0);
    }
    let aligned_st_size = align_up(string_table.len(), 0x10);
    string_table.resize(aligned_st_size, 0);

    let mut header = Vec::with_capacity(0x10 + files.len() * 0x18 + aligned_st_size);
    header.extend_from_slice(b"PFS0");
    header.extend_from_slice(&(files.len() as u32).to_le_bytes());
    header.extend_from_slice(&(aligned_st_size as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());

    let mut data_off = 0u64;
    for (i, (_, size)) in files.iter().enumerate() {
        header.extend_from_slice(&data_off.to_le_bytes());
        header.extend_from_slice(&size.to_le_bytes());
        header.extend_from_slice(&name_offsets[i].to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        data_off += *size;
    }
    header.extend_from_slice(&string_table);
    header
}

fn parse_cnmt_from_meta_nca_file(path: &Path, ks: &KeyStore) -> Option<Cnmt> {
    let mut file = File::open(path).ok()?;
    let header = crate::formats::nca::NcaHeader::from_reader(&mut file, 0, ks).ok()?;
    let keys = header.decrypt_key_area(ks).ok()?;
    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        let mut section = vec![0u8; sec.size() as usize];
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(sec.start_offset())).ok()?;
        std::io::Read::read_exact(&mut file, &mut section).ok()?;

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
    let mut c = std::io::Cursor::new(section);
    let pfs = Pfs0::parse_at(&mut c, 0).ok()?;
    for e in &pfs.entries {
        if e.name.ends_with(".cnmt") {
            let b = pfs.read_file(&mut c, &e.name).ok()?;
            if let Ok(cnmt) = Cnmt::from_bytes(&b) {
                if !cnmt.content_entries.is_empty() {
                    return Some(cnmt);
                }
            }
        }
    }
    None
}

fn aes_ctr_transform_in_place(key: &[u8; 16], nonce8: &[u8; 8], file_offset: u64, data: &mut [u8]) {
    let cipher = Aes128::new_from_slice(key);
    let Ok(cipher) = cipher else { return };
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
