use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::crypto::hash;
use crate::error::{NscbError, Result};
use crate::formats::hfs0::Hfs0Builder;
use crate::formats::nca::NcaHeader;
use crate::formats::ncz::{self, NczSection};
use crate::formats::nsp::Nsp;
use crate::formats::ticket::Ticket;
use crate::formats::types::ContentType;
use crate::formats::xci::{Xci, XciBuilder, XCI_PREFIX_SIZE};
use crate::keys::KeyStore;
use crate::util::{io as uio, progress};

enum EntrySource {
    Temp(tempfile::NamedTempFile),
    Input { abs_offset: u64, size: u64 },
}

struct PackedSecureEntry {
    name: String,
    size: u64,
    hash: [u8; 32],
    source: EntrySource,
}

/// Compress NSP to NSZ or XCI to XCZ.
pub fn compress(input_path: &str, output_path: &str, level: i32, ks: &KeyStore) -> Result<()> {
    let ext = Path::new(input_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "nsp" => compress_nsp(input_path, output_path, level, ks),
        "xci" => compress_xci(input_path, output_path, level, ks),
        _ => Err(NscbError::UnsupportedFormat(format!(
            "Cannot compress {} files",
            ext
        ))),
    }
}

fn compress_nsp(input_path: &str, output_path: &str, level: i32, ks: &KeyStore) -> Result<()> {
    println!("Compressing NSP to NSZ...");

    let mut file = BufReader::new(File::open(input_path)?);
    let nsp = Nsp::parse(&mut file)?;
    let title_keys = collect_enc_title_keys_from_nsp(&mut file, &nsp)?;

    let total_nca_bytes: u64 = nsp
        .all_entries()
        .iter()
        .filter(|e| e.name.ends_with(".nca"))
        .map(|e| e.size.saturating_sub(0x4000))
        .sum();
    let compress_pb = progress::file_progress(total_nca_bytes, "Compressing NCAs");

    let mut compressed_files: Vec<(String, tempfile::NamedTempFile)> = Vec::new();
    let mut other_files: Vec<(String, u64, u64)> = Vec::new();

    for entry in nsp.all_entries() {
        if entry.name.ends_with(".nca") {
            let abs_offset = nsp.file_abs_offset(entry);
            let nca_size = entry.size;
            let header = match NcaHeader::from_reader(&mut file, abs_offset, ks) {
                Ok(h) => h,
                Err(_) => {
                    other_files.push((entry.name.clone(), abs_offset, entry.size));
                    continue;
                }
            };

            let should_compress = matches!(
                header.content_type_enum(),
                Some(ContentType::Program) | Some(ContentType::PublicData)
            );
            if !should_compress {
                other_files.push((entry.name.clone(), abs_offset, entry.size));
                continue;
            }

            let sections = match build_ncz_sections(&mut file, abs_offset, &header, &title_keys, ks)? {
                Some(s) => s,
                None => {
                    // Missing title key for rights-based NCA: keep as-is.
                    other_files.push((entry.name.clone(), abs_offset, entry.size));
                    continue;
                }
            };

            let ncz_name = entry.name.replace(".nca", ".ncz");
            println!(
                "  Compressing {} ({} MB)...",
                entry.name,
                nca_size / (1024 * 1024)
            );

            let mut tmp = tempfile::NamedTempFile::new()?;
            file.seek(SeekFrom::Start(abs_offset))?;
            ncz::compress_nca(&mut file, &mut tmp, nca_size, &sections, level, Some(&compress_pb))?;
            compressed_files.push((ncz_name, tmp));
        } else {
            other_files.push((entry.name.clone(), nsp.file_abs_offset(entry), entry.size));
        }
    }
    compress_pb.finish_with_message("NCAs compressed");

    let mut builder = crate::formats::pfs0::Pfs0Builder::new();
    for (name, tmp) in &compressed_files {
        builder.add_file(name.clone(), tmp.as_file().metadata()?.len());
    }
    for (name, _, size) in &other_files {
        builder.add_file(name.clone(), *size);
    }

    let header = builder.build_header();
    let total = builder.total_size();
    let build_pb = progress::file_progress(total, "Building NSZ");
    let mut out = BufWriter::new(File::create(output_path)?);
    out.write_all(&header)?;
    build_pb.set_position(header.len() as u64);

    for (_name, mut tmp) in compressed_files {
        let size = tmp.as_file().metadata()?.len();
        tmp.seek(SeekFrom::Start(0))?;
        uio::copy_with_progress(&mut tmp, &mut out, size, Some(&build_pb))?;
    }

    for (_, abs_offset, size) in &other_files {
        uio::copy_section(&mut file, &mut out, *abs_offset, *size, Some(&build_pb))?;
    }

    out.flush()?;
    build_pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}

fn compress_xci(input_path: &str, output_path: &str, level: i32, ks: &KeyStore) -> Result<()> {
    println!("Compressing XCI to XCZ...");

    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;
    let secure = xci.secure_partition(&mut file)?;

    let total_nca_bytes: u64 = secure
        .entries
        .iter()
        .filter(|e| e.name.ends_with(".nca"))
        .map(|e| e.size.saturating_sub(0x4000))
        .sum();
    let compress_pb = progress::file_progress(total_nca_bytes, "Compressing secure NCAs");

    let mut secure_out: Vec<PackedSecureEntry> = Vec::new();
    let empty_title_keys: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    for entry in &secure.entries {
        let abs_offset = secure.file_abs_offset(entry);
        if entry.name.ends_with(".nca") {
            let header = match NcaHeader::from_reader(&mut file, abs_offset, ks) {
                Ok(h) => h,
                Err(_) => {
                    secure_out.push(PackedSecureEntry {
                        name: entry.name.clone(),
                        size: entry.size,
                        hash: hash_first_n_from_reader(&mut file, abs_offset, entry.size.min(0x200))?,
                        source: EntrySource::Input {
                            abs_offset,
                            size: entry.size,
                        },
                    });
                    continue;
                }
            };
            let should_compress = matches!(
                header.content_type_enum(),
                Some(ContentType::Program) | Some(ContentType::PublicData)
            );
            if !should_compress {
                secure_out.push(PackedSecureEntry {
                    name: entry.name.clone(),
                    size: entry.size,
                    hash: hash_first_n_from_reader(&mut file, abs_offset, entry.size.min(0x200))?,
                    source: EntrySource::Input {
                        abs_offset,
                        size: entry.size,
                    },
                });
                continue;
            }

            let sections = match build_ncz_sections(&mut file, abs_offset, &header, &empty_title_keys, ks)? {
                Some(s) => s,
                None => {
                    secure_out.push(PackedSecureEntry {
                        name: entry.name.clone(),
                        size: entry.size,
                        hash: hash_first_n_from_reader(
                            &mut file,
                            abs_offset,
                            entry.size.min(0x200),
                        )?,
                        source: EntrySource::Input {
                            abs_offset,
                            size: entry.size,
                        },
                    });
                    continue;
                }
            };

            let mut tmp = tempfile::NamedTempFile::new()?;
            file.seek(SeekFrom::Start(abs_offset))?;
            ncz::compress_nca(&mut file, &mut tmp, entry.size, &sections, level, Some(&compress_pb))?;
            let size = tmp.as_file().metadata()?.len();
            let hash = hash_first_n_from_temp(&mut tmp, size.min(0x200))?;
            secure_out.push(PackedSecureEntry {
                name: entry.name.replace(".nca", ".ncz"),
                size,
                hash,
                source: EntrySource::Temp(tmp),
            });
        } else {
            secure_out.push(PackedSecureEntry {
                name: entry.name.clone(),
                size: entry.size,
                hash: hash_first_n_from_reader(&mut file, abs_offset, entry.size.min(0x200))?,
                source: EntrySource::Input {
                    abs_offset,
                    size: entry.size,
                },
            });
        }
    }
    compress_pb.finish_with_message("Secure NCAs compressed");

    let mut secure_builder = Hfs0Builder::new();
    for e in &secure_out {
        secure_builder.add_file(e.name.clone(), e.size, e.hash, 0x200);
    }
    let secure_header = secure_builder.build_header_aligned(0x200);
    let secure_total = secure_header.len() as u64 + secure_out.iter().map(|e| e.size).sum::<u64>();
    let secure_hash = hash::sha256(&secure_header);

    let mut root_builder = Hfs0Builder::new();
    for root_e in &xci.root_hfs0.entries {
        if root_e.name == "secure" {
            root_builder.add_file(
                root_e.name.clone(),
                secure_total,
                secure_hash,
                secure_header.len() as u32,
            );
        } else {
            root_builder.add_file(
                root_e.name.clone(),
                root_e.size,
                root_e.hash,
                root_e.hash_target_size,
            );
        }
    }
    let root_header = root_builder.build_header_aligned(0x200);
    let root_hash = hash::sha256(&root_header);

    let hfs0_offset = xci.header.hfs0_offset;
    let mut cursor = hfs0_offset + root_header.len() as u64;
    let mut secure_offset = 0u64;
    for root_e in &xci.root_hfs0.entries {
        if root_e.name == "secure" {
            secure_offset = cursor;
            cursor += secure_total;
        } else {
            cursor += root_e.size;
        }
    }
    if secure_offset == 0 {
        return Err(NscbError::InvalidData(
            "XCI secure partition not found in root HFS0".into(),
        ));
    }
    if secure_offset % crate::formats::types::MEDIA_SIZE != 0 {
        return Err(NscbError::InvalidData(
            "Secure partition offset is not media-aligned".into(),
        ));
    }
    let total_size = cursor;

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

    let pb = progress::file_progress(total_size, "Building XCZ");
    let mut out = BufWriter::new(File::create(output_path)?);
    out.write_all(&xci_header)?;
    out.write_all(&game_info)?;
    out.write_all(&sig_padding)?;
    out.write_all(&fake_cert)?;
    if (xci_header.len() + game_info.len() + sig_padding.len() + fake_cert.len()) as u64
        != XCI_PREFIX_SIZE
    {
        return Err(NscbError::InvalidData("XCI prefix size mismatch".into()));
    }
    out.write_all(&root_header)?;
    pb.set_position((XCI_PREFIX_SIZE + root_header.len() as u64).min(total_size));

    for root_e in &xci.root_hfs0.entries {
        if root_e.name == "secure" {
            out.write_all(&secure_header)?;
            pb.inc(secure_header.len() as u64);
            for e in &mut secure_out {
                match &mut e.source {
                    EntrySource::Temp(tmp) => {
                        tmp.seek(SeekFrom::Start(0))?;
                        uio::copy_with_progress(tmp, &mut out, e.size, Some(&pb))?;
                    }
                    EntrySource::Input { abs_offset, size } => {
                        uio::copy_section(&mut file, &mut out, *abs_offset, *size, Some(&pb))?;
                    }
                }
            }
        } else {
            let abs_offset = xci.root_hfs0.file_abs_offset(root_e);
            uio::copy_section(&mut file, &mut out, abs_offset, root_e.size, Some(&pb))?;
        }
    }

    out.flush()?;
    pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}

fn collect_enc_title_keys_from_nsp<R: Read + Seek>(
    reader: &mut R,
    nsp: &Nsp,
 ) -> Result<HashMap<[u8; 16], [u8; 16]>> {
    let mut out = HashMap::new();
    for tik in nsp.ticket_entries() {
        let abs_offset = nsp.file_abs_offset(tik);
        reader.seek(SeekFrom::Start(abs_offset))?;
        let mut raw = vec![0u8; tik.size as usize];
        reader.read_exact(&mut raw)?;
        if let Ok(t) = Ticket::from_bytes(&raw) {
            out.entry(t.rights_id).or_insert(t.title_key_block);
        }
    }
    Ok(out)
}

fn build_ncz_sections<R: Read + Seek>(
    reader: &mut R,
    nca_base: u64,
    header: &NcaHeader,
    enc_title_keys: &HashMap<[u8; 16], [u8; 16]>,
    ks: &KeyStore,
) -> Result<Option<Vec<NczSection>>> {
    let section_key = if header.has_rights_id() {
        match enc_title_keys.get(&header.rights_id) {
            Some(k) => ks.decrypt_title_key(k, header.master_key_revision())?,
            None => return Ok(None),
        }
    } else {
        header.decrypt_key_area(ks)?[2]
    };

    let mut sections = Vec::new();
    let raw = header.raw_bytes();
    for i in 0..4 {
        let sec = header.section_table[i];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        let mut crypto_type = header.section_crypto_type(i) as u64;
        if crypto_type == 4 {
            crypto_type = 3;
        }
        let base_ctr = section_base_counter(header, i);

        // Python parity: BKTR sections expand to subsection entries with per-entry counters.
        if let Some(mut bktr_sections) = parse_bktr_sections_for_index(
            reader,
            nca_base,
            header,
            raw,
            i,
            sec,
            crypto_type,
            section_key,
            base_ctr,
        )? {
            sections.append(&mut bktr_sections);
            continue;
        }

        sections.push(NczSection {
            offset: sec.start_offset(),
            size: sec.size(),
            crypto_type,
            _padding: 0,
            crypto_key: section_key,
            crypto_counter: base_ctr,
        });
    }

    sections.retain(|s| s.size > 0);
    sections.sort_by_key(|s| s.offset);
    if let Some(first) = sections.first().cloned() {
        if first.offset > 0x4000 {
            sections.insert(
                0,
                NczSection {
                    offset: 0x4000,
                    size: first.offset - 0x4000,
                    crypto_type: 1,
                    _padding: 0,
                    crypto_key: first.crypto_key,
                    crypto_counter: first.crypto_counter,
                },
            );
        }
    }
    Ok(Some(sections))
}

fn section_base_counter(header: &NcaHeader, section_index: usize) -> [u8; 16] {
    let nonce = header.section_ctr_nonce(section_index);
    let mut ctr = [0u8; 16];
    for j in 0..8 {
        ctr[j] = nonce[7 - j];
    }
    ctr
}

fn parse_bktr_sections_for_index<R: Read + Seek>(
    reader: &mut R,
    nca_base: u64,
    _header: &NcaHeader,
    raw: &[u8],
    section_index: usize,
    sec: crate::formats::nca::SectionTableEntry,
    crypto_type: u64,
    section_key: [u8; 16],
    base_ctr: [u8; 16],
) -> Result<Option<Vec<NczSection>>> {
    let fs_hdr_off = 0x400 + section_index * 0x200;
    if fs_hdr_off + 0x200 > raw.len() {
        return Ok(None);
    }
    let fs = &raw[fs_hdr_off..fs_hdr_off + 0x200];
    let section_start = u64::from_le_bytes(fs[0x00..0x08].try_into().unwrap());

    // BKTR2 header at 0x120..0x140 in section fs header.
    let bktr2 = &fs[0x120..0x140];
    let bktr_off = u64::from_le_bytes(bktr2[0x00..0x08].try_into().unwrap());
    let bktr_size = u64::from_le_bytes(bktr2[0x08..0x10].try_into().unwrap());
    if bktr_size == 0 {
        return Ok(None);
    }

    let section_abs = nca_base + sec.start_offset();
    let bktr_abs = section_abs + bktr_off;
    let mut enc = vec![0u8; bktr_size as usize];
    reader.seek(SeekFrom::Start(bktr_abs))?;
    reader.read_exact(&mut enc)?;
    if crypto_type == 3 || crypto_type == 4 {
        let cipher = Aes128::new_from_slice(&section_key)
            .map_err(|e| NscbError::Crypto(format!("AES key init: {e}")))?;
        aes_ctr_transform_in_place(&cipher, &base_ctr[..8], sec.start_offset() + bktr_off, &mut enc);
    }

    let mut cur = Cursor::new(enc);
    if cur.get_ref().len() < 0x10 + 0x3FF0 {
        return Ok(None);
    }
    let _padding = read_u32(&mut cur)?;
    let bucket_count = read_u32(&mut cur)? as usize;
    let _total_patch = read_u64(&mut cur)?;
    // basePhysicalOffsets table (unused for our section listing, but present in structure)
    for _ in 0..(0x3FF0 / 8) {
        let _ = read_u64(&mut cur)?;
    }

    let mut sub_sections: Vec<(u64, u64, u32)> = Vec::new();
    for _ in 0..bucket_count {
        if (cur.position() as usize) + 0x10 > cur.get_ref().len() {
            break;
        }
        let _bucket_pad = read_u32(&mut cur)?;
        let entry_count = read_u32(&mut cur)? as usize;
        let end_offset = read_u64(&mut cur)?;
        let mut entries: Vec<(u64, u32)> = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if (cur.position() as usize) + 0x10 > cur.get_ref().len() {
                break;
            }
            let virtual_offset = read_u64(&mut cur)?;
            let _entry_pad = read_u32(&mut cur)?;
            let ctr = read_u32(&mut cur)?;
            entries.push((virtual_offset, ctr));
        }
        for idx in 0..entries.len() {
            let (off, ctr) = entries[idx];
            let end = if idx + 1 < entries.len() {
                entries[idx + 1].0
            } else {
                end_offset
            };
            if end > off {
                sub_sections.push((off, end - off, ctr));
            }
        }
    }

    let section_offset = sec
        .start_offset()
        .saturating_sub(section_start)
        .saturating_add(0x4000);
    let section_size = sec.size();

    let mut out = Vec::new();
    if sub_sections.is_empty() {
        if section_size > 0 {
            out.push(NczSection {
                offset: section_offset,
                size: section_size,
                crypto_type,
                _padding: 0,
                crypto_key: section_key,
                crypto_counter: base_ctr,
            });
        }
        return Ok(Some(out));
    }

    sub_sections.sort_by_key(|(off, _, _)| *off);
    for (virt_off, size, ctr_val) in &sub_sections {
        let mut ctr = base_ctr;
        ctr[4..8].copy_from_slice(&ctr_val.to_be_bytes());
        out.push(NczSection {
            offset: section_offset + *virt_off,
            size: *size,
            crypto_type,
            _padding: 0,
            crypto_key: section_key,
            crypto_counter: ctr,
        });
    }
    let last = out.last().cloned();
    if let Some(last) = last {
        let tail_start = last.offset + last.size;
        let tail_end = section_offset + section_size;
        if tail_end > tail_start {
            out.push(NczSection {
                offset: tail_start,
                size: tail_end - tail_start,
                crypto_type,
                _padding: 0,
                crypto_key: section_key,
                crypto_counter: base_ctr,
            });
        }
    }
    Ok(Some(out))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn aes_ctr_transform_in_place(cipher: &Aes128, nonce8: &[u8], file_offset: u64, data: &mut [u8]) {
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
            let mut blk = aes::Block::from(ctr);
            cipher.encrypt_block(&mut blk);
            cached_keystream.copy_from_slice(&blk);
            cached_block_index = block_index;
        }
        *byte ^= cached_keystream[byte_in_block];
    }
}

fn hash_first_n_from_reader<R: Read + Seek>(reader: &mut R, offset: u64, n: u64) -> Result<[u8; 32]> {
    if n == 0 {
        return Ok(hash::sha256(&[]));
    }
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; n as usize];
    reader.read_exact(&mut buf)?;
    Ok(hash::sha256(&buf))
}

fn hash_first_n_from_temp(tmp: &mut tempfile::NamedTempFile, n: u64) -> Result<[u8; 32]> {
    if n == 0 {
        return Ok(hash::sha256(&[]));
    }
    let f = tmp.as_file_mut();
    f.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; n as usize];
    f.read_exact(&mut buf)?;
    Ok(hash::sha256(&buf))
}
