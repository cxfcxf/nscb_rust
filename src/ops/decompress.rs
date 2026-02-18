use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::hash;
use crate::error::{NscbError, Result};
use crate::formats::hfs0::Hfs0Builder;
use crate::formats::ncz;
use crate::formats::nsp::Nsp;
use crate::formats::xci::{Xci, XciBuilder, XCI_PREFIX_SIZE};
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

/// Decompress NSZ to NSP or XCZ to XCI.
pub fn decompress(input_path: &str, output_path: &str) -> Result<()> {
    let ext = Path::new(input_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "nsz" => decompress_nsz(input_path, output_path),
        "xcz" => decompress_xcz(input_path, output_path),
        "ncz" => decompress_single_ncz(input_path, output_path),
        _ => Err(NscbError::UnsupportedFormat(format!(
            "Cannot decompress {} files",
            ext
        ))),
    }
}

fn decompress_nsz(input_path: &str, output_path: &str) -> Result<()> {
    println!("Decompressing NSZ to NSP...");

    let mut file = BufReader::new(File::open(input_path)?);
    let nsp = Nsp::parse(&mut file)?;

    let mut decompressed_files: Vec<(String, tempfile::NamedTempFile, u64)> = Vec::new();
    let mut passthrough_files: Vec<(String, u64, u64)> = Vec::new();

    for entry in nsp.all_entries() {
        if entry.name.ends_with(".ncz") {
            let nca_name = entry.name.replace(".ncz", ".nca");
            let abs_offset = nsp.file_abs_offset(entry);

            println!("  Decompressing {}...", entry.name);
            let mut tmp = tempfile::NamedTempFile::new()?;
            let ncz = ncz::NczReader::parse_at(&mut file, abs_offset)?;
            let nca_size = ncz
                .sections
                .iter()
                .map(|s| s.offset + s.size)
                .max()
                .unwrap_or(entry.size);
            ncz::decompress_ncz(&mut file, &mut tmp, nca_size, abs_offset)?;
            let actual_size = tmp.as_file().metadata()?.len();
            decompressed_files.push((nca_name, tmp, actual_size));
        } else {
            passthrough_files.push((entry.name.clone(), nsp.file_abs_offset(entry), entry.size));
        }
    }

    let mut builder = crate::formats::pfs0::Pfs0Builder::new();
    for (name, _, size) in &decompressed_files {
        builder.add_file(name.clone(), *size);
    }
    for (name, _, size) in &passthrough_files {
        builder.add_file(name.clone(), *size);
    }

    let header = builder.build_header();
    let total = builder.total_size();
    let pb = progress::file_progress(total, "Building NSP");
    let mut out = BufWriter::new(File::create(output_path)?);
    out.write_all(&header)?;
    pb.set_position(header.len() as u64);

    for (_name, mut tmp, size) in decompressed_files {
        tmp.seek(SeekFrom::Start(0))?;
        uio::copy_with_progress(&mut tmp, &mut out, size, Some(&pb))?;
    }
    for (_, abs_offset, size) in &passthrough_files {
        uio::copy_section(&mut file, &mut out, *abs_offset, *size, Some(&pb))?;
    }

    out.flush()?;
    pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}

fn decompress_xcz(input_path: &str, output_path: &str) -> Result<()> {
    println!("Decompressing XCZ to XCI...");

    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;
    let secure = xci.secure_partition(&mut file)?;

    let total_ncz_bytes: u64 = secure
        .entries
        .iter()
        .filter(|e| e.name.ends_with(".ncz"))
        .map(|e| e.size)
        .sum();
    let decomp_pb = progress::file_progress(total_ncz_bytes, "Decompressing secure NCZ");

    let mut secure_out: Vec<PackedSecureEntry> = Vec::new();
    for entry in &secure.entries {
        let abs_offset = secure.file_abs_offset(entry);
        if entry.name.ends_with(".ncz") {
            let mut tmp = tempfile::NamedTempFile::new()?;
            let ncz_meta = ncz::NczReader::parse_at(&mut file, abs_offset)?;
            let nca_size = ncz_meta
                .sections
                .iter()
                .map(|s| s.offset + s.size)
                .max()
                .unwrap_or(entry.size);
            ncz::decompress_ncz(&mut file, &mut tmp, nca_size, abs_offset)?;
            decomp_pb.inc(entry.size);
            let size = tmp.as_file().metadata()?.len();
            let hash = hash_first_n_from_temp(&mut tmp, size.min(0x200))?;
            secure_out.push(PackedSecureEntry {
                name: entry.name.replace(".ncz", ".nca"),
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
    decomp_pb.finish_with_message("Secure NCZ decompressed");

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
            "XCZ secure partition not found in root HFS0".into(),
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

    let pb = progress::file_progress(total_size, "Building XCI");
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

fn decompress_single_ncz(input_path: &str, output_path: &str) -> Result<()> {
    println!("Decompressing NCZ to NCA...");

    let mut file = BufReader::new(File::open(input_path)?);
    let ncz = ncz::NczReader::parse_at(&mut file, 0)?;
    let nca_size = ncz
        .sections
        .iter()
        .map(|s| s.offset + s.size)
        .max()
        .unwrap_or(0);

    let mut out = File::create(output_path)?;
    ncz::decompress_ncz(&mut file, &mut out, nca_size, 0)?;
    out.flush()?;

    println!("Written: {}", output_path);
    Ok(())
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
