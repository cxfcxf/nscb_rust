use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{NscbError, Result};
use crate::formats::ncz;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::Pfs0Builder;
use crate::formats::xci::Xci;
use crate::util::{io as uio, progress};

/// Compress NSP to NSZ or XCI to XCZ.
pub fn compress(input_path: &str, output_path: &str, level: i32) -> Result<()> {
    let ext = Path::new(input_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "nsp" => compress_nsp(input_path, output_path, level),
        "xci" => compress_xci(input_path, output_path, level),
        _ => Err(NscbError::UnsupportedFormat(format!(
            "Cannot compress {} files",
            ext
        ))),
    }
}

fn compress_nsp(input_path: &str, output_path: &str, level: i32) -> Result<()> {
    println!("Compressing NSP to NSZ...");

    let mut file = BufReader::new(File::open(input_path)?);
    let nsp = Nsp::parse(&mut file)?;
    let total_nca_bytes: u64 = nsp
        .all_entries()
        .iter()
        .filter(|e| e.name.ends_with(".nca"))
        .map(|e| e.size.saturating_sub(0x4000))
        .sum();
    let compress_pb = progress::file_progress(total_nca_bytes, "Compressing NCAs");

    // First pass: compress each NCA to a temp file and collect sizes
    let mut compressed_files: Vec<(String, tempfile::NamedTempFile)> = Vec::new();
    let mut other_files: Vec<(String, u64, u64)> = Vec::new(); // (name, abs_offset, size)

    for entry in nsp.all_entries() {
        if entry.name.ends_with(".nca") {
            let abs_offset = nsp.file_abs_offset(entry);
            let nca_size = entry.size;
            let ncz_name = entry.name.replace(".nca", ".ncz");

            println!("  Compressing {} ({} MB)...", entry.name, nca_size / (1024 * 1024));

            // Create temp file for compressed output
            let mut tmp = tempfile::NamedTempFile::new()?;

            // Create a sub-reader for this NCA
            file.seek(SeekFrom::Start(abs_offset))?;

            ncz::compress_nca(&mut file, &mut tmp, nca_size, level, Some(&compress_pb))?;

            compressed_files.push((ncz_name, tmp));
        } else {
            // Non-NCA files (tickets, certs) pass through
            other_files.push((
                entry.name.clone(),
                nsp.file_abs_offset(entry),
                entry.size,
            ));
        }
    }
    compress_pb.finish_with_message("NCAs compressed");

    // Build output NSZ (PFS0 of NCZ + other files)
    let mut builder = Pfs0Builder::new();

    for (name, tmp) in &compressed_files {
        let size = tmp.as_file().metadata()?.len();
        builder.add_file(name.clone(), size);
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

    // Write compressed NCAs
    for (_name, mut tmp) in compressed_files {
        let size = tmp.as_file().metadata()?.len();
        tmp.seek(SeekFrom::Start(0))?;
        uio::copy_with_progress(&mut tmp, &mut out, size, Some(&build_pb))?;
    }

    // Write other files
    for (_, abs_offset, size) in &other_files {
        uio::copy_section(&mut file, &mut out, *abs_offset, *size, Some(&build_pb))?;
    }

    out.flush()?;
    build_pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}

fn compress_xci(input_path: &str, output_path: &str, level: i32) -> Result<()> {
    println!("Compressing XCI to XCZ...");

    // For XCI compression, we compress the NCAs within the secure partition
    // This is a simplified version — a full implementation would rebuild
    // the XCI structure with compressed NCAs
    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;
    let secure_entries = xci.secure_nca_entries(&mut file)?;
    let total_nca_bytes: u64 = secure_entries
        .iter()
        .filter(|e| e.name.ends_with(".nca"))
        .map(|e| e.size.saturating_sub(0x4000))
        .sum();
    let compress_pb = progress::file_progress(total_nca_bytes, "Compressing NCAs");

    // Compress each NCA and collect
    let mut compressed_files: Vec<(String, tempfile::NamedTempFile)> = Vec::new();

    for entry in &secure_entries {
        if entry.name.ends_with(".nca") {
            let ncz_name = entry.name.replace(".nca", ".ncz");
            println!("  Compressing {} ({} MB)...", entry.name, entry.size / (1024 * 1024));

            let mut tmp = tempfile::NamedTempFile::new()?;
            file.seek(SeekFrom::Start(entry.abs_offset))?;
            ncz::compress_nca(&mut file, &mut tmp, entry.size, level, Some(&compress_pb))?;
            compressed_files.push((ncz_name, tmp));
        }
    }
    compress_pb.finish_with_message("NCAs compressed");

    // Build output as NSZ (PFS0 with NCZ files) since XCZ is less standard
    // Most tools accept NSZ more broadly
    let mut builder = Pfs0Builder::new();
    for (name, tmp) in &compressed_files {
        let size = tmp.as_file().metadata()?.len();
        builder.add_file(name.clone(), size);
    }

    let header = builder.build_header();
    let total = builder.total_size();
    let build_pb = progress::file_progress(total, "Building XCZ");
    let mut out = BufWriter::new(File::create(output_path)?);
    out.write_all(&header)?;
    build_pb.set_position(header.len() as u64);

    for (_, mut tmp) in compressed_files {
        let size = tmp.as_file().metadata()?.len();
        tmp.seek(SeekFrom::Start(0))?;
        uio::copy_with_progress(&mut tmp, &mut out, size, Some(&build_pb))?;
    }

    out.flush()?;
    build_pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}
