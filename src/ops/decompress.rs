use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{NscbError, Result};
use crate::formats::ncz;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::Pfs0Builder;
use crate::util::{io as uio, progress};

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

    // NSZ is a PFS0 containing NCZ files + other files
    let nsp = Nsp::parse(&mut file)?;

    // First pass: decompress NCZ files to temp files, pass through others
    let mut decompressed_files: Vec<(String, tempfile::NamedTempFile, u64)> = Vec::new();
    let mut passthrough_files: Vec<(String, u64, u64)> = Vec::new(); // (name, offset, size)

    for entry in nsp.all_entries() {
        if entry.name.ends_with(".ncz") {
            let nca_name = entry.name.replace(".ncz", ".nca");
            let abs_offset = nsp.file_abs_offset(entry);

            println!("  Decompressing {}...", entry.name);

            let mut tmp = tempfile::NamedTempFile::new()?;

            // Parse NCZ header to find the original NCA size from sections
            let ncz = ncz::NczReader::parse_at(&mut file, abs_offset)?;

            // Estimate NCA size from sections
            let nca_size = ncz
                .sections
                .iter()
                .map(|s| s.offset + s.size)
                .max()
                .unwrap_or(entry.size);

            // Decompress
            ncz::decompress_ncz(&mut file, &mut tmp, nca_size, abs_offset)?;

            let actual_size = tmp.as_file().metadata()?.len();
            decompressed_files.push((nca_name, tmp, actual_size));
        } else {
            passthrough_files.push((
                entry.name.clone(),
                nsp.file_abs_offset(entry),
                entry.size,
            ));
        }
    }

    // Build output NSP
    let mut builder = Pfs0Builder::new();

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

    // Write decompressed NCAs
    for (_name, mut tmp, size) in decompressed_files {
        tmp.seek(SeekFrom::Start(0))?;
        uio::copy_with_progress(&mut tmp, &mut out, size, Some(&pb))?;
    }

    // Write passthrough files
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
    // XCZ uses the same PFS0-of-NCZ structure internally
    // For now, decompress to NSP format
    decompress_nsz(input_path, output_path)
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

    let mut out = BufWriter::new(File::create(output_path)?);
    ncz::decompress_ncz(&mut file, &mut out, nca_size, 0)?;
    out.flush()?;

    println!("Written: {}", output_path);
    Ok(())
}
