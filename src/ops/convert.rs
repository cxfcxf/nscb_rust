use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{NscbError, Result};
use crate::formats::hfs0::Hfs0Builder;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::Pfs0Builder;
use crate::formats::xci::{Xci, XciBuilder};
use crate::keys::KeyStore;
use crate::util::{io as uio, progress};

/// Convert NSP to XCI or XCI to NSP.
pub fn convert(input_path: &str, output_path: &str, output_type: &str, ks: &KeyStore) -> Result<()> {
    let input_ext = Path::new(input_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match (input_ext.as_str(), output_type) {
        ("nsp" | "nsz", "xci") => nsp_to_xci(input_path, output_path, ks),
        ("xci" | "xcz", "nsp") => xci_to_nsp(input_path, output_path, ks),
        ("nsp", "nsp") | ("xci", "xci") => {
            Err(NscbError::InvalidData("Input and output formats are the same".into()))
        }
        _ => Err(NscbError::UnsupportedFormat(format!(
            "Cannot convert {} to {}",
            input_ext, output_type
        ))),
    }
}

fn nsp_to_xci(input_path: &str, output_path: &str, _ks: &KeyStore) -> Result<()> {
    println!("Converting NSP to XCI...");

    let mut file = BufReader::new(File::open(input_path)?);
    let nsp = Nsp::parse(&mut file)?;

    // Collect NCA entries only (XCI doesn't include tickets/certs)
    let nca_entries = nsp.nca_entries();
    if nca_entries.is_empty() {
        return Err(NscbError::InvalidData("NSP contains no NCA files".into()));
    }

    // Build secure HFS0
    let mut secure_builder = Hfs0Builder::new();
    for entry in &nca_entries {
        let abs_offset = nsp.file_abs_offset(entry);
        file.seek(SeekFrom::Start(abs_offset))?;
        let hash_size = entry.size.min(0x200) as usize;
        let mut hash_buf = vec![0u8; hash_size];
        file.read_exact(&mut hash_buf)?;
        let hash = crate::crypto::hash::sha256(&hash_buf);
        secure_builder.add_file(entry.name.clone(), entry.size, hash, hash_size as u32);
    }

    let secure_header = secure_builder.build_header();
    let secure_total = secure_builder.total_size();

    // Build root HFS0
    let mut root_builder = Hfs0Builder::new();
    let secure_hash = crate::crypto::hash::sha256(&secure_header);
    root_builder.add_file(
        "secure".to_string(),
        secure_total,
        secure_hash,
        secure_header.len() as u32,
    );

    let root_header = root_builder.build_header();
    let root_hash = crate::crypto::hash::sha256(&root_header);

    let hfs0_offset: u64 = 0xF000;
    let total_size = hfs0_offset + root_header.len() as u64 + secure_total;

    let mut xci_builder = XciBuilder::new();
    xci_builder.auto_card_size(total_size);
    let xci_header = xci_builder.build_header(
        hfs0_offset,
        root_header.len() as u64,
        &root_hash,
        total_size,
    );

    // Write output
    let pb = progress::file_progress(total_size, "Converting to XCI");
    let mut out = BufWriter::new(File::create(output_path)?);

    out.write_all(&xci_header)?;
    uio::write_padding(&mut out, hfs0_offset - xci_header.len() as u64)?;
    out.write_all(&root_header)?;
    out.write_all(&secure_header)?;

    for entry in &nca_entries {
        let abs_offset = nsp.file_abs_offset(entry);
        uio::copy_section(&mut file, &mut out, abs_offset, entry.size, Some(&pb))?;
    }

    out.flush()?;
    pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}

fn xci_to_nsp(input_path: &str, output_path: &str, _ks: &KeyStore) -> Result<()> {
    println!("Converting XCI to NSP...");

    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;

    let secure_entries = xci.secure_nca_entries(&mut file)?;
    if secure_entries.is_empty() {
        return Err(NscbError::InvalidData(
            "XCI secure partition contains no NCA files".into(),
        ));
    }

    // Build NSP PFS0
    let mut builder = Pfs0Builder::new();
    for entry in &secure_entries {
        builder.add_file(entry.name.clone(), entry.size);
    }

    let header = builder.build_header();
    let total = builder.total_size();
    let pb = progress::file_progress(total, "Converting to NSP");

    let mut out = BufWriter::new(File::create(output_path)?);

    out.write_all(&header)?;
    pb.set_position(header.len() as u64);

    for entry in &secure_entries {
        uio::copy_section(&mut file, &mut out, entry.abs_offset, entry.size, Some(&pb))?;
    }

    out.flush()?;
    pb.finish_with_message("Done");
    println!("Written: {}", output_path);
    Ok(())
}
