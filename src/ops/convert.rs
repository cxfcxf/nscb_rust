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
use crate::util::{io as uio, progress};

/// Convert NSP to XCI or XCI to NSP.
pub fn convert(
    input_path: &str,
    output_path: &str,
    output_type: &str,
    ks: &KeyStore,
) -> Result<()> {
    let input_ext = Path::new(input_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match (input_ext.as_str(), output_type) {
        ("nsp" | "nsz", "xci") => nsp_to_xci(input_path, output_path, ks),
        ("xci" | "xcz", "nsp") => xci_to_nsp(input_path, output_path, ks),
        ("nsp", "nsp") | ("xci", "xci") => Err(NscbError::InvalidData(
            "Input and output formats are the same".into(),
        )),
        _ => Err(NscbError::UnsupportedFormat(format!(
            "Cannot convert {} to {}",
            input_ext, output_type
        ))),
    }
}

fn nsp_to_xci(input_path: &str, output_path: &str, ks: &KeyStore) -> Result<()> {
    println!("Converting NSP to XCI...");

    let mut file = BufReader::new(File::open(input_path)?);
    let nsp = Nsp::parse(&mut file)?;

    // Collect NCA entries only (XCI doesn't include tickets/certs)
    let nca_entries = nsp.nca_entries();
    if nca_entries.is_empty() {
        return Err(NscbError::InvalidData("NSP contains no NCA files".into()));
    }

    let mut fallback_title_key: Option<[u8; 16]> = None;
    for tik in nsp.ticket_entries() {
        let abs_offset = nsp.file_abs_offset(tik);
        file.seek(SeekFrom::Start(abs_offset))?;
        let mut raw = vec![0u8; tik.size as usize];
        file.read_exact(&mut raw)?;
        if let Ok(t) = Ticket::from_bytes(&raw) {
            if let Ok(title_key) = t.decrypt_title_key(ks) {
                // NSC_BUILDER behavior: effective key is driven by ticket scan order.
                fallback_title_key = Some(title_key);
            }
        }
    }

    struct PreparedNca {
        size: u64,
        abs_offset: u64,
        patched_header: Vec<u8>,
    }
    let mut prepared = Vec::with_capacity(nca_entries.len());

    // Build secure HFS0
    let mut secure_builder = Hfs0Builder::new();
    for entry in &nca_entries {
        let abs_offset = nsp.file_abs_offset(entry);
        file.seek(SeekFrom::Start(abs_offset))?;
        let mut enc_header = vec![0u8; 0xC00];
        file.read_exact(&mut enc_header)?;

        let parsed = NcaHeader::from_encrypted(&enc_header, ks)?;
        let title_key = if parsed.has_rights_id() {
            fallback_title_key
        } else {
            None
        };
        let patched_header =
            crate::formats::nca::rewrite_header_for_xci(&enc_header, ks, title_key)?;
        let hash = crate::crypto::hash::sha256(&patched_header[..0x200]);
        secure_builder.add_file(entry.name.clone(), entry.size, hash, 0x200);
        prepared.push(PreparedNca {
            size: entry.size,
            abs_offset,
            patched_header,
        });
    }

    let secure_header = secure_builder.build_header_aligned(0x200);
    let secure_total = secure_builder.total_size();

    // Build root HFS0 with gamecard-like partitions: update, normal, secure.
    let empty_partition = empty_hfs0_partition_0x200();
    let empty_hash = crate::crypto::hash::sha256(&empty_partition);
    let secure_hash = crate::crypto::hash::sha256(&secure_header);

    let mut root_builder = Hfs0Builder::new();
    root_builder.add_file(
        "update".to_string(),
        empty_partition.len() as u64,
        empty_hash,
        0x200,
    );
    root_builder.add_file(
        "normal".to_string(),
        empty_partition.len() as u64,
        empty_hash,
        0x200,
    );
    root_builder.add_file(
        "secure".to_string(),
        secure_total,
        secure_hash,
        secure_header.len() as u32,
    );

    let root_header = root_builder.build_header_aligned(0x200);
    let root_hash = crate::crypto::hash::sha256(&root_header);

    let hfs0_offset: u64 = 0xF000;
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

    // Write output
    let pb = progress::file_progress(total_size, "Converting to XCI");
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
    out.write_all(&empty_partition)?;
    out.write_all(&empty_partition)?;
    out.write_all(&secure_header)?;

    for nca in &prepared {
        out.write_all(&nca.patched_header)?;
        pb.inc(nca.patched_header.len() as u64);
        if nca.size > nca.patched_header.len() as u64 {
            uio::copy_section(
                &mut file,
                &mut out,
                nca.abs_offset + nca.patched_header.len() as u64,
                nca.size - nca.patched_header.len() as u64,
                Some(&pb),
            )?;
        }
    }

    out.flush()?;
    pb.finish_with_message("Done");
    println!("Written: {}", output_path);
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
