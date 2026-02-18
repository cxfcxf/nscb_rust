use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{NscbError, Result};
use crate::formats::nca;
use crate::formats::nca::NcaHeader;
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::Pfs0Builder;
use crate::formats::ticket::Ticket;
use crate::formats::types::ContentType;
use crate::formats::xci::Xci;
use crate::keys::KeyStore;
use crate::util::{io as uio, progress};

/// An NCA file to be included in the merged output.
#[derive(Debug, Clone)]
struct MergeEntry {
    /// Source file path.
    source_path: String,
    /// NCA filename (e.g., "abcdef0123456789.nca").
    nca_name: String,
    /// Absolute offset in the source file.
    abs_offset: u64,
    /// Size of the NCA.
    size: u64,
    /// Title ID this NCA belongs to.
    title_id: u64,
    /// Content type.
    content_type: Option<ContentType>,
    /// Is delta fragment.
    is_delta: bool,
}

/// A ticket to include in the output.
#[derive(Debug, Clone)]
struct TicketEntry {
    source_path: String,
    name: String,
    abs_offset: u64,
    size: u64,
}

/// A cert to include.
#[derive(Debug, Clone)]
struct CertEntry {
    source_path: String,
    name: String,
    abs_offset: u64,
    size: u64,
}

/// Merge multiple NSP/XCI files into one NSP.
pub fn merge(
    input_paths: &[&str],
    output_path: &str,
    ks: &KeyStore,
    exclude_deltas: bool,
    output_type: &str,
) -> Result<()> {
    println!("Collecting NCA files from {} inputs...", input_paths.len());

    let mut all_ncas: Vec<MergeEntry> = Vec::new();
    let mut all_tickets: Vec<TicketEntry> = Vec::new();
    let mut all_certs: Vec<CertEntry> = Vec::new();
    let mut seen_nca_ids: HashMap<String, usize> = HashMap::new();

    // Auto-decompress NSZ/XCZ inputs to temp files first
    let mut temp_files: Vec<tempfile::NamedTempFile> = Vec::new();
    let mut effective_paths: Vec<String> = Vec::new();

    for path_str in input_paths {
        let path = Path::new(path_str);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "nsz" | "xcz" => {
                // Decompress to a temp file first
                println!(
                    "  Auto-decompressing {}...",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
                let tmp = tempfile::NamedTempFile::new()?;
                let tmp_path = tmp.path().to_string_lossy().to_string();
                crate::ops::decompress::decompress(path_str, &tmp_path)?;
                effective_paths.push(tmp_path);
                temp_files.push(tmp);
            }
            _ => {
                effective_paths.push(path_str.to_string());
            }
        }
    }

    for path_str in &effective_paths {
        let path = Path::new(path_str);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "nsp" => {
                collect_from_nsp(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut all_certs,
                    &mut seen_nca_ids,
                )?;
            }
            "xci" => {
                collect_from_xci(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut seen_nca_ids,
                )?;
            }
            _ => {
                // Temp files from decompression don't have .nsp extension
                // Try as NSP first
                match collect_from_nsp(
                    path_str,
                    ks,
                    &mut all_ncas,
                    &mut all_tickets,
                    &mut all_certs,
                    &mut seen_nca_ids,
                ) {
                    Ok(()) => {}
                    Err(_) => {
                        return Err(NscbError::UnsupportedFormat(format!(
                            "Unknown input format: {}",
                            ext
                        )));
                    }
                }
            }
        }
    }

    // Filter deltas if requested
    if exclude_deltas {
        let before = all_ncas.len();
        all_ncas.retain(|e| !e.is_delta);
        let removed = before - all_ncas.len();
        if removed > 0 {
            println!("Excluded {} delta fragment NCAs", removed);
        }
    }

    println!(
        "Merging {} NCAs, {} tickets, {} certs",
        all_ncas.len(),
        all_tickets.len(),
        all_certs.len()
    );

    match output_type {
        "xci" => build_xci_output(output_path, &all_ncas, &all_tickets, ks)?,
        _ => build_nsp_output(output_path, &all_ncas, &all_tickets, &all_certs)?,
    }

    println!("Output written to {}", output_path);
    Ok(())
}

fn collect_from_nsp(
    path: &str,
    ks: &KeyStore,
    ncas: &mut Vec<MergeEntry>,
    tickets: &mut Vec<TicketEntry>,
    certs: &mut Vec<CertEntry>,
    seen: &mut HashMap<String, usize>,
) -> Result<()> {
    let mut file = BufReader::new(File::open(path)?);
    let nsp = Nsp::parse(&mut file)?;

    // Collect NCA files
    for entry in nsp.nca_entries() {
        let nca_id = entry
            .name
            .trim_end_matches(".nca")
            .trim_end_matches(".ncz")
            .to_lowercase();

        if seen.contains_key(&nca_id) {
            continue; // Dedup
        }
        seen.insert(nca_id, ncas.len());

        let abs_offset = nsp.file_abs_offset(entry);

        // Try to parse NCA header to get metadata
        let (title_id, content_type) =
            match nca::parse_nca_info(&mut file, abs_offset, entry.size, &entry.name, ks) {
                Ok(info) => (info.title_id, info.content_type),
                Err(_) => (0, None),
            };

        ncas.push(MergeEntry {
            source_path: path.to_string(),
            nca_name: entry.name.clone(),
            abs_offset,
            size: entry.size,
            title_id,
            content_type,
            is_delta: false,
        });
    }

    // Collect tickets
    for entry in nsp.ticket_entries() {
        tickets.push(TicketEntry {
            source_path: path.to_string(),
            name: entry.name.clone(),
            abs_offset: nsp.file_abs_offset(entry),
            size: entry.size,
        });
    }

    // Collect certs
    for entry in nsp.cert_entries() {
        certs.push(CertEntry {
            source_path: path.to_string(),
            name: entry.name.clone(),
            abs_offset: nsp.file_abs_offset(entry),
            size: entry.size,
        });
    }

    Ok(())
}

fn collect_from_xci(
    path: &str,
    ks: &KeyStore,
    ncas: &mut Vec<MergeEntry>,
    _tickets: &mut Vec<TicketEntry>,
    seen: &mut HashMap<String, usize>,
) -> Result<()> {
    let mut file = BufReader::new(File::open(path)?);
    let xci = Xci::parse(&mut file)?;

    let secure_entries = xci.secure_nca_entries(&mut file)?;

    for entry in &secure_entries {
        let nca_id = entry
            .name
            .trim_end_matches(".nca")
            .trim_end_matches(".ncz")
            .to_lowercase();

        if seen.contains_key(&nca_id) {
            continue;
        }
        seen.insert(nca_id, ncas.len());

        let (title_id, content_type) =
            match nca::parse_nca_info(&mut file, entry.abs_offset, entry.size, &entry.name, ks) {
                Ok(info) => (info.title_id, info.content_type),
                Err(_) => (0, None),
            };

        ncas.push(MergeEntry {
            source_path: path.to_string(),
            nca_name: entry.name.clone(),
            abs_offset: entry.abs_offset,
            size: entry.size,
            title_id,
            content_type,
            is_delta: false,
        });
    }

    Ok(())
}

fn build_nsp_output(
    output_path: &str,
    ncas: &[MergeEntry],
    tickets: &[TicketEntry],
    certs: &[CertEntry],
) -> Result<()> {
    let mut builder = Pfs0Builder::new();

    // Add NCAs
    for nca in ncas {
        builder.add_file(nca.nca_name.clone(), nca.size);
    }

    // Add tickets
    for tik in tickets {
        builder.add_file(tik.name.clone(), tik.size);
    }

    // Add certs
    for cert in certs {
        builder.add_file(cert.name.clone(), cert.size);
    }

    let header = builder.build_header();
    let total = builder.total_size();
    let pb = progress::file_progress(total, "Building NSP");

    let mut out = BufWriter::new(File::create(output_path)?);

    // Write PFS0 header
    out.write_all(&header)?;
    pb.set_position(header.len() as u64);

    // Write NCA data
    for nca in ncas {
        let mut src = BufReader::new(File::open(&nca.source_path)?);
        uio::copy_section(&mut src, &mut out, nca.abs_offset, nca.size, Some(&pb))?;
    }

    // Write ticket data
    for tik in tickets {
        let mut src = BufReader::new(File::open(&tik.source_path)?);
        uio::copy_section(&mut src, &mut out, tik.abs_offset, tik.size, Some(&pb))?;
    }

    // Write cert data
    for cert in certs {
        let mut src = BufReader::new(File::open(&cert.source_path)?);
        uio::copy_section(&mut src, &mut out, cert.abs_offset, cert.size, Some(&pb))?;
    }

    out.flush()?;
    pb.finish_with_message("Done");
    Ok(())
}

fn build_xci_output(
    output_path: &str,
    ncas: &[MergeEntry],
    tickets: &[TicketEntry],
    ks: &KeyStore,
) -> Result<()> {
    use crate::formats::hfs0::Hfs0Builder;
    use crate::formats::types;
    use crate::formats::xci::{XciBuilder, XCI_PREFIX_SIZE};

    let mut enc_title_keys_by_rights: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    for tik in tickets {
        let mut src = BufReader::new(File::open(&tik.source_path)?);
        src.seek(SeekFrom::Start(tik.abs_offset))?;
        let mut raw = vec![0u8; tik.size as usize];
        src.read_exact(&mut raw)?;
        if let Ok(t) = Ticket::from_bytes(&raw) {
            enc_title_keys_by_rights
                .entry(t.rights_id)
                .or_insert(t.title_key_block);
        }
    }

    struct PreparedNca {
        source_path: String,
        abs_offset: u64,
        size: u64,
        patched_header: Vec<u8>,
    }
    let mut prepared = Vec::with_capacity(ncas.len());

    // Build secure partition HFS0
    let mut secure_builder = Hfs0Builder::new();
    for nca in ncas {
        let mut src = BufReader::new(File::open(&nca.source_path)?);
        src.seek(SeekFrom::Start(nca.abs_offset))?;
        let mut enc_header = vec![0u8; 0xC00];
        src.read_exact(&mut enc_header)?;
        let parsed = NcaHeader::from_encrypted(&enc_header, ks)?;
        let title_key = if parsed.has_rights_id() {
            if let Some(enc_title_key) = enc_title_keys_by_rights.get(&parsed.rights_id) {
                let mkrev = parsed.key_generation().saturating_sub(1);
                Some(ks.decrypt_title_key(enc_title_key, mkrev)?)
            } else {
                None
            }
        } else {
            None
        };
        let patched_header =
            crate::formats::nca::rewrite_header_for_xci(&enc_header, ks, title_key)?;
        let hash = crate::crypto::hash::sha256(&patched_header[..0x200]);
        secure_builder.add_file(nca.nca_name.clone(), nca.size, hash, 0x200);
        prepared.push(PreparedNca {
            source_path: nca.source_path.clone(),
            abs_offset: nca.abs_offset,
            size: nca.size,
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

    // Build XCI header
    let hfs0_offset: u64 = 0xF000; // Standard offset
    let secure_offset = hfs0_offset + root_header.len() as u64 + (empty_partition.len() as u64 * 2);
    let total_data_size = secure_offset + secure_total;

    if secure_offset % types::MEDIA_SIZE != 0 {
        return Err(NscbError::InvalidData(
            "Secure partition offset is not media-aligned".into(),
        ));
    }

    let mut xci_builder = XciBuilder::new();
    xci_builder.auto_card_size(total_data_size);

    let xci_header = xci_builder.build_header(
        hfs0_offset,
        secure_offset,
        root_header.len() as u64,
        &root_hash,
        total_data_size,
    );
    let game_info = xci_builder.build_game_info(total_data_size);
    let sig_padding = xci_builder.sig_padding();
    let fake_cert = xci_builder.fake_certificate();

    // Write output
    let pb = progress::file_progress(total_data_size, "Building XCI");
    let mut out = BufWriter::new(File::create(output_path)?);

    // Write XCI header
    out.write_all(&xci_header)?;
    out.write_all(&game_info)?;
    out.write_all(&sig_padding)?;
    out.write_all(&fake_cert)?;
    if (xci_header.len() + game_info.len() + sig_padding.len() + fake_cert.len()) as u64
        != XCI_PREFIX_SIZE
    {
        return Err(NscbError::InvalidData("XCI prefix size mismatch".into()));
    }

    // Write root HFS0 header
    out.write_all(&root_header)?;

    // Write empty update/normal partitions
    out.write_all(&empty_partition)?;
    out.write_all(&empty_partition)?;

    // Write secure partition header
    out.write_all(&secure_header)?;

    // Write NCA data
    for nca in &prepared {
        out.write_all(&nca.patched_header)?;
        pb.inc(nca.patched_header.len() as u64);
        if nca.size > nca.patched_header.len() as u64 {
            let mut src = BufReader::new(File::open(&nca.source_path)?);
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
