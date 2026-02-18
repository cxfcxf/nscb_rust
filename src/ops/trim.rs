use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};

use crate::error::{NscbError, Result};
use crate::formats::types;
use crate::formats::xci::Xci;
use crate::util::{io as uio, progress};

/// Trim an XCI file — remove empty padding after the last NCA.
pub fn trim(input_path: &str, output_path: &str) -> Result<()> {
    println!("Trimming XCI...");

    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;

    let data_end = xci.header.data_end_bytes();
    let file_size = fs::metadata(input_path)?.len();

    if data_end >= file_size {
        println!(
            "XCI is already trimmed (data end: {}, file size: {})",
            data_end, file_size
        );
        return Ok(());
    }

    let saved = file_size - data_end;
    println!(
        "Trimming from {} to {} bytes (saving {} MB)",
        file_size,
        data_end,
        saved / (1024 * 1024)
    );

    let pb = progress::file_progress(data_end, "Trimming");
    let mut out = BufWriter::new(File::create(output_path)?);
    file.seek(SeekFrom::Start(0))?;
    uio::copy_with_progress(&mut file, &mut out, data_end, Some(&pb))?;
    out.flush()?;
    pb.finish_with_message("Done");

    println!("Trimmed: {}", output_path);
    Ok(())
}

/// Super-trim an XCI — find the actual last used byte from secure partition contents.
pub fn super_trim(input_path: &str, output_path: &str) -> Result<()> {
    println!("Super-trimming XCI...");

    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;

    // Find the actual end of data in the secure partition
    let secure = xci.secure_partition(&mut file)?;
    let actual_end = secure.header_offset + secure.total_size();

    let file_size = fs::metadata(input_path)?.len();

    if actual_end >= file_size {
        println!("XCI cannot be super-trimmed further");
        return Ok(());
    }

    // Align to media size
    let trim_end = crate::util::align::align_up(actual_end, types::MEDIA_SIZE);
    let saved = file_size - trim_end;

    println!(
        "Super-trimming from {} to {} bytes (saving {} MB)",
        file_size,
        trim_end,
        saved / (1024 * 1024)
    );

    let pb = progress::file_progress(trim_end, "Super-trimming");
    let mut out = BufWriter::new(File::create(output_path)?);
    file.seek(SeekFrom::Start(0))?;
    uio::copy_with_progress(&mut file, &mut out, trim_end, Some(&pb))?;
    out.flush()?;
    pb.finish_with_message("Done");

    println!("Super-trimmed: {}", output_path);
    Ok(())
}

/// Untrim an XCI — pad with 0xFF to the declared card capacity.
pub fn untrim(input_path: &str, output_path: &str) -> Result<()> {
    println!("Untrimming XCI...");

    let mut file = BufReader::new(File::open(input_path)?);
    let xci = Xci::parse(&mut file)?;

    let card_size = xci.header.card_size();
    if card_size == 0 {
        return Err(NscbError::InvalidData(format!(
            "Unknown card size byte: 0x{:02X}",
            xci.header.card_size_byte
        )));
    }

    let file_size = fs::metadata(input_path)?.len();

    if file_size >= card_size {
        println!("XCI is already at full card size ({} bytes)", card_size);
        return Ok(());
    }

    let padding_needed = card_size - file_size;
    println!(
        "Untrimming from {} to {} bytes (adding {} MB of padding)",
        file_size,
        card_size,
        padding_needed / (1024 * 1024)
    );

    let pb = progress::file_progress(card_size, "Untrimming");

    // Copy original data
    let mut out = BufWriter::new(File::create(output_path)?);
    file.seek(SeekFrom::Start(0))?;
    uio::copy_with_progress(&mut file, &mut out, file_size, Some(&pb))?;

    // Pad with 0xFF
    uio::write_fill(&mut out, 0xFF, padding_needed)?;

    out.flush()?;
    pb.finish_with_message("Done");

    println!("Untrimmed: {}", output_path);
    Ok(())
}
