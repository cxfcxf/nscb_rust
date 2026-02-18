use std::io::{Read, Seek, SeekFrom, Write};

use indicatif::ProgressBar;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

/// Copy `size` bytes from src to dst with progress reporting.
pub fn copy_with_progress<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    size: u64,
    pb: Option<&ProgressBar>,
) -> std::io::Result<u64> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut remaining = size;
    let mut total = 0u64;

    while remaining > 0 {
        let to_read = buf.len().min(remaining as usize);
        let n = src.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        remaining -= n as u64;
        total += n as u64;
        if let Some(pb) = pb {
            pb.inc(n as u64);
        }
    }
    Ok(total)
}

/// Copy `size` bytes from a specific offset in src.
pub fn copy_section<R: Read + Seek, W: Write>(
    src: &mut R,
    dst: &mut W,
    offset: u64,
    size: u64,
    pb: Option<&ProgressBar>,
) -> std::io::Result<u64> {
    src.seek(SeekFrom::Start(offset))?;
    copy_with_progress(src, dst, size, pb)
}

/// Write padding zeros to align the writer position.
pub fn write_padding<W: Write>(dst: &mut W, count: u64) -> std::io::Result<()> {
    write_fill(dst, 0, count)
}

/// Write padding with a specific byte value.
pub fn write_fill<W: Write>(dst: &mut W, byte: u8, count: u64) -> std::io::Result<()> {
    let fill = [byte; 4096];
    let mut remaining = count;
    while remaining > 0 {
        let n = fill.len().min(remaining as usize);
        dst.write_all(&fill[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Read exactly `size` bytes from a specific offset.
pub fn read_at<R: Read + Seek>(src: &mut R, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
    src.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; size];
    src.read_exact(&mut buf)?;
    Ok(buf)
}
