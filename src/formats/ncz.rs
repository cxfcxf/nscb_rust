//! NCZ/NSZ/XCZ compression format support.
//!
//! NCZ is a compressed NCA. An NSZ is a PFS0 of NCZ files.
//! An XCZ is an XCI with NCZ files in the secure partition.
//!
//! NCZ format:
//! - First 0x4000 bytes: original NCA header + section headers (unmodified)
//! - NCZSECTN magic + section table at 0x4000
//! - Then EITHER:
//!   - Block table (version, block_size, etc.) + compressed blocks  (block-based)
//!   - Raw zstd stream (starts with zstd magic 0xFD2FB528)          (stream-based)

use std::io::{Read, Seek, SeekFrom, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use indicatif::ProgressBar;

use crate::error::{NscbError, Result};

/// Magic bytes at the start of the NCZ section table.
pub const NCZ_MAGIC: &[u8; 8] = b"NCZSECTN";

/// Zstd frame magic (little-endian).
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// NCZ section entry — describes one encrypted section of the NCA.
#[derive(Debug, Clone)]
pub struct NczSection {
    pub offset: u64,
    pub size: u64,
    pub crypto_type: u64,
    pub _padding: u64,
    pub crypto_key: [u8; 16],
    pub crypto_counter: [u8; 16],
}

/// NCZ block table — maps compressed blocks to decompressed data.
#[derive(Debug, Clone)]
pub struct NczBlockTable {
    pub version: u8,
    pub block_type: u8,
    pub _unused: u8,
    pub block_size_exponent: u8,
    pub block_count: u32,
    pub decompressed_size: u64,
    /// Compressed sizes for each block.
    pub block_sizes: Vec<u32>,
}

/// Parse NCZ metadata from a reader.
pub struct NczReader {
    /// Sections describing the encrypted layout.
    pub sections: Vec<NczSection>,
    /// Block table for block-based decompression (None for stream-based).
    pub block_table: Option<NczBlockTable>,
    /// Whether this is a stream-based NCZ (raw zstd after sections).
    pub is_stream: bool,
    /// Offset where the compressed data starts (after header + sections + optional block table).
    pub data_start: u64,
    /// The original NCA header bytes (first 0x4000 bytes).
    pub nca_header: Vec<u8>,
}

impl NczReader {
    /// Parse NCZ from a reader at current position.
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let pos = reader.stream_position()?;
        Self::parse_at(reader, pos)
    }

    /// Parse NCZ from a reader at a specific offset.
    pub fn parse_at<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<Self> {
        reader.seek(SeekFrom::Start(offset))?;

        // Read original NCA header (0x4000 bytes)
        let mut nca_header = vec![0u8; 0x4000];
        reader.read_exact(&mut nca_header)?;

        // Check for section magic
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;

        if &magic != NCZ_MAGIC {
            return Err(NscbError::InvalidMagic {
                expected: "NCZSECTN".into(),
                got: String::from_utf8_lossy(&magic).into(),
            });
        }

        let section_count = reader.read_u64::<LittleEndian>()? as usize;

        // Parse sections (64 bytes each)
        let mut sections = Vec::with_capacity(section_count);
        for _ in 0..section_count {
            let sec_offset = reader.read_u64::<LittleEndian>()?;
            let size = reader.read_u64::<LittleEndian>()?;
            let crypto_type = reader.read_u64::<LittleEndian>()?;
            let padding = reader.read_u64::<LittleEndian>()?;

            let mut crypto_key = [0u8; 16];
            reader.read_exact(&mut crypto_key)?;

            let mut crypto_counter = [0u8; 16];
            reader.read_exact(&mut crypto_counter)?;

            sections.push(NczSection {
                offset: sec_offset,
                size,
                crypto_type,
                _padding: padding,
                crypto_key,
                crypto_counter,
            });
        }

        // Check what follows: block table or raw zstd stream?
        let after_sections = reader.stream_position()?;
        let mut peek = [0u8; 4];
        reader.read_exact(&mut peek)?;

        if peek == ZSTD_MAGIC {
            // Stream-based NCZ: raw zstd data follows sections
            Ok(Self {
                sections,
                block_table: None,
                is_stream: true,
                data_start: after_sections,
                nca_header,
            })
        } else {
            // Block-based NCZ: parse block table
            // Seek back and read block table header
            reader.seek(SeekFrom::Start(after_sections))?;
            let block_table = Self::parse_block_table(reader)?;
            let data_start = reader.stream_position()?;

            Ok(Self {
                sections,
                block_table: Some(block_table),
                is_stream: false,
                data_start,
                nca_header,
            })
        }
    }

    fn parse_block_table<R: Read + Seek>(reader: &mut R) -> Result<NczBlockTable> {
        let version = reader.read_u8()?;
        let block_type = reader.read_u8()?;
        let unused = reader.read_u8()?;
        let block_size_exponent = reader.read_u8()?;
        let block_count = reader.read_u32::<LittleEndian>()?;
        let decompressed_size = reader.read_u64::<LittleEndian>()?;

        let mut block_sizes = Vec::with_capacity(block_count as usize);
        for _ in 0..block_count {
            let bs = reader.read_u32::<LittleEndian>()?;
            block_sizes.push(bs);
        }

        Ok(NczBlockTable {
            version,
            block_type,
            _unused: unused,
            block_size_exponent,
            block_count,
            decompressed_size,
            block_sizes,
        })
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> usize {
        match &self.block_table {
            Some(bt) => 1 << bt.block_size_exponent,
            None => 1 << 15, // 32KB default
        }
    }
}

/// Decompress an NCZ file to NCA.
/// `offset` is where the NCZ data starts in the reader.
pub fn decompress_ncz<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    total_nca_size: u64,
    offset: u64,
) -> Result<()> {
    let ncz = NczReader::parse_at(reader, offset)?;

    // Write the original NCA header
    writer.write_all(&ncz.nca_header)?;

    // Seek to compressed data
    reader.seek(SeekFrom::Start(ncz.data_start))?;

    let mut written = ncz.nca_header.len() as u64;
    let target = total_nca_size;

    if ncz.is_stream {
        // Stream-based: decompress a single zstd stream
        decompress_stream(reader, writer, &mut written, target)?;
    } else if let Some(block_table) = &ncz.block_table {
        // Block-based: decompress individual blocks
        let block_size = 1usize << block_table.block_size_exponent;
        decompress_blocks(reader, writer, block_table, block_size, &mut written, target)?;
    } else {
        return Err(NscbError::InvalidData(
            "NCZ has neither block table nor zstd stream".into(),
        ));
    }

    // Pad to target size if needed
    if written < target {
        crate::util::io::write_padding(writer, target - written)?;
    }

    Ok(())
}

/// Decompress a stream-based NCZ (single zstd stream).
fn decompress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    written: &mut u64,
    target: u64,
) -> Result<()> {
    let mut decoder = zstd::Decoder::new(reader).map_err(|e| {
        NscbError::Crypto(format!("zstd decoder init error: {e}"))
    })?;

    let mut buf = vec![0u8; 1024 * 1024]; // 1MB read buffer
    loop {
        if *written >= target {
            break;
        }

        let to_read = buf.len().min((target - *written) as usize);
        let n = decoder.read(&mut buf[..to_read]).map_err(|e| {
            NscbError::Crypto(format!("zstd decompress error: {e}"))
        })?;

        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n])?;
        *written += n as u64;
    }

    Ok(())
}

/// Decompress block-based NCZ.
fn decompress_blocks<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    block_table: &NczBlockTable,
    block_size: usize,
    written: &mut u64,
    target: u64,
) -> Result<()> {
    for &compressed_size in &block_table.block_sizes {
        if *written >= target {
            break;
        }

        let mut compressed = vec![0u8; compressed_size as usize];
        reader.read_exact(&mut compressed)?;

        // Check if block is stored uncompressed (compressed_size == block_size)
        let decompressed = if compressed_size as usize == block_size {
            compressed
        } else {
            zstd::decode_all(&compressed[..]).map_err(|e| {
                NscbError::Crypto(format!("zstd decompress error: {e}"))
            })?
        };

        let to_write = decompressed.len().min((target - *written) as usize);
        writer.write_all(&decompressed[..to_write])?;
        *written += to_write as u64;
    }

    Ok(())
}

/// Compress an NCA to NCZ format (block-based).
pub fn compress_nca<R: Read + Seek, W: Write + Seek>(
    reader: &mut R,
    writer: &mut W,
    nca_size: u64,
    compression_level: i32,
    pb: Option<&ProgressBar>,
) -> Result<()> {
    reader.seek(SeekFrom::Start(0))?;

    // Copy original NCA header (0x4000 bytes)
    let mut nca_header = vec![0u8; 0x4000];
    reader.read_exact(&mut nca_header)?;
    writer.write_all(&nca_header)?;

    // Write section magic + a single data section, then a solid zstd stream.
    // This yields better compression ratio than independent block streams.
    writer.write_all(NCZ_MAGIC)?;
    let data_to_compress = nca_size.saturating_sub(0x4000);
    if data_to_compress > 0 {
        writer.write_u64::<LittleEndian>(1)?; // section count
        writer.write_u64::<LittleEndian>(0x4000)?; // section offset in NCA
        writer.write_u64::<LittleEndian>(data_to_compress)?; // section size
        writer.write_u64::<LittleEndian>(0)?; // crypto_type
        writer.write_u64::<LittleEndian>(0)?; // padding
        writer.write_all(&[0u8; 16])?; // crypto_key
        writer.write_all(&[0u8; 16])?; // crypto_counter

        let mut limited = reader.take(data_to_compress);
        let mut enc = zstd::stream::write::Encoder::new(writer, compression_level).map_err(|e| {
            NscbError::Crypto(format!("zstd encoder init error: {e}"))
        })?;
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = limited.read(&mut buf)?;
            if n == 0 {
                break;
            }
            enc.write_all(&buf[..n])?;
            if let Some(pb) = pb {
                pb.inc(n as u64);
            }
        }
        enc.finish().map_err(|e| {
            NscbError::Crypto(format!("zstd stream finalize error: {e}"))
        })?;
    } else {
        writer.write_u64::<LittleEndian>(0)?; // section count
    }

    Ok(())
}
