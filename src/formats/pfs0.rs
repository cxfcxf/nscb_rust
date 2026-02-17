use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{NscbError, Result};

pub const PFS0_MAGIC: &[u8; 4] = b"PFS0";
const ENTRY_SIZE: u64 = 0x18; // 24 bytes per file entry
const PFS0_ALIGN: u64 = 0x10;

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

/// A parsed PFS0 file entry.
#[derive(Debug, Clone)]
pub struct Pfs0Entry {
    pub name: String,
    /// Offset relative to the data region start.
    pub data_offset: u64,
    pub size: u64,
}

/// A parsed PFS0 container.
#[derive(Debug)]
pub struct Pfs0 {
    pub entries: Vec<Pfs0Entry>,
    /// Absolute offset in the source where the PFS0 header starts.
    pub header_offset: u64,
    /// Absolute offset where the data region starts.
    pub data_offset: u64,
    /// Total header size (magic + entry table + string table + padding).
    pub header_size: u64,
}

impl Pfs0 {
    /// Parse a PFS0 from a reader at the current position.
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let pos = reader.stream_position()?;
        Self::parse_at(reader, pos)
    }

    /// Parse a PFS0 at a specific offset.
    pub fn parse_at<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<Self> {
        reader.seek(SeekFrom::Start(offset))?;

        // Read magic
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != PFS0_MAGIC {
            return Err(NscbError::InvalidMagic {
                expected: "PFS0".into(),
                got: String::from_utf8_lossy(&magic).into(),
            });
        }

        let file_count = reader.read_u32::<LittleEndian>()? as usize;
        let string_table_size = reader.read_u32::<LittleEndian>()? as usize;
        let _padding = reader.read_u32::<LittleEndian>()?;

        // Read entry table
        struct RawEntry {
            data_offset: u64,
            size: u64,
            name_offset: u32,
        }

        let mut raw_entries = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let data_offset = reader.read_u64::<LittleEndian>()?;
            let size = reader.read_u64::<LittleEndian>()?;
            let name_offset = reader.read_u32::<LittleEndian>()?;
            let _reserved = reader.read_u32::<LittleEndian>()?;
            raw_entries.push(RawEntry {
                data_offset,
                size,
                name_offset,
            });
        }

        // Read string table
        let mut string_table = vec![0u8; string_table_size];
        reader.read_exact(&mut string_table)?;

        // Resolve file names from string table
        let mut entries = Vec::with_capacity(file_count);
        for raw in &raw_entries {
            let start = raw.name_offset as usize;
            let name = if start < string_table.len() {
                let end = string_table[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| start + p)
                    .unwrap_or(string_table.len());
                String::from_utf8_lossy(&string_table[start..end]).into_owned()
            } else {
                String::new()
            };

            entries.push(Pfs0Entry {
                name,
                data_offset: raw.data_offset,
                size: raw.size,
            });
        }

        // Calculate data region start.
        // Some files align PFS0 headers to 0x10 with zero padding; others do not.
        let raw_header_size = 0x10 + (file_count as u64 * ENTRY_SIZE) + string_table_size as u64;
        let aligned_header_size = align_up(raw_header_size, PFS0_ALIGN);
        let mut header_size = raw_header_size;
        if aligned_header_size > raw_header_size {
            let pad_len = (aligned_header_size - raw_header_size) as usize;
            let mut padding = vec![0u8; pad_len];
            reader.read_exact(&mut padding)?;
            if padding.iter().all(|&b| b == 0) {
                header_size = aligned_header_size;
            }
        }
        let data_offset = offset + header_size;

        Ok(Self {
            entries,
            header_offset: offset,
            data_offset,
            header_size,
        })
    }

    /// Get absolute offset of a file entry in the underlying reader.
    pub fn file_abs_offset(&self, entry: &Pfs0Entry) -> u64 {
        self.data_offset + entry.data_offset
    }

    /// Find an entry by name.
    pub fn find(&self, name: &str) -> Option<&Pfs0Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Find entries by extension.
    pub fn find_by_ext(&self, ext: &str) -> Vec<&Pfs0Entry> {
        self.entries
            .iter()
            .filter(|e| e.name.ends_with(ext))
            .collect()
    }

    /// Read the full contents of a named file.
    pub fn read_file<R: Read + Seek>(&self, reader: &mut R, name: &str) -> Result<Vec<u8>> {
        let entry = self.find(name).ok_or_else(|| {
            NscbError::InvalidData(format!("File '{}' not found in PFS0", name))
        })?;
        let abs_offset = self.file_abs_offset(entry);
        reader.seek(SeekFrom::Start(abs_offset))?;
        let mut buf = vec![0u8; entry.size as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Total size of all files plus header.
    pub fn total_size(&self) -> u64 {
        let max_end = self
            .entries
            .iter()
            .map(|e| e.data_offset + e.size)
            .max()
            .unwrap_or(0);
        self.header_size + max_end
    }
}

/// Builder for creating new PFS0 containers.
pub struct Pfs0Builder {
    files: Vec<BuilderEntry>,
}

struct BuilderEntry {
    name: String,
    size: u64,
}

impl Pfs0Builder {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Add a file to be packed. Files will be written in order added.
    pub fn add_file(&mut self, name: String, size: u64) {
        self.files.push(BuilderEntry { name, size });
    }

    /// Calculate the header size for the current file list.
    pub fn header_size(&self) -> u64 {
        let string_table_size: u64 = self.files.iter().map(|f| (f.name.len() + 1) as u64).sum();
        let raw = 0x10 + (self.files.len() as u64 * ENTRY_SIZE) + string_table_size;
        align_up(raw, PFS0_ALIGN)
    }

    /// Write the PFS0 header. Returns the header bytes.
    /// After writing the header, callers should write file data in order.
    pub fn build_header(&self) -> Vec<u8> {
        let file_count = self.files.len() as u32;

        // Build string table
        let mut string_table = Vec::new();
        let mut name_offsets = Vec::new();
        for f in &self.files {
            name_offsets.push(string_table.len() as u32);
            string_table.extend_from_slice(f.name.as_bytes());
            string_table.push(0); // null terminator
        }

        let string_table_size = string_table.len() as u32;

        let mut header = Vec::new();
        // Magic
        header.extend_from_slice(PFS0_MAGIC);
        // File count
        header.extend_from_slice(&file_count.to_le_bytes());
        // String table size
        header.extend_from_slice(&string_table_size.to_le_bytes());
        // Padding
        header.extend_from_slice(&0u32.to_le_bytes());

        // File entries
        let mut data_offset: u64 = 0;
        for (i, f) in self.files.iter().enumerate() {
            header.extend_from_slice(&data_offset.to_le_bytes()); // data offset
            header.extend_from_slice(&f.size.to_le_bytes()); // size
            header.extend_from_slice(&name_offsets[i].to_le_bytes()); // name offset
            header.extend_from_slice(&0u32.to_le_bytes()); // reserved
            data_offset += f.size;
        }

        // String table
        header.extend_from_slice(&string_table);

        // Pad header to 0x10 alignment.
        let padded_len = align_up(header.len() as u64, PFS0_ALIGN) as usize;
        if padded_len > header.len() {
            header.resize(padded_len, 0);
        }

        header
    }

    /// Total output size (header + all file data).
    pub fn total_size(&self) -> u64 {
        let data_size: u64 = self.files.iter().map(|f| f.size).sum();
        self.header_size() + data_size
    }

    /// Number of files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_pfs0_builder_then_parse() {
        let mut builder = Pfs0Builder::new();
        builder.add_file("test.nca".into(), 100);
        builder.add_file("other.tik".into(), 50);

        let header = builder.build_header();

        // Create a full PFS0 image with fake data
        let mut image = header.clone();
        image.extend_from_slice(&vec![0xAA; 100]); // test.nca data
        image.extend_from_slice(&vec![0xBB; 50]); // other.tik data

        let mut cursor = Cursor::new(&image);
        let pfs0 = Pfs0::parse(&mut cursor).unwrap();

        assert_eq!(pfs0.entries.len(), 2);
        assert_eq!(pfs0.entries[0].name, "test.nca");
        assert_eq!(pfs0.entries[0].size, 100);
        assert_eq!(pfs0.entries[1].name, "other.tik");
        assert_eq!(pfs0.entries[1].size, 50);

        // Verify we can read the file data
        let data = pfs0.read_file(&mut cursor, "test.nca").unwrap();
        assert_eq!(data, vec![0xAA; 100]);

        let data = pfs0.read_file(&mut cursor, "other.tik").unwrap();
        assert_eq!(data, vec![0xBB; 50]);
    }
}
