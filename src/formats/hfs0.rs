use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::crypto::hash;
use crate::error::{NscbError, Result};

pub const HFS0_MAGIC: &[u8; 4] = b"HFS0";
const ENTRY_SIZE: u64 = 0x40; // 64 bytes per file entry

/// A parsed HFS0 file entry.
#[derive(Debug, Clone)]
pub struct Hfs0Entry {
    pub name: String,
    /// Offset relative to the data region start.
    pub data_offset: u64,
    pub size: u64,
    /// SHA-256 hash of the first `hash_target_size` bytes.
    pub hash: [u8; 32],
    /// Number of bytes at the start of the file covered by the hash.
    pub hash_target_size: u32,
}

/// A parsed HFS0 container (used in XCI partitions).
#[derive(Debug)]
pub struct Hfs0 {
    pub entries: Vec<Hfs0Entry>,
    /// Absolute offset where this HFS0 starts.
    pub header_offset: u64,
    /// Absolute offset where the data region starts.
    pub data_offset: u64,
    /// Header size in bytes.
    pub header_size: u64,
}

impl Hfs0 {
    /// Parse an HFS0 at a specific offset.
    pub fn parse_at<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<Self> {
        reader.seek(SeekFrom::Start(offset))?;

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != HFS0_MAGIC {
            return Err(NscbError::InvalidMagic {
                expected: "HFS0".into(),
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
            hash_target_size: u32,
            _reserved: u64,
            hash: [u8; 32],
        }

        let mut raw_entries = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let data_offset = reader.read_u64::<LittleEndian>()?;
            let size = reader.read_u64::<LittleEndian>()?;
            let name_offset = reader.read_u32::<LittleEndian>()?;
            let hash_target_size = reader.read_u32::<LittleEndian>()?;
            let reserved = reader.read_u64::<LittleEndian>()?;
            let mut file_hash = [0u8; 32];
            reader.read_exact(&mut file_hash)?;

            raw_entries.push(RawEntry {
                data_offset,
                size,
                name_offset,
                hash_target_size,
                _reserved: reserved,
                hash: file_hash,
            });
        }

        // Read string table
        let mut string_table = vec![0u8; string_table_size];
        reader.read_exact(&mut string_table)?;

        // Resolve names
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

            entries.push(Hfs0Entry {
                name,
                data_offset: raw.data_offset,
                size: raw.size,
                hash: raw.hash,
                hash_target_size: raw.hash_target_size,
            });
        }

        let header_size = 0x10 + (file_count as u64 * ENTRY_SIZE) + string_table_size as u64;
        let data_offset = offset + header_size;

        Ok(Self {
            entries,
            header_offset: offset,
            data_offset,
            header_size,
        })
    }

    /// Get absolute offset of a file in the underlying reader.
    pub fn file_abs_offset(&self, entry: &Hfs0Entry) -> u64 {
        self.data_offset + entry.data_offset
    }

    /// Find an entry by name.
    pub fn find(&self, name: &str) -> Option<&Hfs0Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Find entries by extension.
    pub fn find_by_ext(&self, ext: &str) -> Vec<&Hfs0Entry> {
        self.entries
            .iter()
            .filter(|e| e.name.ends_with(ext))
            .collect()
    }

    /// Verify the hash of a file entry.
    pub fn verify_entry<R: Read + Seek>(
        &self,
        reader: &mut R,
        entry: &Hfs0Entry,
    ) -> Result<bool> {
        let abs_offset = self.file_abs_offset(entry);
        reader.seek(SeekFrom::Start(abs_offset))?;

        let hash_size = if entry.hash_target_size > 0 {
            entry.hash_target_size as u64
        } else {
            entry.size.min(0x200)
        };

        let computed = hash::sha256_n(reader, hash_size)?;
        Ok(computed == entry.hash)
    }

    /// Read the full contents of a file entry.
    pub fn read_file<R: Read + Seek>(&self, reader: &mut R, name: &str) -> Result<Vec<u8>> {
        let entry = self.find(name).ok_or_else(|| {
            NscbError::InvalidData(format!("File '{}' not found in HFS0", name))
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

/// Builder for creating HFS0 containers.
pub struct Hfs0Builder {
    files: Vec<Hfs0BuilderEntry>,
}

struct Hfs0BuilderEntry {
    name: String,
    size: u64,
    hash: [u8; 32],
    hash_target_size: u32,
}

impl Hfs0Builder {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Add a file with a pre-computed hash.
    pub fn add_file(&mut self, name: String, size: u64, hash: [u8; 32], hash_target_size: u32) {
        self.files.push(Hfs0BuilderEntry {
            name,
            size,
            hash,
            hash_target_size,
        });
    }

    /// Calculate header size.
    pub fn header_size(&self) -> u64 {
        let string_table_size: usize = self.files.iter().map(|f| f.name.len() + 1).sum();
        0x10 + (self.files.len() as u64 * ENTRY_SIZE) + string_table_size as u64
    }

    /// Build the HFS0 header bytes.
    pub fn build_header(&self) -> Vec<u8> {
        let file_count = self.files.len() as u32;

        let mut string_table = Vec::new();
        let mut name_offsets = Vec::new();
        for f in &self.files {
            name_offsets.push(string_table.len() as u32);
            string_table.extend_from_slice(f.name.as_bytes());
            string_table.push(0);
        }

        let string_table_size = string_table.len() as u32;

        let mut header = Vec::new();
        header.extend_from_slice(HFS0_MAGIC);
        header.extend_from_slice(&file_count.to_le_bytes());
        header.extend_from_slice(&string_table_size.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());

        let mut data_offset: u64 = 0;
        for (i, f) in self.files.iter().enumerate() {
            header.extend_from_slice(&data_offset.to_le_bytes());
            header.extend_from_slice(&f.size.to_le_bytes());
            header.extend_from_slice(&name_offsets[i].to_le_bytes());
            header.extend_from_slice(&f.hash_target_size.to_le_bytes());
            header.extend_from_slice(&0u64.to_le_bytes()); // reserved
            header.extend_from_slice(&f.hash);
            data_offset += f.size;
        }

        header.extend_from_slice(&string_table);
        header
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn total_size(&self) -> u64 {
        let data_size: u64 = self.files.iter().map(|f| f.size).sum();
        self.header_size() + data_size
    }
}
