use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{NscbError, Result};
use crate::formats::hfs0::Hfs0;
use crate::formats::types;

/// XCI card header offsets.
const XCI_MAGIC_OFFSET: u64 = 0x100;
const XCI_SECURE_OFFSET: u64 = 0x104;
const XCI_CARD_SIZE_BYTE: u64 = 0x10D;
const XCI_FLAGS_OFFSET: u64 = 0x10F;
const XCI_PACKAGE_ID: u64 = 0x110;
const XCI_DATA_END: u64 = 0x118;
const XCI_HFS0_OFFSET: u64 = 0x130;
const XCI_HFS0_SIZE: u64 = 0x138;
const XCI_HFS0_HASH: u64 = 0x140;

/// XCI header size (RSA sig + header).
pub const XCI_HEADER_SIZE: u64 = 0x200;

/// Parsed XCI card header.
#[derive(Debug, Clone)]
pub struct XciHeader {
    pub magic: [u8; 4],
    pub secure_offset: u32,
    pub card_size_byte: u8,
    pub flags: u8,
    pub package_id: u64,
    pub data_end_offset: u64,
    pub hfs0_offset: u64,
    pub hfs0_size: u64,
    pub hfs0_hash: [u8; 32],
}

impl XciHeader {
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        // Read magic at 0x100
        reader.seek(SeekFrom::Start(XCI_MAGIC_OFFSET))?;
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"HEAD" {
            return Err(NscbError::InvalidMagic {
                expected: "HEAD".into(),
                got: String::from_utf8_lossy(&magic).into(),
            });
        }

        reader.seek(SeekFrom::Start(XCI_SECURE_OFFSET))?;
        let secure_offset = reader.read_u32::<LittleEndian>()?;

        reader.seek(SeekFrom::Start(XCI_CARD_SIZE_BYTE))?;
        let card_size_byte = reader.read_u8()?;

        reader.seek(SeekFrom::Start(XCI_FLAGS_OFFSET))?;
        let flags = reader.read_u8()?;

        reader.seek(SeekFrom::Start(XCI_PACKAGE_ID))?;
        let package_id = reader.read_u64::<LittleEndian>()?;

        reader.seek(SeekFrom::Start(XCI_DATA_END))?;
        let data_end_offset = reader.read_u64::<LittleEndian>()?;

        reader.seek(SeekFrom::Start(XCI_HFS0_OFFSET))?;
        let hfs0_offset = reader.read_u64::<LittleEndian>()?;

        reader.seek(SeekFrom::Start(XCI_HFS0_SIZE))?;
        let hfs0_size = reader.read_u64::<LittleEndian>()?;

        reader.seek(SeekFrom::Start(XCI_HFS0_HASH))?;
        let mut hfs0_hash = [0u8; 32];
        reader.read_exact(&mut hfs0_hash)?;

        Ok(Self {
            magic,
            secure_offset,
            card_size_byte,
            flags,
            package_id,
            data_end_offset,
            hfs0_offset,
            hfs0_size,
            hfs0_hash,
        })
    }

    /// Declared card capacity in bytes.
    pub fn card_size(&self) -> u64 {
        types::xci_card_size(self.card_size_byte)
    }

    /// Actual data end in bytes (data_end_offset is in media units).
    pub fn data_end_bytes(&self) -> u64 {
        (self.data_end_offset + 1) * types::MEDIA_SIZE
    }
}

/// An opened XCI file.
pub struct Xci {
    pub header: XciHeader,
    /// Root HFS0 containing partition entries (update, normal, secure, logo).
    pub root_hfs0: Hfs0,
}

impl Xci {
    /// Open an XCI from a reader.
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let header = XciHeader::parse(reader)?;
        let root_hfs0 = Hfs0::parse_at(reader, header.hfs0_offset)?;
        Ok(Self { header, root_hfs0 })
    }

    /// Get the secure partition HFS0.
    pub fn secure_partition<R: Read + Seek>(&self, reader: &mut R) -> Result<Hfs0> {
        self.partition(reader, "secure")
    }

    /// Get the update partition HFS0.
    pub fn update_partition<R: Read + Seek>(&self, reader: &mut R) -> Result<Hfs0> {
        self.partition(reader, "update")
    }

    /// Get the normal partition HFS0.
    pub fn normal_partition<R: Read + Seek>(&self, reader: &mut R) -> Result<Hfs0> {
        self.partition(reader, "normal")
    }

    /// Get a named partition.
    fn partition<R: Read + Seek>(&self, reader: &mut R, name: &str) -> Result<Hfs0> {
        let entry = self.root_hfs0.find(name).ok_or_else(|| {
            NscbError::InvalidData(format!("XCI partition '{}' not found", name))
        })?;
        let abs_offset = self.root_hfs0.file_abs_offset(entry);
        Hfs0::parse_at(reader, abs_offset)
    }

    /// List partition names in the root HFS0.
    pub fn partition_names(&self) -> Vec<&str> {
        self.root_hfs0.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Get NCA files from the secure partition.
    pub fn secure_nca_entries<R: Read + Seek>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<SecureNcaEntry>> {
        let secure = self.secure_partition(reader)?;
        let mut entries = Vec::new();
        for entry in &secure.entries {
            if entry.name.ends_with(".nca") || entry.name.ends_with(".ncz") {
                entries.push(SecureNcaEntry {
                    name: entry.name.clone(),
                    abs_offset: secure.file_abs_offset(entry),
                    size: entry.size,
                });
            }
        }
        Ok(entries)
    }
}

/// An NCA entry found in the XCI secure partition.
#[derive(Debug, Clone)]
pub struct SecureNcaEntry {
    pub name: String,
    pub abs_offset: u64,
    pub size: u64,
}

/// Build an XCI file from components.
pub struct XciBuilder {
    /// Card size byte (determines declared capacity).
    pub card_size_byte: u8,
}

impl XciBuilder {
    pub fn new() -> Self {
        Self {
            card_size_byte: 0xF0, // 4GB default
        }
    }

    /// Set card size to fit the given data size.
    pub fn auto_card_size(&mut self, data_size: u64) {
        self.card_size_byte = if data_size <= 1024 * 1024 * 1024 {
            0xFA // 1GB
        } else if data_size <= 2 * 1024 * 1024 * 1024 {
            0xF8 // 2GB
        } else if data_size <= 4 * 1024 * 1024 * 1024 {
            0xF0 // 4GB
        } else if data_size <= 8 * 1024 * 1024 * 1024 {
            0xE0 // 8GB
        } else if data_size <= 16 * 1024 * 1024 * 1024 {
            0xE1 // 16GB
        } else {
            0xE2 // 32GB
        };
    }

    /// Build XCI header bytes (0x200 bytes).
    /// `hfs0_offset` is where the root HFS0 starts (typically 0xF000).
    /// `hfs0_header_size` is the size of the root HFS0 header.
    /// `hfs0_hash` is the SHA-256 of the root HFS0 header.
    /// `data_end` is the total data size in bytes.
    pub fn build_header(
        &self,
        hfs0_offset: u64,
        hfs0_header_size: u64,
        hfs0_hash: &[u8; 32],
        data_end: u64,
    ) -> Vec<u8> {
        let mut header = vec![0u8; 0x200];

        // RSA signature placeholder (0x000-0x100): zeros
        // Magic "HEAD" at 0x100
        header[0x100..0x104].copy_from_slice(b"HEAD");

        // Secure offset at 0x104 (in media units)
        let secure_offset_mu = (hfs0_offset / types::MEDIA_SIZE) as u32;
        header[0x104..0x108].copy_from_slice(&secure_offset_mu.to_le_bytes());

        // Card size byte at 0x10D
        header[0x10D] = self.card_size_byte;

        // Data end offset at 0x118 (in media units, minus 1)
        let data_end_mu = data_end / types::MEDIA_SIZE;
        let data_end_val = if data_end_mu > 0 { data_end_mu - 1 } else { 0 };
        header[0x118..0x120].copy_from_slice(&data_end_val.to_le_bytes());

        // HFS0 offset at 0x130
        header[0x130..0x138].copy_from_slice(&hfs0_offset.to_le_bytes());

        // HFS0 header size at 0x138
        header[0x138..0x140].copy_from_slice(&hfs0_header_size.to_le_bytes());

        // HFS0 header hash at 0x140
        header[0x140..0x160].copy_from_slice(hfs0_hash);

        header
    }
}
