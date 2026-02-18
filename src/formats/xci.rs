use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::crypto::hash;
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

/// NSCB-style XCI header block size.
pub const XCI_HEADER_SIZE: u64 = 0x190;
pub const XCI_GAME_INFO_SIZE: u64 = 0x70;
pub const XCI_SIG_PADDING_SIZE: u64 = 0x6E00;
pub const XCI_CERT_SIZE: u64 = 0x8000;
pub const XCI_PREFIX_SIZE: u64 =
    XCI_HEADER_SIZE + XCI_GAME_INFO_SIZE + XCI_SIG_PADDING_SIZE + XCI_CERT_SIZE;

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
        let entry = self
            .root_hfs0
            .find(name)
            .ok_or_else(|| NscbError::InvalidData(format!("XCI partition '{}' not found", name)))?;
        let abs_offset = self.root_hfs0.file_abs_offset(entry);
        Hfs0::parse_at(reader, abs_offset)
    }

    /// List partition names in the root HFS0.
    pub fn partition_names(&self) -> Vec<&str> {
        self.root_hfs0
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect()
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
        secure_offset: u64,
        hfs0_header_size: u64,
        hfs0_hash: &[u8; 32],
        data_end: u64,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(XCI_HEADER_SIZE as usize);

        // Placeholder signature block (NSCB uses random data here).
        let mut sig_seed = Vec::new();
        sig_seed.extend_from_slice(hfs0_hash);
        sig_seed.extend_from_slice(&data_end.to_le_bytes());
        let mut digest = hash::sha256(&sig_seed);
        for _ in 0..(0x100 / 32) {
            header.extend_from_slice(&digest);
            digest = hash::sha256(&digest);
        }

        // "HEAD"
        header.extend_from_slice(b"HEAD");

        // Secure offset (media units)
        let secure_offset_mu = (secure_offset / types::MEDIA_SIZE) as u32;
        header.extend_from_slice(&secure_offset_mu.to_le_bytes());
        header.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // backup offset
        header.push(0x00); // kek index

        // Card size / version / flags
        header.push(self.card_size_byte);
        header.push(0x00);
        header.push(0x00);

        // Pack ID (NSCB constant, BE)
        header.extend_from_slice(&0x8750F4C0A9C5A966u64.to_be_bytes());

        // Valid data end (media units, minus 1, LE).
        // Round up so partially filled media units are still covered.
        let data_end_mu = data_end.div_ceil(types::MEDIA_SIZE) as u64;
        let data_end_val = data_end_mu.saturating_sub(1);
        header.extend_from_slice(&data_end_val.to_le_bytes());

        // IV (default/fallback constant used when xci_header_key is absent in NSCB).
        header.extend_from_slice(&0x5B408B145E277E81E5BF677C94888D7Bu128.to_be_bytes());

        header.extend_from_slice(&hfs0_offset.to_le_bytes());
        header.extend_from_slice(&hfs0_header_size.to_le_bytes());
        header.extend_from_slice(hfs0_hash);

        // Fixed initial-data hash + flags used by NSCB.
        header.extend_from_slice(&[
            0x1A, 0xB7, 0xC7, 0xB2, 0x63, 0xE7, 0x4E, 0x44, 0xCD, 0x3C, 0x68, 0xE4, 0x0F, 0x7E,
            0xF4, 0xA4, 0xD6, 0x57, 0x15, 0x51, 0xD0, 0x43, 0xFC, 0xA8, 0xEC, 0xF5, 0xC4, 0x89,
            0xF2, 0xC6, 0x6E, 0x7E,
        ]);
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&2u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&secure_offset_mu.to_le_bytes()); // normal-area end

        debug_assert_eq!(header.len(), XCI_HEADER_SIZE as usize);
        header
    }

    /// Build the NSCB fallback game-info block (0x70 bytes).
    pub fn build_game_info(&self, total_size: u64) -> Vec<u8> {
        let gbytes = (total_size as f64) / (1024.0 * 1024.0 * 1024.0);
        let large = gbytes >= 4.0;
        let mut gi = Vec::with_capacity(XCI_GAME_INFO_SIZE as usize);
        if large {
            gi.extend_from_slice(&0x9298F35088F09F7Du64.to_be_bytes());
            gi.extend_from_slice(&0xA89A60D4u32.to_be_bytes());
            gi.extend_from_slice(&0xCBA6F96Fu32.to_be_bytes());
            gi.extend_from_slice(&0xA45BB6ACu32.to_be_bytes());
            gi.extend_from_slice(&0xABC751F9u32.to_be_bytes());
            gi.extend_from_slice(&0x5D398742u32.to_be_bytes());
            gi.extend_from_slice(&0x6B38C3F2u32.to_be_bytes());
            gi.extend_from_slice(&0x10DA0B70u32.to_be_bytes());
            gi.extend_from_slice(&0x0E5ECE29u32.to_be_bytes());
            gi.extend_from_slice(&0xA13CBE1DA6D052CBu64.to_be_bytes());
            gi.extend_from_slice(&0xF2087CE9AF590538u64.to_be_bytes());
            gi.extend_from_slice(&[
                0x57, 0x0D, 0x78, 0xB9, 0xCD, 0xD2, 0x7F, 0xBE, 0xB4, 0xA0, 0xAC, 0x2A, 0xDF, 0xF9,
                0xBA, 0x77, 0x75, 0x4D, 0xD6, 0x67, 0x5A, 0xC7, 0x62, 0x23, 0x50, 0x6B, 0x3B, 0xDA,
                0xBC, 0xB2, 0xE2, 0x12, 0xFA, 0x46, 0x51, 0x11, 0xAB, 0x7D, 0x51, 0xAF, 0xC8, 0xB5,
                0xB2, 0xB2, 0x1C, 0x4B, 0x3F, 0x40, 0x65, 0x45, 0x98, 0x62, 0x02, 0x82, 0xAD, 0xD6,
            ]);
        } else {
            gi.extend_from_slice(&0x9109FF82971EE993u64.to_be_bytes());
            gi.extend_from_slice(&0x5011CA06u32.to_be_bytes());
            gi.extend_from_slice(&0x3F3C4D87u32.to_be_bytes());
            gi.extend_from_slice(&0xA13D28A9u32.to_be_bytes());
            gi.extend_from_slice(&0x928D74F1u32.to_be_bytes());
            gi.extend_from_slice(&0x49919EB7u32.to_be_bytes());
            gi.extend_from_slice(&0x82E1F0CFu32.to_be_bytes());
            gi.extend_from_slice(&0xE4A5A3BDu32.to_be_bytes());
            gi.extend_from_slice(&0xF978295Cu32.to_be_bytes());
            gi.extend_from_slice(&0xD52639A4991BDB1Fu64.to_be_bytes());
            gi.extend_from_slice(&0xED841779A3F85D23u64.to_be_bytes());
            gi.extend_from_slice(&[
                0xAA, 0x42, 0x42, 0x13, 0x56, 0x16, 0xF5, 0x18, 0x7C, 0x03, 0xCF, 0x0D, 0x97, 0xE5,
                0xD2, 0x18, 0xFD, 0xB2, 0x45, 0x38, 0x1F, 0xD1, 0xCF, 0x8D, 0xFB, 0x79, 0x6F, 0xBE,
                0xDA, 0x4B, 0xF7, 0xF7, 0xD6, 0xB1, 0x28, 0xCE, 0x89, 0xBC, 0x9E, 0xAA, 0x85, 0x52,
                0xD4, 0x2F, 0x59, 0x7C, 0x5D, 0xB8, 0x66, 0xC6, 0x7B, 0xB0, 0xDD, 0x8E, 0xEA, 0x11,
            ]);
        }
        debug_assert_eq!(gi.len(), XCI_GAME_INFO_SIZE as usize);
        gi
    }

    pub fn sig_padding(&self) -> Vec<u8> {
        vec![0u8; XCI_SIG_PADDING_SIZE as usize]
    }

    pub fn fake_certificate(&self) -> Vec<u8> {
        vec![0xFFu8; XCI_CERT_SIZE as usize]
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_xci_prefix_size_matches_expected_offset() {
        assert_eq!(XCI_PREFIX_SIZE, 0xF000);
    }

    #[test]
    fn test_build_header_encodes_core_offsets() {
        let mut builder = XciBuilder::new();
        builder.card_size_byte = 0xF0;

        let hfs0_offset = 0xF000;
        let secure_offset = 0xF400;
        let hfs0_header_size = 0x600;
        let hfs0_hash = [0xAB; 32];
        let data_end = 0x12345;

        let header = builder.build_header(
            hfs0_offset,
            secure_offset,
            hfs0_header_size,
            &hfs0_hash,
            data_end,
        );

        assert_eq!(header.len(), XCI_HEADER_SIZE as usize);

        let mut cursor = Cursor::new(header);
        let parsed = XciHeader::parse(&mut cursor).unwrap();
        assert_eq!(&parsed.magic, b"HEAD");
        assert_eq!(
            parsed.secure_offset as u64,
            secure_offset / types::MEDIA_SIZE
        );
        assert_eq!(parsed.card_size_byte, 0xF0);
        assert_eq!(parsed.hfs0_offset, hfs0_offset);
        assert_eq!(parsed.hfs0_size, hfs0_header_size);
        assert_eq!(parsed.hfs0_hash, hfs0_hash);

        let expected_data_end = data_end.div_ceil(types::MEDIA_SIZE).saturating_sub(1);
        assert_eq!(parsed.data_end_offset, expected_data_end);
    }

    #[test]
    fn test_auxiliary_blocks_have_expected_sizes() {
        let builder = XciBuilder::new();
        assert_eq!(
            builder.build_game_info(3 * 1024 * 1024 * 1024).len(),
            XCI_GAME_INFO_SIZE as usize
        );
        assert_eq!(builder.sig_padding().len(), XCI_SIG_PADDING_SIZE as usize);
        assert_eq!(builder.fake_certificate().len(), XCI_CERT_SIZE as usize);
    }
}
