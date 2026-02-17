use std::io::{Read, Seek, SeekFrom};

use crate::crypto::aes_xts::NintendoXts;
use crate::error::{NscbError, Result};
use crate::formats::types::*;
use crate::keys::KeyStore;

/// NCA section table entry (16 bytes each, 4 entries at header offset 0x240).
#[derive(Debug, Clone, Copy)]
pub struct SectionTableEntry {
    /// Start offset in media units (multiply by 0x200).
    pub media_start: u32,
    /// End offset in media units.
    pub media_end: u32,
    pub _unknown1: u32,
    pub _unknown2: u32,
}

impl SectionTableEntry {
    pub fn start_offset(&self) -> u64 {
        self.media_start as u64 * MEDIA_SIZE
    }

    pub fn end_offset(&self) -> u64 {
        self.media_end as u64 * MEDIA_SIZE
    }

    pub fn size(&self) -> u64 {
        self.end_offset() - self.start_offset()
    }

    pub fn is_present(&self) -> bool {
        self.media_start != 0 || self.media_end != 0
    }
}

/// Parsed NCA header (0xC00 bytes after XTS decryption).
#[derive(Debug, Clone)]
pub struct NcaHeader {
    /// NCA3 or NCA2
    pub magic: [u8; 4],
    pub distribution_type: u8,
    pub content_type: u8,
    /// Legacy crypto type field at 0x206
    pub crypto_type: u8,
    /// Key area key index (0=app, 1=ocean, 2=system)
    pub key_index: u8,
    /// Total NCA size
    pub nca_size: u64,
    /// Title ID
    pub title_id: u64,
    /// SDK version
    pub sdk_version: u32,
    /// Extended crypto type at 0x220
    pub crypto_type2: u8,
    /// Rights ID (non-zero means title-key crypto)
    pub rights_id: [u8; 16],
    /// Section table entries (4)
    pub section_table: [SectionTableEntry; 4],
    /// Section SHA-256 hashes (4 × 32 bytes)
    pub section_hashes: [[u8; 32]; 4],
    /// Encrypted key area (4 × 16 bytes = 64 bytes)
    pub key_area: [u8; 64],
    /// The raw decrypted header bytes (for re-encryption)
    raw: Vec<u8>,
}

impl NcaHeader {
    /// Parse an NCA header by decrypting the first 0xC00 bytes with XTS.
    pub fn from_reader<R: Read + Seek>(reader: &mut R, offset: u64, ks: &KeyStore) -> Result<Self> {
        reader.seek(SeekFrom::Start(offset))?;

        let mut encrypted = vec![0u8; 0xC00];
        reader.read_exact(&mut encrypted)?;

        Self::from_encrypted(&encrypted, ks)
    }

    /// Parse from encrypted 0xC00 bytes.
    pub fn from_encrypted(encrypted: &[u8], ks: &KeyStore) -> Result<Self> {
        if encrypted.len() < 0xC00 {
            return Err(NscbError::InvalidData("NCA header too short".into()));
        }

        let header_key = ks.header_key()?;
        let mut swapped_key = [0u8; 32];
        swapped_key[..16].copy_from_slice(&header_key[16..]);
        swapped_key[16..].copy_from_slice(&header_key[..16]);

        // Try likely variants seen across tooling:
        // - LE or BE sector number tweak encoding
        // - normal or swapped XTS key halves (data/tweak order)
        let attempts = [
            (header_key, true),
            (header_key, false),
            (swapped_key, true),
            (swapped_key, false),
        ];

        let mut last_err: Option<NscbError> = None;
        for (key, le_sector) in attempts {
            let xts = NintendoXts::new(&key)?;
            let mut decrypted = encrypted[..0xC00].to_vec();
            xts.decrypt_with_endian(0, &mut decrypted, le_sector);
            match Self::from_decrypted(decrypted) {
                Ok(header) => return Ok(header),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            NscbError::InvalidData("Failed to decrypt NCA header with known XTS variants".into())
        }))
    }

    /// Parse from already-decrypted header bytes.
    pub fn from_decrypted(data: Vec<u8>) -> Result<Self> {
        if data.len() < 0xC00 {
            return Err(NscbError::InvalidData("NCA header too short".into()));
        }

        let magic: [u8; 4] = data[0x200..0x204].try_into().unwrap();

        // Validate magic
        if &magic != b"NCA3" && &magic != b"NCA2" {
            return Err(NscbError::InvalidMagic {
                expected: "NCA3/NCA2".into(),
                got: String::from_utf8_lossy(&magic).into(),
            });
        }

        let distribution_type = data[0x204];
        let content_type = data[0x205];
        let crypto_type = data[0x206];
        let key_index = data[0x207];

        let nca_size = u64::from_le_bytes(data[0x208..0x210].try_into().unwrap());
        let title_id = u64::from_le_bytes(data[0x210..0x218].try_into().unwrap());
        let sdk_version = u32::from_le_bytes(data[0x21C..0x220].try_into().unwrap());
        let crypto_type2 = data[0x220];

        let mut rights_id = [0u8; 16];
        rights_id.copy_from_slice(&data[0x230..0x240]);

        // Section table (4 entries x 16 bytes at 0x240)
        const EMPTY: SectionTableEntry = SectionTableEntry { media_start: 0, media_end: 0, _unknown1: 0, _unknown2: 0 };
        let mut section_table = [EMPTY; 4];
        for (i, entry) in section_table.iter_mut().enumerate() {
            let base = 0x240 + i * 16;
            entry.media_start = u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
            entry.media_end = u32::from_le_bytes(data[base + 4..base + 8].try_into().unwrap());
            entry._unknown1 = u32::from_le_bytes(data[base + 8..base + 12].try_into().unwrap());
            entry._unknown2 = u32::from_le_bytes(data[base + 12..base + 16].try_into().unwrap());
        }

        // Section hashes (4 × 32 bytes at 0x280)
        let mut section_hashes = [[0u8; 32]; 4];
        for (i, hash) in section_hashes.iter_mut().enumerate() {
            let base = 0x280 + i * 32;
            hash.copy_from_slice(&data[base..base + 32]);
        }

        // Key area (64 bytes at 0x300)
        let mut key_area = [0u8; 64];
        key_area.copy_from_slice(&data[0x300..0x340]);

        Ok(Self {
            magic,
            distribution_type,
            content_type,
            crypto_type,
            key_index,
            nca_size,
            title_id,
            sdk_version,
            crypto_type2,
            rights_id,
            section_table,
            section_hashes,
            key_area,
            raw: data,
        })
    }

    /// Effective key generation — max of the two crypto type fields.
    pub fn key_generation(&self) -> u8 {
        self.crypto_type.max(self.crypto_type2)
    }

    /// Master key revision for key derivation (key_generation - 1, clamped to 0).
    pub fn master_key_revision(&self) -> u8 {
        let kg = self.key_generation();
        if kg > 0 { kg - 1 } else { 0 }
    }

    /// Whether this NCA uses title-key crypto (has a non-zero rights ID).
    pub fn has_rights_id(&self) -> bool {
        self.rights_id.iter().any(|&b| b != 0)
    }

    /// Get the content type as an enum.
    pub fn content_type_enum(&self) -> Option<ContentType> {
        ContentType::from_u8(self.content_type)
    }

    /// Get the distribution type as an enum.
    pub fn distribution_type_enum(&self) -> Option<DistributionType> {
        DistributionType::from_u8(self.distribution_type)
    }

    /// Get the key area key type.
    pub fn key_area_key_type(&self) -> Option<KeyAreaKeyType> {
        KeyAreaKeyType::from_u8(self.key_index)
    }

    /// Title ID as hex string.
    pub fn title_id_hex(&self) -> String {
        format!("{:016x}", self.title_id)
    }

    /// Rights ID as hex string.
    pub fn rights_id_hex(&self) -> String {
        hex::encode(self.rights_id)
    }

    /// Decrypt the key area and return 4 × 16-byte keys.
    pub fn decrypt_key_area(&self, ks: &KeyStore) -> Result<[[u8; 16]; 4]> {
        let revision = self.master_key_revision();
        let key_type = self.key_index;

        let mut keys = [[0u8; 16]; 4];
        for i in 0..4 {
            let src = &self.key_area[i * 16..(i + 1) * 16];
            let mut block = [0u8; 16];
            block.copy_from_slice(src);
            keys[i] = ks.decrypt_key_area_entry(&block, revision, key_type)?;
        }
        Ok(keys)
    }

    /// Get the section crypto nonce from the FS header at offset 0x400 + section_index * 0x200.
    /// The nonce is 8 bytes at offset 0x140 within each FS header.
    pub fn section_ctr_nonce(&self, section_index: usize) -> [u8; 8] {
        let fs_header_offset = 0x400 + section_index * 0x200;
        let nonce_offset = fs_header_offset + 0x140;
        let mut nonce = [0u8; 8];
        if nonce_offset + 8 <= self.raw.len() {
            nonce.copy_from_slice(&self.raw[nonce_offset..nonce_offset + 8]);
        }
        nonce
    }

    /// Get the filesystem type byte from the section FS header.
    /// Offset 0x03 in each FS header (0x400 + section_index * 0x200 + 0x03).
    pub fn section_fs_type(&self, section_index: usize) -> u8 {
        let offset = 0x400 + section_index * 0x200 + 0x03;
        if offset < self.raw.len() {
            self.raw[offset]
        } else {
            0
        }
    }

    /// Get the encryption type byte from the section FS header.
    /// Offset 0x04 in each FS header.
    pub fn section_crypto_type(&self, section_index: usize) -> u8 {
        let offset = 0x400 + section_index * 0x200 + 0x04;
        if offset < self.raw.len() {
            self.raw[offset]
        } else {
            0
        }
    }

    /// Get the raw decrypted header bytes.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// Summary info for an NCA file (parsed from header).
#[derive(Debug, Clone)]
pub struct NcaInfo {
    pub filename: String,
    pub title_id: u64,
    pub content_type: Option<ContentType>,
    pub key_generation: u8,
    pub has_rights_id: bool,
    pub size: u64,
}

/// Parse just the NCA header info from a file within a container.
/// This reads 0xC00 bytes from the given offset and decrypts with XTS.
pub fn parse_nca_info<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    size: u64,
    filename: &str,
    ks: &KeyStore,
) -> Result<NcaInfo> {
    let header = NcaHeader::from_reader(reader, offset, ks)?;
    Ok(NcaInfo {
        filename: filename.to_string(),
        title_id: header.title_id,
        content_type: header.content_type_enum(),
        key_generation: header.key_generation(),
        has_rights_id: header.has_rights_id(),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_table_entry_offsets() {
        let entry = SectionTableEntry {
            media_start: 2,
            media_end: 10,
            _unknown1: 0,
            _unknown2: 0,
        };
        assert_eq!(entry.start_offset(), 0x400);
        assert_eq!(entry.end_offset(), 0x1400);
        assert_eq!(entry.size(), 0x1000);
        assert!(entry.is_present());
    }

    #[test]
    fn test_key_generation() {
        let mut header_data = vec![0u8; 0xC00];
        // Set magic to NCA3
        header_data[0x200..0x204].copy_from_slice(b"NCA3");
        // Set crypto_type = 3
        header_data[0x206] = 3;
        // Set crypto_type2 = 5
        header_data[0x220] = 5;

        let header = NcaHeader::from_decrypted(header_data).unwrap();
        assert_eq!(header.key_generation(), 5);
        assert_eq!(header.master_key_revision(), 4);
    }

    #[test]
    fn test_rights_id() {
        let mut header_data = vec![0u8; 0xC00];
        header_data[0x200..0x204].copy_from_slice(b"NCA3");

        let header = NcaHeader::from_decrypted(header_data.clone()).unwrap();
        assert!(!header.has_rights_id());

        header_data[0x230] = 0x01;
        let header2 = NcaHeader::from_decrypted(header_data).unwrap();
        assert!(header2.has_rights_id());
    }
}
