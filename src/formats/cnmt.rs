use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

use crate::error::{NscbError, Result};
use crate::formats::types::TitleType;

/// A content entry within the CNMT — references one NCA.
#[derive(Debug, Clone)]
pub struct ContentEntry {
    /// NCA content ID (first 16 bytes = NCA filename without .nca extension).
    pub content_id: [u8; 16],
    /// SHA-256 hash of the NCA file.
    pub hash: [u8; 32],
    /// Size in bytes (6 bytes LE, stored as u64).
    pub size: u64,
    /// Content type (0=Meta, 1=Program, 2=Data, 3=Control, 4=HtmlDocument, 5=LegalInformation, 6=DeltaFragment).
    pub content_type: u8,
    /// ID offset.
    pub id_offset: u8,
}

impl ContentEntry {
    /// NCA ID as hex string (used as filename: {id}.nca).
    pub fn nca_id(&self) -> String {
        hex::encode(self.content_id)
    }

    /// Is this a delta fragment NCA?
    pub fn is_delta(&self) -> bool {
        self.content_type == 6
    }
}

/// Parsed CNMT (Content Meta) — describes what NCAs belong to a title.
#[derive(Debug, Clone)]
pub struct Cnmt {
    pub title_id: u64,
    pub version: u32,
    pub title_type: u8,
    pub table_offset: u16,
    pub content_entry_count: u16,
    pub meta_entry_count: u16,
    /// Required download system version.
    pub required_system_version: u32,
    /// Application title ID (for patches/DLC, this is the base game title ID).
    pub application_title_id: u64,
    /// Content entries (NCA references).
    pub content_entries: Vec<ContentEntry>,
    /// Raw CNMT bytes.
    pub raw: Vec<u8>,
}

impl Cnmt {
    /// Parse CNMT from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 0x20 {
            return Err(NscbError::InvalidData("CNMT too short".into()));
        }

        let mut cursor = Cursor::new(data);

        let title_id = cursor.read_u64::<LittleEndian>()?;
        let version = cursor.read_u32::<LittleEndian>()?;
        let title_type = cursor.read_u8()?;
        let _reserved1 = cursor.read_u8()?;
        let table_offset = cursor.read_u16::<LittleEndian>()?;
        let content_entry_count = cursor.read_u16::<LittleEndian>()?;
        let meta_entry_count = cursor.read_u16::<LittleEndian>()?;
        let _attributes = cursor.read_u8()?;
        let _storage_id = cursor.read_u8()?;
        let _content_install_type = cursor.read_u8()?;
        cursor.read_exact(&mut [0u8; 3])?; // reserved

        // Extended header depends on title type
        let required_system_version;
        let application_title_id;

        let extended_header_offset = 0x20;
        let content_entries_offset = extended_header_offset + table_offset as usize;

        match TitleType::from_u8(title_type) {
            Some(TitleType::Application) => {
                // Extended header: 16 bytes
                // +0x00: patch title ID (u64), +0x08: required system version (u32)
                if data.len() >= extended_header_offset + 12 {
                    required_system_version = u32::from_le_bytes(
                        data[extended_header_offset + 8..extended_header_offset + 12]
                            .try_into()
                            .unwrap(),
                    );
                } else {
                    required_system_version = 0;
                }
                application_title_id = title_id;
            }
            Some(TitleType::Patch) | Some(TitleType::AddOnContent) => {
                // Extended header: +0x00: application title ID (u64), +0x08: required version (u32)
                if data.len() >= extended_header_offset + 12 {
                    application_title_id = u64::from_le_bytes(
                        data[extended_header_offset..extended_header_offset + 8]
                            .try_into()
                            .unwrap(),
                    );
                    required_system_version = u32::from_le_bytes(
                        data[extended_header_offset + 8..extended_header_offset + 12]
                            .try_into()
                            .unwrap(),
                    );
                } else {
                    application_title_id = title_id;
                    required_system_version = 0;
                }
            }
            _ => {
                application_title_id = title_id;
                required_system_version = 0;
            }
        }

        // Parse content entries
        let mut content_entries = Vec::with_capacity(content_entry_count as usize);
        let entry_size = 0x38; // 56 bytes per content entry

        for i in 0..content_entry_count as usize {
            let offset = content_entries_offset + i * entry_size;
            if offset + entry_size > data.len() {
                break;
            }

            let entry_data = &data[offset..offset + entry_size];

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&entry_data[0x00..0x20]);

            let mut content_id = [0u8; 16];
            content_id.copy_from_slice(&entry_data[0x20..0x30]);

            // Size is 6 bytes LE at +0x30
            let mut size_bytes = [0u8; 8];
            size_bytes[..6].copy_from_slice(&entry_data[0x30..0x36]);
            let size = u64::from_le_bytes(size_bytes);

            let content_type = entry_data[0x36];
            let id_offset = entry_data[0x37];

            content_entries.push(ContentEntry {
                content_id,
                hash,
                size,
                content_type,
                id_offset,
            });
        }

        Ok(Self {
            title_id,
            version,
            title_type,
            table_offset,
            content_entry_count,
            meta_entry_count,
            required_system_version,
            application_title_id,
            content_entries,
            raw: data.to_vec(),
        })
    }

    /// Title type as enum.
    pub fn title_type_enum(&self) -> Option<TitleType> {
        TitleType::from_u8(self.title_type)
    }

    /// Title ID as hex string.
    pub fn title_id_hex(&self) -> String {
        format!("{:016x}", self.title_id)
    }

    /// Application (base) title ID as hex string.
    pub fn application_title_id_hex(&self) -> String {
        format!("{:016x}", self.application_title_id)
    }

    /// Base title ID — the application ID with the last 3 nibbles zeroed.
    /// For applications: same as title_id.
    /// For patches: title_id & 0xFFFFFFFFFFFFE000 (roughly).
    /// For DLC: application_title_id.
    pub fn base_title_id(&self) -> u64 {
        match self.title_type_enum() {
            Some(TitleType::Application) => self.title_id,
            Some(TitleType::Patch) | Some(TitleType::AddOnContent) | Some(TitleType::Delta) => {
                self.application_title_id
            }
            _ => self.title_id,
        }
    }

    /// List of NCA IDs referenced by this CNMT.
    pub fn nca_ids(&self) -> Vec<String> {
        self.content_entries.iter().map(|e| e.nca_id()).collect()
    }

    /// Content entries excluding delta fragments.
    pub fn non_delta_entries(&self) -> Vec<&ContentEntry> {
        self.content_entries.iter().filter(|e| !e.is_delta()).collect()
    }

    /// Version as a display string (major.minor.patch.revision).
    pub fn version_string(&self) -> String {
        let major = (self.version >> 26) & 0x3F;
        let minor = (self.version >> 20) & 0x3F;
        let patch = (self.version >> 16) & 0xF;
        let revision = self.version & 0xFFFF;
        format!("{}.{}.{}.{}", major, minor, patch, revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_cnmt() -> Vec<u8> {
        let mut data = vec![0u8; 0x80];
        // Title ID
        data[0..8].copy_from_slice(&0x0100000000001000u64.to_le_bytes());
        // Version
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        // Title type: Application (0x80)
        data[12] = 0x80;
        // Table offset (extended header size)
        data[14..16].copy_from_slice(&16u16.to_le_bytes());
        // Content entry count
        data[16..18].copy_from_slice(&1u16.to_le_bytes());
        // Meta entry count
        data[18..20].copy_from_slice(&0u16.to_le_bytes());

        // Extended header (16 bytes at 0x20)
        // Skip — already zeros

        // Content entry at 0x30 (0x20 + 16 table offset)
        let entry_offset = 0x30;
        // Hash: 32 bytes (zeros)
        // Content ID at +0x20
        data[entry_offset + 0x20] = 0xAA;
        // Size at +0x30: 1MB
        let size = 1024u64 * 1024;
        data[entry_offset + 0x30..entry_offset + 0x36]
            .copy_from_slice(&size.to_le_bytes()[..6]);
        // Content type at +0x36: Program (1)
        data[entry_offset + 0x36] = 1;

        data
    }

    #[test]
    fn test_cnmt_parse() {
        let data = make_test_cnmt();
        let cnmt = Cnmt::from_bytes(&data).unwrap();
        assert_eq!(cnmt.title_id, 0x0100000000001000);
        assert_eq!(cnmt.title_type, 0x80);
        assert_eq!(cnmt.content_entries.len(), 1);
        assert_eq!(cnmt.content_entries[0].content_type, 1);
        assert_eq!(cnmt.content_entries[0].size, 1024 * 1024);
    }

    #[test]
    fn test_version_string() {
        let mut data = make_test_cnmt();
        // Version: v65536 = 1.0.0.0
        data[8..12].copy_from_slice(&65536u32.to_le_bytes());
        let cnmt = Cnmt::from_bytes(&data).unwrap();
        assert_eq!(cnmt.version_string(), "0.0.1.0");
    }
}
