use std::io::{Read, Seek};

use crate::error::Result;
use crate::formats::nca::NcaInfo;
use crate::formats::pfs0::{Pfs0, Pfs0Entry};
use crate::keys::KeyStore;

/// An opened NSP file (PFS0 container with NCAs + tickets + certs).
pub struct Nsp {
    pub pfs0: Pfs0,
}

impl Nsp {
    /// Open an NSP from a reader at offset 0.
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let pfs0 = Pfs0::parse_at(reader, 0)?;
        Ok(Self { pfs0 })
    }

    /// Open an NSP at a specific offset.
    pub fn parse_at<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<Self> {
        let pfs0 = Pfs0::parse_at(reader, offset)?;
        Ok(Self { pfs0 })
    }

    /// Get all NCA file entries.
    pub fn nca_entries(&self) -> Vec<&Pfs0Entry> {
        self.pfs0.find_by_ext(".nca")
    }

    /// Get all NCZ (compressed NCA) file entries.
    pub fn ncz_entries(&self) -> Vec<&Pfs0Entry> {
        self.pfs0.find_by_ext(".ncz")
    }

    /// Get all ticket file entries.
    pub fn ticket_entries(&self) -> Vec<&Pfs0Entry> {
        self.pfs0.find_by_ext(".tik")
    }

    /// Get all cert file entries.
    pub fn cert_entries(&self) -> Vec<&Pfs0Entry> {
        self.pfs0.find_by_ext(".cert")
    }

    /// Get CNMT NCA entries (NCA files whose name contains "cnmt" or content type is Meta).
    pub fn cnmt_nca_entries<R: Read + Seek>(&self, reader: &mut R, ks: &KeyStore) -> Vec<NcaInfo> {
        let mut result = Vec::new();
        for entry in self.nca_entries() {
            let offset = self.pfs0.file_abs_offset(entry);
            if let Ok(info) =
                crate::formats::nca::parse_nca_info(reader, offset, entry.size, &entry.name, ks)
            {
                if info.content_type == Some(crate::formats::types::ContentType::Meta) {
                    result.push(info);
                }
            }
        }
        result
    }

    /// Parse all NCA headers and return info about each.
    pub fn nca_infos<R: Read + Seek>(&self, reader: &mut R, ks: &KeyStore) -> Vec<NcaInfo> {
        let mut result = Vec::new();
        for entry in self.nca_entries() {
            let offset = self.pfs0.file_abs_offset(entry);
            match crate::formats::nca::parse_nca_info(reader, offset, entry.size, &entry.name, ks) {
                Ok(info) => result.push(info),
                Err(e) => {
                    log::warn!("Failed to parse NCA {}: {}", entry.name, e);
                }
            }
        }
        result
    }

    /// Get all entries (all files in the PFS0).
    pub fn all_entries(&self) -> &[Pfs0Entry] {
        &self.pfs0.entries
    }

    /// Get absolute offset of a file entry.
    pub fn file_abs_offset(&self, entry: &Pfs0Entry) -> u64 {
        self.pfs0.file_abs_offset(entry)
    }

    /// Total file size.
    pub fn total_size(&self) -> u64 {
        self.pfs0.total_size()
    }
}
