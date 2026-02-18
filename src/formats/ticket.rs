use std::io::Read;

use crate::error::{NscbError, Result};
use crate::keys::KeyStore;

/// Signature type → signature byte length.
fn sig_size(sig_type: u32) -> Option<usize> {
    match sig_type {
        0x010000 => Some(0x200), // RSA-4096 SHA-1
        0x010001 => Some(0x100), // RSA-2048 SHA-1
        0x010002 => Some(0x03C), // ECDSA SHA-1
        0x010003 => Some(0x200), // RSA-4096 SHA-256
        0x010004 => Some(0x100), // RSA-2048 SHA-256
        0x010005 => Some(0x03C), // ECDSA SHA-256
        _ => None,
    }
}

/// Padding after signature to align to 0x40.
fn sig_padding(sig_size: usize) -> usize {
    let total = 4 + sig_size; // sig_type(4) + signature
    let aligned = (total + 0x3F) & !0x3F;
    aligned - total
}

/// A parsed Nintendo Switch ticket (.tik file).
#[derive(Debug, Clone)]
pub struct Ticket {
    pub sig_type: u32,
    pub signature: Vec<u8>,
    /// Issuer string (64 bytes, null-terminated).
    pub issuer: String,
    /// Encrypted title key (first 16 bytes of the 256-byte title key block).
    pub title_key_block: [u8; 16],
    /// Title key type: 0=common, 1=personalized.
    pub title_key_type: u8,
    /// Master key revision from the ticket body.
    pub master_key_revision: u8,
    /// Rights ID (16 bytes).
    pub rights_id: [u8; 16],
    /// Account ID.
    pub account_id: u32,
    /// Raw ticket bytes for passthrough copying.
    pub raw: Vec<u8>,
}

impl Ticket {
    /// Parse a ticket from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(NscbError::InvalidData("Ticket too short".into()));
        }

        // Signature type is stored little-endian in retail tickets.
        let sig_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let ss = sig_size(sig_type).ok_or_else(|| {
            NscbError::InvalidData(format!("Unknown ticket signature type: 0x{:06X}", sig_type))
        })?;

        let sig_end = 4 + ss;
        if data.len() < sig_end {
            return Err(NscbError::InvalidData(
                "Ticket truncated at signature".into(),
            ));
        }
        let signature = data[4..sig_end].to_vec();

        let padding = sig_padding(ss);
        let body_start = sig_end + padding;

        if data.len() < body_start + 0x174 {
            return Err(NscbError::InvalidData("Ticket body too short".into()));
        }

        let body = &data[body_start..];

        // Issuer at +0x00, 64 bytes
        let issuer_bytes = &body[0x00..0x40];
        let issuer = String::from_utf8_lossy(
            &issuer_bytes[..issuer_bytes.iter().position(|&b| b == 0).unwrap_or(0x40)],
        )
        .into_owned();

        // Title key block at +0x40 (only first 16 bytes are used by NSCB)
        let mut title_key_block = [0u8; 16];
        title_key_block.copy_from_slice(&body[0x40..0x50]);

        // Title key type at +0x141
        let title_key_type = body[0x141];

        // Master key revision at +0x144 | +0x145 (NSCB behavior)
        let mut master_key_revision = body[0x144] | body[0x145];
        if master_key_revision == 0 && body.len() > 0x146 {
            master_key_revision = body[0x145] | body[0x146];
        }

        // Rights ID at +0x160
        let mut rights_id = [0u8; 16];
        rights_id.copy_from_slice(&body[0x160..0x170]);

        // Account ID at +0x170 (big-endian)
        let account_id = u32::from_be_bytes(body[0x170..0x174].try_into().unwrap());

        Ok(Self {
            sig_type,
            signature,
            issuer,
            title_key_block,
            title_key_type,
            master_key_revision,
            rights_id,
            account_id,
            raw: data.to_vec(),
        })
    }

    /// Parse from a reader at the current position.
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Self::from_bytes(&data)
    }

    /// Decrypt the title key using the keystore.
    pub fn decrypt_title_key(&self, ks: &KeyStore) -> Result<[u8; 16]> {
        ks.decrypt_title_key(&self.title_key_block, self.master_key_revision)
    }

    /// Title ID derived from the first 8 bytes of the rights ID.
    pub fn title_id(&self) -> u64 {
        u64::from_be_bytes(self.rights_id[..8].try_into().unwrap())
    }

    /// Title ID as hex string.
    pub fn title_id_hex(&self) -> String {
        format!("{:016x}", self.title_id())
    }

    /// Rights ID as hex string.
    pub fn rights_id_hex(&self) -> String {
        hex::encode(self.rights_id)
    }

    /// Is this a common (not personalized) ticket?
    pub fn is_common(&self) -> bool {
        self.title_key_type == 0
    }

    /// Raw size of this ticket.
    pub fn size(&self) -> usize {
        self.raw.len()
    }
}

/// Generate a standard ticket for building NSPs.
pub fn generate_ticket(title_key: &[u8; 16], rights_id: &[u8; 16], key_generation: u8) -> Vec<u8> {
    let mut ticket = Vec::new();

    // Signature type: RSA-2048 SHA-256
    ticket.extend_from_slice(&0x00010004u32.to_be_bytes());
    // Signature: 256 bytes of zeros
    ticket.extend_from_slice(&[0u8; 0x100]);
    // Padding to 0x40 alignment
    ticket.extend_from_slice(&[0u8; 0x3C]);

    // Body (0x2C0 bytes)
    let mut body = vec![0u8; 0x2C0];

    // Issuer at +0x00
    let issuer = b"Root-CA00000003-XS00000020\0";
    body[..issuer.len()].copy_from_slice(issuer);

    // Title key block at +0x180
    body[0x180..0x190].copy_from_slice(title_key);

    // Title key type at +0x281: common
    body[0x281] = 0;

    // Master key revision at +0x285
    body[0x285] = key_generation;

    // Rights ID at +0x2A0
    body[0x2A0..0x2B0].copy_from_slice(rights_id);

    ticket.extend_from_slice(&body);
    ticket
}

/// Generate a standard certificate chain for building NSPs.
/// This is the hardcoded fake cert used by all homebrew tools.
pub fn generate_cert() -> Vec<u8> {
    // Minimal valid cert chain (CA + XS certs)
    // This is a well-known public constant used by all NSP builders
    let mut cert = vec![0u8; 0x700];

    // CA cert
    cert[0x00..0x04].copy_from_slice(&0x00010003u32.to_be_bytes()); // RSA-4096 SHA-256
                                                                    // ... signature and body would go here
                                                                    // For a proper implementation, this should be the actual public cert chain
                                                                    // For now, this is a placeholder — real certs are ~1792 bytes total

    cert
}
