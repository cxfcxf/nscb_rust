use std::io::{Read, Seek, SeekFrom};

use crate::crypto::aes_ecb;
use crate::crypto::aes_xts::NintendoXts;
use crate::error::{NscbError, Result};
use crate::formats::pfs0::Pfs0;
use crate::formats::types::*;
use crate::keys::KeyStore;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use sha2::{Digest, Sha256};

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
        const EMPTY: SectionTableEntry = SectionTableEntry {
            media_start: 0,
            media_end: 0,
            _unknown1: 0,
            _unknown2: 0,
        };
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

    /// Key generation as interpreted by squirrel.py's patcher_meta path.
    pub fn python_patcher_key_generation(&self) -> u8 {
        if self.crypto_type == 2 {
            self.crypto_type.max(self.crypto_type2)
        } else {
            self.crypto_type2
        }
    }

    /// Master key revision for key derivation (key_generation - 1, clamped to 0).
    pub fn master_key_revision(&self) -> u8 {
        let kg = self.key_generation();
        if kg > 0 {
            kg - 1
        } else {
            0
        }
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

    /// Get the filesystem crypto counter as squirrel.py derives it in `BaseFs`.
    /// It builds a 16-byte counter from 8 zero bytes plus FS header bytes 0x140..0x148,
    /// then reverses the full 16-byte buffer.
    pub fn section_crypto_counter(&self, section_index: usize) -> [u8; 16] {
        let fs_header_offset = 0x400 + section_index * 0x200;
        let counter_offset = fs_header_offset + 0x140;
        let mut counter = [0u8; 16];
        if counter_offset + 8 <= self.raw.len() {
            counter[8..].copy_from_slice(&self.raw[counter_offset..counter_offset + 8]);
        }
        counter.reverse();
        counter
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

    pub fn hblock_block_size(&self) -> u32 {
        u32::from_le_bytes(self.raw[0x428..0x42C].try_into().unwrap_or([0u8; 4]))
    }

    pub fn htable_offset(&self) -> u64 {
        u64::from_le_bytes(self.raw[0x430..0x438].try_into().unwrap_or([0u8; 8]))
    }

    pub fn htable_size(&self) -> u64 {
        u64::from_le_bytes(self.raw[0x438..0x440].try_into().unwrap_or([0u8; 8]))
    }

    pub fn pfs0_offset(&self) -> u64 {
        u64::from_le_bytes(self.raw[0x440..0x448].try_into().unwrap_or([0u8; 8]))
    }

    pub fn pfs0_size(&self) -> u64 {
        u64::from_le_bytes(self.raw[0x448..0x450].try_into().unwrap_or([0u8; 8]))
    }
}

fn decrypt_header_for_edit(encrypted: &[u8], ks: &KeyStore) -> Result<(Vec<u8>, [u8; 32], bool)> {
    if encrypted.len() < 0xC00 {
        return Err(NscbError::InvalidData("NCA header too short".into()));
    }

    let header_key = ks.header_key()?;
    let mut swapped_key = [0u8; 32];
    swapped_key[..16].copy_from_slice(&header_key[16..]);
    swapped_key[16..].copy_from_slice(&header_key[..16]);

    // Prefer NSC_BUILDER mode first; keep fallback variants for compatibility.
    let attempts = [
        (header_key, true),
        (header_key, false),
        (swapped_key, true),
        (swapped_key, false),
    ];

    for (key, le_sector) in attempts {
        let xts = NintendoXts::new(&key)?;
        let mut decrypted = encrypted[..0xC00].to_vec();
        xts.decrypt_with_endian(0, &mut decrypted, le_sector);
        if NcaHeader::from_decrypted(decrypted.clone()).is_ok() {
            return Ok((decrypted, key, le_sector));
        }
    }

    Err(NscbError::InvalidData(
        "Failed to decrypt NCA header with known XTS variants".into(),
    ))
}

/// Rewrite an encrypted NCA header for gamecard/XCI style distribution.
///
/// This mirrors NSC_BUILDER behavior:
/// - preserve the original gamecard/eShop flag from the source header
/// - clear rights ID
/// - for rights-based NCAs, re-encrypt title key into all key area slots
pub fn rewrite_header_for_xci(
    encrypted_header: &[u8],
    ks: &KeyStore,
    title_key: Option<[u8; 16]>,
    gamecard_flag: u8,
) -> Result<Vec<u8>> {
    let (mut dec, key, le_sector) = decrypt_header_for_edit(encrypted_header, ks)?;

    let had_rights = dec[0x230..0x240].iter().any(|&b| b != 0);
    let key_index = dec[0x207];
    let key_generation = dec[0x206].max(dec[0x220]);

    dec[0x204] = gamecard_flag;
    // Clear rights ID for gamecard-style headers.
    dec[0x230..0x240].fill(0);

    if had_rights {
        let tk = title_key.ok_or_else(|| {
            NscbError::KeyNotFound(
                "Missing matching ticket/titlekey for rights-based NCA while creating XCI".into(),
            )
        })?;
        let mkrev = if key_generation > 0 {
            key_generation - 1
        } else {
            0
        };
        let kak = ks.key_area_key(mkrev, key_index)?;
        let enc_slot = aes_ecb::encrypt_block(&kak, &tk)?;
        for i in 0..4 {
            let base = 0x300 + i * 16;
            dec[base..base + 16].copy_from_slice(&enc_slot);
        }
    }

    let xts = NintendoXts::new(&key)?;
    xts.encrypt_with_endian(0, &mut dec, le_sector);
    Ok(dec)
}

pub fn python_xci_is_cartridge(headers: &[NcaHeader], ks: &KeyStore) -> bool {
    !headers.is_empty()
        && headers.iter().all(|header| {
            if header.distribution_type != 0 {
                return true;
            }
            header
                .decrypt_key_area(ks)
                .map(|keys| keys[0].iter().all(|&b| b == 0))
                .unwrap_or(false)
        })
}

pub fn python_xci_gamecard_flag(header: &NcaHeader, ks: &KeyStore, is_cartridge: bool) -> u8 {
    if !is_cartridge {
        return 0;
    }
    if header.distribution_type != 0 {
        return 1;
    }
    header
        .decrypt_key_area(ks)
        .map(|keys| {
            if keys[0].iter().all(|&b| b == 0) {
                1
            } else {
                0
            }
        })
        .unwrap_or(0)
}

/// Rewrite encrypted NCA header to force eShop distribution flag.
///
/// Mirrors NSC_BUILDER create path behavior where `setgamecard(0)` is applied
/// before packing NSPs.
pub fn rewrite_header_for_nsp(encrypted_header: &[u8], ks: &KeyStore) -> Result<Vec<u8>> {
    let (mut dec, key, le_sector) = decrypt_header_for_edit(encrypted_header, ks)?;
    dec[0x204] = 0x00;
    let xts = NintendoXts::new(&key)?;
    xts.encrypt_with_endian(0, &mut dec, le_sector);
    Ok(dec)
}

pub fn rewrite_header_with_keygen(
    encrypted_header: &[u8],
    ks: &KeyStore,
    new_keygen: u8,
    _for_xci: bool,
) -> Result<Vec<u8>> {
    if encrypted_header.len() < 0xC00 {
        return Err(NscbError::InvalidData("NCA header too short".into()));
    }

    let (mut dec, key, le_sector) = decrypt_header_for_edit(encrypted_header, ks)?;
    let old_crypto2 = dec[0x220];
    if new_keygen >= old_crypto2 {
        return Ok(encrypted_header[..0xC00].to_vec());
    }

    let key_index = dec[0x207];
    let key_block_nonzero = dec[0x300..0x340].iter().any(|&b| b != 0);

    if key_block_nonzero {
        let old_mkrev = old_crypto2.saturating_sub(1);
        let new_mkrev = new_keygen.saturating_sub(1);
        let old_kak = ks.key_area_key(old_mkrev, key_index)?;
        let new_kak = ks.key_area_key(new_mkrev, key_index)?;
        for i in 0..4 {
            let base = 0x300 + i * 16;
            let mut encrypted_slot = [0u8; 16];
            encrypted_slot.copy_from_slice(&dec[base..base + 16]);
            let clear_slot = aes_ecb::decrypt_block(&old_kak, &encrypted_slot)?;
            let reenc_slot = aes_ecb::encrypt_block(&new_kak, &clear_slot)?;
            dec[base..base + 16].copy_from_slice(&reenc_slot);
        }
    }

    let (crypto1, crypto2) = if new_keygen >= 3 {
        (2, new_keygen)
    } else if new_keygen == 2 {
        (2, 0)
    } else {
        (new_keygen, 0)
    };
    dec[0x206] = crypto1;
    dec[0x220] = crypto2;

    let xts = NintendoXts::new(&key)?;
    xts.encrypt_with_endian(0, &mut dec, le_sector);
    Ok(dec)
}

pub fn patch_meta_nca_with_rsvcap(
    encrypted_nca: &[u8],
    ks: &KeyStore,
    new_rsv: u32,
    keygen_hint: Option<u8>,
) -> Result<Option<(Vec<u8>, u32, u32)>> {
    if encrypted_nca.len() < 0xC00 {
        return Err(NscbError::InvalidData("NCA image too short".into()));
    }

    let (mut header_dec, xts_key, le_sector) =
        decrypt_header_for_edit(&encrypted_nca[..0xC00], ks)?;
    let header = NcaHeader::from_decrypted(header_dec.clone())?;
    if header.content_type_enum() != Some(ContentType::Meta) {
        return Ok(None);
    }

    let section_keys = header.decrypt_key_area(ks)?;

    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 {
            continue;
        }
        let sec_start = sec.start_offset() as usize;
        let sec_end = sec.end_offset() as usize;
        if sec_end > encrypted_nca.len() || sec_start >= sec_end {
            continue;
        }

        let section_enc = &encrypted_nca[sec_start..sec_end];
        if let Some((mut section_plain, mode, before, after)) = patch_meta_section(
            section_enc,
            &header,
            sec_idx,
            &section_keys,
            new_rsv,
            keygen_hint,
        ) {
            update_meta_hashes(&mut header_dec, &mut section_plain, &header)?;

            let mut output = encrypted_nca.to_vec();
            match mode {
                SectionCryptoMode::Raw => {
                    output[sec_start..sec_end].copy_from_slice(&section_plain);
                }
                SectionCryptoMode::Ctr {
                    key,
                    nonce,
                    file_offset,
                    little_endian,
                } => {
                    let mut reenc = section_plain;
                    aes_ctr_transform_in_place(
                        &key,
                        &nonce,
                        file_offset,
                        little_endian,
                        &mut reenc,
                    );
                    output[sec_start..sec_end].copy_from_slice(&reenc);
                }
            }

            let xts = NintendoXts::new(&xts_key)?;
            xts.encrypt_with_endian(0, &mut header_dec, le_sector);
            output[..0xC00].copy_from_slice(&header_dec);
            return Ok(Some((output, before, after)));
        }
    }

    Ok(None)
}

#[derive(Clone, Copy)]
enum SectionCryptoMode {
    Raw,
    Ctr {
        key: [u8; 16],
        nonce: [u8; 8],
        file_offset: u64,
        little_endian: bool,
    },
}

fn patch_meta_section(
    section_enc: &[u8],
    header: &NcaHeader,
    sec_idx: usize,
    section_keys: &[[u8; 16]; 4],
    new_rsv: u32,
    keygen_hint: Option<u8>,
) -> Option<(Vec<u8>, SectionCryptoMode, u32, u32)> {
    let mut raw = section_enc.to_vec();
    if let Some((before, after)) =
        patch_cnmt_required_system_version_in_section(&mut raw, header, new_rsv, keygen_hint)
    {
        return Some((raw, SectionCryptoMode::Raw, before, after));
    }

    let nonce = header.section_ctr_nonce(sec_idx);
    for key in section_keys {
        for &file_offset in &[header.section_table[sec_idx].start_offset(), 0u64] {
            for &little_endian in &[true, false] {
                let mut dec = section_enc.to_vec();
                aes_ctr_transform_in_place(key, &nonce, file_offset, little_endian, &mut dec);
                if let Some((before, after)) = patch_cnmt_required_system_version_in_section(
                    &mut dec,
                    header,
                    new_rsv,
                    keygen_hint,
                ) {
                    return Some((
                        dec,
                        SectionCryptoMode::Ctr {
                            key: *key,
                            nonce,
                            file_offset,
                            little_endian,
                        },
                        before,
                        after,
                    ));
                }
            }
        }
    }

    None
}

fn patch_cnmt_required_system_version_in_section(
    section_plain: &mut [u8],
    header: &NcaHeader,
    new_rsv: u32,
    keygen_hint: Option<u8>,
) -> Option<(u32, u32)> {
    for off in pfs0_candidate_offsets(section_plain) {
        let mut cursor = std::io::Cursor::new(&section_plain[..]);
        let Ok(pfs) = Pfs0::parse_at(&mut cursor, off as u64) else {
            continue;
        };
        for entry in &pfs.entries {
            if !entry.name.ends_with(".cnmt") {
                continue;
            }
            let abs = pfs.file_abs_offset(entry) as usize;
            let end = abs.saturating_add(entry.size as usize);
            if end > section_plain.len() || abs + 0x2C > end {
                continue;
            }
            let mut cnmt = crate::formats::cnmt::Cnmt::from_bytes(&section_plain[abs..end]).ok()?;
            let before = cnmt.required_system_version;
            let keygen = keygen_hint.unwrap_or_else(|| header.python_patcher_key_generation());
            let after = crate::formats::types::apply_patcher_meta_rsv(keygen, before, new_rsv);
            cnmt.patch_required_system_version(after);
            section_plain[abs..end].copy_from_slice(&cnmt.raw);
            return Some((before, after));
        }
    }
    None
}

fn update_meta_hashes(
    header_dec: &mut [u8],
    section_plain: &mut [u8],
    header: &NcaHeader,
) -> Result<()> {
    let block_size = header.hblock_block_size() as usize;
    let htable_offset = header.htable_offset() as usize;
    let htable_size = header.htable_size() as usize;
    let pfs0_offset = header.pfs0_offset() as usize;
    let pfs0_size = header.pfs0_size() as usize;
    if block_size == 0 || pfs0_size == 0 {
        return Ok(());
    }

    let mult = pfs0_size.div_ceil(block_size);
    let pfs0_hash_len = 0x20usize.saturating_mul(mult);
    if htable_offset + pfs0_hash_len > section_plain.len()
        || pfs0_offset + pfs0_size > section_plain.len()
    {
        return Ok(());
    }

    let pfs0_block_len = block_size.min(pfs0_size);
    let pfs0_hash = Sha256::digest(&section_plain[pfs0_offset..pfs0_offset + pfs0_block_len]);
    section_plain[htable_offset..htable_offset + 0x20].copy_from_slice(&pfs0_hash);

    let htable_hash = Sha256::digest(
        &section_plain[htable_offset..htable_offset + pfs0_hash_len.min(htable_size)],
    );
    header_dec[0x408..0x428].copy_from_slice(&htable_hash);

    let hblock_hash = Sha256::digest(&header_dec[0x400..0x600]);
    header_dec[0x280..0x2A0].copy_from_slice(&hblock_hash);

    Ok(())
}

fn pfs0_candidate_offsets(section: &[u8]) -> Vec<usize> {
    let mut out = vec![0usize];
    let scan_len = section.len().min(1024 * 1024);
    for i in 0..scan_len.saturating_sub(4) {
        if &section[i..i + 4] == b"PFS0" {
            out.push(i);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn aes_ctr_transform_in_place(
    key: &[u8; 16],
    nonce8: &[u8; 8],
    file_offset: u64,
    little_endian: bool,
    data: &mut [u8],
) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block_index = file_offset >> 4;
    for chunk in data.chunks_mut(16) {
        let mut counter_block = [0u8; 16];
        counter_block[..8].copy_from_slice(nonce8);
        if little_endian {
            counter_block[8..].copy_from_slice(&block_index.to_le_bytes());
        } else {
            counter_block[8..].copy_from_slice(&block_index.to_be_bytes());
        }
        let mut block = GenericArray::clone_from_slice(&counter_block);
        cipher.encrypt_block(&mut block);
        for (dst, src) in chunk.iter_mut().zip(block.as_slice()) {
            *dst ^= *src;
        }
        block_index = block_index.wrapping_add(1);
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
