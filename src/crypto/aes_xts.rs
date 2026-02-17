use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::error::{NscbError, Result};

const SECTOR_SIZE: usize = 0x200;

/// Nintendo Switch AES-128-XTS implementation.
///
/// Used for NCA header decryption (0xC00 bytes = 6 sectors of 0x200).
pub struct NintendoXts {
    data_cipher: Aes128,
    tweak_cipher: Aes128,
}

impl NintendoXts {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(NscbError::Crypto(format!(
                "XTS key must be 32 bytes, got {}",
                key.len()
            )));
        }
        let data_cipher = Aes128::new_from_slice(&key[..16])
            .map_err(|e| NscbError::Crypto(format!("XTS data key init: {e}")))?;
        let tweak_cipher = Aes128::new_from_slice(&key[16..])
            .map_err(|e| NscbError::Crypto(format!("XTS tweak key init: {e}")))?;
        Ok(Self {
            data_cipher,
            tweak_cipher,
        })
    }

    /// Decrypt a single 0x200-byte sector.
    pub fn decrypt_sector(&self, sector_num: u64, data: &mut [u8]) {
        self.decrypt_sector_with_endian(sector_num, data, false);
    }

    /// Decrypt a single sector with explicit sector number endianness.
    pub fn decrypt_sector_with_endian(
        &self,
        sector_num: u64,
        data: &mut [u8],
        little_endian_sector_num: bool,
    ) {
        assert_eq!(data.len(), SECTOR_SIZE);

        // Compute tweak from the sector number with selectable byte order.
        let mut tweak = [0u8; 16];
        let sector_bytes = if little_endian_sector_num {
            (sector_num as u128).to_le_bytes()
        } else {
            (sector_num as u128).to_be_bytes()
        };
        tweak.copy_from_slice(&sector_bytes);
        let tweak_block = aes::Block::from_mut_slice(&mut tweak);
        self.tweak_cipher.encrypt_block(tweak_block);

        // Process each 16-byte block in the sector
        for chunk in data.chunks_exact_mut(16) {
            // XOR with tweak
            xor_block(chunk, &tweak);

            // Decrypt
            let block = aes::Block::from_mut_slice(chunk);
            self.data_cipher.decrypt_block(block);

            // XOR with tweak again
            xor_block(chunk, &tweak);

            // Multiply tweak by x in GF(2^128)
            gf128_mul_x(&mut tweak);
        }
    }

    /// Encrypt a single 0x200-byte sector.
    pub fn encrypt_sector(&self, sector_num: u64, data: &mut [u8]) {
        self.encrypt_sector_with_endian(sector_num, data, false);
    }

    /// Encrypt a single sector with explicit sector number endianness.
    pub fn encrypt_sector_with_endian(
        &self,
        sector_num: u64,
        data: &mut [u8],
        little_endian_sector_num: bool,
    ) {
        assert_eq!(data.len(), SECTOR_SIZE);

        let mut tweak = [0u8; 16];
        let sector_bytes = if little_endian_sector_num {
            (sector_num as u128).to_le_bytes()
        } else {
            (sector_num as u128).to_be_bytes()
        };
        tweak.copy_from_slice(&sector_bytes);
        let tweak_block = aes::Block::from_mut_slice(&mut tweak);
        self.tweak_cipher.encrypt_block(tweak_block);

        for chunk in data.chunks_exact_mut(16) {
            xor_block(chunk, &tweak);
            let block = aes::Block::from_mut_slice(chunk);
            self.data_cipher.encrypt_block(block);
            xor_block(chunk, &tweak);
            gf128_mul_x(&mut tweak);
        }
    }

    /// Decrypt multiple contiguous sectors starting at `start_sector`.
    pub fn decrypt(&self, start_sector: u64, data: &mut [u8]) {
        self.decrypt_with_endian(start_sector, data, false);
    }

    /// Decrypt multiple contiguous sectors with explicit sector number endianness.
    pub fn decrypt_with_endian(
        &self,
        start_sector: u64,
        data: &mut [u8],
        little_endian_sector_num: bool,
    ) {
        assert_eq!(data.len() % SECTOR_SIZE, 0);
        for (i, sector) in data.chunks_exact_mut(SECTOR_SIZE).enumerate() {
            self.decrypt_sector_with_endian(
                start_sector + i as u64,
                sector,
                little_endian_sector_num,
            );
        }
    }

    /// Encrypt multiple contiguous sectors starting at `start_sector`.
    pub fn encrypt(&self, start_sector: u64, data: &mut [u8]) {
        self.encrypt_with_endian(start_sector, data, false);
    }

    /// Encrypt multiple contiguous sectors with explicit sector number endianness.
    pub fn encrypt_with_endian(
        &self,
        start_sector: u64,
        data: &mut [u8],
        little_endian_sector_num: bool,
    ) {
        assert_eq!(data.len() % SECTOR_SIZE, 0);
        for (i, sector) in data.chunks_exact_mut(SECTOR_SIZE).enumerate() {
            self.encrypt_sector_with_endian(
                start_sector + i as u64,
                sector,
                little_endian_sector_num,
            );
        }
    }
}

/// XOR 16 bytes in place.
#[inline]
fn xor_block(data: &mut [u8], mask: &[u8; 16]) {
    for (d, m) in data.iter_mut().zip(mask.iter()) {
        *d ^= m;
    }
}

/// Multiply a 128-bit value by x in GF(2^128) with the XTS polynomial.
/// The polynomial is x^128 + x^7 + x^2 + x + 1 (0x87 feedback).
#[inline]
fn gf128_mul_x(tweak: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let new_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }
    // If the high bit was set, XOR with the reduction polynomial
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xts_roundtrip() {
        let key = [0u8; 32];
        let xts = NintendoXts::new(&key).unwrap();

        let original = vec![0xABu8; SECTOR_SIZE];
        let mut data = original.clone();

        xts.encrypt_sector(0, &mut data);
        assert_ne!(data, original); // Should be encrypted

        xts.decrypt_sector(0, &mut data);
        assert_eq!(data, original); // Should be back to original
    }

    #[test]
    fn test_xts_multi_sector_roundtrip() {
        let key = [0x42u8; 32];
        let xts = NintendoXts::new(&key).unwrap();

        let original = vec![0xCDu8; SECTOR_SIZE * 6]; // 6 sectors like NCA header
        let mut data = original.clone();

        xts.encrypt(0, &mut data);
        assert_ne!(data, original);

        xts.decrypt(0, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xts_different_sectors_differ() {
        let key = [0x11u8; 32];
        let xts = NintendoXts::new(&key).unwrap();

        let mut sector0 = vec![0u8; SECTOR_SIZE];
        let mut sector1 = vec![0u8; SECTOR_SIZE];

        xts.encrypt_sector(0, &mut sector0);
        xts.encrypt_sector(1, &mut sector1);

        // Same plaintext encrypted with different sector numbers should differ
        assert_ne!(sector0, sector1);
    }

    #[test]
    fn test_gf128_mul_x() {
        let mut tweak = [0u8; 16];
        tweak[0] = 1;
        gf128_mul_x(&mut tweak);
        assert_eq!(tweak[0], 2);

        // Test carry/feedback
        let mut tweak2 = [0u8; 16];
        tweak2[15] = 0x80; // High bit set
        gf128_mul_x(&mut tweak2);
        assert_eq!(tweak2[0], 0x87); // Feedback
        assert_eq!(tweak2[15], 0x00);
    }
}
