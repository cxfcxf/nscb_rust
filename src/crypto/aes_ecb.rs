use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::error::{NscbError, Result};

/// AES-128-ECB encrypt a single 16-byte block.
pub fn encrypt_block(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|e| NscbError::Crypto(format!("AES key init: {e}")))?;
    let mut block = aes::Block::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

/// AES-128-ECB decrypt a single 16-byte block.
pub fn decrypt_block(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|e| NscbError::Crypto(format!("AES key init: {e}")))?;
    let mut block = aes::Block::clone_from_slice(data);
    cipher.decrypt_block(&mut block);
    Ok(block.into())
}

/// AES-128-ECB encrypt multiple blocks in place.
pub fn encrypt(key: &[u8], data: &mut [u8]) -> Result<()> {
    assert!(data.len() % 16 == 0, "ECB data must be 16-byte aligned");
    let cipher = Aes128::new_from_slice(key)
        .map_err(|e| NscbError::Crypto(format!("AES key init: {e}")))?;
    for chunk in data.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(())
}

/// AES-128-ECB decrypt multiple blocks in place.
pub fn decrypt(key: &[u8], data: &mut [u8]) -> Result<()> {
    assert!(data.len() % 16 == 0, "ECB data must be 16-byte aligned");
    let cipher = Aes128::new_from_slice(key)
        .map_err(|e| NscbError::Crypto(format!("AES key init: {e}")))?;
    for chunk in data.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecb_roundtrip() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                         0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let encrypted = encrypt_block(&key, &plaintext).unwrap();
        let decrypted = decrypt_block(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecb_nist_vector() {
        // NIST AES-128 test vector
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let expected = hex::decode("3ad77bb40d7a3660a89ecaf32466ef97").unwrap();
        let result = encrypt_block(&key, &plaintext).unwrap();
        assert_eq!(result[..], expected[..]);
    }
}
