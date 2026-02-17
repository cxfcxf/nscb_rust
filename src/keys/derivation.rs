use crate::crypto::aes_ecb;
use crate::error::Result;

/// Three-stage key derivation used by Nintendo Switch.
///
/// ```text
/// stage1 = AES_ECB_decrypt(kek_seed, key=master_key)
/// stage2 = AES_ECB_decrypt(source, key=stage1)
/// stage3 = AES_ECB_decrypt(key_seed, key=stage2)  // optional
/// ```
pub fn generate_kek(
    source: &[u8; 16],
    master_key: &[u8; 16],
    kek_seed: &[u8; 16],
    key_seed: Option<&[u8; 16]>,
) -> Result<[u8; 16]> {
    // Stage 1: derive KEK from master key
    let stage1 = aes_ecb::decrypt_block(master_key, kek_seed)?;

    // Stage 2: unwrap source with KEK
    let stage2 = aes_ecb::decrypt_block(&stage1, source)?;

    // Stage 3: optional final derivation
    match key_seed {
        Some(seed) => aes_ecb::decrypt_block(&stage2, seed),
        None => Ok(stage2),
    }
}

/// Derive a title KEK for a given master key revision.
///
/// ```text
/// titleKek = generateKek(titlekek_source, master_key, aes_kek_generation_source, aes_key_generation_source)
/// ```
pub fn derive_title_kek(
    master_key: &[u8; 16],
    titlekek_source: &[u8; 16],
    aes_kek_generation_source: &[u8; 16],
    aes_key_generation_source: &[u8; 16],
) -> Result<[u8; 16]> {
    generate_kek(
        titlekek_source,
        master_key,
        aes_kek_generation_source,
        Some(aes_key_generation_source),
    )
}

/// Derive a key area key for a given master key revision and key type.
///
/// key_type: 0=application, 1=ocean, 2=system
///
/// ```text
/// keyAreaKey = generateKek(key_area_key_*_source, master_key, aes_kek_generation_source, None)
/// ```
pub fn derive_key_area_key(
    master_key: &[u8; 16],
    key_area_source: &[u8; 16],
    aes_kek_generation_source: &[u8; 16],
) -> Result<[u8; 16]> {
    generate_kek(
        key_area_source,
        master_key,
        aes_kek_generation_source,
        None,
    )
}

/// Decrypt a title key using the appropriate title KEK.
pub fn decrypt_title_key(encrypted_key: &[u8; 16], title_kek: &[u8; 16]) -> Result<[u8; 16]> {
    aes_ecb::decrypt_block(title_kek, encrypted_key)
}

/// Encrypt a title key using the appropriate title KEK.
pub fn encrypt_title_key(plain_key: &[u8; 16], title_kek: &[u8; 16]) -> Result<[u8; 16]> {
    aes_ecb::encrypt_block(title_kek, plain_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_kek_roundtrip_structure() {
        // With all-zero keys, verify the derivation chain executes without error
        let source = [0u8; 16];
        let master = [0u8; 16];
        let kek_seed = [0u8; 16];
        let key_seed = [0u8; 16];

        let result = generate_kek(&source, &master, &kek_seed, Some(&key_seed));
        assert!(result.is_ok());

        let result2 = generate_kek(&source, &master, &kek_seed, None);
        assert!(result2.is_ok());

        // With vs without key_seed should differ (unless keys happen to collide)
        // Just verify both succeed
    }
}
