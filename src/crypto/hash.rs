use sha2::{Digest, Sha256};
use std::io::Read;

/// Compute SHA-256 of a byte slice.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 by streaming from a reader (1MB chunks).
pub fn sha256_streaming<R: Read>(reader: &mut R) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Compute SHA-256 of a specific number of bytes from a reader.
pub fn sha256_n<R: Read>(reader: &mut R, size: u64) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut remaining = size;
    let mut buf = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let to_read = buf.len().min(remaining as usize);
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }
}
