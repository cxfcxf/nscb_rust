use std::io::{self, Read, Seek, SeekFrom};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::error::{NscbError, Result};

/// Seekable AES-128-CTR reader that decrypts on the fly.
///
/// Nintendo Switch NCA sections use AES-CTR with an 8-byte nonce
/// (from the section header) and an 8-byte big-endian counter that
/// increments per 16-byte block.
pub struct CtrReader<R> {
    inner: R,
    cipher: Aes128,
    /// The initial 16-byte counter/nonce (first 8 = nonce, last 8 = initial counter value).
    initial_counter: [u8; 16],
    /// Current logical position in the decrypted stream.
    position: u64,
    /// Offset of section start in the underlying reader.
    section_offset: u64,
    /// Size of the section (for bounds checking).
    section_size: u64,
}

impl<R: Read + Seek> CtrReader<R> {
    pub fn new(
        inner: R,
        key: &[u8],
        nonce: &[u8; 8],
        section_offset: u64,
        section_size: u64,
    ) -> Result<Self> {
        let cipher = Aes128::new_from_slice(key)
            .map_err(|e| NscbError::Crypto(format!("AES key init: {e}")))?;

        let mut initial_counter = [0u8; 16];
        initial_counter[..8].copy_from_slice(nonce);
        // Last 8 bytes are the counter, starting at section_offset / 16 (big-endian)
        let initial_block = section_offset / 16;
        initial_counter[8..].copy_from_slice(&initial_block.to_be_bytes());

        Ok(Self {
            inner,
            cipher,
            initial_counter,
            position: 0,
            section_offset,
            section_size,
        })
    }

    /// Compute the 16-byte counter value for a given byte position.
    fn counter_at(&self, position: u64) -> [u8; 16] {
        let mut ctr = self.initial_counter;
        let block_offset = position / 16;
        // Add block_offset to the big-endian counter in bytes 8..16
        let base = u64::from_be_bytes(ctr[8..16].try_into().unwrap());
        let new_val = base.wrapping_add(block_offset);
        ctr[8..16].copy_from_slice(&new_val.to_be_bytes());
        ctr
    }

    /// Generate keystream for a single block.
    fn keystream_block(&self, counter: &[u8; 16]) -> [u8; 16] {
        let mut block = aes::Block::clone_from_slice(counter);
        self.cipher.encrypt_block(&mut block);
        block.into()
    }
}

impl<R: Read + Seek> Read for CtrReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.section_size {
            return Ok(0);
        }

        let remaining = (self.section_size - self.position) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }

        // Seek underlying reader to correct position
        self.inner
            .seek(SeekFrom::Start(self.section_offset + self.position))?;

        let n = self.inner.read(&mut buf[..to_read])?;
        if n == 0 {
            return Ok(0);
        }

        // XOR with keystream
        let start_pos = self.position;
        for i in 0..n {
            let byte_pos = start_pos + i as u64;
            let counter = self.counter_at(byte_pos);
            let ks = self.keystream_block(&counter);
            buf[i] ^= ks[byte_pos as usize % 16];
        }

        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for CtrReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.position as i64 + n,
            SeekFrom::End(n) => self.section_size as i64 + n,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }

        self.position = new_pos as u64;
        Ok(self.position)
    }
}

/// Optimized version that caches the current keystream block.
pub struct CtrStream<R> {
    inner: R,
    cipher: Aes128,
    initial_counter: [u8; 16],
    position: u64,
    section_offset: u64,
    section_size: u64,
    /// Cached keystream block and its block index.
    cached_ks: [u8; 16],
    cached_block_idx: u64,
}

impl<R: Read + Seek> CtrStream<R> {
    pub fn new(
        inner: R,
        key: &[u8],
        nonce: &[u8; 8],
        section_offset: u64,
        section_size: u64,
    ) -> Result<Self> {
        let cipher = Aes128::new_from_slice(key)
            .map_err(|e| NscbError::Crypto(format!("AES key init: {e}")))?;

        let mut initial_counter = [0u8; 16];
        initial_counter[..8].copy_from_slice(nonce);
        let initial_block = section_offset / 16;
        initial_counter[8..].copy_from_slice(&initial_block.to_be_bytes());

        Ok(Self {
            inner,
            cipher,
            initial_counter,
            position: 0,
            section_offset,
            section_size,
            cached_ks: [0u8; 16],
            cached_block_idx: u64::MAX,
        })
    }

    fn get_keystream_byte(&mut self, byte_pos: u64) -> u8 {
        let block_idx = byte_pos / 16;
        let byte_in_block = (byte_pos % 16) as usize;

        if block_idx != self.cached_block_idx {
            let mut ctr = self.initial_counter;
            let base = u64::from_be_bytes(ctr[8..16].try_into().unwrap());
            let new_val = base.wrapping_add(block_idx);
            ctr[8..16].copy_from_slice(&new_val.to_be_bytes());

            let mut block = aes::Block::clone_from_slice(&ctr);
            self.cipher.encrypt_block(&mut block);
            self.cached_ks = block.into();
            self.cached_block_idx = block_idx;
        }

        self.cached_ks[byte_in_block]
    }
}

impl<R: Read + Seek> Read for CtrStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.section_size {
            return Ok(0);
        }

        let remaining = (self.section_size - self.position) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }

        self.inner
            .seek(SeekFrom::Start(self.section_offset + self.position))?;

        let n = self.inner.read(&mut buf[..to_read])?;
        if n == 0 {
            return Ok(0);
        }

        let start_pos = self.position;
        for i in 0..n {
            buf[i] ^= self.get_keystream_byte(start_pos + i as u64);
        }

        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for CtrStream<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.position as i64 + n,
            SeekFrom::End(n) => self.section_size as i64 + n,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }

        self.position = new_pos as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_ctr_stream_seek_consistency() {
        let key = [0u8; 16];
        let nonce = [0u8; 8];
        let data = vec![0u8; 256];
        let cursor = Cursor::new(data);

        let mut reader = CtrStream::new(cursor, &key, &nonce, 0, 256).unwrap();

        // Read first 16 bytes
        let mut buf1 = [0u8; 16];
        reader.read_exact(&mut buf1).unwrap();

        // Seek back to start, read again
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut buf2 = [0u8; 16];
        reader.read_exact(&mut buf2).unwrap();

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_ctr_stream_partial_block() {
        let key = [0u8; 16];
        let nonce = [0u8; 8];
        let data = vec![0u8; 256];
        let cursor = Cursor::new(data);

        let mut reader = CtrStream::new(cursor, &key, &nonce, 0, 256).unwrap();

        // Read 3 bytes, then seek to byte 3, read 13 more — should match reading 16 at once
        let mut buf_a = [0u8; 3];
        reader.read_exact(&mut buf_a).unwrap();

        let mut buf_b = [0u8; 13];
        reader.read_exact(&mut buf_b).unwrap();

        let mut combined = Vec::new();
        combined.extend_from_slice(&buf_a);
        combined.extend_from_slice(&buf_b);

        // Reset and read 16
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut buf_full = [0u8; 16];
        reader.read_exact(&mut buf_full).unwrap();

        assert_eq!(&combined[..], &buf_full[..]);
    }
}
