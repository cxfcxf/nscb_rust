use std::io;

#[derive(Debug, thiserror::Error)]
pub enum NscbError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid magic: expected {expected}, got {got}")]
    InvalidMagic { expected: String, got: String },

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Hash mismatch for {file}")]
    HashMismatch { file: String },

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, NscbError>;
