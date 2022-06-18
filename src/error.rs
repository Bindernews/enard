use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnardError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    InvalidBufferSize(#[from] digest::InvalidBufferSize),
    #[error(transparent)]
    MacError(#[from] digest::MacError),
    #[error("invalid key or iv length")]
    InvalidLength,
    #[error("unsupported encryption method '{kind}'")]
    UnsupportedEncryption { kind: Box<str> },
    #[error("expected magic header '{exp}' but found '{found}'")]
    InvalidMagic { exp: Box<str>, found: Box<str> },
    #[error("unsupported format version {version}, supported versions: 1")]
    UnsupportedVersion { version: u16 },
    #[error("block too large, size: {size}, limit: {limit}")]
    BlockTooLarge { size: u64, limit: u64 },
}

impl EnardError {
    pub(crate) fn new_unsupported_encryption(kind_buf: &[u8]) -> Self {
        let kind = u8_to_box_str(kind_buf);
        Self::UnsupportedEncryption { kind }
    }

    pub(crate) fn new_invalid_magic(exp: &[u8], found: &[u8]) -> Self {
        let exp = u8_to_box_str(exp);
        let found = u8_to_box_str(found);
        Self::InvalidMagic { exp, found }
    }

    pub(crate) fn new_block_size(size: u64, limit: u64) -> Self {
        Self::BlockTooLarge { size, limit }
    }
}
impl From<crypto_common::InvalidLength> for EnardError {
    fn from(_: crypto_common::InvalidLength) -> Self {
        Self::InvalidLength
    }
}

fn u8_to_box_str(slice: &[u8]) -> Box<str> {
    slice.escape_ascii().to_string().into_boxed_str()
}
