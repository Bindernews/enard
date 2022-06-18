use crate::cipher_factory::*;
use crate::error::EnardError;
use crate::nothing_cipher::NothingCipher;
use cipher::{IvSizeUser, KeySizeUser, StreamCipher, StreamCipherError, StreamCipherSeek};

type TResult<T> = Result<T, EnardError>;

/// Object-safe wrapper around [`StreamCipherSeek`].
pub trait DynCipherCore {
    /// Try to seek to the given position in the key stream
    fn try_seek(&mut self, new_pos: u64) -> Result<(), StreamCipherError>;

    /// Returns the current position in the key stream
    fn current_pos(&self) -> u64;

    /// Returns the ascii name of this cipher
    fn get_name(&self) -> &'static [u8];

    /// IV size in bytes
    fn iv_size(&self) -> usize;

    /// Key size in bytes
    fn key_size(&self) -> usize;
}
impl<T> DynCipherCore for T
where
    T: StreamCipherSeek + CipherName + IvSizeUser + KeySizeUser,
{
    fn try_seek(&mut self, new_pos: u64) -> Result<(), StreamCipherError> {
        self.try_seek(new_pos)
    }

    fn current_pos(&self) -> u64 {
        self.current_pos::<u64>()
    }

    fn get_name(&self) -> &'static [u8] {
        T::name()
    }

    fn iv_size(&self) -> usize {
        T::iv_size()
    }

    fn key_size(&self) -> usize {
        T::key_size()
    }
}

/// Object-safe interface for seekable stream ciphers
pub trait DynCipher: StreamCipher + DynCipherCore + Send {}
impl<T: StreamCipher + DynCipherCore + Send> DynCipher for T {}

/// Wraps a [`Box<dyn DynCipher>`] and also provides a [`CipherFactory`] which dynamically
/// selects the cipher implementation based on the provided name.
///
pub struct BoxDynCipher(pub Box<dyn DynCipher>);
impl GetFactory<BoxDynCipherFactory> for BoxDynCipher {
    fn factory() -> BoxDynCipherFactory {
        BoxDynCipherFactory
    }
}
impl StreamCipher for BoxDynCipher {
    #[inline]
    fn try_apply_keystream_inout(
        &mut self,
        buf: cipher::inout::InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        self.0.try_apply_keystream_inout(buf)
    }
}
impl DynCipherCore for BoxDynCipher {
    delegate::delegate! {
        to self.0 {
            fn try_seek(&mut self, new_pos: u64) -> Result<(), StreamCipherError>;
            fn current_pos(&self) -> u64;
            fn get_name(&self) -> &'static [u8];
            fn iv_size(&self) -> usize;
            fn key_size(&self) -> usize;
        }
    }
}

pub struct BoxDynCipherFactory;
impl CipherFactory<BoxDynCipher> for BoxDynCipherFactory {
    fn get_meta(&self, name: &[u8]) -> TResult<CipherMeta> {
        macro_rules! name_check {
            ($type:ty) => {
                if name == <$type>::name() {
                    return <$type>::factory().get_meta(name);
                }
            };
        }

        name_check! { NothingCipher }
        #[cfg(feature = "chacha20")]
        {
            use chacha20::*;
            name_check! { ChaCha8 }
            name_check! { ChaCha12 }
            name_check! { ChaCha20 }
        }
        // If that all fails, error out
        Err(EnardError::new_unsupported_encryption(name))
    }

    fn create(&self, name: &[u8], key: &[u8], iv: &[u8]) -> TResult<BoxDynCipher> {
        macro_rules! w_create {
            ($type:ty) => {
                if name == <$type>::name() {
                    let cipher = <$type>::factory().create(name, key, iv)?;
                    return Ok(BoxDynCipher(Box::new(cipher)));
                }
            };
        }

        w_create! { NothingCipher }
        #[cfg(feature = "chacha20")]
        {
            use chacha20::*;
            w_create! { ChaCha8 }
            w_create! { ChaCha12 }
            w_create! { ChaCha20 }
        }
        // If that all fails, error out
        Err(EnardError::new_unsupported_encryption(name))
    }
}
