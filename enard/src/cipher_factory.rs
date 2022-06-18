use std::marker::PhantomData;

use crate::error::EnardError;
use cipher::{IvSizeUser, KeyIvInit, KeySizeUser};
#[cfg(feature = "random")]
use rand::{CryptoRng, Rng};

type TResult<T> = Result<T, EnardError>;

/// Name a cipher implementation. Used for auto-implementing [`CipherFactory`].
pub trait CipherName {
    fn name() -> &'static [u8];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherMeta {
    pub name: &'static [u8],
    pub key_size: usize,
    pub iv_size: usize,
}
impl CipherMeta {
    /// Helper function to generate an IV for this cipher using a cryptographic RNG
    #[cfg(feature = "random")]
    pub fn generate_iv<R: CryptoRng + Rng>(&self, rng: &mut R) -> Vec<u8> {
        let mut iv = vec![0u8; self.iv_size];
        rng.fill_bytes(iv.as_mut_slice());
        iv
    }
}

/// Factory for creating [`crate::dyn_cipher::DynCipher`] objects.
///
/// When calling [`CipherFactory::create`] on concrete objects it generally
/// won't fail, however [`crate::dyn_cipher::BoxDynCipher`] may not support the
/// named cipher type, thus the builder construction *may* return an error.
///
/// ```rust
/// use chacha20::ChaCha20;
/// use enard::cipher_factory::*;
/// let key = [0x42; 32];
/// let nonce = [0x24; 12];
/// let cipher = ChaCha20::factory().create(b"", &key, &nonce).unwrap();
/// ```
///
pub trait CipherFactory<C> {
    /// Returns a [`CipherMeta`] representing the cipher with the given name,
    /// or an error if this factory doesn't support that cipher.
    fn get_meta(&self, name: &[u8]) -> TResult<CipherMeta>;

    /// Construct a new cipher with the given name, encryption key, and IV.
    ///
    /// Returns an error if this factory doesn't support the named cipher, or the
    /// cipher construction failed, such as due to incorrect key or iv lengths.
    /// If the name is an empty slice AND this factory only creates one type of
    /// cipher, it should ignore the name. See [`check_supported_name`].
    fn create(&self, name: &[u8], key: &[u8], iv: &[u8]) -> TResult<C>;
}

/// Default implementation of [`CipherFactory`] for concrete ciphers (e.g. ChaCha12).
///
pub struct SimpleCipherFactory<C> {
    phantom: PhantomData<C>,
}
impl<C> SimpleCipherFactory<C> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
impl<C> CipherFactory<C> for SimpleCipherFactory<C>
where
    C: CipherName + IvSizeUser + KeySizeUser + KeyIvInit,
{
    fn get_meta(&self, name: &[u8]) -> TResult<CipherMeta> {
        check_supported_name::<C>(name)?;
        Ok(CipherMeta {
            name: C::name(),
            key_size: C::key_size(),
            iv_size: C::iv_size(),
        })
    }

    fn create(&self, name: &[u8], key: &[u8], iv: &[u8]) -> TResult<C> {
        check_supported_name::<C>(name)?;
        Ok(C::new_from_slices(key, iv)?)
    }
}

/// If `name` is either the same `C`'s name or an empty slice, returns `()`,
/// otherwise returns an error.
///
/// ```rust
/// use chacha20::*;
/// use enard::cipher_factory::*;
/// assert!(check_supported_name::<ChaCha20>(b"ChaCha20").is_ok());
/// assert!(check_supported_name::<ChaCha20>(b"").is_ok());
/// assert!(check_supported_name::<ChaCha20>(b"ChaCha12").is_err());
/// ```
pub fn check_supported_name<C: CipherName>(name: &[u8]) -> TResult<()> {
    if name == b"" || name == C::name() {
        Ok(())
    } else {
        Err(EnardError::new_unsupported_encryption(name))
    }
}

/// Simple trait to allow easily getting the a factory object for the given cipher type.
///
/// Primarily this enabled implementing [`GetFactory::factory`] on foreign types. This
/// trait is auto-implemented for anything where [`SimpleCipherFactory`] is also implemented.
pub trait GetFactory<Cf> {
    fn factory() -> Cf;
}
impl<C> GetFactory<SimpleCipherFactory<C>> for C
where
    C: CipherName + IvSizeUser + KeySizeUser + KeyIvInit,
{
    fn factory() -> SimpleCipherFactory<C> {
        SimpleCipherFactory::new()
    }
}

macro_rules! impl_cipher_name {
    (for $type:ty) => {
        impl $crate::cipher_factory::CipherName for $type {
            fn name() -> &'static [u8] {
                stringify!($type).as_bytes()
            }
        }
    };
    (for $type:ty => $name:expr) => {
        impl $crate::cipher_factory::CipherName for $type {
            fn name() -> &'static [u8] {
                $name.as_bytes()
            }
        }
    };
}
pub(crate) use impl_cipher_name;
