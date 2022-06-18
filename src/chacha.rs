use crate::cipher_factory::impl_cipher_name;
use chacha20::*;

impl_cipher_name! { for ChaCha8 }
impl_cipher_name! { for ChaCha12 }
impl_cipher_name! { for ChaCha20 }
