use cipher::consts::{U0, U32};
use cipher::generic_array::GenericArray;
use cipher::*;

use crate::cipher_factory::CipherName;

/// Cipher implementation that just copies data without encrypting it.
///
/// This is useful for testing purposes as well as being able to verify
/// an archive without actually encrypting it.
#[derive(Debug)]
pub struct NothingCipher {
    pos: u32,
}
impl NothingCipher {
    pub fn new() -> Self {
        Self { pos: 0 }
    }
}
impl Default for NothingCipher {
    fn default() -> Self {
        Self::new()
    }
}
impl StreamCipher for NothingCipher {
    fn try_apply_keystream_inout(
        &mut self,
        buf: cipher::inout::InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        let xor_buf: GenericArray<u8, U32> = Default::default();
        let (chunks, mut tail) = buf.into_chunks::<U32>();
        for mut chunk in chunks {
            chunk.xor_in2out(&xor_buf);
        }
        let n = tail.len();
        tail.xor_in2out(&xor_buf[0..n]);
        Ok(())
    }
}
impl StreamCipherSeek for NothingCipher {
    fn try_current_pos<T: cipher::SeekNum>(&self) -> Result<T, OverflowError> {
        let block = self.pos >> 2;
        let byte = (self.pos % 4) as u8;
        T::from_block_byte(block, byte, 4)
    }

    fn try_seek<T: cipher::SeekNum>(&mut self, pos: T) -> Result<(), StreamCipherError> {
        let (a, b) = pos.into_block_byte::<u64>(4)?;
        self.pos = a as u32 + b as u32;
        Ok(())
    }
}
impl CipherName for NothingCipher {
    fn name() -> &'static [u8] {
        b""
    }
}
impl IvSizeUser for NothingCipher {
    type IvSize = U0;
    fn iv_size() -> usize {
        0
    }
}
impl KeySizeUser for NothingCipher {
    type KeySize = U0;
    fn key_size() -> usize {
        0
    }
}
impl KeyIvInit for NothingCipher {
    fn new(_key: &Key<Self>, _iv: &Iv<Self>) -> Self {
        Self::new()
    }
}
