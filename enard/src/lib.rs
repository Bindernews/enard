//! Enard is an encrypted container format and associated library with the goal
//! of enabling on-the-fly game asset decryption.
//!
//!
pub mod cipher_factory;
mod core;
mod dyn_cipher;
mod error;
pub mod nothing_cipher;

pub use crate::core::{EnardReader, EnardWriter, MetaMap};
pub use crate::dyn_cipher::{BoxDynCipher, DynCipher, DynCipherCore};
pub use error::EnardError;

#[cfg(feature = "chacha")]
mod chacha;

#[cfg(test)]
mod tests {
    use crate::cipher_factory::{CipherName, GetFactory};
    use crate::dyn_cipher::BoxDynCipher;
    use chacha20::ChaCha12;
    use std::fs;
    use std::io::{Cursor, Read};

    use super::error::*;
    use super::*;

    const KB: usize = 1024;
    const KEY1: [u8; 32] = [0x42u8; 32];
    const NONCE: [u8; 12] = [0x24u8; 12];

    fn read_all(mut rd: impl Read) -> Vec<u8> {
        let mut buf = Vec::new();
        rd.read_to_end(&mut buf).unwrap();
        buf
    }

    fn compare_bufs(a: &[u8], exp: &[u8]) {
        assert_eq!(a.len(), exp.len());
        for i in 0..a.len() {
            if a[i] != exp[i] {
                assert!(false, "index {} was {}, expected {}", i, a[i], exp[i]);
            }
        }
    }

    #[test]
    fn test_roundtrip() {
        const TEST_DATA_SIZE: usize = 10000;
        let mut out = vec![0u8; TEST_DATA_SIZE + 1000];
        let data = vec![0x42; TEST_DATA_SIZE];
        let n = || -> Result<usize, EnardError> {
            let inner = Cursor::new(&mut out);
            let n = EnardWriter::new(
                inner,
                BoxDynCipher::factory(),
                ChaCha12::name(),
                &KEY1,
                &NONCE,
                MetaMap::new(),
            )?
            .write_complete(data.as_slice())?;
            Ok(n as usize)
        }()
        .unwrap();
        out.resize(n, 0u8);
        let rd = EnardReader::new_boxed(Cursor::new(&mut out), &KEY1).unwrap();
        // Check to make sure it came out right
        let dst_buf = read_all(rd);
        compare_bufs(&dst_buf, &data);
    }

    #[test]
    fn roundtrip_in_memory_zip() {
        let in_path = "./arrow_up.zip";
        let iv = [77u8; 12];

        let src_buf = fs::read(in_path).unwrap();
        let mut tmp_buf = vec![0u8; 200 * KB];
        let mut en_wr = EnardWriter::new(
            Cursor::new(&mut tmp_buf),
            BoxDynCipher::factory(),
            ChaCha12::name(),
            &KEY1,
            &iv,
            MetaMap::new(),
        )
        .unwrap();
        let n = en_wr.write_complete(Cursor::new(&src_buf)).unwrap();
        tmp_buf.resize(n as usize, 0u8);

        let rd = EnardReader::new(
            // io::BufReader::new(Cursor::new(&tmp_buf)), BoxDynCipher::factory(), &KEY1
            Cursor::new(&tmp_buf),
            BoxDynCipher::factory(),
            &KEY1,
        )
        .unwrap();
        let dst_buf = read_all(rd);
        compare_bufs(&dst_buf, &src_buf);
    }
}
