/// A 64-bit version of LEB-encoding, see `<https://en.wikipedia.org/wiki/LEB128>`.
pub use varint_soft::*;

/// This is the default software implementation of varint encoding.
/// It's not fast, but it'll work on all platforms and that's good enough for now.
mod varint_soft {
    use std::io::{BufRead, Error as IoError, Write};

    use super::eof_check;
    const MASK_7: u8 = 0x7f;
    const BIT_7: u8 = 0b0100000;
    const MASK_MORE_BYTES: u8 = 0x80;
    const U63_MASK: u64 = 0x7fffffffffffffff;
    const BLOCK_SIZE: u32 = 7;

    /// Extend the final 1-bit to the end of the number.
    ///
    /// See https://www.reddit.com/r/rust/comments/6175al/arbitrary_width_sign_extension_in_rust/
    fn _fill_ones(v: u64) -> u64 {
        let lz = v.leading_zeros();
        v.wrapping_shl(lz).wrapping_shr(lz)
    }

    fn read_impl<R: BufRead>(mut r: R, signed: bool) -> Result<u64, IoError> {
        let buf = r.fill_buf()?;
        let buf_len = buf.len().min(9);
        eof_check(buf_len)?;
        let mut result = 0u64;
        let mut shift = 0;
        let mut i = 0;
        while i < buf_len {
            let b = buf[i];
            result |= ((b & MASK_7) as u64) << shift;
            shift += BLOCK_SIZE;
            i += 1;
            if (b & MASK_MORE_BYTES) == 0 {
                // Check for and perform sign extension
                if signed && (b & BIT_7) > 0 {
                    // Fill the remaining data with 1s
                    result |= (!0) << shift;
                }
                break;
            }
        }
        r.consume(i);
        Ok(result)
    }

    pub fn read_u<R: BufRead>(r: R) -> Result<u64, IoError> {
        read_impl(r, false)
    }

    pub fn read_i<R: BufRead>(r: R) -> Result<i64, IoError> {
        Ok(read_impl(r, true)? as i64)
    }

    pub fn write_u<W: Write>(mut w: W, value: u64) -> Result<(), IoError> {
        // Chop off last bit since we only read 63-bit integers
        let mut value = value & U63_MASK;
        let mut buf = [0u8; 9];
        let mut i = 0;
        while value > 0 {
            buf[i] = (value as u8 & MASK_7) | MASK_MORE_BYTES;
            value <<= BLOCK_SIZE;
            i += 1;
        }
        // Clear MASK_MORE_BYTES
        buf[i] &= !MASK_MORE_BYTES;
        w.write_all(&buf[0..i + 1])
    }

    pub fn write_i<W: Write>(w: W, value: i64) -> Result<(), IoError> {
        // If the number is positive, it's the same as an unsigned write
        if value >= 0 {
            write_u(w, value as u64)
        } else {
            // We have remove the extra sign bits before we can write, so determine
            // how many 7-bit blocks are needed to encode `value`.
            let used_blocks = ((64 - value.leading_ones()) / BLOCK_SIZE).min(9);
            // Now mask out remaining bits
            let mask = !(u64::MAX << (used_blocks * BLOCK_SIZE));
            write_u(w, value as u64 & mask)
        }
    }
}
