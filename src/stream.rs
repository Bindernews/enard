use cipher::StreamCipherError;
use std::fmt::Debug;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write, BufRead};

use crate::{dyn_cipher::*, error::*};


/// Wraps anything that implements [`Seek`] limits it to the given section.
/// 
/// This is similar to [Take](`std::io::Take`) but implements additional traits
/// depending on the traits of the inner type.
pub struct SubSeek<S> {
    inner: S,
    /// Start of the subset (bytes)
    start: u64,
    /// Size of the subset (bytes)
    size: u64,
    /// Current position
    current: u64,
}
impl<S: Seek> SubSeek<S> {
    pub fn new(mut inner: S, start: u64, size: u64) -> io::Result<Self> {
        let current = inner.stream_position()? - start;
        Ok(Self { inner, start, size, current })
    }

    /// Get the inner [`Seek`]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Returns the number of bytes that may be read before this will return EOF.
    /// In case the limit is larger than a [usize], it will return `usize::MAX`.
    pub fn limit(&self) -> usize {
        usize::try_from(self.size - self.current).unwrap_or(usize::MAX)
    }
}
impl<S: Seek> Seek for SubSeek<S> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos_raw = match pos {
            SeekFrom::Current(rel) => self.current as i64 + rel,
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(rel) => self.size as i64 + rel,
        };
        if new_pos_raw < 0 || new_pos_raw > self.size as i64 {
            let msg = format!(
                "invalid seek to a negative or overflowing position: {:?}",
                pos
            );
            return Err(io::Error::new(ErrorKind::InvalidInput, msg));
        }
        // Note: if the seek fails, the stream will be in an invalid state because
        // `current` will be incorrect, however that's fine as it shouldn't be used
        // after an IO failure anyways.
        self.current = new_pos_raw as u64;
        self.inner.seek(SeekFrom::Start(self.start + self.current))?;
        Ok(self.current)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.current)
    }
}

impl<S: Seek + Read> Read for SubSeek<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Make sure we properly limit the conversion in case usize < u64
        let max = self.limit().min(buf.len());
        if max == 0 {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "SubSeek EOF"))
        } else {
            self.inner.read(&mut buf[0..max])
        }
    }
}

impl<S: Seek + BufRead> BufRead for SubSeek<S> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let limit = self.limit();
        let buf = self.inner.fill_buf()?;
        let max = limit.min(buf.len());
        Ok(&buf[0..max])
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt.min(self.limit()))
    }
}

impl<S: Seek + Write> Write for SubSeek<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Wraps an internal reader (usually [`std::fs::File`]) and implements
/// [`Read`] and [`Seek`], decrypting the contents of the internal reader on the fly.
#[derive(Debug)]
pub struct CipherRead<R: Read + Seek, C: DynCipher> {
    /// Wrapped reader
    inner: R,
    /// Cipher used for decryption
    cipher: C,
}
impl<R, C> CipherRead<R, C>
where
    R: Read + Seek,
    C: DynCipher,
{
    /// Construct a new [`CipherReadStream`] which decrypts content from
    /// `reader` as data is read.
    pub fn new(mut reader: R, mut cipher: C) -> Result<Self, EnardError> {
        reader.seek(SeekFrom::Start(0))?;
        cipher.try_seek(0).map_err(cipher_to_io_error)?;
        Ok(Self {
            inner: reader,
            cipher,
        })
    }

    /// Extract the wrapped reader and cipher from this object
    pub fn into_inner(self) -> (R, C) {
        (self.inner, self.cipher)
    }
}

impl<R, C> Read for CipherRead<R, C>
where
    R: Read + Seek,
    C: DynCipher,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Read the data into the destination buffer
        let n = self.inner.read(buf)?;
        // decrypt buffer data in-place
        self.cipher
            .try_apply_keystream(&mut buf[0..n])
            .map_err(cipher_to_io_error)?;
        Ok(n)
    }
}

impl<R, C> Seek for CipherRead<R, C>
where
    R: Read + Seek,
    C: DynCipher,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Note: if the cipher seek fails, the stream will be in an invalid state.
        // However seek failing is considered an error, so this shouldn't be used after a failure.
        let new_pos = self.inner.seek(pos)?;
        self.cipher.try_seek(new_pos).map_err(cipher_to_io_error)?;
        Ok(new_pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        self.inner.stream_position()
    }
}

/// Wraps a [`Write`] and a [`DynCipher`] to integrate encryption with Rust's
/// standard IO library.
#[derive(Debug)]
pub struct CipherWriteStream<W, C> {
    inner: W,
    cipher: C,
}
impl<W, C> CipherWriteStream<W, C>
where
    W: Write,
    C: DynCipher,
{
    /// Construct a new [`CipherWriteStream`] with the given inner writer
    /// and cipher.
    /// 
    /// `inner` must be positioned at the start of the cipher stream when
    /// passed into this function.
    pub fn new(
        inner: W,
        cipher: C,
    ) -> Self {
        Self {
            inner,
            cipher,
        }
    }

    /// Extracts the inner writer and cipher
    pub fn into_inner(self) -> (W, C) {
        (self.inner, self.cipher)
    }
}

impl<W, C> Write for CipherWriteStream<W, C>
where
    W: Write,
    C: DynCipher,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        const B_SIZE: usize = 256;
        let mut crypt_buf = [0u8; B_SIZE];
        // Encrypt each part of the input using the cipher and then write it out
        for chunk in buf.chunks(crypt_buf.len()) {
            let cbuf = &mut crypt_buf[0..B_SIZE.min(chunk.len())];
            cbuf.clone_from_slice(chunk);
            self.cipher.try_apply_keystream(cbuf).map_err(cipher_to_io_error)?;
            self.inner.write_all(cbuf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W, C> Seek for CipherWriteStream<W, C>
where
    W: Write + Seek,
    C: DynCipher,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = self.inner.seek(pos)?;
        self.cipher.try_seek(new_pos).map_err(cipher_to_io_error)?;
        Ok(new_pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        self.inner.stream_position()
    }
}

/// Helper to convert [`StreamCipherError`]s to [`io::Error`]s.
fn cipher_to_io_error(e: StreamCipherError) -> io::Error {
    io::Error::new(ErrorKind::Other, format!("{:?}", e))
}


