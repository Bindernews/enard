use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use cipher::StreamCipherError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt::Debug;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::{collections::HashMap, marker::PhantomData};

use crate::{cipher_factory::*, dyn_cipher::*, error::*};

pub const MAGIC: &[u8; 6] = b"\x03ENARD";
pub const DATA_ALIGNMENT: usize = 8;
/// Start of the header data relative to the file start.
/// MAGIC + u16 + u32 + u64
const HEADER_START: usize = 6 + 2 + 4 + 8;

/// Map of metadata keys to values
pub type MetaMap = HashMap<Vec<u8>, Vec<u8>>;
/// Hmac type for format v1
type HmacV1 = Hmac<Sha256>;

/// Wraps an internal reader (usually [`std::fs::File`]) and implements
/// [`Read`] and [`Seek`], decrypting the contents of the internal reader on the fly
/// and acting as a reader for only the "wrapped" contents of the enard file.
///
/// It's *highly* recommended to ensure the inner reader is buffered (e.g. using
/// [`std::io::BufReader`]) as it will usually improve performance significantly.
///
pub struct EnardReader<R: Read + Seek, C: DynCipher> {
    inner: R,
    cipher: C,
    /// Offset in the inner reader where the data section starts
    data_start: u64,
    /// Size in bytes of the data section
    data_size: u64,
    /// Current offset in the data for seek purposes
    current: u64,
    meta: MetaMap,
}
impl<R, C> EnardReader<R, C>
where
    R: Read + Seek,
    C: DynCipher,
{
    pub fn new<Cf: CipherFactory<C>>(
        reader: R,
        factory: Cf,
        key: &[u8],
    ) -> Result<Self, EnardError> {
        EnardBuilder::new(reader, factory, key).build()
    }

    /// Access the metadata from the enard file
    pub fn meta(&self) -> &HashMap<Vec<u8>, Vec<u8>> {
        &self.meta
    }

    /// Unwraps this [`EnardReader`], returning the underlying writer.
    pub fn into_inner(self) -> R {
        self.inner
    }
}
impl<R> EnardReader<R, BoxDynCipher>
where
    R: Read + Seek,
{
    /// Create a new [`EnardReader`] that will determine the cipher based on the metadata in
    /// the enard file.
    pub fn new_boxed(reader: R, key: &[u8]) -> Result<Self, EnardError> {
        Self::new(reader, BoxDynCipher::factory(), key)
    }
}

// Manually implement debug for user convenience and to ensure we don't leak sensitive information
// if a reader gets printed.
impl<R, C> Debug for EnardReader<R, C>
where
    R: Read + Seek + Debug,
    C: DynCipher,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnardReader")
            .field("inner", &self.inner)
            .field("cipher", &self.cipher.get_name())
            .field("data_start", &self.data_start)
            .field("data_size", &self.data_size)
            .field("current", &self.current)
            .field("meta", &self.meta)
            .finish()
    }
}

impl<R, C> Read for EnardReader<R, C>
where
    R: Read + Seek,
    C: DynCipher,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Determine the maximum number of bytes we're allowed to read
        let limit = buf.len().min((self.data_size - self.current) as usize);
        // Read the data into the destination buffer
        let n = self.inner.read(&mut buf[0..limit])?;
        // update current position
        self.current += n as u64;
        // decrypt buffer data in-place
        self.cipher
            .try_apply_keystream(&mut buf[0..n])
            .map_err(cipher_to_io_error)?;
        // println!("current = {}, n = {}, cipher_pos = {} -> {}", self.current, n, cipher_pos_before, cipher_pos);
        Ok(n)
    }
}

impl<R, C> Seek for EnardReader<R, C>
where
    R: Read + Seek,
    C: DynCipher,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos_raw = match pos {
            SeekFrom::Current(rel) => self.current as i64 + rel,
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(rel) => self.data_size as i64 + rel,
        };
        if new_pos_raw < 0 || new_pos_raw > self.data_size as i64 {
            let msg = format!(
                "invalid seek to a negative or overflowing position: {:?}",
                pos
            );
            return Err(io::Error::new(ErrorKind::InvalidInput, msg));
        }
        // Note: if the cipher seek fails, the stream will be in an invalid state.
        // However seek failing is considered an error, so this shouldn't be used after a failure.
        let new_pos = new_pos_raw as u64;
        self.inner
            .seek(SeekFrom::Start(self.data_start + new_pos))?;
        self.cipher.try_seek(new_pos).map_err(cipher_to_io_error)?;
        self.current = new_pos;
        Ok(new_pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.current)
    }
}

fn cipher_to_io_error(e: StreamCipherError) -> io::Error {
    io::Error::new(ErrorKind::Other, format!("{:?}", e))
}

/// Reader-builder that parses the enard format and returns a new [`EnardReader`].
pub(crate) struct EnardBuilder<R, C, Cf> {
    reader: R,
    factory: Cf,
    key: Vec<u8>,
    phantom: PhantomData<C>,
}
impl<R, C, Cf> EnardBuilder<R, C, Cf>
where
    R: Read + Seek,
    C: DynCipher,
    Cf: CipherFactory<C>,
{
    pub fn new(reader: R, factory: Cf, key: &[u8]) -> Self {
        let key = Vec::from(key);
        let phantom = PhantomData;
        Self {
            reader,
            factory,
            key,
            phantom,
        }
    }

    pub fn build(mut self) -> Result<EnardReader<R, C>, EnardError> {
        let mut magic_buf = [0u8; MAGIC.len()];
        self.reader.read_exact(&mut magic_buf)?;
        if &magic_buf != MAGIC {
            return Err(EnardError::new_invalid_magic(MAGIC, &magic_buf));
        }

        let version = self.reader.read_u16::<LE>()?;
        match version {
            1 => self.read_v1(),
            _ => Err(EnardError::UnsupportedVersion { version }),
        }
    }

    fn read_v1(mut self) -> Result<EnardReader<R, C>, EnardError> {
        // First is the header size, which includes metadata about the encryption scheme.
        // This SHOULD be padded to make the data 8-byte aligned, but it's not required.
        let header_size = self.reader.read_u32::<LE>()?;
        // Next comes the data size. This is useful both to make sure we don't
        // read outside the data, but also to easily jump to the MAC which is at the file end.
        // Sure this COULD be a varint, but this is easier and helps keep alignment.
        let data_size = self.reader.read_u64::<LE>()?;
        // We'll need to know the header position for later
        let header_start = self.reader.stream_position()?;
        // Calculate the start of the data given
        let data_start = header_start + header_size as u64;
        // Verify the MAC
        Self::verify_mac(&mut self.reader, &self.key, header_size as u64 + data_size)?;
        // Now jump back and read the header
        self.reader.seek(SeekFrom::Start(header_start))?;

        // Read cipher type
        let cipher_kind = Self::read_u8_block(&mut self.reader)?;
        // Read cipher iv (aka nonce), may be empty
        let cipher_iv = Self::read_u8_block(&mut self.reader)?;
        // Try to create the cipher
        let cipher = self.factory.create(&cipher_kind, &self.key, &cipher_iv)?;

        // Now we can read additional metadata
        let meta = Self::read_meta_blocks(&mut self.reader, header_size as u64)?;
        // Seek back to the start of the data (avoid padding)
        self.reader.seek(SeekFrom::Start(data_start))?;

        // And FINALLY we can construct the actual object
        Ok(EnardReader {
            inner: self.reader,
            cipher,
            data_start,
            data_size,
            current: 0,
            meta,
        })
    }

    fn verify_mac<R2: Read>(mut reader: R2, key: &[u8], data_size: u64) -> Result<(), EnardError> {
        let mut rd = (&mut reader).take(data_size);
        let mut mac = HmacV1::new_from_slice(key)?;
        io::copy(&mut rd, &mut mac)?;
        // Assume the mac tag is right after the data
        let mut tag_buf = [0u8; 32];
        reader.read_exact(&mut tag_buf)?;
        mac.verify_slice(&tag_buf)?;
        Ok(())
    }

    /// Allocates a [`Vec<u8>`] with the given size, reads that many bytes
    /// into it, and returns the vec.
    pub fn read_vec<R2: Read>(mut reader: R2, size: usize) -> io::Result<Vec<u8>> {
        let mut b_buf = vec![0u8; size];
        reader.read_exact(&mut b_buf)?;
        Ok(b_buf)
    }

    pub fn read_u8_block<R2: Read>(mut reader: R2) -> io::Result<Vec<u8>> {
        let size = reader.read_u8()? as usize;
        Self::read_vec(reader, size)
    }

    pub fn read_u16_block<R2: Read>(mut reader: R2, limit: usize) -> Result<Vec<u8>, EnardError> {
        let size = reader.read_u16::<LE>()? as usize;
        if size > limit {
            return Err(EnardError::new_block_size(size as u64, limit as u64));
        }
        Ok(Self::read_vec(reader, size)?)
    }

    pub fn read_meta_blocks<R2: Read>(
        mut reader: R2,
        max_size: u64,
    ) -> Result<MetaMap, EnardError> {
        let mut result = HashMap::new();
        let count = reader.read_u8()? as usize;
        for _ in 0..count {
            // Read the key
            let key = Self::read_u8_block(&mut reader)?;
            // Read the value, with a more specific error message to be helpful
            let value = Self::read_u16_block(&mut reader, max_size as usize)?;
            // Put into hashmap
            result.insert(key, value);
        }
        Ok(result)
    }
}

/// Wraps a [`Write`] + [`Seek`] to produce new encrypted enard files.
/// 
/// When creating a new file, first call [write_header](EnardWriter::write_header)
pub struct EnardWriter<W, C> {
    inner: W,
    cipher: C,
    iv: Vec<u8>,
    mac: Option<HmacV1>,
    start_pos: u64,
    meta: Option<MetaMap>,
    header_size: u32,
    crypt_buf: Vec<u8>,
}
impl<'a, W, C> EnardWriter<W, C>
where
    W: Write + Seek,
    C: DynCipher,
{
    pub fn new<Cf: CipherFactory<C>>(
        inner: W,
        factory: Cf,
        name: &[u8],
        key: &[u8],
        iv: &[u8],
        meta: MetaMap,
    ) -> Result<Self, EnardError> {
        let cipher = factory.create(name, key, iv)?;
        Ok(Self {
            inner,
            cipher,
            iv: Vec::from(iv),
            mac: Some(HmacV1::new_from_slice(key)?),
            start_pos: 0,
            meta: Some(meta),
            header_size: 0,
            crypt_buf: vec![0u8; 256],
        })
    }

    /// Writes the header, the contents of `rd`, and then calls `finish()`,
    /// returning the total number of bytes written.
    ///
    pub fn write_complete(&mut self, mut rd: impl Read) -> io::Result<u64> {
        let mut n = self.write_header()? as u64;
        n += io::copy(&mut rd, self)?;
        n += self.finish()? as u64;
        Ok(n)
    }

    /// Writes the header of an enard file, returns the number of bytes written.
    /// This should be called immediately after creating a new [`EnardWriter`].
    pub fn write_header(&mut self) -> io::Result<usize> {
        self.write_header_v1()?;
        Ok(HEADER_START + self.header_size as usize)
    }

    /// Finalize writing the file and clean up internal resources.
    /// 
    /// After calling this method, [`EnardWriter::write`] will panic.
    /// [`EnardWriter::into_inner`] and some other methods will still work though.
    pub fn finish(&mut self) -> io::Result<usize> {
        self.finish_v1()
    }

    /// Extracts the inner writer
    pub fn into_inner(self) -> W {
        self.inner
    }

    fn write_header_v1(&mut self) -> io::Result<()> {
        // See `EnardBuilder::read_v1` for format details

        // Store the start position for when we need to re-write the sizes
        self.start_pos = self.inner.stream_position()?;

        // Write magic and version
        self.inner.write_all(MAGIC)?;
        self.inner.write_u16::<LE>(1)?;
        // Write placeholders for header and data sizes
        self.inner.write_all(&[0u8; 4 + 8])?;
        // Track the header size
        let mut hs = 0;
        // Write required blocks
        let name = self.cipher.get_name();
        let iv = self.iv.clone();
        hs += self.write_u8_block(name)?;
        hs += self.write_u8_block(&iv)?;
        // Write meta blocks
        hs += self.write_meta_blocks()?;
        // Pad to 8-byte alignment
        let data_start = hs + HEADER_START;
        let padding = (DATA_ALIGNMENT - (data_start % DATA_ALIGNMENT)) % DATA_ALIGNMENT;
        let pad_buf = [0u8; DATA_ALIGNMENT];
        self.mac_write(&pad_buf[0..padding])?;
        hs += padding;
        self.header_size = hs as u32;

        Ok(())
    }

    /// Write a slice to the inner writer and also add the slice to the MAC.
    fn mac_write(&mut self, b: &[u8]) -> io::Result<()> {
        self.inner.write_all(b)?;
        self.mac.as_mut().unwrap().update(b);
        Ok(())
    }

    fn finish_v1(&mut self) -> io::Result<usize> {
        let data_start = self.start_pos + (self.header_size + HEADER_START as u32) as u64;
        let data_len = self.inner.stream_position()? - data_start;
        // Write the MAC tag
        let tag = self.mac.take().unwrap().finalize_reset().into_bytes();
        self.inner.write_all(&tag)?;
        // Save the end position
        let end_pos = self.inner.stream_position()?;
        // Update original header and data sizes
        self.inner.seek(SeekFrom::Start(self.start_pos + 6 + 2))?;
        self.inner.write_u32::<LE>(self.header_size)?;
        self.inner.write_u64::<LE>(data_len)?;
        // Jump back to the end
        self.inner.seek(SeekFrom::Start(end_pos))?;
        self.flush()?;
        Ok(tag.len())
    }

    fn write_u8_block(&mut self, block: &[u8]) -> io::Result<usize> {
        Self::block_size_check(block, u8::MAX as usize)?;
        let blen = block.len() as u8;
        self.mac_write(&blen.to_le_bytes())?;
        self.mac_write(block)?;
        Ok(1 + block.len())
    }

    fn block_size_check(block: &[u8], size: usize) -> io::Result<()> {
        if block.len() >= size {
            let msg = format!("block size must be 0-{}, is {}", size - 1, block.len());
            Err(io::Error::new(ErrorKind::Other, msg))
        } else {
            Ok(())
        }
    }

    fn write_meta_blocks(&mut self) -> io::Result<usize> {
        // Move meta out of self so we can safely mutate self.
        // We'll put it back at the end.
        let meta = self.meta.take().unwrap();
        // Track how many bytes we're writing
        let mut n = 0;
        // Write meta count
        let count = meta.len() as u8;
        self.mac_write(&count.to_le_bytes())?;
        n += 1;

        for (key, val) in meta.iter() {
            Self::block_size_check(key, u8::MAX as usize)?;
            Self::block_size_check(val, u16::MAX as usize)?;
            let k_len = key.len() as u8;
            let v_len = val.len() as u16;
            // Write data
            self.mac_write(&k_len.to_le_bytes())?;
            self.mac_write(key)?;
            self.mac_write(&v_len.to_le_bytes())?;
            self.mac_write(val)?;
            // Update size
            n += 1 + key.len() + 2 + val.len();
        }
        // Put the metadata back
        self.meta = Some(meta);
        Ok(n)
    }
}

impl<W, C> Write for EnardWriter<W, C>
where
    W: Write + Seek,
    C: DynCipher,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let b_size = self.crypt_buf.len();
        // Encrypt each part of the input using the cipher and then write it out
        for chunk in buf.chunks(b_size) {
            let cbuf = &mut self.crypt_buf[0..b_size.min(chunk.len())];
            cbuf.clone_from_slice(chunk);
            self.cipher
                .try_apply_keystream(cbuf)
                .map_err(cipher_to_io_error)?;
            self.inner.write_all(cbuf)?;
            self.mac.as_mut().unwrap().update(cbuf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl<W, C> Debug for EnardWriter<W, C>
where
    W: Write + Seek + Debug,
    C: DynCipher,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnardWriter")
            .field("inner", &self.inner)
            .field("cipher", &self.cipher.get_name())
            .field("iv", &self.iv)
            .field("mac", &self.mac)
            .field("start_pos", &self.start_pos)
            .field("meta", &self.meta)
            .field("header_size", &self.header_size)
            .field("crypt_buf", &self.crypt_buf)
            .finish()
    }
}
