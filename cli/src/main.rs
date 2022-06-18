use std::fs::File;
use std::io::{self, BufRead, Read, Seek, Write};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, ensure, Error};
use clap::Parser;
use enard::cipher_factory::{CipherFactory, GetFactory};
use enard::{BoxDynCipher, EnardReader, EnardWriter, MetaMap};
use log::{log, trace, Level, LevelFilter};
use rand::prelude::*;

pub const ENV_VAR_KEY: &'static str = "ENARD_KEY";

/// CLI tool for for the enard encryption container format/library.
/// (https://github.com/bindernews/enard)
///
/// By default the encryption key is passed using the `ENARD_KEY` environment
/// variable. This may be overriden with either --key or --keyfile. If a key
/// starts with "0x" it will be decoded as a hex string, otherwise it will
/// be interpreted as bytes and treated as the key directly.
#[derive(Debug, Parser)]
#[clap(author, version, about, name = "enard")]
struct CliArgs {
    /// Input file or `-` to read from stdin
    #[clap(value_parser)]
    input: String,

    /// Output file name or `-` to write to stdout
    #[clap(value_parser)]
    output: String,

    /// Provide the cipher key on the command line (not very safe)
    ///
    /// Normally the key is passed via the environment variable ENARD_KEY
    #[clap(long, value_parser)]
    key: Option<String>,

    /// Read the cipher key from a file instead of the environment variable `ENARD_KEY`
    #[clap(long, value_parser)]
    keyfile: Option<PathBuf>,

    // /// Don't delete the input file
    // #[clap(short, long, action)]
    // keep: bool,
    /// Encrypt the input
    ///
    /// When encrypting to stdout the output will be written to a temporary
    /// file first, then forwarded to stdout.
    #[clap(short, long, action)]
    encrypt: bool,

    /// Decrypt the input
    ///
    /// When decrypting a file from stdin, the input will be buffered in memory
    /// because it's necessary to be able to jump around in the file. When
    /// decrypting large files please store them on disk.
    #[clap(short, long, action)]
    decrypt: bool,

    /// Encryption cipher to use
    #[clap(long, value_enum, action, default_value_t)]
    cipher: SupportedCiphers,

    /// Set the logging level
    #[clap(long, value_enum, action, default_value_t)]
    log: ArgLogLevel,

    /// Metadata to add when encrypting a file, may be specified multiple times
    #[clap(short, long, value_parser)]
    meta: Vec<MetaValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetaValue {
    key: String,
    value: String,
}
impl FromStr for MetaValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((k, v)) = s.split_once("=") {
            Ok(Self {
                key: k.to_string(),
                value: v.to_string(),
            })
        } else {
            Err(anyhow!("\"{}\" must be in the format <KEY>=<VALUE>", s))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ArgLogLevel {
    Off,
    Error,
    Info,
    Debug,
    Trace,
}
impl Default for ArgLogLevel {
    fn default() -> Self {
        Self::Info
    }
}
impl From<ArgLogLevel> for LevelFilter {
    fn from(v: ArgLogLevel) -> Self {
        use ArgLogLevel as S;
        match v {
            S::Off => LevelFilter::Off,
            S::Error => LevelFilter::Error,
            S::Info => LevelFilter::Info,
            S::Debug => LevelFilter::Debug,
            S::Trace => LevelFilter::Trace,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum SupportedCiphers {
    None,
    ChaCha8,
    ChaCha12,
    ChaCha20,
}
impl SupportedCiphers {
    pub fn name_bytes(&self) -> &[u8] {
        match self {
            Self::None => b"",
            Self::ChaCha8 => b"ChaCha8",
            Self::ChaCha12 => b"ChaCha12",
            Self::ChaCha20 => b"ChaCha20",
        }
    }
}
impl Default for SupportedCiphers {
    fn default() -> Self {
        Self::ChaCha12
    }
}

fn main() -> Result<(), Error> {
    let args = CliArgs::parse();
    env_logger::builder().filter_level(args.log.into()).init();

    if args.decrypt == args.encrypt {
        log!(Level::Error, "must specify either --encrypt or --decrypt");
        return Err(Error::msg(""));
    }

    let key = get_encryption_key(&args)?;

    if args.encrypt {
        trace!("beginning encrypt");
        let input: Box<dyn Read> = if args.input == "-" {
            trace!("locking stdin for reading");
            Box::new(io::stdin().lock())
        } else {
            Box::new(File::open(&args.input)?)
        };

        let write_stdout = args.output == "-";
        let mut output = if write_stdout {
            trace!("creating temporary output file");
            tempfile::tempfile()?
        } else {
            File::create(&args.output)?
        };

        trace!("building metadata map");
        let mut meta_map = MetaMap::new();
        for m in args.meta {
            meta_map.insert(m.key.into_bytes(), m.value.into_bytes());
        }

        encrypt_file(input, &mut output, args.cipher, &key, meta_map)?;
        // If we wrote to a temp-file, write that file back out to stdout
        if write_stdout {
            trace!("writing temporary file to stdout");
            output.rewind()?;
            io::copy(&mut output, &mut io::stdout().lock())?;
        }
    }
    if args.decrypt {
        trace!("beginning decrypt");
        let output: Box<dyn Write> = if args.output == "-" {
            trace!("locking stdout");
            Box::new(io::stdout().lock())
        } else {
            Box::new(File::create(&args.output)?)
        };

        if args.input == "-" {
            trace!("buffering stdin to memory");
            // If we're reading from stdin we have to buffer
            let mut buf = Vec::new();
            io::stdin().lock().read_to_end(&mut buf)?;
            let input = io::Cursor::new(buf);
            decrypt_file(input, output, &key)?;
        } else {
            let input = io::BufReader::new(File::open(&args.input)?);
            decrypt_file(input, output, &key)?;
        }
    }

    Ok(())
}

fn get_encryption_key(args: &CliArgs) -> Result<Vec<u8>, Error> {
    if let Some(keyfile) = &args.keyfile {
        trace!("encryption key from file");
        let mut file = File::open(&keyfile).map_err(|e| {
            Error::from(e).context(format!("file not found {}", keyfile.to_string_lossy()))
        })?;
        let mut key_buf = Vec::new();
        file.read_to_end(&mut key_buf)?;
        key_to_buf(&key_buf)
    } else if let Some(cli_key) = &args.key {
        trace!("encryption key from cli");
        key_to_buf(cli_key.as_bytes())
    } else if let Ok(env_key) = std::env::var(ENV_VAR_KEY) {
        trace!("encryption key from environment variable");
        key_to_buf(env_key.as_bytes())
    } else {
        Err(anyhow!(
            "no secret key supplied, either use --key, --keyfile, or set environment variable {}",
            ENV_VAR_KEY,
        ))
    }
}

fn key_to_buf(key: &[u8]) -> Result<Vec<u8>, Error> {
    if key.starts_with(b"0x") {
        ensure!(
            key.len() % 2 == 0,
            "hex string length must be a multiple of 2"
        );
        let mut buf = Vec::new();
        for i in (2..key.len()).step_by(2) {
            let n0 = nibble(key[i])?;
            let n1 = nibble(key[i + 1])?;
            buf.push(n0 | (n1 << 4));
        }
        Ok(buf)
    } else {
        Ok(Vec::from(key))
    }
}

/// Returns a nibble from a hex character
fn nibble(b: u8) -> Result<u8, Error> {
    (b as char)
        .to_digit(16)
        .map(|v| v as u8)
        .ok_or_else(|| Error::msg("character is not a hex digit"))
}

fn encrypt_file<R: Read, W: Write + Seek>(
    input: R,
    output: W,
    cipher_kind: SupportedCiphers,
    key: &[u8],
    meta: MetaMap,
) -> Result<u64, Error> {
    // Get the meta for the selected cipher type and generate an IV
    let factory = BoxDynCipher::factory();
    let c_meta = factory.get_meta(cipher_kind.name_bytes())?;
    if key.len() != c_meta.key_size {
        return Err(anyhow!(
            "key length is {} bytes, should be {}",
            key.len(),
            c_meta.key_size
        ));
    }
    let iv = c_meta.generate_iv(&mut StdRng::from_entropy());
    let mut wr = EnardWriter::new(output, factory, cipher_kind.name_bytes(), key, &iv, meta)?;
    Ok(wr.write_complete(input)?)
}

fn decrypt_file<R: BufRead + Seek, W: Write>(
    input: R,
    mut output: W,
    key: &[u8],
) -> Result<u64, Error> {
    let mut rd = EnardReader::new_boxed(input, key)?;
    Ok(io::copy(&mut rd, &mut output)?)
}
