# Enard
[![Crates.io](https://img.shields.io/crates/v/enard)](https://crates.io/crates/enard)
[![MIT](https://img.shields.io/badge/license-MIT--2.0-blue)](./LICENSE)

Enard is an encrypted container format, intended to allow on-the-fly decryption of game assets
stored in a different format (e.g. a zip file). Enard encrypts the "wrapped" file and provides
a reader which implements Rust's `std::io::Read` and `std::io::Seek` traits, allowing users
to treat it similarly to a file. In practice this means it's very easy to wrap the
[zip](https://crates.io/crates/zip) library around an `EnardReader` and it just works.

Here's an example
```rust
let key = [0x42u8; 32];
let file = File::open("example.zip.enard")?;
let e_reader = EnardReader::new(BufReader::new(file), RuntimeCipherFactory, &key)?;
let archive = ZipArchive::new(e_reader)?;
for names in archive.file_names() {
    println!("{}", name);
}
```

# Details

Enard uses a stream cipher for encryption to be able to jump to any point in the file when
decrypting, allowing the reader to implement `std::io::Seek` and thus act like a file. 
Enard also uses a SHA2-256 Message Authentication Code to verify that the file hasn't
been modified. 

# F.A.Q.

### Why is the default cipher ChaCha12 instead of ChaCha20?
The default cipher is ChaCha12 instead of ChaCha20 because the intent of this library is to
load encrypted assets from disk for games, and ChaCha12 is a good mix of security and performance.
Enard is not meant to make game assets impossible to steal, it's a deterrent.

### What if someone changes the metadata size or data size fields?
Those fields are both unencrypted and not part of the MAC, meaning an attacker can easily change
both. The problem is that doing so would change what data is fed into the MAC, meaning it would
fail to authenticate and the decryption would fail.

### ZIP files have encryption already, why not use it?
First, you might not want to use ZIP files. Second, ZIP file encryption is relatively weak,
doesn't apply to the whole file, requires that the file be decrypted all at once, and many zip
implementations simply don't support it.

### Why not make your own archive format?
There are many reasonable archive formats out there that are well-specified and have well-tested
implementations. Enard isn't trying to reinvent the wheel, just put a bike-lock on it.

