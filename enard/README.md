# Enard
For an overview of `enard` please see the [Github repo](https://github.com/bindernews/enard).

# Format v01
This documents version 01 of the enard file format. 
All numbers are stored little-endian, and types (e.g. `u16`) are as defined in Rust. 

**Terms:**
- *u8-block*: A `u8` (*N*) followed by *N* bytes
- *u16-block*: A `u16` (*N*) followed by *N* bytes

## Overview
This list shows the enard file structure in general, and the tables below
give details about data structures, sizes, etc.

- Magic header
- Format version
- Header size
- Data size
- Header
  - Encryption cipher name
  - Encryption cipher initial value (IV)
  - Count of "metadata blocks"
  - 0 or more "metadata blocks" where each has a "name" and "data"
  - optional padding to 8-byte alignment
- Encrypted data
- MAC tag

## Main
| Offset | Size | Description |
|--------|------|-------------|
| 0      | 6    | Magic header `"\x03ENARD"` |
| 6      | 2    | Version (`u16`) |
| 8      | 4    | Header size - `H` (`u32`) |
| 12     | 8    | Data Size - `D` (`u64`) |
| 20     | *H*  | Header |
| 20 + *H*       | *D* | Encrypted data |
| 20 + *H* + *D* | 32  | MAC tag |

## Header
| Data Type | Description |
|-----------|-------------|
| u8-block  | The ascii name of the encryption cipher used in this enard file |
| u8-block  | The IV for the cipher (may be length 0) |
| u8        | Metadata block count |
| u8-block  | Metadata-*N* name, may be any bytes |
| u16-block | Metadata-*N* data, may be any bytes |
| 0-bytes   | Padding to align the data section to 8 bytes for better SIMD compatibility |

