// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Consensus-encodable types
//!
//! This is basically a replacement of the `Encodable` trait which does
//! normalization for endianness, etc., to ensure that the encoding
//! matches for endianness, etc., to ensure that the encoding matches
//! the network consensus encoding.
//!
//! Essentially, anything that must go on the -disk- or -network- must
//! be encoded using the `Encodable` trait, since this data
//! must be the same for all systems. Any data going to the -user-, e.g.
//! over JSONRPC, should use the ordinary `Encodable` trait. (This
//! should also be the same across systems, of course, but has some
//! critical differences from the network format, e.g. scripts come
//! with an opcode decode, hashes are big-endian, numbers are typically
//! big-endian decimals, etc.)
//!

use core::{fmt, mem, u32, convert::From};
use std::borrow::Cow;
#[cfg(feature = "std")] use std::error;

use std::io::{self, Cursor, Read};
use std::{rc, sync};
use hashes::{Hash, sha256, sha256d};
use crate::crypto::UInt256;
use crate::hash_types::{BlockHash, FilterHash, FilterHeader, TxMerkleNode};
use crate::hashes::hex::ToHex;

// use hashes::hex::ToHex;

use crate::tx::{TransactionInput, TransactionOutput};
// use blockdata::transaction::{TxOut, Transaction, TxIn};
// #[cfg(feature = "std")]
// use network::{message_blockdata::Inventory, address::{Address, AddrV2Message}};
use crate::util::{endian, psbt};

/// Encoding error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// PSBT-related error
    Psbt(psbt::Error),
    /// Network magic was not expected
    UnexpectedNetworkMagic {
        /// The expected network magic
        expected: u32,
        /// The unexpected network magic
        actual: u32,
    },
    /// Tried to allocate an oversized vector
    OversizedVectorAllocation{
        /// The capacity requested
        requested: usize,
        /// The maximum capacity
        max: usize,
    },
    /// Checksum was invalid
    InvalidChecksum {
        /// The expected checksum
        expected: [u8; 4],
        /// The invalid checksum
        actual: [u8; 4],
    },
    /// VarInt was encoded in a non-minimal way
    NonMinimalVarInt,
    /// Network magic was unknown
    UnknownNetworkMagic(u32),
    /// Parsing error
    ParseFailed(&'static str),
    /// Unsupported Segwit flag
    UnsupportedSegwitFlag(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::Psbt(ref e) => write!(f, "PSBT error: {}", e),
            Error::UnexpectedNetworkMagic { expected: ref e, actual: ref a } => write!(f,
                                                                                       "unexpected network magic: expected {}, actual {}", e, a),
            Error::OversizedVectorAllocation { requested: ref r, max: ref m } => write!(f,
                                                                                        "allocation of oversized vector: requested {}, maximum {}", r, m),
            Error::InvalidChecksum { expected: ref e, actual: ref a } => write!(f,
                                                                                "invalid checksum: expected {}, actual {}", e.to_hex(), a.to_hex()),
            Error::NonMinimalVarInt => write!(f, "non-minimal varint"),
            Error::UnknownNetworkMagic(ref m) => write!(f, "unknown network magic: {}", m),
            Error::ParseFailed(ref e) => write!(f, "parse failed: {}", e),
            Error::UnsupportedSegwitFlag(ref swflag) => write!(f,
                                                               "unsupported segwit version: {}", swflag),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for Error {
    fn cause(&self) -> Option<&dyn  error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::Psbt(ref e) => Some(e),
            Error::UnexpectedNetworkMagic { .. }
            | Error::OversizedVectorAllocation { .. }
            | Error::InvalidChecksum { .. }
            | Error::NonMinimalVarInt
            | Error::UnknownNetworkMagic(..)
            | Error::ParseFailed(..)
            | Error::UnsupportedSegwitFlag(..) => None,
        }
    }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

#[doc(hidden)]
impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error {
        Error::Psbt(e)
    }
}

/// Encode an object into a vector
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).unwrap();
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    serialize(data)[..].to_hex()
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
    let (rv, consumed) = deserialize_partial(data)?;
    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(
    data: &[u8],
) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;
    Ok((rv, consumed))
}


/// Extensions of `Write` to encode data as per Bitcoin consensus
pub trait WriteExt {
    /// Output a 64-bit uint
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Output a 32-bit uint
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Output a 16-bit uint
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Output a 8-bit uint
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Output a 64-bit int
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Output a 32-bit int
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Output a 16-bit int
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Output a 8-bit int
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Output a boolean
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Output a byte slice
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error>;
}

/// Extensions of `Read` to decode data as per Bitcoin consensus
pub trait ReadExt {
    /// Read a 64-bit uint
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Read a 32-bit uint
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Read a 16-bit uint
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Read a 8-bit uint
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Read a 64-bit int
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Read a 32-bit int
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Read a 16-bit int
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Read a 8-bit int
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Read a boolean
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Read a byte slice
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), io::Error> {
            self.write_all(&endian::$writefn(v))
        }
    }
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            debug_assert_eq!(::core::mem::size_of::<$val_type>(), $byte_len); // size_of isn't a constfn in 1.22
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(Error::Io)?;
            Ok(endian::$readfn(&val))
        }
    }
}

impl<W: io::Write> WriteExt for W {
    encoder_fn!(emit_u64, u64, u64_to_array_le);
    encoder_fn!(emit_u32, u32, u32_to_array_le);
    encoder_fn!(emit_u16, u16, u16_to_array_le);
    encoder_fn!(emit_i64, i64, i64_to_array_le);
    encoder_fn!(emit_i32, i32, i32_to_array_le);
    encoder_fn!(emit_i16, i16, i16_to_array_le);

    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> {
        self.write_all(&[v])
    }
    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error> {
        self.write_all(v)
    }
}

impl<R: Read> ReadExt for R {
    decoder_fn!(read_u64, u64, slice_to_u64_le, 8);
    decoder_fn!(read_u32, u32, slice_to_u32_le, 4);
    decoder_fn!(read_u16, u16, slice_to_u16_le, 2);
    decoder_fn!(read_i64, i64, slice_to_i64_le, 8);
    decoder_fn!(read_i32, i32, slice_to_i32_le, 4);
    decoder_fn!(read_i16, i16, slice_to_i16_le, 2);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0])
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0] as i8)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        ReadExt::read_i8(self).map(|bit| bit != 0)
    }
    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error> {
        self.read_exact(slice).map_err(Error::Io)
    }
}

/// Maximum size, in bytes, of a vector we are allowed to decode
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: io::Write>(&self, writer: W) -> Result<usize, io::Error>;

    /// laconic shorthand + supress unwrap panic
    fn enc<W: io::Write>(&self, writer: W) -> usize {
        self.consensus_encode(writer).unwrap()
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error>;
}

/// A variable-length unsigned integer
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct VarInt(pub u64);

/// Data which must be preceded by a 4-byte checksum
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData(pub Vec<u8>);

// Primitive types
macro_rules! impl_int_encodable{
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => (
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                ReadExt::$meth_dec(&mut d)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<S: WriteExt>(
                &self,
                mut s: S,
            ) -> Result<usize, io::Error> {
                s.$meth_enc(*self)?;
                Ok(mem::size_of::<$ty>())
            }
        }
    )
}

impl_int_encodable!(u8,  read_u8,  emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8,  read_i8,  emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

impl VarInt {
    /// Gets the length of this VarInt when encoded.
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1),
    /// and 9 otherwise.
    #[inline]
    pub fn len(&self) -> usize {
        match self.0 {
            0..=0xFC             => { 1 }
            0xFD..=0xFFFF        => { 3 }
            0x10000..=0xFFFFFFFF => { 5 }
            _                    => { 9 }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Display for VarInt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[val: {}, len: {}]", self.0, self.len())?;
        Ok(())
    }
}


impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(s)?;
                Ok(1)
            },
            0xFD..=0xFFFF => {
                s.emit_u8(0xFD)?;
                (self.0 as u16).consensus_encode(s)?;
                Ok(3)
            },
            0x10000..=0xFFFFFFFF => {
                s.emit_u8(0xFE)?;
                (self.0 as u32).consensus_encode(s)?;
                Ok(5)
            },
            _ => {
                s.emit_u8(0xFF)?;
                (self.0 as u64).consensus_encode(s)?;
                Ok(9)
            },
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let n = ReadExt::read_u8(&mut d)?;
        match n {
            0xFF => {
                let x = ReadExt::read_u64(&mut d)?;
                if x < 0x100000000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x))
                }
            }
            0xFE => {
                let x = ReadExt::read_u32(&mut d)?;
                if x < 0x10000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            0xFD => {
                let x = ReadExt::read_u16(&mut d)?;
                if x < 0xFD {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            n => Ok(VarInt(n as u64))
        }
    }
}


// Booleans
impl Encodable for bool {
    #[inline]
    fn consensus_encode<S: WriteExt>(&self, mut s: S) -> Result<usize, io::Error> {
        s.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<bool, Error> {
        ReadExt::read_bool(&mut d)
    }
}

// Strings
impl Encodable for String {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(&mut s)?;
        s.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}

// Cow<'static, str>
impl Encodable for Cow<'static, str> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(&mut s)?;
        s.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for Cow<'static, str> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Cow<'static, str>, Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
            .map(Cow::Owned)
    }
}


// Arrays
macro_rules! impl_array {
    ( $size:expr ) => (
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<S: WriteExt>(
                &self,
                mut s: S,
            ) -> Result<usize, io::Error> {
                s.emit_slice(&self[..])?;
                Ok(self.len())
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let mut ret = [0; $size];
                d.read_slice(&mut ret)?;
                Ok(ret)
            }
        }
    );
}

impl_array!(2);
impl_array!(4);
impl_array!(8);
impl_array!(10);
impl_array!(12);
impl_array!(16);
impl_array!(32);
impl_array!(33);

impl Decodable for [u16; 8] {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut res = [0; 8];
        for item in &mut res {
            *item = Decodable::consensus_decode(&mut d)?;
        }
        Ok(res)
    }
}

impl Encodable for [u16; 8] {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        for c in self.iter() { c.consensus_encode(&mut s)?; }
        Ok(16)
    }
}

// Vectors
macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<S: io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, io::Error> {
                let mut len = 0;
                len += VarInt(self.len() as u64).consensus_encode(&mut s)?;
                for c in self.iter() {
                    len += c.consensus_encode(&mut s)?;
                }
                Ok(len)
            }
        }
        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let len = VarInt::consensus_decode(&mut d)?.0;
                let byte_size = (len as usize)
                                    .checked_mul(mem::size_of::<$type>())
                                    .ok_or(self::Error::ParseFailed("Invalid length"))?;
                if byte_size > MAX_VEC_SIZE {
                    return Err(self::Error::OversizedVectorAllocation { requested: byte_size, max: MAX_VEC_SIZE })
                }
                let mut ret = Vec::with_capacity(len as usize);
                let mut d = d.take(MAX_VEC_SIZE as u64);
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode(&mut d)?);
                }
                Ok(ret)
            }
        }
    }
}
impl_vec!(BlockHash);
impl_vec!(FilterHash);
impl_vec!(FilterHeader);
impl_vec!(TxMerkleNode);
// impl_vec!(Transaction);
// impl_vec!(TxOut);
// impl_vec!(TxIn);
impl_vec!(Vec<u8>);
impl_vec!(u64);

impl_vec!(bool);
impl_vec!(UInt256);
impl_vec!(TransactionInput);
impl_vec!(TransactionOutput);
// impl_vec!(MasternodeEntry);
// impl_vec!(crate::models::LLMQEntry);

// #[cfg(feature = "std")] impl_vec!(Inventory);
// #[cfg(feature = "std")] impl_vec!((u32, Address));
// #[cfg(feature = "std")] impl_vec!(AddrV2Message);

pub fn consensus_encode_with_size<S: io::Write>(data: &[u8], mut s: S) -> Result<usize, io::Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(&mut s)?;
    s.emit_slice(data)?;
    Ok(vi_len + data.len())
}


impl Encodable for Vec<u8> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, s)
    }
}

impl Decodable for Vec<u8> {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(&mut d)?.0 as usize;
        if len > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation { requested: len, max: MAX_VEC_SIZE })
        }
        let mut ret = vec![0u8; len];
        d.read_slice(&mut ret)?;
        Ok(ret)
    }
}

impl Encodable for Box<[u8]> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, s)
    }
}

impl Decodable for Box<[u8]> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        <Vec<u8>>::consensus_decode(d).map(From::from)
    }
}


/// Do a double-SHA256 on some data and return the first 4 bytes
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

// Checked data
impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        (self.0.len() as u32).consensus_encode(&mut s)?;
        sha2_checksum(&self.0).consensus_encode(&mut s)?;
        s.emit_slice(&self.0)?;
        Ok(8 + self.0.len())
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = u32::consensus_decode(&mut d)?;
        if len > MAX_VEC_SIZE as u32 {
            return Err(self::Error::OversizedVectorAllocation {
                requested: len as usize,
                max: MAX_VEC_SIZE
            });
        }
        let checksum = <[u8; 4]>::consensus_decode(&mut d)?;
        let mut ret = vec![0u8; len as usize];
        d.read_slice(&mut ret)?;
        let expected_checksum = sha2_checksum(&ret);
        if expected_checksum != checksum {
            Err(self::Error::InvalidChecksum {
                expected: expected_checksum,
                actual: checksum,
            })
        } else {
            Ok(CheckedData(ret))
        }
    }
}

// References
impl<'a, T: Encodable> Encodable for &'a T {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        (&**self).consensus_encode(s)
    }
}

impl<'a, T: Encodable> Encodable for &'a mut T {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        (&**self).consensus_encode(s)
    }
}

impl<T: Encodable> Encodable for rc::Rc<T> {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        (&**self).consensus_encode(s)
    }
}

impl<T: Encodable> Encodable for sync::Arc<T> {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        (&**self).consensus_encode(s)
    }
}

// Tuples
macro_rules! tuple_encode {
    ($($x:ident),*) => (
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode<S: io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(&mut s)?;)*
                Ok(len)
            }
        }

        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                Ok(($({let $x = Decodable::consensus_decode(&mut d)?; $x }),*))
            }
        }
    );
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

impl Encodable for sha256d::Hash {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        self.into_inner().consensus_encode(s)
    }
}

impl Decodable for sha256d::Hash {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_inner(<<Self as Hash>::Inner>::consensus_decode(d)?))
    }
}

impl Encodable for sha256::Hash {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        self.into_inner().consensus_encode(s)
    }
}

impl Decodable for sha256::Hash {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_inner(<<Self as Hash>::Inner>::consensus_decode(d)?))
    }
}
