// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
//     The Dash Core Developers
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

//! Dash consensus-encodable types.
//!
//! This is basically a replacement of the `Encodable` trait which does
//! normalization of endianness etc., to ensure that the encoding matches
//! the network consensus encoding.
//!
//! Essentially, anything that must go on the _disk_ or _network_ must be
//! encoded using the `Encodable` trait, since this data must be the same for
//! all systems. Any data going to the _user_ e.g., over JSONRPC, should use the
//! ordinary `Encodable` trait. (This should also be the same across systems, of
//! course, but has some critical differences from the network format e.g.,
//! scripts come with an opcode decode, hashes are big-endian, numbers are
//! typically big-endian decimals, etc.)
//!

use core::convert::From;
use core::{fmt, mem};
use std::io::Write;

#[cfg(feature = "core-block-hash-use-x11")]
use hashes::hash_x11;
use hashes::{Hash, hash160, sha256, sha256d};
use internals::write_err;

use crate::bip152::{PrefilledTransaction, ShortId};
use crate::blockdata::transaction::Transaction;
use crate::bls_sig_utils::BLSSignature;
use crate::hash_types::{
    BlockHash, FilterHash, FilterHeader, MerkleRootMasternodeList, TxMerkleNode,
};
use crate::io::{self, Cursor, Read};
use crate::network::message_qrinfo::QuorumSnapshot;
use crate::network::message_sml::{DeletedQuorum, MnListDiff, QuorumCLSigObject};
#[cfg(feature = "std")]
use crate::network::{
    address::{AddrV2Message, Address},
    message_blockdata::Inventory,
};
use crate::prelude::*;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::transaction::special_transaction::TransactionType;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
use crate::transaction::txin::TxIn;
use crate::transaction::txout::TxOut;
use crate::{OutPoint, ProTxHash, ScriptBuf, address};

/// Encoding error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// And I/O error.
    Io(io::Error),
    /// Tried to allocate an oversized vector.
    OversizedVectorAllocation {
        /// The capacity requested.
        requested: usize,
        /// The maximum capacity.
        max: usize,
    },
    /// Checksum was invalid.
    InvalidChecksum {
        /// The expected checksum.
        expected: [u8; 4],
        /// The invalid checksum.
        actual: [u8; 4],
    },
    /// VarInt was encoded in a non-minimal way.
    NonMinimalVarInt,
    /// Parsing error.
    ParseFailed(&'static str),

    /// A Vector was trying to be converted to a fixed size vector, but was the wrong size
    InvalidVectorSize {
        /// The expected size
        expected: usize,
        /// The actual size of the vector
        actual: usize,
    },
    /// The Transaction type was not identified
    UnknownSpecialTransactionType(u16),
    /// We tried to convert the payload to the wrong type
    WrongSpecialTransactionPayloadConversion {
        /// The expected transaction type
        expected: TransactionType,
        /// The invalid transaction type
        actual: TransactionType,
    },
    /// The script type was non standard
    NonStandardScriptPayout(ScriptBuf),
    /// Hex error
    Hex(hashes::hex::Error),
    /// Address error
    Address(address::Error),
    /// Invalid enum value
    InvalidEnumValue {
        max: u16,
        received: u16,
        msg: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => write_err!(f, "IO error"; e),
            Error::OversizedVectorAllocation {
                requested: r,
                max: m,
            } => {
                write!(f, "allocation of oversized vector: requested {}, maximum {}", r, m)
            }
            Error::InvalidChecksum {
                expected: e,
                actual: a,
            } => {
                write!(f, "invalid checksum: expected {:x}, actual {:x}", e.as_hex(), a.as_hex())
            }
            Error::NonMinimalVarInt => write!(f, "non-minimal varint"),
            Error::ParseFailed(s) => write!(f, "parse failed: {}", s),
            Error::UnknownSpecialTransactionType(stt) => {
                write!(f, "unknown special transaction type: {}", stt)
            }
            Error::WrongSpecialTransactionPayloadConversion {
                expected: e,
                actual: a,
            } => {
                write!(f, "wrong special transaction payload conversion expected: {} got: {}", e, a)
            }
            Error::NonStandardScriptPayout(script) => {
                write!(f, "non standard script payout: {}", script.to_hex_string())
            }
            Error::InvalidVectorSize {
                expected,
                actual,
            } => {
                write!(f, "invalid vector size error expected: {} got: {}", expected, actual)
            }
            Error::Hex(e) => write!(f, "hex error {}", e),
            Error::Address(e) => write!(f, "address error {}", e),
            Error::InvalidEnumValue {
                max,
                received,
                msg,
            } => {
                write!(f, "invalid enum value, max: {} received: {} ({})", max, received, msg)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Io(e) => Some(e),
            OversizedVectorAllocation {
                ..
            }
            | InvalidChecksum {
                ..
            }
            | NonMinimalVarInt
            | ParseFailed(_)
            | Error::UnknownSpecialTransactionType(..)
            | Error::WrongSpecialTransactionPayloadConversion {
                ..
            }
            | Error::NonStandardScriptPayout(..)
            | Error::InvalidVectorSize {
                ..
            }
            | Error::Hex(_)
            | Error::Address(_)
            | InvalidEnumValue {
                ..
            } => None,
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
impl From<address::Error> for Error {
    fn from(error: address::Error) -> Self {
        Error::Address(error)
    }
}

/// Encodes an object into a vector.
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).expect("in-memory writers don't error");
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encodes an object into a hex-encoded string.
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    serialize(data).to_lower_hex_string()
}

/// Deserializes an object from a vector, will error if said deserialization
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

/// Deserializes an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode_from_finite_reader(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

/// Extensions of `Write` to encode data as per Bitcoin consensus.
pub trait WriteExt: io::Write {
    /// Outputs a 128-bit unsigned integer.
    fn emit_u128(&mut self, v: u128) -> Result<(), io::Error>;
    /// Outputs a 64-bit unsigned integer.
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Outputs a 32-bit unsigned integer.
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Outputs a 16-bit unsigned integer.
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Outputs an 8-bit unsigned integer.
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Outputs a 64-bit signed integer.
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Outputs a 32-bit signed integer.
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Outputs a 16-bit signed integer.
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Outputs an 8-bit signed integer.
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Outputs a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Outputs a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error>;
}

/// Extensions of `Read` to decode data as per Bitcoin consensus.
pub trait ReadExt: io::Read {
    /// Reads a 128-bit unsigned integer.
    fn read_u128(&mut self) -> Result<u128, Error>;
    /// Reads a 64-bit unsigned integer.
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Reads a 32-bit unsigned integer.
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Reads a 16-bit unsigned integer.
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Reads an 8-bit unsigned integer.
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Reads a 64-bit signed integer.
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Reads a 32-bit signed integer.
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Reads a 16-bit signed integer.
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Reads an 8-bit signed integer.
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Reads a boolean.
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Reads a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), io::Error> {
            self.write_all(&v.to_le_bytes())
        }
    };
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(Error::Io)?;
            Ok(<$val_type>::from_le_bytes(val))
        }
    };
}

impl<W: io::Write + ?Sized> WriteExt for W {
    encoder_fn!(emit_u128, u128);
    encoder_fn!(emit_u64, u64);
    encoder_fn!(emit_u32, u32);
    encoder_fn!(emit_u16, u16);
    encoder_fn!(emit_i64, i64);
    encoder_fn!(emit_i32, i32);
    encoder_fn!(emit_i16, i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> {
        self.write_all(&[v])
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

impl<R: Read + ?Sized> ReadExt for R {
    decoder_fn!(read_u128, u128, 16);
    decoder_fn!(read_u64, u64, 8);
    decoder_fn!(read_u32, u32, 4);
    decoder_fn!(read_u16, u16, 2);
    decoder_fn!(read_i64, i64, 8);
    decoder_fn!(read_i32, i32, 4);
    decoder_fn!(read_i16, i16, 2);

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

/// Maximum size, in bytes, of a vector we are allowed to decode.
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Data which can be encoded in a consensus-consistent way.
pub trait Encodable {
    /// Encodes an object with a well-defined format.
    ///
    /// # Returns
    ///
    /// The number of bytes written on success. The only errors returned are errors propagated from
    /// the writer.
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Data which can be encoded in a consensus-consistent way.
pub trait Decodable: Sized {
    /// Decode `Self` from a size-limited reader.
    ///
    /// Like `consensus_decode` but relies on the reader being limited in the amount of data it
    /// returns, e.g. by being wrapped in [`std::io::Take`].
    ///
    /// Failing to obide to this requirement might lead to memory exhaustion caused by malicious
    /// inputs.
    ///
    /// Users should default to `consensus_decode`, but when data to be decoded is already in a byte
    /// vector of a limited size, calling this function directly might be marginally faster (due to
    /// avoiding extra checks).
    ///
    /// ### Rules for trait implementations
    ///
    /// * Simple types that that have a fixed size (own and member fields), don't have to overwrite
    ///   this method, or be concern with it.
    /// * Types that deserialize using externally provided length should implement it:
    ///   * Make `consensus_decode` forward to `consensus_decode_bytes_from_finite_reader` with the
    ///     reader wrapped by `Take`. Failure to do so, without other forms of memory exhaustion
    ///     protection might lead to resource exhaustion vulnerability.
    ///   * Put a max cap on things like `Vec::with_capacity` to avoid oversized allocations, and
    ///     rely on the reader running out of data, and collections reallocating on a legitimately
    ///     oversized input data, instead of trying to enforce arbitrary length limits.
    /// * Types that contain other types that implement custom
    ///   `consensus_decode_from_finite_reader`, should also implement it applying same rules, and
    ///   in addition make sure to call `consensus_decode_from_finite_reader` on all members, to
    ///   avoid creating redundant `Take` wrappers. Failure to do so might result only in a tiny
    ///   performance hit.
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, Error> {
        // This method is always strictly less general than, `consensus_decode`, so it's safe and
        // make sense to default to just calling it. This way most types, that don't care about
        // protecting against resource exhaustion due to malicious input, can just ignore it.
        Self::consensus_decode(reader)
    }

    /// Decode an object with a well-defined format.
    ///
    /// This is the method that should be implemented for a typical, fixed sized type
    /// implementing this trait. Default implementation is wrapping the reader
    /// in [`crate::io::Take`] to limit the input size to [`MAX_VEC_SIZE`], and forwards the call to
    /// [`Self::consensus_decode_from_finite_reader`], which is convenient
    /// for types that override [`Self::consensus_decode_from_finite_reader`]
    /// instead.
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        Self::consensus_decode_from_finite_reader(reader.take(MAX_VEC_SIZE as u64).by_ref())
    }
}

/// A variable-length unsigned integer.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64);

/// Data which must be preceded by a 4-byte checksum.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData(pub Vec<u8>);

// Primitive types
macro_rules! impl_int_encodable {
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => {
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
                ReadExt::$meth_dec(r)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                w.$meth_enc(*self)?;
                Ok(mem::size_of::<$ty>())
            }
        }
    };
}

impl_int_encodable!(u8, read_u8, emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(u128, read_u128, emit_u128);
impl_int_encodable!(i8, read_i8, emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

#[allow(clippy::len_without_is_empty)] // VarInt has on concept of 'is_empty'.
impl VarInt {
    /// Gets the length of this VarInt when encoded.
    ///
    /// *Important: this method is only `const` in Rust 1.46 or higher!*
    ///
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1),
    /// and 9 otherwise.
    #[inline]
    pub const fn len(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }
}

impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(w)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                w.emit_u8(0xFD)?;
                (self.0 as u16).consensus_encode(w)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                w.emit_u8(0xFE)?;
                (self.0 as u32).consensus_encode(w)?;
                Ok(5)
            }
            _ => {
                w.emit_u8(0xFF)?;
                self.0.consensus_encode(w)?;
                Ok(9)
            }
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let n = ReadExt::read_u8(r)?;
        match n {
            0xFF => {
                let x = ReadExt::read_u64(r)?;
                if x < 0x100000000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x))
                }
            }
            0xFE => {
                let x = ReadExt::read_u32(r)?;
                if x < 0x10000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            0xFD => {
                let x = ReadExt::read_u16(r)?;
                if x < 0xFD {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            n => Ok(VarInt(n as u64)),
        }
    }
}

impl Encodable for bool {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<bool, Error> {
        ReadExt::read_bool(r)
    }
}

impl Encodable for String {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(w)?;
        w.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}

impl Encodable for Cow<'static, str> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(w)?;
        w.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for Cow<'static, str> {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Cow<'static, str>, Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
            .map(Cow::Owned)
    }
}

macro_rules! impl_array {
    ( $size:literal ) => {
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<W: WriteExt + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                w.emit_slice(&self[..])?;
                Ok(self.len())
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
                let mut ret = [0; $size];
                r.read_slice(&mut ret)?;
                Ok(ret)
            }
        }
    };
}

impl_array!(2);
impl_array!(4);
impl_array!(6);
impl_array!(8);
impl_array!(10);
impl_array!(12);
impl_array!(16);
impl_array!(20);
impl_array!(32);
impl_array!(33);
impl_array!(48);
impl_array!(64);
impl_array!(96);

impl Decodable for [u16; 8] {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut res = [0; 8];
        for item in &mut res {
            *item = Decodable::consensus_decode(r)?;
        }
        Ok(res)
    }
}

impl Encodable for [u16; 8] {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        for c in self.iter() {
            c.consensus_encode(w)?;
        }
        Ok(16)
    }
}

macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                let mut len = 0;
                len += VarInt(self.len() as u64).consensus_encode(w)?;
                for c in self.iter() {
                    len += c.consensus_encode(w)?;
                }
                Ok(len)
            }
        }

        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<Self, Error> {
                let len = VarInt::consensus_decode_from_finite_reader(r)?.0;
                // Do not allocate upfront more items than if the sequence of type
                // occupied roughly quarter a block. This should never be the case
                // for normal data, but even if that's not true - `push` will just
                // reallocate.
                // Note: OOM protection relies on reader eventually running out of
                // data to feed us.
                let max_capacity = MAX_VEC_SIZE / 4 / mem::size_of::<$type>();
                let mut ret = Vec::with_capacity(core::cmp::min(len as usize, max_capacity));
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode_from_finite_reader(r)?);
                }
                Ok(ret)
            }
        }
    };
}
impl_vec!(BlockHash);
impl_vec!(FilterHash);
impl_vec!(FilterHeader);
impl_vec!(TxMerkleNode);
impl_vec!(Transaction);
impl_vec!(TxOut);
impl_vec!(TxIn);
impl_vec!(Vec<u8>);
impl_vec!(u16);
impl_vec!(u32);
impl_vec!(i32);
impl_vec!(u64);
impl_vec!(VarInt);
impl_vec!(ShortId);
impl_vec!(OutPoint);
impl_vec!(PrefilledTransaction);
impl_vec!(QuorumEntry);
impl_vec!(QuorumCLSigObject);
impl_vec!(DeletedQuorum);
impl_vec!(BLSSignature);
impl_vec!(ProTxHash);
impl_vec!(MerkleRootMasternodeList);
impl_vec!(MasternodeListEntry);
impl_vec!(MnListDiff);
impl_vec!(QuorumSnapshot);

#[cfg(feature = "std")]
impl_vec!(Inventory);
#[cfg(feature = "std")]
impl_vec!((u32, Address));
#[cfg(feature = "std")]
impl_vec!(AddrV2Message);

pub(crate) fn consensus_encode_with_size<S: io::Write>(
    data: &[u8],
    mut s: S,
) -> Result<usize, io::Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(&mut s)?;
    s.emit_slice(data)?;
    Ok(vi_len + data.len())
}

struct ReadBytesFromFiniteReaderOpts {
    len: usize,
    chunk_size: usize,
}

/// Read `opts.len` bytes from reader, where `opts.len` could potentially be malicious.
///
/// This function relies on reader being bound in amount of data
/// it returns for OOM protection. See [`Decodable::consensus_decode_from_finite_reader`].
#[inline]
fn read_bytes_from_finite_reader<D: io::Read>(
    mut d: D,
    mut opts: ReadBytesFromFiniteReaderOpts,
) -> Result<Vec<u8>, Error> {
    let mut ret = vec![];

    assert_ne!(opts.chunk_size, 0);

    while opts.len > 0 {
        let chunk_start = ret.len();
        let chunk_size = core::cmp::min(opts.len, opts.chunk_size);
        let chunk_end = chunk_start + chunk_size;
        ret.resize(chunk_end, 0u8);
        d.read_slice(&mut ret[chunk_start..chunk_end])?;
        opts.len -= chunk_size;
    }

    Ok(ret)
}

impl Encodable for Vec<u8> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, w)
    }
}

impl Decodable for Vec<u8> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(r)?.0 as usize;
        // most real-world vec of bytes data, wouldn't be larger than 128KiB
        let opts = ReadBytesFromFiniteReaderOpts {
            len,
            chunk_size: 128 * 1024,
        };
        read_bytes_from_finite_reader(r, opts)
    }
}

impl Encodable for Box<[u8]> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, w)
    }
}

impl Decodable for Box<[u8]> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        <Vec<u8>>::consensus_decode_from_finite_reader(r).map(From::from)
    }
}

/// Does a double-SHA256 on `data` and returns the first 4 bytes.
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (self.0.len() as u32).consensus_encode(w)?;
        sha2_checksum(&self.0).consensus_encode(w)?;
        w.emit_slice(&self.0)?;
        Ok(8 + self.0.len())
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let len = u32::consensus_decode_from_finite_reader(r)? as usize;

        let checksum = <[u8; 4]>::consensus_decode_from_finite_reader(r)?;
        let opts = ReadBytesFromFiniteReaderOpts {
            len,
            chunk_size: MAX_VEC_SIZE,
        };
        let ret = read_bytes_from_finite_reader(r, opts)?;
        let expected_checksum = sha2_checksum(&ret);
        if expected_checksum != checksum {
            // Debug logging for checksum mismatches
            eprintln!(
                "CHECKSUM DEBUG: len={}, checksum={:02x?}, payload_len={}, payload={:02x?}",
                len,
                checksum,
                ret.len(),
                &ret[..ret.len().min(32)]
            );

            // Special case: all-zeros checksum is definitely corruption
            if checksum == [0, 0, 0, 0] {
                eprintln!(
                    "CORRUPTION DETECTED: All-zeros checksum indicates corrupted stream or connection"
                );
            }

            Err(self::Error::InvalidChecksum {
                expected: expected_checksum,
                actual: checksum,
            })
        } else {
            Ok(CheckedData(ret))
        }
    }
}

impl<T: Encodable> Encodable for &T {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

impl<T: Encodable> Encodable for &mut T {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

impl<T: Encodable> Encodable for rc::Rc<T> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(target_has_atomic = "ptr")]
impl<T: Encodable> Encodable for sync::Arc<T> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

macro_rules! tuple_encode {
    ($($x:ident),*) => {
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(w)?;)*
                Ok(len)
            }
        }

        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
                Ok(($({let $x = Decodable::consensus_decode(r)?; $x }),*))
            }
        }
    };
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

#[cfg(feature = "core-block-hash-use-x11")]
impl Decodable for hash_x11::Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

#[cfg(feature = "core-block-hash-use-x11")]
impl Encodable for hash_x11::Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Encodable for hash160::Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for hash160::Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

impl Encodable for sha256d::Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for sha256d::Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

impl Encodable for sha256::Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for sha256::Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

pub fn read_compact_size<R: Read + ?Sized>(r: &mut R) -> io::Result<u32> {
    let mut marker = [0u8; 1];
    r.read_exact(&mut marker)?;
    match marker[0] {
        0xFD => {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf)?;
            let value = u16::from_le_bytes(buf) as u32;
            if value < 0xFD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Non-minimal compact size encoding",
                ));
            }
            Ok(value)
        }
        0xFE => {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            let value = u32::from_le_bytes(buf);
            if value <= 0xFFFF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Non-minimal compact size encoding",
                ));
            }
            Ok(value)
        }
        0xFF => {
            // Value is too large to fit in u32
            Err(io::Error::new(io::ErrorKind::InvalidData, "CompactSize value exceeds u32::MAX"))
        }
        value => Ok(value as u32),
    }
}

pub fn write_compact_size<W: Write + ?Sized>(w: &mut W, value: u32) -> io::Result<usize> {
    let bytes_written = if value < 253 {
        // For values less than 253, write the value as a single byte.
        w.write_all(&[value as u8])?;
        1 // 1 byte written
    } else if value <= 0xFFFF {
        // For values from 253 to 65535, write 0xFD followed by the value as a little-endian u16.
        w.write_all(&[0xFDu8])?;
        w.write_all(&(value as u16).to_le_bytes())?;
        3 // 1 byte marker + 2 bytes for u16
    } else {
        // For values from 65536 to 0xFFFFFFFF, write 0xFE followed by the value as a little-endian u32.
        w.write_all(&[0xFEu8])?;
        w.write_all(&value.to_le_bytes())?;
        5 // 1 byte marker + 4 bytes for u32
    };
    Ok(bytes_written)
}

pub fn compact_size_len(value: u32) -> usize {
    let mut size: usize = 0;
    if value < 253 {
        size += 1;
    } else if value < 65536 {
        size += 3;
    } else {
        size += 5;
    }
    size
}

pub fn read_fixed_bitset<R: Read + ?Sized>(r: &mut R, size: usize) -> std::io::Result<Vec<bool>> {
    // Define a reasonable maximum size to prevent excessive memory allocation
    const MAX_BITSET_SIZE: usize = 1_000_000;
    if size > MAX_BITSET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Bitset size exceeds maximum allowed value",
        ));
    }
    // Calculate the number of bytes needed
    let num_bytes = size.div_ceil(8);
    let mut bytes = vec![0u8; num_bytes];

    // Read bytes from the reader
    r.read_exact(&mut bytes)?;

    // Unpack bits into a vector of bools
    let mut bits = Vec::with_capacity(size);
    for p in 0..size {
        let byte = bytes[p / 8];
        let bit = (byte >> (p % 8)) & 1;
        bits.push(bit != 0);
    }

    Ok(bits)
}

pub fn write_fixed_bitset<W: Write + ?Sized>(
    w: &mut W,
    bits: &[bool],
    size: usize,
) -> io::Result<usize> {
    if bits.len() < size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Bits length is less than the specified size",
        ));
    }
    // Define a reasonable maximum size to prevent excessive memory allocation
    const MAX_BITSET_SIZE: usize = 1_000_000;
    if size > MAX_BITSET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Bitset size exceeds maximum allowed value",
        ));
    }
    // Calculate the number of bytes needed to represent 'size' bits
    let num_bytes = size.div_ceil(8);
    let mut bytes = vec![0u8; num_bytes];

    // Determine the minimum size to handle cases where bits.len() < size
    let ms = std::cmp::min(size, bits.len());

    // Pack the bits into the byte buffer
    for p in 0..ms {
        if bits[p] {
            bytes[p / 8] |= 1 << (p % 8);
        }
    }

    // Write the bytes to the writer
    w.write_all(&bytes)?;

    // Return the number of bytes written
    Ok(bytes.len())
}

pub fn fixed_bitset_len(bits: &[bool], size: usize) -> usize {
    // Calculate the minimum size between `size` and `bits.len()`
    let ms = std::cmp::min(size, bits.len());

    // Calculate the number of bytes needed to represent `ms` bits
    ms.div_ceil(8)
}

#[cfg(test)]
mod tests {
    use core::fmt;
    use core::mem::{self, discriminant};

    use super::*;
    use crate::consensus::{Decodable, Encodable, deserialize_partial};
    #[cfg(feature = "std")]
    use crate::network::{Address, message_blockdata::Inventory};
    use crate::{TxIn, TxOut};

    #[test]
    fn serialize_int_test() {
        // bool
        assert_eq!(serialize(&false), vec![0u8]);
        assert_eq!(serialize(&true), vec![1u8]);
        // u8
        assert_eq!(serialize(&1u8), vec![1u8]);
        assert_eq!(serialize(&0u8), vec![0u8]);
        assert_eq!(serialize(&255u8), vec![255u8]);
        // u16
        assert_eq!(serialize(&1u16), vec![1u8, 0]);
        assert_eq!(serialize(&256u16), vec![0u8, 1]);
        assert_eq!(serialize(&5000u16), vec![136u8, 19]);
        // u32
        assert_eq!(serialize(&1u32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256u32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000u32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000u32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090u32), vec![10u8, 10, 10, 10]);
        // i32
        assert_eq!(serialize(&-1i32), vec![255u8, 255, 255, 255]);
        assert_eq!(serialize(&-256i32), vec![0u8, 255, 255, 255]);
        assert_eq!(serialize(&-5000i32), vec![120u8, 236, 255, 255]);
        assert_eq!(serialize(&-500000i32), vec![224u8, 94, 248, 255]);
        assert_eq!(serialize(&-168430090i32), vec![246u8, 245, 245, 245]);
        assert_eq!(serialize(&1i32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256i32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000i32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000i32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090i32), vec![10u8, 10, 10, 10]);
        // u64
        assert_eq!(serialize(&1u64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256u64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000u64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000u64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730u64), vec![10u8, 10, 10, 10, 10, 10, 10, 10]);
        // i64
        assert_eq!(serialize(&-1i64), vec![255u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-256i64), vec![0u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-5000i64), vec![120u8, 236, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-500000i64), vec![224u8, 94, 248, 255, 255, 255, 255, 255]);
        assert_eq!(
            serialize(&-723401728380766730i64),
            vec![246u8, 245, 245, 245, 245, 245, 245, 245]
        );
        assert_eq!(serialize(&1i64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256i64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000i64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000i64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730i64), vec![10u8, 10, 10, 10, 10, 10, 10, 10]);
    }

    #[test]
    fn serialize_varint_test() {
        assert_eq!(serialize(&VarInt(10)), vec![10u8]);
        assert_eq!(serialize(&VarInt(0xFC)), vec![0xFCu8]);
        assert_eq!(serialize(&VarInt(0xFD)), vec![0xFDu8, 0xFD, 0]);
        assert_eq!(serialize(&VarInt(0xFFF)), vec![0xFDu8, 0xFF, 0xF]);
        assert_eq!(serialize(&VarInt(0xF0F0F0F)), vec![0xFEu8, 0xF, 0xF, 0xF, 0xF]);
        assert_eq!(
            serialize(&VarInt(0xF0F0F0F0F0E0)),
            vec![0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0]
        );
        assert_eq!(
            test_varint_encode(0xFF, &0x100000000_u64.to_le_bytes()).unwrap(),
            VarInt(0x100000000)
        );
        assert_eq!(test_varint_encode(0xFE, &0x10000_u64.to_le_bytes()).unwrap(), VarInt(0x10000));
        assert_eq!(test_varint_encode(0xFD, &0xFD_u64.to_le_bytes()).unwrap(), VarInt(0xFD));

        // Test that length calc is working correctly
        test_varint_len(VarInt(0), 1);
        test_varint_len(VarInt(0xFC), 1);
        test_varint_len(VarInt(0xFD), 3);
        test_varint_len(VarInt(0xFFFF), 3);
        test_varint_len(VarInt(0x10000), 5);
        test_varint_len(VarInt(0xFFFFFFFF), 5);
        test_varint_len(VarInt(0xFFFFFFFF + 1), 9);
        test_varint_len(VarInt(u64::MAX), 9);
    }

    fn test_varint_len(varint: VarInt, expected: usize) {
        let mut encoder = vec![];
        assert_eq!(varint.consensus_encode(&mut encoder).unwrap(), expected);
        assert_eq!(varint.len(), expected);
    }

    fn test_varint_encode(n: u8, x: &[u8]) -> Result<VarInt, Error> {
        let mut input = [0u8; 9];
        input[0] = n;
        input[1..x.len() + 1].copy_from_slice(x);
        deserialize_partial::<VarInt>(&input).map(|t| t.0)
    }

    #[test]
    fn deserialize_nonminimal_vec() {
        // Check the edges for variant int
        assert_eq!(
            discriminant(
                &test_varint_encode(0xFF, &(0x100000000_u64 - 1).to_le_bytes()).unwrap_err()
            ),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&test_varint_encode(0xFE, &(0x10000_u64 - 1).to_le_bytes()).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&test_varint_encode(0xFD, &(0xFD_u64 - 1).to_le_bytes()).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );

        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0x00, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0x00, 0x00, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0xff, 0x00, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(
                &deserialize::<Vec<u8>>(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .unwrap_err()
            ),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(
                &deserialize::<Vec<u8>>(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .unwrap_err()
            ),
            discriminant(&Error::NonMinimalVarInt)
        );

        let mut vec_256 = vec![0; 259];
        vec_256[0] = 0xfd;
        vec_256[1] = 0x00;
        vec_256[2] = 0x01;
        assert!(deserialize::<Vec<u8>>(&vec_256).is_ok());

        let mut vec_253 = vec![0; 256];
        vec_253[0] = 0xfd;
        vec_253[1] = 0xfd;
        vec_253[2] = 0x00;
        assert!(deserialize::<Vec<u8>>(&vec_253).is_ok());
    }

    #[test]
    fn serialize_checkeddata_test() {
        let cd = CheckedData(vec![1u8, 2, 3, 4, 5]);
        assert_eq!(serialize(&cd), vec![5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn serialize_vector_test() {
        assert_eq!(serialize(&vec![1u8, 2, 3]), vec![3u8, 1, 2, 3]);
        // TODO: test vectors of more interesting objects
    }

    #[test]
    fn serialize_strbuf_test() {
        assert_eq!(serialize(&"Andrew".to_string()), vec![6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]);
    }

    #[test]
    fn deserialize_int_test() {
        // bool
        assert!((deserialize(&[58u8, 0]) as Result<bool, _>).is_err());
        assert_eq!(deserialize(&[58u8]).ok(), Some(true));
        assert_eq!(deserialize(&[1u8]).ok(), Some(true));
        assert_eq!(deserialize(&[0u8]).ok(), Some(false));
        assert!((deserialize(&[0u8, 1]) as Result<bool, _>).is_err());

        // u8
        assert_eq!(deserialize(&[58u8]).ok(), Some(58u8));

        // u16
        assert_eq!(deserialize(&[0x01u8, 0x02]).ok(), Some(0x0201u16));
        assert_eq!(deserialize(&[0xABu8, 0xCD]).ok(), Some(0xCDABu16));
        assert_eq!(deserialize(&[0xA0u8, 0x0D]).ok(), Some(0xDA0u16));
        let failure16: Result<u16, _> = deserialize(&[1u8]);
        assert!(failure16.is_err());

        // i16
        assert_eq!(deserialize(&[0x32_u8, 0xF4]).ok(), Some(-0x0bce_i16));
        assert_eq!(deserialize(&[0xFF_u8, 0xFE]).ok(), Some(-0x0101_i16));
        assert_eq!(deserialize(&[0x00_u8, 0x00]).ok(), Some(-0_i16));
        assert_eq!(deserialize(&[0xFF_u8, 0xFA]).ok(), Some(-0x0501_i16));

        // u32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABu32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD]).ok(), Some(0xCDAB0DA0u32));

        let failure32: Result<u32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failure32.is_err());

        // i32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABi32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0x2D]).ok(), Some(0x2DAB0DA0i32));

        assert_eq!(deserialize(&[0, 0, 0, 0]).ok(), Some(-0_i32));
        assert_eq!(deserialize(&[0, 0, 0, 0]).ok(), Some(0_i32));

        assert_eq!(deserialize(&[0xFF, 0xFF, 0xFF, 0xFF]).ok(), Some(-1_i32));
        assert_eq!(deserialize(&[0xFE, 0xFF, 0xFF, 0xFF]).ok(), Some(-2_i32));
        assert_eq!(deserialize(&[0x01, 0xFF, 0xFF, 0xFF]).ok(), Some(-255_i32));
        assert_eq!(deserialize(&[0x02, 0xFF, 0xFF, 0xFF]).ok(), Some(-254_i32));

        let failurei32: Result<i32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failurei32.is_err());

        // u64
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABu64));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(0x99000099CDAB0DA0u64)
        );
        let failure64: Result<u64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failure64.is_err());

        // i64
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABi64));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(-0x66ffff663254f260i64)
        );
        assert_eq!(
            deserialize(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-1_i64)
        );
        assert_eq!(
            deserialize(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-2_i64)
        );
        assert_eq!(
            deserialize(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-255_i64)
        );
        assert_eq!(
            deserialize(&[0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-254_i64)
        );

        let failurei64: Result<i64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failurei64.is_err());
    }

    #[test]
    fn deserialize_vec_test() {
        assert_eq!(deserialize(&[3u8, 2, 3, 4]).ok(), Some(vec![2u8, 3, 4]));
        assert!((deserialize(&[4u8, 2, 3, 4, 5, 6]) as Result<Vec<u8>, _>).is_err());
        // found by cargo fuzz
        assert!(
            deserialize::<Vec<u64>>(&[
                0xff, 0xff, 0xff, 0xff, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
                0x6b, 0x6b, 0xa, 0xa, 0x3a
            ])
            .is_err()
        );

        let rand_io_err = Error::Io(io::Error::other(""));

        // Check serialization that `if len > MAX_VEC_SIZE {return err}` isn't inclusive,
        // by making sure it fails with IO Error and not an `OversizedVectorAllocation` Error.
        let err =
            deserialize::<CheckedData>(&serialize(&(super::MAX_VEC_SIZE as u32))).unwrap_err();
        assert_eq!(discriminant(&err), discriminant(&rand_io_err));

        test_len_is_max_vec::<u8>();
        test_len_is_max_vec::<BlockHash>();
        test_len_is_max_vec::<FilterHash>();
        test_len_is_max_vec::<TxMerkleNode>();
        test_len_is_max_vec::<Transaction>();
        test_len_is_max_vec::<TxOut>();
        test_len_is_max_vec::<TxIn>();
        test_len_is_max_vec::<Vec<u8>>();
        test_len_is_max_vec::<u64>();
        #[cfg(feature = "std")]
        test_len_is_max_vec::<(u32, Address)>();
        #[cfg(feature = "std")]
        test_len_is_max_vec::<Inventory>();
    }

    fn test_len_is_max_vec<T>()
    where
        Vec<T>: Decodable,
        T: fmt::Debug,
    {
        let rand_io_err = Error::Io(io::Error::other(""));
        let varint = VarInt((super::MAX_VEC_SIZE / mem::size_of::<T>()) as u64);
        let err = deserialize::<Vec<T>>(&serialize(&varint)).unwrap_err();
        assert_eq!(discriminant(&err), discriminant(&rand_io_err));
    }

    #[test]
    fn deserialize_strbuf_test() {
        assert_eq!(
            deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(),
            Some("Andrew".to_string())
        );
        assert_eq!(
            deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(),
            Some(Cow::Borrowed("Andrew"))
        );
    }

    #[test]
    fn deserialize_checkeddata_test() {
        let cd: Result<CheckedData, _> =
            deserialize(&[5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
        assert_eq!(cd.ok(), Some(CheckedData(vec![1u8, 2, 3, 4, 5])));
    }

    #[test]
    fn limit_read_test() {
        let large_data = vec![vec![0u8; 3_999_999]; 2];
        let ser = serialize(&large_data);
        let mut reader = io::Cursor::new(ser);
        let err = Vec::<Vec<u8>>::consensus_decode(&mut reader);
        assert!(err.is_err());
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn serialization_round_trips() {
        use secp256k1::rand::{Rng, thread_rng};

        macro_rules! round_trip {
            ($($val_type:ty),*) => {
                $(
                    let r: $val_type = thread_rng().r#gen();
                    assert_eq!(deserialize::<$val_type>(&serialize(&r)).unwrap(), r);
                )*
            };
        }
        macro_rules! round_trip_bytes {
            ($(($val_type:ty, $data:expr)),*) => {
                $(
                    thread_rng().fill(&mut $data[..]);
                    assert_eq!(deserialize::<$val_type>(&serialize(&$data)).unwrap()[..], $data[..]);
                )*
            };
        }

        let mut data = Vec::with_capacity(256);
        let mut data64 = Vec::with_capacity(256);
        for _ in 0..10 {
            round_trip! {bool, i8, u8, i16, u16, i32, u32, i64, u64,
            (bool, i8, u16, i32), (u64, i64, u32, i32, u16, i16), (i8, u8, i16, u16, i32, u32, i64, u64),
            [u8; 2], [u8; 4], [u8; 8], [u8; 12], [u8; 16], [u8; 32]}

            data.clear();
            data64.clear();
            let len = thread_rng().gen_range(1..256);
            data.resize(len, 0u8);
            data64.resize(len, 0u64);
            let mut arr33 = [0u8; 33];
            let mut arr16 = [0u16; 8];
            round_trip_bytes! {(Vec<u8>, data), ([u8; 33], arr33), ([u16; 8], arr16), (Vec<u64>, data64)}
        }
    }

    #[test]
    fn test_read_bytes_from_finite_reader() {
        let data: Vec<u8> = (0..10).collect();

        for chunk_size in 1..20 {
            assert_eq!(
                read_bytes_from_finite_reader(
                    io::Cursor::new(&data),
                    ReadBytesFromFiniteReaderOpts {
                        len: data.len(),
                        chunk_size
                    },
                )
                .unwrap(),
                data
            );
        }
    }

    #[test]
    fn test_compact_size_round_trip() {
        let test_values =
            vec![0u32, 1, 252, 253, 254, 255, 300, 5000, 65535, 65536, 70000, 1_000_000, u32::MAX];

        for &value in &test_values {
            let mut buffer = Vec::new();
            // Write the value to the buffer
            write_compact_size(&mut buffer, value).expect("Failed to write");
            // Read the value back from the buffer
            let mut cursor = Cursor::new(&buffer);
            let read_value = read_compact_size(&mut cursor).expect("Failed to read");

            // Assert that the original value matches the deserialized value
            assert_eq!(
                value, read_value,
                "Deserialized value does not match original for value {}",
                value
            );

            // Ensure that we've consumed all bytes (no extra bytes left)
            let position = cursor.position();
            assert_eq!(
                position as usize,
                buffer.len(),
                "Not all bytes were consumed for value {}",
                value
            );
        }
    }

    #[test]
    fn test_fixed_bitset_round_trip() {
        let test_cases = vec![
            (vec![], 0, true), // (bits, size, expect_success)
            (vec![true, false, true, false, true, false, true, false], 8, true),
            (vec![true; 10], 10, true),
            (vec![false; 15], 15, true),
            (vec![true, false, true], 16, false), // size greater than bits.len()
            (
                vec![
                    true, false, true, false, true, false, true, false, true, false, true, false,
                    true, false, true, false, true, false, true, false, true, false, true, false,
                ],
                24,
                true,
            ),
        ];

        for (bits, size, expect_success) in test_cases {
            let mut buffer = Vec::new();
            // Attempt to write the bitset to the buffer
            let result = write_fixed_bitset(&mut buffer, &bits, size);

            if expect_success {
                // Expect the write to succeed
                let bytes_written = result.expect("Failed to write");
                // Calculate expected bytes written
                let expected_bytes = size.div_ceil(8);
                assert_eq!(
                    bytes_written, expected_bytes,
                    "Incorrect number of bytes written for bitset with size {}",
                    size
                );

                // Read the bitset back from the buffer
                let mut cursor = Cursor::new(&buffer);
                let read_bits = read_fixed_bitset(&mut cursor, size).expect("Failed to read");

                // Assert that the original bits match the deserialized bits
                assert_eq!(
                    read_bits, bits,
                    "Deserialized bits do not match original for size {}",
                    size
                );

                // Ensure that we've consumed all bytes (no extra bytes left)
                let position = cursor.position();
                assert_eq!(
                    position as usize,
                    buffer.len(),
                    "Not all bytes were consumed for size {}",
                    size
                );
            } else {
                // Expect the write to fail
                assert!(
                    result.is_err(),
                    "Expected write to fail for bits.len() < size (size: {}, bits.len(): {})",
                    size,
                    bits.len()
                );
            }
        }
    }
}
