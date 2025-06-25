//! Bitcoin Connection Bloom filtering network messages.
//!
//! This module describes BIP37 Connection Bloom filtering network messages.
//!

use std::io;

use crate::bloom::BloomFilter;
use crate::consensus::{Decodable, Encodable, ReadExt, encode};
use crate::internal_macros::impl_consensus_encoding;

/// `filterload` message sets the current bloom filter
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterLoad {
    /// The filter itself
    pub filter: Vec<u8>,
    /// The number of hash functions to use
    pub hash_funcs: u32,
    /// A random value
    pub tweak: u32,
    /// Controls how matched items are added to the filter
    pub flags: BloomFlags,
}

impl FilterLoad {
    /// Create a FilterLoad message from a BloomFilter
    pub fn from_bloom_filter(filter: &BloomFilter) -> Self {
        FilterLoad {
            filter: filter.to_bytes(),
            hash_funcs: filter.hash_funcs(),
            tweak: filter.tweak(),
            flags: filter.flags(),
        }
    }

    /// Convert to a BloomFilter
    pub fn to_bloom_filter(&self) -> Result<BloomFilter, crate::bloom::BloomError> {
        BloomFilter::from_bytes(
            self.filter.clone(),
            self.hash_funcs,
            self.tweak,
            self.flags,
        )
    }
}

impl_consensus_encoding!(FilterLoad, filter, hash_funcs, tweak, flags);

/// Bloom filter update flags
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BloomFlags {
    /// Never update the filter with outpoints.
    None,
    /// Always update the filter with outpoints.
    All,
    /// Only update the filter with outpoints if it is P2PK or P2MS
    PubkeyOnly,
}

impl Encodable for BloomFlags {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.write_all(&[match self {
            BloomFlags::None => 0,
            BloomFlags::All => 1,
            BloomFlags::PubkeyOnly => 2,
        }])?;
        Ok(1)
    }
}

impl Decodable for BloomFlags {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(match r.read_u8()? {
            0 => BloomFlags::None,
            1 => BloomFlags::All,
            2 => BloomFlags::PubkeyOnly,
            _ => return Err(encode::Error::ParseFailed("unknown bloom flag")),
        })
    }
}

/// `filteradd` message updates the current filter with new data
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterAdd {
    /// The data element to add to the current filter.
    pub data: Vec<u8>,
}

impl_consensus_encoding!(FilterAdd, data);
