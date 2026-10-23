// Rust Dash Library
// Originally written in 2014 by
//     Dmitrii Golubev <dmitrii.golubev@dash.org>
//     For Dash
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

//! An implementation of a hash engine to support the X11 hash,
//! which is a wrapper around the rs-x11-hash library.

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;
use std::io;
use std::vec::Vec;

use crate::{FromSliceError, HashEngine as _};

/// Output of the X11 hash function.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Hash([u8; 32]);

crate::hex_fmt_impl!(<Hash as crate::Hash>::DISPLAY_BACKWARD, 32, Hash);
crate::serde_impl!(Hash, 32);
crate::bincode_impl!(Hash, 32);
crate::borrow_slice_impl!(Hash);

impl str::FromStr for Hash {
    type Err = hex_conservative::DecodeFixedLengthBytesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes: [u8; 32] = hex_conservative::decode_to_array(s)?;
        bytes.reverse();
        Ok(Hash(bytes))
    }
}

impl AsRef<[u8; 32]> for Hash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<I: SliceIndex<[u8]>> Index<I> for Hash {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> [u8; 32] {
        hash.0
    }
}

impl crate::Hash for Hash {
    type Engine = HashEngine;
    type Bytes = [u8; 32];

    const LEN: usize = 32;
    const DISPLAY_BACKWARD: bool = true;

    fn from_engine(e: HashEngine) -> Self {
        Hash(e.midstate())
    }

    fn from_slice(sl: &[u8]) -> Result<Self, FromSliceError> {
        // `FromSliceError` is only constructible upstream, so a hash of the
        // same size checks the length.
        crate::sha256d::Hash::from_slice(sl).map(|h| Hash(h.to_byte_array()))
    }

    fn to_byte_array(self) -> [u8; 32] {
        self.0
    }

    fn as_byte_array(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_byte_array(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    fn all_zeros() -> Self {
        Hash([0; 32])
    }
}

/// An X11 hashing engine. X11 is not incremental, so the input is buffered.
#[derive(Clone, Default)]
pub struct HashEngine {
    buf: Vec<u8>,
}

impl crate::HashEngine for HashEngine {
    type MidState = [u8; 32];

    const BLOCK_SIZE: usize = 32;

    fn midstate(&self) -> [u8; 32] {
        rs_x11_hash::get_x11_hash(self.buf.as_slice())
    }

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn n_bytes_hashed(&self) -> usize {
        self.buf.len()
    }
}

impl io::Write for HashEngine {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hex_conservative::hex;

    use crate::{hash_x11, Hash, HashEngine};

    const HEADER: [u8; 80] = hex!("020000002cc0081be5039a54b686d24d5d8747ee9770d9973ec1ace02e5c0500000000008d7139724b11c52995db4370284c998b9114154b120ad3486f1a360a1d4253d310d40e55b8f70a1be8e32300");
    const HEADER_HASH: [u8; 32] =
        hex!("f29c0f286fd8071669286c6987eb941181134ff5f3978bf89f34070000000000");

    /// The block header vector from `rs-x11-hash`.
    #[test]
    fn block_header() {
        assert_eq!(hash_x11::Hash::hash(&HEADER).to_byte_array(), HEADER_HASH);
    }

    /// A header split across writes hashes like the whole.
    #[test]
    fn split_header() {
        let mut engine = hash_x11::Hash::engine();
        engine.input(&HEADER[..50]);
        engine.input(&HEADER[50..]);
        assert_eq!(engine.n_bytes_hashed(), 80);
        assert_eq!(hash_x11::Hash::from_engine(engine).to_byte_array(), HEADER_HASH);
    }
}
