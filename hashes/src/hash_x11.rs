//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! An implementation of a hash engine wrapper for the proof of work hash.

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;
use std::io;

use dash_pow::__deps::digest::Digest;
use dash_pow::X11;

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
        Hash(e.hasher.finalize().into())
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

/// An X11 hashing engine.
#[derive(Clone, Default)]
pub struct HashEngine {
    hasher: X11,
    length: usize,
}

impl crate::HashEngine for HashEngine {
    type MidState = [u8; 32];

    const BLOCK_SIZE: usize = 32;

    fn midstate(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.length += data.len();
    }

    fn n_bytes_hashed(&self) -> usize {
        self.length
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
    use test_case::test_case;

    use crate::{hash_x11, Hash, HashEngine};

    #[test_case(&[], hex!("51b572209083576ea221c27e62b4e22063257571ccb6cc3dc3cd17eb67584eba"); "empty")]
    #[test_case(&hex!("020000002cc0081be5039a54b686d24d5d8747ee9770d9973ec1ace02e5c0500000000008d7139724b11c52995db4370284c998b9114154b120ad3486f1a360a1d4253d310d40e55b8f70a1be8e32300"), hex!("f29c0f286fd8071669286c6987eb941181134ff5f3978bf89f34070000000000"); "header")]
    #[test_case(&(0..123).collect::<Vec<u8>>(), hex!("132ead25e64bf5cda54d198b3dc77bd7032e856f724dcd39c503ef3183462b5d"); "123 bytes")]
    fn hash(data: &[u8], expected: [u8; 32]) {
        assert_eq!(hash_x11::Hash::hash(data).to_byte_array(), expected);

        let mut engine = hash_x11::Hash::engine();
        let (head, tail) = data.split_at(data.len() / 2);
        engine.input(head);
        engine.input(tail);
        assert_eq!(engine.n_bytes_hashed(), data.len());
        assert_eq!(hash_x11::Hash::from_engine(engine).to_byte_array(), expected);
    }
}
