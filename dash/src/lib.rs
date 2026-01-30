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

//! # Rust Dash Library
//!
//! This is a library that supports the Dash network protocol and associated
//! primitives. It is designed for Rust programs built to work with the Bitcoin
//! network.
//!
//! It is also written entirely in Rust to illustrate the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!
//! See README.md for detailed documentation about development and supported
//! environments.
//!
//! ## Available feature flags
//!
//! * `std` - the usual dependency on `std` (default).
//! * `secp-recovery` - enables calculating public key from a signature and message.
//! * `signer` - enables singing and validation ECDSA helpers.
//! * `base64` - (dependency), enables encoding of PSBTs and message signatures.
//! * `unstable` - enables unstable features for testing.
//! * `rand` - (dependency), makes it more convenient to generate random values.
//! * `bincode` - (dependency), implements bincode serialization and deserialization.
//! * `serde` - (dependency), implements `serde`-based serialization and deserialization.
//! * `secp-lowmemory` - optimizations for low-memory devices.
//! * `no-std` - enables additional features required for this crate to be usable
//!   without std. Does **not** disable `std`. Depends on `core2`.
//!

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions
// #![warn(missing_docs)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!(
    "rust-dash currently only supports architectures with pointers wider than 16 bits, let us
    know if you want 16-bit support. Note that we do NOT guarantee that we will implement it!"
);

#[cfg(bench)]
extern crate test;

#[macro_use]
extern crate alloc;

#[cfg(feature = "base64")]
pub extern crate base64;
pub extern crate bech32;
#[cfg(feature = "bitcoinconsensus")]
pub extern crate bitcoinconsensus;
pub extern crate dashcore_hashes as hashes;
pub extern crate secp256k1;

#[cfg(feature = "blsful")]
pub use blsful;
#[cfg(feature = "ed25519-dalek")]
pub use ed25519_dalek;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
extern crate core;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(test)]
#[macro_use]
mod test_macros;
mod internal_macros;
mod parse;
#[cfg(feature = "serde")]
pub mod serde_utils;

#[macro_use]
pub mod network;
pub mod address;
pub mod amount;
pub mod base58;
pub mod bip152;
pub mod bip158;
pub mod blockdata;
pub mod bloom;
pub mod consensus;
// Private until we either make this a crate or flatten it - still to be decided.
pub mod bls_sig_utils;
pub mod crypto;
pub mod ephemerealdata;
pub mod error;
pub mod hash_types;
pub mod merkle_tree;
pub mod policy;
pub mod pow;
pub mod sign_message;
pub mod signer;
pub mod sml;
pub mod string;
pub mod util;
// pub mod serialize;

// May depend on crate features and we don't want to bother with it
#[allow(unused)]
#[cfg(feature = "std")]
use std::error::Error as StdError;
#[cfg(feature = "std")]
pub use std::io;

#[allow(unused)]
#[cfg(not(feature = "std"))]
use core2::error::Error as StdError;
#[cfg(not(feature = "std"))]
use core2::io;

pub use crate::address::{Address, AddressType};
pub use crate::amount::{Amount, Denomination, SignedAmount};
pub use crate::blockdata::block::{self, Block, Header};
pub use crate::blockdata::fee_rate::FeeRate;
pub use crate::blockdata::locktime::{self, absolute, relative};
pub use crate::blockdata::script::{self, Script, ScriptBuf};
pub use crate::blockdata::transaction::{self, Transaction};
pub use crate::blockdata::weight::Weight;
pub use crate::blockdata::{constants, opcodes};
pub use crate::consensus::encode::VarInt;
pub use crate::crypto::key::{self, PrivateKey, PublicKey};
pub use crate::crypto::{ecdsa, sighash, sighash::EcdsaSighashType};
pub use crate::ephemerealdata::chain_lock::ChainLock;
pub use crate::ephemerealdata::instant_lock::InstantLock;
pub use crate::error::Error;
pub use crate::hash_types::{
    BlockHash, FilterHash, ProTxHash, PubkeyHash, QuorumHash, QuorumSigningRequestId, ScriptHash,
    TxMerkleNode, Txid,
};
pub use crate::merkle_tree::MerkleBlock;
pub use crate::pow::{CompactTarget, Target, Work};
pub use crate::transaction::outpoint::OutPoint;
pub use crate::transaction::txin::TxIn;
pub use crate::transaction::txout::TxOut;
pub use dash_network::Network;

#[cfg(not(feature = "std"))]
mod io_extras {
    /// A writer which will move data into the void.
    pub struct Sink {
        _priv: (),
    }

    /// Creates an instance of a writer which will successfully consume all data.
    pub const fn sink() -> Sink {
        Sink {
            _priv: (),
        }
    }

    impl core2::io::Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
            Ok(buf.len())
        }

        #[inline]
        fn flush(&mut self) -> core2::io::Result<()> {
            Ok(())
        }
    }
}

#[rustfmt::skip]
pub mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, Cow, ToOwned}, slice, rc};

    #[cfg(all(not(feature = "std"), not(test), target_has_atomic = "ptr"))]
    pub use alloc::sync;

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, Cow, ToOwned}, slice, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "std")]
    pub use std::io::sink;

    #[cfg(not(feature = "std"))]
    pub use crate::io_extras::sink;

    pub use internals::hex::display::DisplayHex;

    pub type CoreBlockHeight = u32;
}

#[cfg(bench)]
use bench::EmptyWrite;

#[cfg(bench)]
mod bench {
    use core::fmt::Arguments;

    use crate::io::{IoSlice, Result, Write};

    #[derive(Default, Clone, Debug, PartialEq, Eq)]
    pub struct EmptyWrite;

    impl Write for EmptyWrite {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            Ok(buf.len())
        }
        fn write_vectored(&mut self, bufs: &[IoSlice]) -> Result<usize> {
            Ok(bufs.iter().map(|s| s.len()).sum())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }

        fn write_all(&mut self, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn write_fmt(&mut self, _: Arguments) -> Result<()> {
            Ok(())
        }
    }
}
