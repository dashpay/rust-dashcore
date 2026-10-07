// Dash Hashes Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Rust hashes library.
//!
//! The hash functions themselves are re-exported from `bitcoin_hashes`. What
//! this crate adds is the Dash newtype machinery over them: `hash_newtype!`
//! and its `bincode`, `serde` and hex surface, plus the batch SipHash used by
//! compact filter matching.
//!
//! ## Commonly used operations
//!
//! Hashing a single byte slice or a string:
//!
//! ```rust
//! use dashcore_hashes::sha256;
//! use dashcore_hashes::Hash;
//!
//! let bytes = [0u8; 5];
//! let hash_of_bytes = sha256::Hash::hash(&bytes);
//! let hash_of_string = sha256::Hash::hash("some string".as_bytes());
//! ```
//!
//!
//! Hashing content from a reader:
//!
//! ```rust
//! use dashcore_hashes::sha256;
//! use dashcore_hashes::Hash;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut reader: &[u8] = b"hello"; // in real code, this could be a `File` or `TcpStream`
//! let mut engine = sha256::HashEngine::default();
//! std::io::copy(&mut reader, &mut engine)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```
//!
//!
//! Hashing content by [`std::io::Write`] on HashEngine:
//!
//! ```rust
//! use dashcore_hashes::sha256;
//! use dashcore_hashes::Hash;
//! use std::io::Write;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut part1: &[u8] = b"hello";
//! let mut part2: &[u8] = b" ";
//! let mut part3: &[u8] = b"world";
//! let mut engine = sha256::HashEngine::default();
//! engine.write_all(part1)?;
//! engine.write_all(part2)?;
//! engine.write_all(part3)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```

// Coding conventions
#![warn(missing_docs)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Benchmarks have been disabled - convert to criterion
// #![cfg_attr(bench, feature(test))]
// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]

#[cfg(feature = "serde")]
pub extern crate serde;

pub extern crate bitcoin_hashes;

#[doc(hidden)]
pub mod _export {
    pub use hex_conservative;

    pub use crate::util::pad_hex;
    /// A re-export of core::*
    pub mod _core {
        pub use core::*;
    }
}

// Primitives come straight from upstream.
// The tag helpers are upstream's verbatim. Only `sha256t_hash_newtype!` stays
// ours, so that tagged hashes route through our `hash_newtype!`.
pub use bitcoin_hashes::{
    cmp, hash160, hmac, ripemd160, sha1, sha256, sha256d, sha512, sha512_256, FromSliceError, Hash,
    HashEngine, Hmac, HmacEngine,
};
pub use bitcoin_hashes::{sha256t_hash_newtype_tag, sha256t_hash_newtype_tag_constructor};

/// Kept under the old Dash name.
pub type Error = FromSliceError;

#[macro_use]
mod util;
#[macro_use]
pub mod serde_macros;
mod bincode_macros;
#[cfg(feature = "x11")]
pub mod hash_x11;
pub mod sha256t;
pub mod siphash24;
