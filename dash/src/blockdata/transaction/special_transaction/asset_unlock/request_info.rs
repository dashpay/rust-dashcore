// Rust Dash Library
// Written for Dash in 2022 by
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

//! Dash Asset unlock Special Transaction request info.
//!
//! The asset unlock special transaction is used to withdraw from the asset lock credit pool.
//!
//! The request info should be added once the quorum selection for signing has been made.

use crate::io;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{QuorumHash};
use crate::prelude::*;

/// An asset unlock request info
/// This is the information about the signing quorum
/// The request height should be the height at which the specified quorum is active on core.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct AssetUnlockRequestInfo {
    /// The core request height of the transaction. This should match a period where the quorum_hash
    /// is still active
    pub request_height: u32,
    /// The quorum hash. This is the block hash when the quorum was created.
    pub quorum_hash: QuorumHash,
}

impl AssetUnlockRequestInfo {
    /// Encodes the asset unlock on top of
    pub fn consensus_append_to_base_encode<S: io::Write>(&self, base_bytes: Vec<u8>, mut s: S) -> Result<usize, io::Error> {
        s.write(base_bytes.as_slice())?;
        let mut len = base_bytes.len();
        len += self.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Encodable for AssetUnlockRequestInfo {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.request_height.consensus_encode(w)?;
        len += self.quorum_hash.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockRequestInfo {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let request_height = u32::consensus_decode(r)?;
        let quorum_hash = QuorumHash::consensus_decode(r)?;
        Ok(AssetUnlockRequestInfo {
            request_height,
            quorum_hash,
        })
    }
}
