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

//! Dash Quorum Commitment Special Transaction.
//!
//! It is defined in DIP6 https://github.com/dashpay/dips/blob/master/dip-0006.md.
//!

use ::{OutPoint, Script};
use ::{QuorumHash, VarInt};

pub struct QuorumFinalizationCommitment {
    version: u16,
    llmq_type: u8,
    quorum_hash: QuorumHash,
    signers: Vec<u8>,
    valid_members: Vec<u8>,
    quorum_public_key: [u8; 48],
    quorum_vvec_hash: [u8; 32],
    quorum_sig: [u8; 96],
    sig: [u8; 96],
}

pub struct QuorumCommitmentPayload {
    version: u16,
    height: u32,
    commitment: QuorumFinalizationCommitment,
}