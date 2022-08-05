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

//! Dash Coinbase Special Transaction.
//!
//! Each time a block is mined it includes a coinbase special transaction.
//! It is defined in DIP4 https://github.com/dashpay/dips/blob/master/dip-0004.md.
//!

use ::{OutPoint, Script};
use ::{MerkleRootMasternodeList, MerkleRootQuorums, VarInt};

pub struct CoinbasePayload {
    version: u16,
    height: u32,
    merkle_root_masternode_list: MerkleRootMasternodeList,
    merkle_root_quorums: MerkleRootQuorums,
}