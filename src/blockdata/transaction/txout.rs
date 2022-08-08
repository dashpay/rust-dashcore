// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Refactored for Dash in 2022 by
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

//! Dash TxOut.
//!
//! A TxOut is an output of a transaction.
//!

use Script;

/// A transaction output, which defines new coins to be created from old ones.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxOut {
    /// The value of the output, in satoshis.
    pub value: u64,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: Script
}

// This is used as a "null txout" in consensus signing code.
impl Default for TxOut {
    fn default() -> TxOut {
        TxOut { value: 0xffffffffffffffff, script_pubkey: Script::new() }
    }
}

impl_consensus_encoding!(TxOut, value, script_pubkey);