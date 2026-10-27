// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use dash_params::{ChainParams, Network as CoreNetwork};
use hashes::{Hash, sha256d};

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::script::ScriptBuf;
use crate::blockdata::transaction::Transaction;
use crate::blockdata::transaction::outpoint::OutPoint;
use crate::blockdata::transaction::txin::TxIn;
use crate::blockdata::transaction::txout::TxOut;
use crate::blockdata::witness::Witness;
use crate::network::constants::Network;
use crate::pow::CompactTarget;

/// How many satoshis are in "one dash".
pub const COIN_VALUE: u64 = 100_000_000;
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (dash) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 76;
// 0x4C
/// Mainnet (dash) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 16;
// 0x10
/// Test (testnet, devnet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 140;
// 0x8C
/// Test (testnet, devnet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 19;
// 0x13
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub const MAX_MONEY: u64 = 21_000_000 * COIN_VALUE;

/// Chain parameters whose genesis block `network` uses: regtest's for devnets.
pub(crate) const fn genesis_chain_params(network: Network) -> &'static ChainParams {
    match network.chain_params() {
        Some(chain) => chain,
        None => CoreNetwork::Regtest.chain(),
    }
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let genesis = &genesis_chain_params(network).genesis;
    let txdata = vec![Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO.to_consensus_u32(),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from(genesis.script_sig.to_vec()),
            sequence: 0xFFFFFFFF,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: genesis.reward.to_sat(),
            script_pubkey: ScriptBuf::from(genesis.script_pubkey.to_vec()),
        }],
        special_transaction_payload: None,
    }];
    let merkle_root: sha256d::Hash = txdata[0].txid().into();

    Block {
        header: block::Header {
            version: block::Version::from_consensus(genesis.version),
            prev_blockhash: Hash::all_zeros(),
            merkle_root: merkle_root.into(),
            time: genesis.time,
            bits: CompactTarget::from_consensus(genesis.bits),
            nonce: genesis.nonce,
        },
        txdata,
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::BlockHash;
    use crate::network::constants::NetworkExt;

    #[test_case(
        Network::Mainnet,
        "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6"
    )]
    #[test_case(
        Network::Testnet,
        "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c"
    )]
    #[test_case(
        Network::Devnet,
        "000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"
    )]
    #[test_case(
        Network::Regtest,
        "000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"
    )]
    fn genesis_block_hashes_to_the_known_genesis_hash(network: Network, hash: &str) {
        let hash: BlockHash = hash.parse().unwrap();
        assert_eq!(genesis_block(network).block_hash(), hash);
        assert_eq!(network.known_genesis_block_hash(), hash);
    }
}
