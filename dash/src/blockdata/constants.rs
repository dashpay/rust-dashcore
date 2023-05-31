// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;
use hashes::{Hash, sha256d};
use hex_lit::hex;
use internals::impl_array_newtype;

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script;
use crate::blockdata::transaction::{outpoint::OutPoint, Transaction, txin::TxIn, txout::TxOut};
use crate::blockdata::witness::Witness;
use crate::internal_macros::impl_bytes_newtype;
use crate::network::constants::Network;
use crate::pow::CompactTarget;

/// How many satoshis are in "one dash".
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (dash) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 76; // 0x4C
/// Mainnet (dash) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 16; // 0x10
/// Test (testnet, devnet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 140; // 0x8C
/// Test (testnet, devnet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 19; // 0x13
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub const MAX_MONEY: u64 = 21_000_000 * COIN_VALUE;

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO.to_consensus_u32(),
        input: vec![],
        output: vec![],
        special_transaction_payload: None,
    };

    // Inputs
    let in_script = script::Builder::new()
        .push_int(486604799)
        .push_int_non_minimal(4)
        .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
        .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: 0xFFFFFFFF,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
    let out_script =
        script::Builder::new().push_slice(script_bytes).push_opcode(OP_CHECKSIG).into_script();
    ret.output.push(TxOut { value: 50 * COIN_VALUE, script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Dash => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1231006505,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 2083236893,
            },
            txdata,
        },
        Network::Testnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 414098458,
            },
            txdata,
        },
        Network::Devnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1598918400,
                bits: CompactTarget::from_consensus(0x1e0377ae),
                nonce: 52613770,
            },
            txdata,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 2,
            },
            txdata,
        },
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet dash.
    pub const DASH: Self = Self([
        158, 200, 179, 141, 168, 16, 7, 209, 175, 9, 245, 190, 45, 242, 47, 39, 206, 210, 244, 95,
        244, 64, 51, 148, 171, 36, 158, 149, 202, 125, 244, 214
    ]);
    /// `ChainHash` for testnet dash.
    pub const TESTNET: Self = Self([
        109, 190, 101, 107, 217, 106, 128, 75, 237, 234, 124, 69, 181, 127, 252, 241, 47, 90, 113,
        76, 240, 10, 107, 143, 205, 30, 239, 201, 20, 200, 170, 223
    ]);
    /// `ChainHash` for devnet dash.
    pub const DEVNET: Self = Self([
        210, 55, 61, 64, 56, 40, 220, 16, 73, 236, 144, 245, 48, 15, 60, 225, 224, 52, 184, 34, 240,
        52, 172, 101, 17, 196, 40, 216, 139, 7, 44, 79
    ]);
    /// `ChainHash` for regtest dash.
    pub const REGTEST: Self = Self([
        12, 114, 216, 95, 211, 222, 54, 46, 230, 206, 30, 27, 105, 136, 123, 6, 215, 189, 206, 15,
        146, 148, 227, 57, 191, 224, 171, 74, 113, 116, 159, 143
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::DASH, Self::TESTNET, Self::DEVNET, Self::REGTEST];
        hashes[network as usize]
    }

    /// Converts genesis block hash into `ChainHash`.
    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::consensus::encode::serialize;
    use crate::internal_macros::hex;
    use crate::network::constants::Network;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"));

        assert_eq!(gen.input[0].sequence, u32::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"));
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, 0);

        assert_eq!(
            gen.wtxid().to_string(),
            "57cd9b1778f398d84234e9101b1c3147cf0dcae52b9ecdc24242dd655ced06cc"
        );
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Dash);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "57cd9b1778f398d84234e9101b1c3147cf0dcae52b9ecdc24242dd655ced06cc"
        );

        assert_eq!(gen.header.time, 1231006505);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header.nonce, 2083236893);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "9ec8b38da81007d1af09f5be2df22f27ced2f45ff4403394ab249e95ca7df4d6"
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "57cd9b1778f398d84234e9101b1c3147cf0dcae52b9ecdc24242dd655ced06cc"
        );
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header.nonce, 414098458);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "6dbe656bd96a804bedea7c45b57ffcf12f5a714cf00a6b8fcd1eefc914c8aadf"
        );
    }

    #[test]
    fn devnet_genesis_full_block() {
        let gen = genesis_block(Network::Devnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "57cd9b1778f398d84234e9101b1c3147cf0dcae52b9ecdc24242dd655ced06cc"
        );
        assert_eq!(gen.header.time, 1598918400);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0377ae));
        assert_eq!(gen.header.nonce, 52613770);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "d2373d403828dc1049ec90f5300f3ce1e034b822f034ac6511c428d88b072c4f"
        );
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        let want = format!("{:02x}", genesis_hash);

        let chain_hash = ChainHash::using_genesis_block(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        #[allow(unreachable_patterns)] // This is specifically trying to catch later added variants.
        match network {
            Network::Dash => {},
            Network::Testnet => {},
            Network::Devnet => {},
            Network::Regtest => {},
            _ => panic!("Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants"),
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Dash;
        testnet_chain_hash_genesis_block, Network::Testnet;
        devnet_chain_hash_genesis_block, Network::Devnet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(Network::Dash).to_string();
        let want = "9ec8b38da81007d1af09f5be2df22f27ced2f45ff4403394ab249e95ca7df4d6";
        assert_eq!(got, want);
    }
}
