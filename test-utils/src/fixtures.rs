//! Common test fixtures and constants

use dashcore::hash_types::{BlockHash, Txid};
use dashcore_hashes::Hash;
use hex::decode;

/// Genesis block hash for mainnet
pub const MAINNET_GENESIS_HASH: &str =
    "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6";

/// Genesis block hash for testnet
pub const TESTNET_GENESIS_HASH: &str =
    "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c";

/// Common test addresses
pub mod addresses {
    pub const MAINNET_P2PKH: &str = "XcQjD5Gs5i6kLmfFGJC3aS14PdLp1bEDk8";
    pub const MAINNET_P2SH: &str = "7gnwGHt17heGpG9CrJQjqXDLpTGeLpJV8s";
    pub const TESTNET_P2PKH: &str = "yNDp7n5JHJnG4yLJbD8pSr8YKuhrFERCTG";
    pub const TESTNET_P2SH: &str = "8j7NfpSwYJrnQKJvvbFckbE9NCUjYCpPN2";
}

/// Get mainnet genesis block hash
pub fn mainnet_genesis_hash() -> BlockHash {
    let bytes = decode(MAINNET_GENESIS_HASH).unwrap();
    let mut reversed = [0u8; 32];
    reversed.copy_from_slice(&bytes);
    reversed.reverse();
    BlockHash::from_slice(&reversed).unwrap()
}

/// Get testnet genesis block hash  
pub fn testnet_genesis_hash() -> BlockHash {
    let bytes = decode(TESTNET_GENESIS_HASH).unwrap();
    let mut reversed = [0u8; 32];
    reversed.copy_from_slice(&bytes);
    reversed.reverse();
    BlockHash::from_slice(&reversed).unwrap()
}

/// Common test transaction IDs
pub mod txids {
    use super::*;

    /// Example coinbase transaction
    pub fn example_coinbase_txid() -> Txid {
        Txid::from_slice(
            &decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
        )
        .unwrap()
    }

    /// Example regular transaction
    pub fn example_regular_txid() -> Txid {
        Txid::from_slice(
            &decode("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468").unwrap(),
        )
        .unwrap()
    }
}

/// Test network parameters
pub mod network_params {
    pub const MAINNET_PORT: u16 = 9999;
    pub const TESTNET_PORT: u16 = 19999;
    pub const REGTEST_PORT: u16 = 19899;

    pub const PROTOCOL_VERSION: u32 = 70228;
    pub const MIN_PEER_PROTO_VERSION: u32 = 70215;
}

/// Common block heights
pub mod heights {
    pub const GENESIS: u32 = 0;
    pub const DIP0001_HEIGHT_MAINNET: u32 = 782208;
    pub const DIP0001_HEIGHT_TESTNET: u32 = 4001;
    pub const DIP0003_HEIGHT_MAINNET: u32 = 1028160;
    pub const DIP0003_HEIGHT_TESTNET: u32 = 7000;
}

/// Test quorum data
pub mod quorums {
    /// Example quorum hash
    pub const EXAMPLE_QUORUM_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";

    /// Example quorum public key (48 bytes)
    pub const EXAMPLE_QUORUM_PUBKEY: &[u8; 48] =
        b"000000000000000000000000000000000000000000000000";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hashes() {
        let mainnet = mainnet_genesis_hash();
        let testnet = testnet_genesis_hash();

        assert_ne!(mainnet, testnet);
        
        // Create expected BlockHash instances from the constants for proper comparison
        let expected_mainnet = {
            let bytes = decode(MAINNET_GENESIS_HASH).unwrap();
            let mut reversed = [0u8; 32];
            reversed.copy_from_slice(&bytes);
            reversed.reverse();
            BlockHash::from_slice(&reversed).unwrap()
        };
        
        let expected_testnet = {
            let bytes = decode(TESTNET_GENESIS_HASH).unwrap();
            let mut reversed = [0u8; 32];
            reversed.copy_from_slice(&bytes);
            reversed.reverse();
            BlockHash::from_slice(&reversed).unwrap()
        };
        
        assert_eq!(mainnet, expected_mainnet);
        assert_eq!(testnet, expected_testnet);
    }

    #[test]
    fn test_txid_fixtures() {
        let coinbase = txids::example_coinbase_txid();
        let regular = txids::example_regular_txid();

        assert_ne!(coinbase, regular);
        let coinbase_bytes: &[u8] = coinbase.as_ref();
        assert_eq!(coinbase_bytes, &[0u8; 32]);
    }
}
