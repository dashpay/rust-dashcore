use crate::{ChainLock, Header};

use crate::bls_sig_utils::BLSSignature;

impl ChainLock {
    pub fn dummy(height: u32) -> ChainLock {
        ChainLock {
            block_height: height,
            block_hash: Header::dummy(height).block_hash(),
            signature: BLSSignature::from([0; 96]),
        }
    }

    /// Built from the block hash and signature as Dash Core prints them.
    pub fn from_hex(block_height: u32, block_hash: &str, signature: &str) -> ChainLock {
        ChainLock {
            block_height,
            block_hash: block_hash.parse().unwrap(),
            signature: BLSSignature::from_hex(signature).unwrap(),
        }
    }

    /// The two genuine ChainLocks, at 2243495 and 2243496, that
    /// `MasternodeListEngine::mainnet_fixture` verifies.
    pub fn mainnet_fixture_pair() -> [ChainLock; 2] {
        [
            ChainLock::from_hex(
                2243495,
                "000000000000000d88580463cafe168b2f465f40f01916ad95fe9be459c26491",
                "a6bc4dcf7afb042e0b0258a994f5a77856971a32a3ad3ee89d21e1011a77211070bec7c2ef50c293722cbae135b904640b482479f836120e0be7d42ce332a7c58096d8d8006920ef3dbcc47b5f7ed00aeb68d58bc514f4401bd72b247bf23699",
            ),
            ChainLock::from_hex(
                2243496,
                "000000000000001f9ff71c513c0ccef0c7c392f0df8bcb3c7c5764dcc1f4c89b",
                "88270e60bee7dd9cea3c0a1b85e51d52f01e55a35033ef0434979b9121bc07ed8e45adae1f99e4d8fa2ea760920d844e1383030103b1c503cee45a2fcddc5cd7e73d1823d199e8231fadee2b3cadb1c6fc2ea255b988334b47d35ce865275699",
            ),
        ]
    }
}
