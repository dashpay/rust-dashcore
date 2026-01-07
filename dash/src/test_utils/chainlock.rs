use crate::{BlockHash, ChainLock};

use crate::bls_sig_utils::BLSSignature;

impl ChainLock {
    pub fn dummy(height: u32) -> ChainLock {
        ChainLock {
            block_height: height,
            block_hash: BlockHash::dummy(height),
            signature: BLSSignature::from([0; 96]),
        }
    }
}
