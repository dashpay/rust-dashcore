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
}
