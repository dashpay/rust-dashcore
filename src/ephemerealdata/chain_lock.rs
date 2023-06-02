//! Instant send lock is a mechanism used by the Dash network to
//! confirm transaction within 1 or 2 seconds. This data structure
//! represents a p2p message containing a data to verify such a lock.

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
use std::io;
#[cfg(any(feature = "std", test))]
pub use std::vec::Vec;
use hashes::{Hash, HashEngine};
use bls_sig_utils::BLSSignature;
use ::{BlockHash, QuorumSigningRequestId};
use consensus::{Encodable, encode};
//#[cfg(feature = "use-serde")]
//use serde_big_array::BigArray;

const CL_REQUEST_ID_PREFIX: &str = "clsig";

impl_consensus_encoding!(ChainLock, block_height, block_hash, signature);

#[derive(Debug, Clone, Eq, PartialEq)]
// #[cfg_attr(feature = "use-serde", derive(Serialize, Deserialize))]
pub struct ChainLock {
    /// Block height
    pub block_height: u32,
    /// Block hash
    pub block_hash: BlockHash,
    /// Quorum signature
    //#[cfg_attr(feature = "use-serde", serde(serialize_with = "<[_]>::serialize"))]
    //#[cfg_attr(feature = "use-serde", serde(with = "BigArray"))]
    pub signature: BLSSignature,
}

impl ChainLock {
    /// Returns quorum signing request ID
    pub fn request_id(&self) -> Result<QuorumSigningRequestId, io::Error> {
        let mut engine = QuorumSigningRequestId::engine();

        // Prefix
        let prefix_len = encode::VarInt(CL_REQUEST_ID_PREFIX.len() as u64);
        prefix_len.consensus_encode(&mut engine)?;

        engine.input(CL_REQUEST_ID_PREFIX.as_bytes());

        // Inputs
        engine.input(&self.block_height.to_le_bytes());

        Ok(QuorumSigningRequestId::from_engine(engine))
    }
}

#[cfg(test)]
mod tests {
    use hashes::hex::{FromHex, ToHex};
    use consensus::deserialize;
    use super::*;

    #[test]
    pub fn should_decode_vec() {
        // {
        //    height: 84202,
        //    blockHash:
        //      '0000000007e0a65b763c0a4fb2274ff757abdbd19c9efe9de189f5828c70a5f4',
        //    signature:
        //      '0a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c',
        //  };

        //     expectedHash2 =
        //       'e0b872dbf38b0f6f04fed617bef820776530b2155429024fbb092fc3a6ad6437';

        let hex = "ea480100f4a5708c82f589e19dfe9e9cd1dbab57f74f27b24f0a3c765ba6e007000000000a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c";

        let vec = Vec::from_hex(hex).unwrap();

        let chain_lock: ChainLock = deserialize(&vec).unwrap();

        let block_hash = BlockHash::from_hex("0000000007e0a65b763c0a4fb2274ff757abdbd19c9efe9de189f5828c70a5f4").expect("should create fromn hex");

        let signature = BLSSignature::from_hex("0a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c").expect("should create from hex");

        assert_eq!(chain_lock.block_height, 84202);
        assert_eq!(chain_lock.block_hash, block_hash);
        assert_eq!(chain_lock.signature, signature);
    }

    #[test]
    pub fn should_create_request_id() {
        let hex = "ea480100f4a5708c82f589e19dfe9e9cd1dbab57f74f27b24f0a3c765ba6e007000000000a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c";

        let expected_request_id = "5d92e094e2aa582b76e8bf519f42c5e8fc141bbe548e9660726f744adad03966";

        let vec = Vec::from_hex(hex).unwrap();

        let chain_lokc: ChainLock = deserialize(&vec).unwrap();

        let request_id = chain_lokc.request_id().expect("should return request id");

        assert_eq!(request_id.to_hex(), expected_request_id);
    }
}
