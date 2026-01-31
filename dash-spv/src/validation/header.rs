use rayon::prelude::*;
use std::time::Instant;

use crate::error::{ValidationError, ValidationResult};
use crate::types::HashedBlockHeader;
use crate::validation::Validator;

#[derive(Default)]
pub struct BlockHeaderValidator {}

impl BlockHeaderValidator {
    pub fn new() -> Self {
        Self {}
    }
}

impl Validator<&[HashedBlockHeader]> for BlockHeaderValidator {
    fn validate(&self, hashed_headers: &[HashedBlockHeader]) -> ValidationResult<()> {
        let start = Instant::now();

        // Check PoW of i and continuity of i-1 to i in parallel
        hashed_headers.par_iter().enumerate().try_for_each(|(i, header)| {
            // For the first header, skip chain continuity check since we don't have i-1 here
            if i > 0 && header.header().prev_blockhash != *hashed_headers[i - 1].hash() {
                return Err(ValidationError::InvalidHeaderChain(format!(
                    "Header {:?} does not connect to {:?}",
                    hashed_headers[i - 1],
                    header
                )));
            }
            // Check if PoW target is met
            if !header.header().target().is_met_by(*header.hash()) {
                return Err(ValidationError::InvalidProofOfWork);
            }
            Ok(())
        })?;

        tracing::trace!(
            "Header chain validation passed for {} headers, duration: {:?}",
            hashed_headers.len(),
            start.elapsed(),
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use dashcore::{
        block::Version, constants::genesis_block, CompactTarget, Header as BlockHeader, Network,
    };
    use dashcore_hashes::Hash;

    use super::*;

    // Very easy target to pass PoW checks for continuity tests
    const MAX_TARGET: u32 = 0x2100ffff;

    fn create_test_header(prev_hash: dashcore::BlockHash, nonce: u32) -> HashedBlockHeader {
        HashedBlockHeader::from(BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: prev_hash,
            merkle_root: dashcore::TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(MAX_TARGET),
            nonce,
        })
    }

    #[test]
    fn test_empty_headers() {
        let validator = BlockHeaderValidator::new();

        assert!(validator.validate(&[]).is_ok());
    }

    #[test]
    fn test_single_header() {
        let validator = BlockHeaderValidator::new();

        let header = create_test_header(dashcore::BlockHash::all_zeros(), 0);
        assert!(validator.validate(&[header]).is_ok());
    }

    #[test]
    fn test_valid_chain() {
        let validator = BlockHeaderValidator::new();

        let mut headers = vec![];
        let mut prev_hash = dashcore::BlockHash::all_zeros();

        for i in 0..10 {
            let header = create_test_header(prev_hash, i);
            prev_hash = *header.hash();
            headers.push(header);
        }

        assert!(validator.validate(&headers).is_ok());
    }

    #[test]
    fn test_broken_chain() {
        let validator = BlockHeaderValidator::new();

        let header1 = create_test_header(dashcore::BlockHash::all_zeros(), 0);
        let header2 = create_test_header(*header1.hash(), 1);
        // header3 doesn't connect to header2
        let header3 = create_test_header(dashcore::BlockHash::all_zeros(), 2);

        let result = validator.validate(&[header1, header2, header3]);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_invalid_pow() {
        let validator = BlockHeaderValidator::new();

        let header = HashedBlockHeader::from(BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: dashcore::BlockHash::all_zeros(),
            merkle_root: dashcore::TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff), // Hard target
            nonce: 0,
        });

        let result = validator.validate(&[header]);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_genesis_blocks() {
        let validator = BlockHeaderValidator::new();

        for network in [Network::Dash, Network::Testnet, Network::Regtest] {
            let genesis = HashedBlockHeader::from(genesis_block(network).header);
            assert!(
                validator.validate(&[genesis]).is_ok(),
                "Genesis block for {:?} should validate",
                network
            );
        }
    }

    #[test]
    fn test_invalid_pow_mid_chain() {
        let validator = BlockHeaderValidator::new();

        let header1 = create_test_header(dashcore::BlockHash::all_zeros(), 0);
        let header2 = create_test_header(*header1.hash(), 1);

        // Header 3 has valid continuity but impossible PoW target
        let header3 = HashedBlockHeader::from(BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: *header2.hash(),
            merkle_root: dashcore::TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff), // Hard target
            nonce: 0,
        });

        let header4 = create_test_header(*header3.hash(), 3);

        let result = validator.validate(&[header1, header2, header3, header4]);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }
}
