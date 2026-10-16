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
    use dashcore::{constants::genesis_block, BlockHash, Header, Network};
    use dashcore_hashes::Hash;

    use super::*;

    fn hashed(headers: Vec<Header>) -> Vec<HashedBlockHeader> {
        headers.into_iter().map(HashedBlockHeader::from).collect()
    }

    #[test]
    fn test_empty_headers() {
        let validator = BlockHeaderValidator::new();

        assert!(validator.validate(&[]).is_ok());
    }

    #[test]
    fn test_single_header() {
        let validator = BlockHeaderValidator::new();

        let headers = hashed(Header::dummy_chain(1, BlockHash::all_zeros()));
        assert!(validator.validate(&headers).is_ok());
    }

    #[test]
    fn test_valid_chain() {
        let validator = BlockHeaderValidator::new();

        let headers = hashed(Header::dummy_chain(10, BlockHash::all_zeros()));
        assert!(validator.validate(&headers).is_ok());
    }

    #[test]
    fn test_broken_chain() {
        let validator = BlockHeaderValidator::new();

        let mut headers = Header::dummy_chain(3, BlockHash::all_zeros());
        // The third header doesn't connect to the second
        headers[2].prev_blockhash = BlockHash::all_zeros();

        let result = validator.validate(&hashed(headers));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_invalid_pow() {
        let validator = BlockHeaderValidator::new();

        // `Header::dummy` has a hard target its hash doesn't meet
        let result = validator.validate(&hashed(vec![Header::dummy(0)]));
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_genesis_blocks() {
        let validator = BlockHeaderValidator::new();

        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
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

        // The third header has valid continuity but a hard target its hash doesn't meet
        let mut headers = Header::dummy_chain(2, BlockHash::all_zeros());
        let hard = Header {
            prev_blockhash: headers[1].block_hash(),
            ..Header::dummy(2)
        };
        headers.push(hard);
        headers.extend(Header::dummy_chain(1, hard.block_hash()));

        let result = validator.validate(&hashed(headers));
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }
}
