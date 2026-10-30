use std::time::Instant;

use dashcore::block::Header;
use dashcore::pow::{bits_meet_required, next_work_required};
use dashcore::Network;

use crate::error::{ValidationError, ValidationResult};
use crate::types::HashedBlockHeader;
use crate::validation::Validator;

/// Checks a batch of headers for continuity, proof of work and the difficulty Dash Core
/// requires. Headers without enough history before them are not checked for difficulty.
pub struct BlockHeaderValidator {
    network: Network,
    /// The stored headers the batch extends, oldest first.
    ancestors: Vec<Header>,
    /// Height of the last of `ancestors`.
    tip_height: u32,
}

impl BlockHeaderValidator {
    /// A validator for a batch on `network` extending `ancestors`, the last of which is at
    /// `tip_height`.
    pub fn new(network: Network, ancestors: Vec<Header>, tip_height: u32) -> Self {
        Self {
            network,
            ancestors,
            tip_height,
        }
    }
}

impl Validator<&[HashedBlockHeader]> for BlockHeaderValidator {
    fn validate(&self, hashed_headers: &[HashedBlockHeader]) -> ValidationResult<()> {
        let start = Instant::now();

        // The headers each one's difficulty is computed from: the ancestors, then the batch
        let chain: Vec<Header> = self
            .ancestors
            .iter()
            .copied()
            .chain(hashed_headers.iter().map(|h| *h.header()))
            .collect();

        // Check PoW of i and continuity of i-1 to i
        hashed_headers.iter().enumerate().try_for_each(|(i, header)| {
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

            // Check the bits against the difficulty required at its height
            let height = self.tip_height + 1 + i as u32;
            let window = &chain[..self.ancestors.len() + i];
            let bits = header.header().bits;
            let required =
                next_work_required(self.network, window, height - 1, header.header().time);

            if let Some(required) = required
                .filter(|required| !bits_meet_required(self.network, height, bits, *required))
            {
                return Err(ValidationError::InvalidDifficulty {
                    height,
                    actual: bits.to_consensus(),
                    required: required.to_consensus(),
                });
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
        let validator = BlockHeaderValidator::new(Network::Regtest, vec![], 0);

        assert!(validator.validate(&[]).is_ok());
    }

    #[test]
    fn test_single_header() {
        let validator = BlockHeaderValidator::new(Network::Regtest, vec![], 0);

        let headers = hashed(Header::dummy_chain(1, BlockHash::all_zeros()));
        assert!(validator.validate(&headers).is_ok());
    }

    #[test]
    fn test_valid_chain() {
        let validator = BlockHeaderValidator::new(Network::Regtest, vec![], 0);

        let headers = hashed(Header::dummy_chain(10, BlockHash::all_zeros()));
        assert!(validator.validate(&headers).is_ok());
    }

    #[test]
    fn test_broken_chain() {
        let validator = BlockHeaderValidator::new(Network::Regtest, vec![], 0);

        let mut headers = Header::dummy_chain(3, BlockHash::all_zeros());
        // The third header doesn't connect to the second
        headers[2].prev_blockhash = BlockHash::all_zeros();

        let result = validator.validate(&hashed(headers));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_invalid_pow() {
        let validator = BlockHeaderValidator::new(Network::Regtest, vec![], 0);

        // `Header::dummy` has a hard target its hash doesn't meet
        let result = validator.validate(&hashed(vec![Header::dummy(0)]));
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_genesis_blocks() {
        let validator = BlockHeaderValidator::new(Network::Regtest, vec![], 0);

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
        let validator = BlockHeaderValidator::new(Network::Regtest, vec![], 0);

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

    #[test]
    fn test_easier_difficulty() {
        let headers = Header::mainnet_fixture();
        let mut batch = headers[24..].to_vec();
        // The easy target of the dummy chain, which the header's hash still meets
        batch.last_mut().unwrap().bits = Header::dummy_chain(1, BlockHash::all_zeros())[0].bits;

        let validator =
            BlockHeaderValidator::new(Network::Mainnet, headers[..24].to_vec(), 1999999);
        let result = validator.validate(&hashed(batch));
        assert!(matches!(
            result,
            Err(ValidationError::InvalidDifficulty {
                height: 2000005,
                ..
            })
        ));
    }
}
