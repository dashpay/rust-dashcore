//! Header validation functionality.

use rayon::prelude::*;
use std::time::Instant;

use crate::error::{ValidationError, ValidationResult};
use crate::types::CachedHeader;

/// Validate a chain of headers.
pub fn validate_headers(headers: &[CachedHeader]) -> ValidationResult<()> {
    let start = Instant::now();

    // Check PoW of i and continuity of i-1 to i in parallel
    headers.par_iter().enumerate().try_for_each(|(i, header)| {
        // For the first header, skip chain continuity check since we don't have i-1 here
        if i > 0 && header.prev_blockhash != headers[i - 1].block_hash() {
            return Err(ValidationError::InvalidHeaderChain(format!(
                "Header {:?} does not connect to {:?}",
                headers[i - 1],
                header
            )));
        }
        // Check if PoW target is met
        if !header.target().is_met_by(header.block_hash()) {
            return Err(ValidationError::InvalidProofOfWork);
        }
        Ok(())
    })?;

    tracing::trace!(
        "Header chain validation passed for {} headers, duration: {:?}",
        headers.len(),
        start.elapsed(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_headers;
    use crate::error::ValidationError;
    use crate::types::CachedHeader;
    use dashcore::{
        block::{Header as BlockHeader, Version},
        blockdata::constants::genesis_block,
        CompactTarget, Network,
    };
    use dashcore_hashes::Hash;

    // Very easy target to pass PoW checks for continuity tests
    const MAX_TARGET: u32 = 0x2100ffff;

    fn create_test_header(prev_hash: dashcore::BlockHash, nonce: u32) -> CachedHeader {
        CachedHeader::new(BlockHeader {
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
        assert!(validate_headers(&[]).is_ok());
    }

    #[test]
    fn test_single_header() {
        let header = create_test_header(dashcore::BlockHash::all_zeros(), 0);
        assert!(validate_headers(&[header]).is_ok());
    }

    #[test]
    fn test_valid_chain() {
        let mut headers = vec![];
        let mut prev_hash = dashcore::BlockHash::all_zeros();

        for i in 0..10 {
            let header = create_test_header(prev_hash, i);
            prev_hash = header.block_hash();
            headers.push(header);
        }

        assert!(validate_headers(&headers).is_ok());
    }

    #[test]
    fn test_broken_chain() {
        let header1 = create_test_header(dashcore::BlockHash::all_zeros(), 0);
        let header2 = create_test_header(header1.block_hash(), 1);
        // header3 doesn't connect to header2
        let header3 = create_test_header(dashcore::BlockHash::all_zeros(), 2);

        let result = validate_headers(&[header1, header2, header3]);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_invalid_pow() {
        let header = CachedHeader::new(BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: dashcore::BlockHash::all_zeros(),
            merkle_root: dashcore::TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff), // Hard target
            nonce: 0,
        });

        let result = validate_headers(&[header]);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_genesis_blocks() {
        for network in [Network::Dash, Network::Testnet, Network::Regtest] {
            let genesis = CachedHeader::new(genesis_block(network).header);
            assert!(
                validate_headers(&[genesis]).is_ok(),
                "Genesis block for {:?} should validate",
                network
            );
        }
    }

    #[test]
    fn test_invalid_pow_mid_chain() {
        let header1 = create_test_header(dashcore::BlockHash::all_zeros(), 0);
        let header2 = create_test_header(header1.block_hash(), 1);

        // Header 3 has valid continuity but impossible PoW target
        let header3 = CachedHeader::new(BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: header2.block_hash(),
            merkle_root: dashcore::TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff), // Hard target
            nonce: 0,
        });

        let header4 = create_test_header(header3.block_hash(), 3);

        let result = validate_headers(&[header1, header2, header3, header4]);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }
}
