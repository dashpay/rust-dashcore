//! Unit tests for header validation.

#[cfg(test)]
mod tests {
    use super::super::validate_headers;
    use crate::error::ValidationError;
    use crate::types::ValidationMode;
    use dashcore::block::{Header as BlockHeader, Version};
    use dashcore_hashes::Hash;

    /// Create a test header with given parameters
    fn create_test_header(
        prev_hash: dashcore::BlockHash,
        nonce: u32,
        bits: u32,
        time: u32,
    ) -> BlockHeader {
        BlockHeader {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: prev_hash,
            merkle_root: dashcore::TxMerkleNode::from_byte_array([0; 32]),
            time,
            bits: dashcore::CompactTarget::from_consensus(bits),
            nonce,
        }
    }

    #[test]
    fn test_validation_mode_none_always_passes() {
        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,
            0x1e0fffff,
            1234567890,
        );

        // Should pass with no previous header
        assert!(validate_headers(&[header], ValidationMode::None).is_ok());

        // Should pass even with invalid chain continuity
        let prev_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [1; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        assert!(validate_headers(&[prev_header, header], ValidationMode::None).is_ok());
    }

    #[test]
    fn test_basic_validation_chain_continuity() {
        // Create two headers that connect properly
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        let header2 = create_test_header(header1.block_hash(), 2, 0x1e0fffff, 1234567900);

        // Should pass when headers connect
        assert!(validate_headers(&[header1, header2], ValidationMode::Basic).is_ok());

        // Should fail when headers don't connect
        let disconnected_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            3,
            0x1e0fffff,
            1234567910,
        );
        let result = validate_headers(&[header1, disconnected_header], ValidationMode::Basic);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_basic_validation_no_pow_check() {
        // Create header with invalid PoW (would fail full validation)
        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0, // Invalid nonce that won't produce valid PoW
            0x1e0fffff,
            1234567890,
        );

        // Should pass basic validation (no PoW check)
        assert!(validate_headers(&[header], ValidationMode::Basic).is_ok());
    }

    #[test]
    fn test_full_validation_includes_pow() {
        // Create header with invalid PoW
        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,          // Invalid nonce
            0x1d00ffff, // Difficulty that requires real PoW
            1234567890,
        );

        // Should fail full validation due to invalid PoW
        let result = validate_headers(&[header], ValidationMode::Full);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_validate_headers_empty() {
        for mode in [ValidationMode::None, ValidationMode::Basic, ValidationMode::Full] {
            let headers: Vec<BlockHeader> = vec![];
            // Empty chain should pass
            assert!(validate_headers(&headers, mode).is_ok());
        }
    }

    #[test]
    fn test_validate_headers_basic_single_header() {
        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );

        // Single header should pass (no chain validation needed)
        assert!(validate_headers(&[header], ValidationMode::Basic).is_ok());
    }

    #[test]
    fn test_validate_headers_basic_valid_chain() {
        // Create a valid chain of headers
        let mut headers = vec![];
        let mut prev_hash = dashcore::BlockHash::from_raw_hash(
            dashcore_hashes::hash_x11::Hash::from_byte_array([0; 32]),
        );

        for i in 0..5 {
            let header = create_test_header(prev_hash, i, 0x1e0fffff, 1234567890 + i * 600);
            prev_hash = header.block_hash();
            headers.push(header);
        }

        // Valid chain should pass
        assert!(validate_headers(&headers, ValidationMode::Basic).is_ok());
    }

    #[test]
    fn test_validate_headers_basic_broken_chain() {
        // Create a chain with a break in the middle
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        let header2 = create_test_header(header1.block_hash(), 2, 0x1e0fffff, 1234567900);
        let header3 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )), // Broken link
            3,
            0x1e0fffff,
            1234567910,
        );

        let headers = vec![header1, header2, header3];

        // Should fail due to broken chain
        let result = validate_headers(&headers, ValidationMode::Basic);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_validate_headers_full_with_pow() {
        // Create headers with invalid PoW
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,          // Invalid nonce
            0x1d00ffff, // Difficulty that requires real PoW
            1234567890,
        );

        // Should fail when PoW validation is enabled
        let result = validate_headers(&[header1], ValidationMode::Full);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }
}
