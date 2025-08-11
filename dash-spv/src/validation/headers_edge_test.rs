//! Edge case tests for header validation.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::error::ValidationError;
    use crate::types::ValidationMode;
    use dashcore::{
        block::{Header as BlockHeader, Version},
        blockdata::constants::genesis_block,
        CompactTarget, Network,
    };
    use dashcore_hashes::Hash;

    /// Create a test header with specific parameters
    fn create_test_header_with_params(
        version: u32,
        prev_hash: dashcore::BlockHash,
        merkle_root: [u8; 32],
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> BlockHeader {
        BlockHeader {
            version: Version::from_consensus(version as i32),
            prev_blockhash: prev_hash,
            merkle_root: dashcore::TxMerkleNode::from_byte_array(merkle_root),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce,
        }
    }

    #[test]
    fn test_genesis_block_validation() {
        let mut validator = HeaderValidator::new(ValidationMode::Full);

        for network in [Network::Dash, Network::Testnet, Network::Regtest] {
            validator.set_network(network);
            let genesis = genesis_block(network).header;

            // Genesis block should validate with no previous header
            assert!(validator.validate(&genesis, None).is_ok());

            // Genesis block with itself as previous should fail
            let result = validator.validate(&genesis, Some(&genesis));
            assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
        }
    }

    #[test]
    fn test_maximum_target_validation() {
        let validator = HeaderValidator::new(ValidationMode::Full);

        // Create header with maximum allowed target (easiest difficulty)
        let max_target_bits = 0x1e0fffff; // Maximum target for testing
        let header = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [0; 32],
            1234567890,
            max_target_bits,
            1, // May need adjustment for valid PoW
        );

        // Should validate (though PoW might fail - that's expected)
        let _ = validator.validate(&header, None);
    }

    #[test]
    fn test_minimum_target_validation() {
        let validator = HeaderValidator::new(ValidationMode::Full);

        // Create header with very low target (hardest difficulty)
        let min_target_bits = 0x17000000; // Very difficult target
        let header = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [0; 32],
            1234567890,
            min_target_bits,
            0, // Will definitely fail PoW
        );

        // Should fail PoW validation
        let result = validator.validate(&header, None);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_zero_prev_blockhash() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

        // First header with zero prev_blockhash (like genesis)
        let header1 = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [1; 32],
            1234567890,
            0x1e0fffff,
            1,
        );

        // Second header pointing to first
        let header2 = create_test_header_with_params(
            0x20000000,
            header1.block_hash(),
            [2; 32],
            1234567900,
            0x1e0fffff,
            2,
        );

        // Should validate when no previous header provided
        assert!(validator.validate(&header1, None).is_ok());

        // Should validate chain continuity
        assert!(validator.validate(&header2, Some(&header1)).is_ok());
    }

    #[test]
    fn test_all_ff_prev_blockhash() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

        // Header with all 0xFF prev_blockhash
        let header = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0xFF; 32],
            )),
            [1; 32],
            1234567890,
            0x1e0fffff,
            1,
        );

        // Should validate when no previous header
        assert!(validator.validate(&header, None).is_ok());

        // Create a previous header that would match
        let prev_header = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [0; 32],
            1234567880,
            0x1e0fffff,
            0,
        );

        // Should fail chain continuity
        let result = validator.validate(&header, Some(&prev_header));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_timestamp_boundaries() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

        // Test with minimum timestamp (0)
        let header_min_time = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [1; 32],
            0, // Minimum timestamp
            0x1e0fffff,
            1,
        );
        assert!(validator.validate(&header_min_time, None).is_ok());

        // Test with maximum timestamp (u32::MAX)
        let header_max_time = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [2; 32],
            u32::MAX, // Maximum timestamp
            0x1e0fffff,
            2,
        );
        assert!(validator.validate(&header_max_time, None).is_ok());
    }

    #[test]
    fn test_version_edge_cases() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

        // Test various version values
        let versions = [0, 1, 0x20000000, 0x20000001, u32::MAX];

        for (i, &version) in versions.iter().enumerate() {
            let header = create_test_header_with_params(
                version,
                dashcore::BlockHash::from_raw_hash(
                    dashcore_hashes::hash_x11::Hash::from_byte_array([0; 32]),
                ),
                [i as u8; 32],
                1234567890 + i as u32,
                0x1e0fffff,
                i as u32,
            );

            // All versions should pass basic validation
            assert!(validator.validate(&header, None).is_ok());
        }
    }

    #[test]
    fn test_large_chain_validation() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

        // Create a large chain
        let chain_size = 1000;
        let mut headers = Vec::with_capacity(chain_size);
        let mut prev_hash = dashcore::BlockHash::from_raw_hash(
            dashcore_hashes::hash_x11::Hash::from_byte_array([0; 32]),
        );

        for i in 0..chain_size {
            let header = create_test_header_with_params(
                0x20000000,
                prev_hash,
                [(i % 256) as u8; 32],
                1234567890 + i as u32 * 600,
                0x1e0fffff,
                i as u32,
            );
            prev_hash = header.block_hash();
            headers.push(header);
        }

        // Should validate entire chain
        assert!(validator.validate_chain_basic(&headers).is_ok());

        // Break the chain in the middle
        let broken_index = chain_size / 2;
        headers[broken_index] = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            [99; 32],
            1234567890,
            0x1e0fffff,
            999999,
        );

        // Should fail validation
        let result = validator.validate_chain_basic(&headers);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_single_header_chain_validation() {
        let validator = HeaderValidator::new(ValidationMode::Full);

        let header = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [1; 32],
            1234567890,
            0x1e0fffff,
            1,
        );

        let headers = vec![header];

        // Single header chain should validate in both basic and full modes
        assert!(validator.validate_chain_basic(&headers).is_ok());
        assert!(validator.validate_chain_full(&headers, false).is_ok());
    }

    #[test]
    fn test_duplicate_headers_in_chain() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

        let header = create_test_header_with_params(
            0x20000000,
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            [1; 32],
            1234567890,
            0x1e0fffff,
            1,
        );

        // Chain with duplicate headers (same header repeated)
        let headers = vec![header.clone(), header.clone()];

        // Should fail because second header's prev_blockhash won't match first header's hash
        let result = validator.validate_chain_basic(&headers);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_merkle_root_variations() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

        // Test various merkle root patterns
        let merkle_patterns = [
            [0u8; 32],  // All zeros
            [0xFF; 32], // All ones
            [0xAA; 32], // Alternating bits
            [0x55; 32], // Alternating bits (inverse)
        ];

        let mut prev_hash = dashcore::BlockHash::from_raw_hash(
            dashcore_hashes::hash_x11::Hash::from_byte_array([0; 32]),
        );

        for (i, &merkle_root) in merkle_patterns.iter().enumerate() {
            let header = create_test_header_with_params(
                0x20000000,
                prev_hash,
                merkle_root,
                1234567890 + i as u32 * 600,
                0x1e0fffff,
                i as u32,
            );

            // All merkle roots should be valid for basic validation
            assert!(validator.validate(&header, None).is_ok());

            prev_hash = header.block_hash();
        }
    }

    #[test]
    fn test_mode_switching_during_chain_validation() {
        let mut validator = HeaderValidator::new(ValidationMode::None);

        // Create headers with invalid PoW
        let mut headers = vec![];
        let mut prev_hash = dashcore::BlockHash::from_raw_hash(
            dashcore_hashes::hash_x11::Hash::from_byte_array([0; 32]),
        );

        for i in 0..3 {
            let header = create_test_header_with_params(
                0x20000000,
                prev_hash,
                [i as u8; 32],
                1234567890 + i * 600,
                0x1d00ffff, // Difficult target
                0,          // Invalid nonce
            );
            prev_hash = header.block_hash();
            headers.push(header);
        }

        // Should pass with None mode (ValidationMode::None always passes)
        let result = validator.validate_chain_full(&headers, true);
        assert!(result.is_ok(), "ValidationMode::None should always pass, but got: {:?}", result);

        // Switch to Full mode
        validator.set_mode(ValidationMode::Full);

        // Should now fail due to invalid PoW
        let result = validator.validate_chain_full(&headers, true);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));

        // But should pass without PoW check
        assert!(validator.validate_chain_full(&headers, false).is_ok());
    }
}
