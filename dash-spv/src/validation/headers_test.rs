//! Unit tests for header validation.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::error::ValidationError;
    use crate::types::ValidationMode;
    use dashcore::{
        block::{Header as BlockHeader, Version},
        blockdata::constants::genesis_block,
        Network,
    };
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

    /// Create a valid test header that connects to previous
    fn create_valid_header(prev_header: &BlockHeader, time_offset: u32) -> BlockHeader {
        create_test_header(
            prev_header.block_hash(),
            12345,
            0x1e0fffff, // Easy difficulty for testing
            prev_header.time + time_offset,
        )
    }

    #[test]
    fn test_validation_mode_none_always_passes() {
        let validator = HeaderValidator::new(ValidationMode::None);
        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,
            0x1e0fffff,
            1234567890,
        );

        // Should pass with no previous header
        assert!(validator.validate(&header, None).is_ok());

        // Should pass even with invalid chain continuity
        let prev_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [1; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        assert!(validator.validate(&header, Some(&prev_header)).is_ok());
    }

    #[test]
    fn test_basic_validation_chain_continuity() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

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
        assert!(validator.validate(&header2, Some(&header1)).is_ok());

        // Should fail when headers don't connect
        let disconnected_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            3,
            0x1e0fffff,
            1234567910,
        );
        let result = validator.validate(&disconnected_header, Some(&header1));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_basic_validation_no_pow_check() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

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
        assert!(validator.validate(&header, None).is_ok());
    }

    #[test]
    fn test_full_validation_includes_pow() {
        let validator = HeaderValidator::new(ValidationMode::Full);

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
        let result = validator.validate(&header, None);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_full_validation_chain_continuity_and_pow() {
        let validator = HeaderValidator::new(ValidationMode::Full);

        // Create headers that don't connect
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        let disconnected_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            2,
            0x1e0fffff,
            1234567900,
        );

        // Should fail due to chain continuity before PoW check
        let result = validator.validate(&disconnected_header, Some(&header1));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_validate_chain_basic_empty() {
        let validator = HeaderValidator::new(ValidationMode::Basic);
        let headers: Vec<BlockHeader> = vec![];

        // Empty chain should pass
        assert!(validator.validate_chain_basic(&headers).is_ok());
    }

    #[test]
    fn test_validate_chain_basic_single_header() {
        let validator = HeaderValidator::new(ValidationMode::Basic);
        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        let headers = vec![header];

        // Single header should pass (no chain validation needed)
        assert!(validator.validate_chain_basic(&headers).is_ok());
    }

    #[test]
    fn test_validate_chain_basic_valid_chain() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

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
        assert!(validator.validate_chain_basic(&headers).is_ok());
    }

    #[test]
    fn test_validate_chain_basic_broken_chain() {
        let validator = HeaderValidator::new(ValidationMode::Basic);

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
        let result = validator.validate_chain_basic(&headers);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_validate_chain_full_with_pow() {
        let validator = HeaderValidator::new(ValidationMode::Full);

        // Create headers with invalid PoW
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,          // Invalid nonce
            0x1d00ffff, // Difficulty that requires real PoW
            1234567890,
        );
        let headers = vec![header1];

        // Should fail when PoW validation is enabled
        let result = validator.validate_chain_full(&headers, true);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));

        // Should pass when PoW validation is disabled
        assert!(validator.validate_chain_full(&headers, false).is_ok());
    }

    #[test]
    fn test_validate_connects_to_genesis_mainnet() {
        let mut validator = HeaderValidator::new(ValidationMode::Basic);
        validator.set_network(Network::Dash);

        let genesis = genesis_block(Network::Dash).header;
        let valid_header =
            create_test_header(genesis.block_hash(), 1, 0x1e0fffff, genesis.time + 600);

        let headers = vec![valid_header];

        // Should pass when connecting to genesis
        assert!(validator.validate_connects_to_genesis(&headers).is_ok());

        // Should fail when not connecting to genesis
        let invalid_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            2,
            0x1e0fffff,
            genesis.time + 1200,
        );
        let headers = vec![invalid_header];

        let result = validator.validate_connects_to_genesis(&headers);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_validate_connects_to_genesis_testnet() {
        let mut validator = HeaderValidator::new(ValidationMode::Basic);
        validator.set_network(Network::Testnet);

        let genesis = genesis_block(Network::Testnet).header;
        let valid_header =
            create_test_header(genesis.block_hash(), 1, 0x1e0fffff, genesis.time + 600);

        let headers = vec![valid_header];

        // Should pass when connecting to testnet genesis
        assert!(validator.validate_connects_to_genesis(&headers).is_ok());
    }

    #[test]
    fn test_validate_connects_to_genesis_empty() {
        let validator = HeaderValidator::new(ValidationMode::Basic);
        let headers: Vec<BlockHeader> = vec![];

        // Empty chain should pass
        assert!(validator.validate_connects_to_genesis(&headers).is_ok());
    }

    #[test]
    fn test_set_validation_mode() {
        let mut validator = HeaderValidator::new(ValidationMode::None);

        // Create header with broken chain continuity
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        let disconnected_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            2,
            0x1e0fffff,
            1234567900,
        );

        // Should pass with ValidationMode::None
        assert!(validator.validate(&disconnected_header, Some(&header1)).is_ok());

        // Change to Basic mode
        validator.set_mode(ValidationMode::Basic);

        // Should now fail
        let result = validator.validate(&disconnected_header, Some(&header1));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));

        // Change back to None
        validator.set_mode(ValidationMode::None);

        // Should pass again
        assert!(validator.validate(&disconnected_header, Some(&header1)).is_ok());
    }

    #[test]
    fn test_network_setting() {
        let mut validator = HeaderValidator::new(ValidationMode::Basic);

        // Test with different networks (skip Regtest as it may not have a known genesis hash)
        for network in [Network::Dash, Network::Testnet] {
            validator.set_network(network);

            let genesis = genesis_block(network).header;
            let valid_header =
                create_test_header(genesis.block_hash(), 1, 0x1e0fffff, genesis.time + 600);

            let headers = vec![valid_header];
            assert!(validator.validate_connects_to_genesis(&headers).is_ok());
        }

        // For Regtest, just verify we can set the network
        validator.set_network(Network::Regtest);
    }

    #[test]
    fn test_validate_difficulty_adjustment() {
        let validator = HeaderValidator::new(ValidationMode::Full);

        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
            1234567890,
        );
        let header2 = create_test_header(
            header1.block_hash(),
            2,
            0x1e0ffff0, // Slightly different difficulty
            1234567900,
        );

        // Currently just passes - SPV trusts network for difficulty
        assert!(validator.validate_difficulty_adjustment(&header2, &header1).is_ok());
    }
}
