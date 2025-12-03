//! Unit tests for ValidationManager.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::error::ValidationError;
    use crate::types::ValidationMode;
    use dashcore::{
        block::{Header as BlockHeader, Version},
        InstantLock, OutPoint, Transaction, TxIn, TxOut,
    };
    use dashcore_hashes::Hash;

    /// Create a test header
    fn create_test_header(prev_hash: dashcore::BlockHash, nonce: u32, bits: u32) -> BlockHeader {
        BlockHeader {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: prev_hash,
            merkle_root: dashcore::TxMerkleNode::from_byte_array([0; 32]),
            time: 1234567890,
            bits: dashcore::CompactTarget::from_consensus(bits),
            nonce,
        }
    }

    /// Create a simple test transaction
    fn create_test_transaction() -> Transaction {
        Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: dashcore::ScriptBuf::new(),
                sequence: u32::MAX,
                witness: dashcore::Witness::new(),
            }],
            output: vec![TxOut {
                value: 50000,
                script_pubkey: dashcore::ScriptBuf::new(),
            }],
            special_transaction_payload: None,
        }
    }

    /// Create a test InstantLock
    fn create_test_instantlock() -> InstantLock {
        let tx = create_test_transaction();
        let txid = tx.txid();
        InstantLock {
            version: 1,
            inputs: tx.input.into_iter().map(|inp| inp.previous_output).collect(),
            txid,
            signature: dashcore::bls_sig_utils::BLSSignature::from([0u8; 96]),
            cyclehash: dashcore::BlockHash::from_raw_hash(
                dashcore_hashes::hash_x11::Hash::from_byte_array([0; 32]),
            ),
        }
    }

    #[test]
    fn test_validation_manager_creation() {
        let manager = ValidationManager::new(ValidationMode::Basic, Network::Dash);
        assert_eq!(manager.mode(), ValidationMode::Basic);

        let manager = ValidationManager::new(ValidationMode::Full, Network::Dash);
        assert_eq!(manager.mode(), ValidationMode::Full);

        let manager = ValidationManager::new(ValidationMode::None, Network::Dash);
        assert_eq!(manager.mode(), ValidationMode::None);
    }

    #[test]
    fn test_validation_manager_mode_change() {
        let mut manager = ValidationManager::new(ValidationMode::None, Network::Dash);
        assert_eq!(manager.mode(), ValidationMode::None);

        manager.set_mode(ValidationMode::Basic);
        assert_eq!(manager.mode(), ValidationMode::Basic);

        manager.set_mode(ValidationMode::Full);
        assert_eq!(manager.mode(), ValidationMode::Full);
    }

    #[test]
    fn test_header_validation_with_mode_none() {
        let manager = ValidationManager::new(ValidationMode::None, Network::Dash);

        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,
            0x1e0fffff,
        );

        // Should always pass with ValidationMode::None
        assert!(manager.validate_header(&header, None).is_ok());

        // Even with invalid chain continuity
        let prev_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            1,
            0x1e0fffff,
        );
        assert!(manager.validate_header(&header, Some(&prev_header)).is_ok());
    }

    #[test]
    fn test_header_validation_with_mode_basic() {
        let manager = ValidationManager::new(ValidationMode::Basic, Network::Dash);

        // Valid chain continuity
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
        );
        let header2 = create_test_header(header1.block_hash(), 2, 0x1e0fffff);

        assert!(manager.validate_header(&header2, Some(&header1)).is_ok());

        // Invalid chain continuity
        let disconnected_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            3,
            0x1e0fffff,
        );

        let result = manager.validate_header(&disconnected_header, Some(&header1));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_header_validation_with_mode_full() {
        let manager = ValidationManager::new(ValidationMode::Full, Network::Dash);

        // Header with invalid PoW
        let header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,          // Invalid nonce
            0x1d00ffff, // Difficulty that requires real PoW
        );

        let result = manager.validate_header(&header, None);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_header_chain_validation_none() {
        let manager = ValidationManager::new(ValidationMode::None, Network::Dash);

        // Even an empty chain should pass
        assert!(manager.validate_headers(&[]).is_ok());

        // Even broken chains should pass
        let headers = vec![
            create_test_header(dashcore::BlockHash::from_byte_array([0; 32]), 1, 0x1e0fffff),
            create_test_header(dashcore::BlockHash::from_byte_array([99; 32]), 2, 0x1e0fffff),
        ];

        assert!(manager.validate_headers(&headers).is_ok());
    }

    #[test]
    fn test_header_chain_validation_basic() {
        let manager = ValidationManager::new(ValidationMode::Basic, Network::Dash);

        // Valid chain
        let mut headers = vec![];
        let mut prev_hash = dashcore::BlockHash::from_raw_hash(
            dashcore_hashes::hash_x11::Hash::from_byte_array([0; 32]),
        );

        for i in 0..3 {
            let header = create_test_header(prev_hash, i, 0x1e0fffff);
            prev_hash = header.block_hash();
            headers.push(header);
        }

        assert!(manager.validate_headers(&headers).is_ok());

        // Broken chain
        headers[2] = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            99,
            0x1e0fffff,
        );

        let result = manager.validate_headers(&headers);
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));
    }

    #[test]
    fn test_header_chain_validation_full() {
        let manager = ValidationManager::new(ValidationMode::Full, Network::Dash);

        // Headers with invalid PoW
        let headers = vec![create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            0,
            0x1d00ffff,
        )];

        // Should fail because of the POW validation
        let result = manager.validate_headers(&headers);
        assert!(matches!(result, Err(ValidationError::InvalidProofOfWork)));
    }

    #[test]
    fn test_instantlock_validation_none() {
        let manager = ValidationManager::new(ValidationMode::None, Network::Dash);
        let instantlock = create_test_instantlock();

        // Should always pass
        assert!(manager.validate_instantlock(&instantlock).is_ok());
    }

    #[test]
    fn test_instantlock_validation_basic() {
        let manager = ValidationManager::new(ValidationMode::Basic, Network::Dash);
        let instantlock = create_test_instantlock();

        // Basic validation should check structure
        let result = manager.validate_instantlock(&instantlock);
        // The actual validation depends on InstantLockValidator implementation
        // For now, we just ensure it runs
        let _ = result;
    }

    #[test]
    fn test_instantlock_validation_full() {
        let manager = ValidationManager::new(ValidationMode::Full, Network::Dash);
        let instantlock = create_test_instantlock();

        // Full validation should check structure and signatures
        let result = manager.validate_instantlock(&instantlock);
        // The actual validation depends on InstantLockValidator implementation
        let _ = result;
    }

    #[test]
    fn test_mode_switching_affects_validation() {
        let mut manager = ValidationManager::new(ValidationMode::None, Network::Dash);

        // Create headers with broken chain
        let header1 = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [0; 32],
            )),
            1,
            0x1e0fffff,
        );
        let disconnected_header = create_test_header(
            dashcore::BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::from_byte_array(
                [99; 32],
            )),
            2,
            0x1e0fffff,
        );

        // Should pass with None
        assert!(manager.validate_header(&disconnected_header, Some(&header1)).is_ok());

        // Switch to Basic
        manager.set_mode(ValidationMode::Basic);

        // Should now fail
        let result = manager.validate_header(&disconnected_header, Some(&header1));
        assert!(matches!(result, Err(ValidationError::InvalidHeaderChain(_))));

        // Switch back to None
        manager.set_mode(ValidationMode::None);

        // Should pass again
        assert!(manager.validate_header(&disconnected_header, Some(&header1)).is_ok());
    }

    #[test]
    fn test_empty_header_chain_validation() {
        for network in [Network::Dash, Network::Testnet, Network::Devnet, Network::Regtest] {
            for mode in [ValidationMode::None, ValidationMode::Basic, ValidationMode::Full] {
                let manager = ValidationManager::new(mode, network);
                let empty_chain: Vec<BlockHeader> = vec![];

                // Empty chains should always pass
                assert!(manager.validate_headers(&empty_chain).is_ok());
            }
        }
    }
}
