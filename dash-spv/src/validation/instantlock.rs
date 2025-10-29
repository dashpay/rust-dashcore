//! InstantLock validation functionality.

use dashcore::InstantLock;
use dashcore_hashes::Hash;

use crate::error::{ValidationError, ValidationResult};

/// Validates InstantLock messages.
pub struct InstantLockValidator {
    // Quorum manager is now passed as parameter to validate_signature
    // to avoid circular dependencies and allow flexible usage
}

impl Default for InstantLockValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl InstantLockValidator {
    /// Create a new InstantLock validator.
    pub fn new() -> Self {
        Self {}
    }

    /// Validate an InstantLock with full BLS signature verification.
    ///
    /// This performs complete validation including:
    /// - Structural validation (non-zero txid, signature, inputs)
    /// - BLS signature verification using cyclehash-based quorum selection (DIP 24)
    ///
    /// **Security Critical**: This method requires a masternode engine to verify
    /// BLS signatures. Never accept InstantLocks from the network without full
    /// signature verification.
    pub fn validate(
        &self,
        instant_lock: &InstantLock,
        masternode_engine: &dashcore::sml::masternode_list_engine::MasternodeListEngine,
    ) -> ValidationResult<()> {
        // Perform structural validation
        self.validate_structure(instant_lock)?;

        // Perform BLS signature verification (REQUIRED for security)
        self.validate_signature(instant_lock, masternode_engine)?;

        tracing::debug!(
            "InstantLock fully validated (structure + signature) for txid {}",
            instant_lock.txid
        );

        Ok(())
    }

    /// Validate InstantLock structure (without BLS signature verification).
    ///
    /// **WARNING**: This is insufficient for accepting network messages.
    /// For production use, always call `validate()` with a masternode engine.
    /// This method is public only for testing purposes.
    pub fn validate_structure(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
        // Check transaction ID is not zero (null txid)
        if instant_lock.txid == dashcore::Txid::all_zeros() {
            return Err(ValidationError::InvalidInstantLock(
                "InstantLock transaction ID cannot be zero".to_string(),
            ));
        }

        // Check signature is not zero (null signature)
        if instant_lock.signature.is_zeroed() {
            return Err(ValidationError::InvalidInstantLock(
                "InstantLock signature cannot be zero".to_string(),
            ));
        }

        // Check inputs are present
        if instant_lock.inputs.is_empty() {
            return Err(ValidationError::InvalidInstantLock(
                "InstantLock must have at least one input".to_string(),
            ));
        }

        // Validate each input - ensure no input has a null txid
        for (idx, input) in instant_lock.inputs.iter().enumerate() {
            if input.txid == dashcore::Txid::all_zeros() {
                return Err(ValidationError::InvalidInstantLock(format!(
                    "InstantLock input {} has null transaction ID",
                    idx
                )));
            }
        }

        Ok(())
    }

    /// Validate InstantLock signature using the masternode list engine.
    ///
    /// This properly uses the cyclehash to select the correct quorum according to DIP 24.
    /// The MasternodeListEngine tracks rotated quorums per cycle and selects the specific
    /// quorum based on the request_id.
    pub fn validate_signature(
        &self,
        instant_lock: &InstantLock,
        masternode_engine: &dashcore::sml::masternode_list_engine::MasternodeListEngine,
    ) -> ValidationResult<()> {
        // Use the proper verification from the masternode engine which:
        // 1. Uses cyclehash to get the set of rotated quorums
        // 2. Uses request_id to select the specific quorum (DIP 24)
        // 3. Verifies the BLS signature with that quorum's public key
        masternode_engine.verify_is_lock(instant_lock).map_err(|e| {
            ValidationError::InvalidSignature(format!(
                "InstantLock BLS signature verification failed: {}",
                e
            ))
        })?;

        tracing::debug!(
            "InstantLock signature verified for txid {} using cyclehash {:x}",
            instant_lock.txid,
            instant_lock.cyclehash
        );

        Ok(())
    }

    /// Check if an InstantLock is still valid (not too old).
    pub fn is_still_valid(&self, _instant_lock: &InstantLock) -> bool {
        // InstantLocks should be processed quickly
        // In a real implementation, we'd check against block height or timestamp
        // For now, we assume all InstantLocks are valid
        true
    }

    /// Check if an InstantLock conflicts with another.
    pub fn conflicts_with(&self, lock1: &InstantLock, lock2: &InstantLock) -> bool {
        // InstantLocks for the same transaction don't conflict
        if lock1.txid == lock2.txid {
            return false;
        }

        // InstantLocks conflict if they try to lock the same input
        for input1 in &lock1.inputs {
            for input2 in &lock2.inputs {
                if input1 == input2 {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::constants::COIN_VALUE;
    use dashcore::{OutPoint, ScriptBuf, Transaction, TxIn, TxOut};
    use dashcore_hashes::{sha256d, Hash};

    /// Helper to create a test transaction
    fn create_test_transaction(inputs: Vec<(sha256d::Hash, u32)>, value: u64) -> Transaction {
        let tx_ins = inputs
            .into_iter()
            .map(|(txid, vout)| TxIn {
                previous_output: OutPoint {
                    txid: dashcore::Txid::from_raw_hash(txid),
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            })
            .collect();

        let tx_outs = vec![TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        }];

        Transaction {
            version: 2,
            lock_time: 0,
            input: tx_ins,
            output: tx_outs,
            special_transaction_payload: None,
        }
    }

    /// Helper to create a test InstantLock
    fn create_test_instant_lock(tx: &Transaction) -> InstantLock {
        let inputs = tx.input.iter().map(|input| input.previous_output).collect();

        InstantLock {
            version: 1,
            inputs,
            txid: tx.txid(),
            signature: dashcore::bls_sig_utils::BLSSignature::from([1; 96]),
            cyclehash: dashcore::BlockHash::from_byte_array([0; 32]),
        }
    }

    /// Helper to create an InstantLock with specific inputs
    fn create_instant_lock_with_inputs(
        txid: sha256d::Hash,
        inputs: Vec<(sha256d::Hash, u32)>,
    ) -> InstantLock {
        let inputs = inputs
            .into_iter()
            .map(|(txid, vout)| OutPoint {
                txid: dashcore::Txid::from_raw_hash(txid),
                vout,
            })
            .collect();

        InstantLock {
            version: 1,
            inputs,
            txid: dashcore::Txid::from_raw_hash(txid),
            signature: dashcore::bls_sig_utils::BLSSignature::from([1; 96]),
            cyclehash: dashcore::BlockHash::from_byte_array([0; 32]),
        }
    }

    #[test]
    fn test_valid_instantlock() {
        let validator = InstantLockValidator::new();
        let tx = create_test_transaction(vec![(sha256d::Hash::hash(&[1, 2, 3]), 0)], COIN_VALUE);
        let is_lock = create_test_instant_lock(&tx);

        // Structural validation only (for testing)
        assert!(validator.validate_structure(&is_lock).is_ok());
    }

    #[test]
    fn test_empty_inputs() {
        let validator = InstantLockValidator::new();
        let mut is_lock = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[1, 2, 3]),
            vec![(sha256d::Hash::hash(&[4, 5, 6]), 0)],
        );
        is_lock.inputs.clear();

        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one input"));
    }

    #[test]
    fn test_empty_signature() {
        let validator = InstantLockValidator::new();
        let mut is_lock = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[1, 2, 3]),
            vec![(sha256d::Hash::hash(&[4, 5, 6]), 0)],
        );
        is_lock.signature = dashcore::bls_sig_utils::BLSSignature::from([0; 96]);

        // Zero signatures should be rejected as invalid structure
        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature cannot be zero"));
    }

    #[test]
    fn test_null_txid() {
        let validator = InstantLockValidator::new();
        let mut is_lock = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[1, 2, 3]),
            vec![(sha256d::Hash::hash(&[4, 5, 6]), 0)],
        );
        is_lock.txid = dashcore::Txid::all_zeros();

        // Null txid should be rejected as invalid structure
        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("transaction ID cannot be zero"));
    }

    #[test]
    fn test_null_input_txid() {
        let validator = InstantLockValidator::new();
        let mut is_lock = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[1, 2, 3]),
            vec![(sha256d::Hash::hash(&[4, 5, 6]), 0), (sha256d::Hash::hash(&[7, 8, 9]), 1)],
        );
        // Set the second input to have a null txid
        is_lock.inputs[1].txid = dashcore::Txid::all_zeros();

        // Null input txid should be rejected as invalid structure
        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("input") && err_str.contains("null transaction ID"));
    }

    #[test]
    fn test_conflicts_with_same_input() {
        let validator = InstantLockValidator::new();
        let input = (sha256d::Hash::hash(&[1, 2, 3]), 0);

        let lock1 =
            create_instant_lock_with_inputs(sha256d::Hash::hash(&[10, 11, 12]), vec![input]);

        let lock2 =
            create_instant_lock_with_inputs(sha256d::Hash::hash(&[13, 14, 15]), vec![input]);

        assert!(validator.conflicts_with(&lock1, &lock2));
    }

    #[test]
    fn test_no_conflict_different_inputs() {
        let validator = InstantLockValidator::new();

        let lock1 = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[10, 11, 12]),
            vec![(sha256d::Hash::hash(&[1, 2, 3]), 0)],
        );

        let lock2 = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[13, 14, 15]),
            vec![(sha256d::Hash::hash(&[4, 5, 6]), 0)],
        );

        assert!(!validator.conflicts_with(&lock1, &lock2));
    }

    #[test]
    fn test_partial_conflict() {
        let validator = InstantLockValidator::new();
        let shared_input = (sha256d::Hash::hash(&[1, 2, 3]), 0);

        let lock1 = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[10, 11, 12]),
            vec![shared_input, (sha256d::Hash::hash(&[4, 5, 6]), 0)],
        );

        let lock2 = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[13, 14, 15]),
            vec![shared_input, (sha256d::Hash::hash(&[7, 8, 9]), 0)],
        );

        assert!(validator.conflicts_with(&lock1, &lock2));
    }

    #[test]
    fn test_multiple_inputs_no_conflict() {
        let validator = InstantLockValidator::new();

        let lock1 = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[10, 11, 12]),
            vec![(sha256d::Hash::hash(&[1, 2, 3]), 0), (sha256d::Hash::hash(&[4, 5, 6]), 0)],
        );

        let lock2 = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[13, 14, 15]),
            vec![(sha256d::Hash::hash(&[7, 8, 9]), 0), (sha256d::Hash::hash(&[10, 11, 12]), 0)],
        );

        assert!(!validator.conflicts_with(&lock1, &lock2));
    }

    #[test]
    fn test_is_still_valid() {
        let validator = InstantLockValidator::new();
        let tx = create_test_transaction(vec![(sha256d::Hash::hash(&[1, 2, 3]), 0)], COIN_VALUE);
        let is_lock = create_test_instant_lock(&tx);

        // For now, all locks are considered valid
        assert!(validator.is_still_valid(&is_lock));
    }

    // Note: test_signature_validation_without_quorum has been removed as BLS signature
    // verification now requires MasternodeListEngine, not the simplified QuorumManager.

    // Note: test_signature_validation_with_quorum_invalid_signature has been removed
    // as BLS signature verification now requires MasternodeListEngine with properly
    // populated rotated quorums implementing DIP 24 quorum selection.

    #[test]
    fn test_request_id_computation() {
        let tx = create_test_transaction(vec![(sha256d::Hash::hash(&[1, 2, 3]), 0)], COIN_VALUE);
        let is_lock = create_test_instant_lock(&tx);

        // Verify request ID can be computed
        let request_id = is_lock.request_id();
        assert!(request_id.is_ok());

        // Same inputs should produce same request ID
        let is_lock2 = create_test_instant_lock(&tx);
        let request_id2 = is_lock2.request_id();
        assert!(request_id2.is_ok());
        assert_eq!(request_id.unwrap(), request_id2.unwrap());
    }

    #[test]
    fn test_edge_case_many_inputs() {
        let validator = InstantLockValidator::new();

        // Create lock with many inputs
        let many_inputs: Vec<(sha256d::Hash, u32)> =
            (0..100u32).map(|i| (sha256d::Hash::hash(&i.to_le_bytes()), i % 10)).collect();

        let lock =
            create_instant_lock_with_inputs(sha256d::Hash::hash(&[100, 101, 102]), many_inputs);

        assert!(validator.validate_structure(&lock).is_ok());
    }

    #[test]
    fn test_same_lock_no_conflict() {
        let validator = InstantLockValidator::new();
        let tx = create_test_transaction(vec![(sha256d::Hash::hash(&[1, 2, 3]), 0)], COIN_VALUE);
        let is_lock = create_test_instant_lock(&tx);

        // Same lock should not conflict with itself
        assert!(!validator.conflicts_with(&is_lock, &is_lock));
    }
}
