//! InstantLock validation functionality.

use dashcore::InstantLock;

use crate::error::{ValidationError, ValidationResult};

/// Validates InstantLock messages.
pub struct InstantLockValidator {
    // TODO: Add masternode list for signature verification
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

    /// Validate an InstantLock.
    pub fn validate(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
        // Basic structural validation
        self.validate_structure(instant_lock)?;

        // TODO: Validate signature using masternode list
        // For now, we just do basic validation
        tracing::debug!("InstantLock validation passed for txid {}", instant_lock.txid);

        Ok(())
    }

    /// Validate InstantLock structure.
    fn validate_structure(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
        // Check transaction ID is not zero (we'll skip this check for now)
        // TODO: Implement proper null txid check

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

        // Validate each input (we'll skip null check for now)
        // TODO: Implement proper null input check

        Ok(())
    }

    /// Validate InstantLock signature (requires masternode quorum info).
    pub fn validate_signature(
        &self,
        _instant_lock: &InstantLock,
        // TODO: Add masternode list parameter
    ) -> ValidationResult<()> {
        // TODO: Implement proper signature validation
        // This requires:
        // 1. Active quorum information for InstantSend
        // 2. BLS signature verification
        // 3. Quorum member validation
        // 4. Input validation against the transaction

        // For now, we skip signature validation
        tracing::warn!("InstantLock signature validation not implemented");
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

        assert!(validator.validate(&is_lock).is_ok());
    }

    #[test]
    fn test_empty_inputs() {
        let validator = InstantLockValidator::new();
        let mut is_lock = create_instant_lock_with_inputs(
            sha256d::Hash::hash(&[1, 2, 3]),
            vec![(sha256d::Hash::hash(&[4, 5, 6]), 0)],
        );
        is_lock.inputs.clear();

        let result = validator.validate(&is_lock);
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
        let result = validator.validate(&is_lock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature cannot be zero"));
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

    #[test]
    fn test_signature_validation_stub() {
        let validator = InstantLockValidator::new();
        let tx = create_test_transaction(vec![(sha256d::Hash::hash(&[1, 2, 3]), 0)], COIN_VALUE);
        let is_lock = create_test_instant_lock(&tx);

        // Should pass for now (not implemented)
        assert!(validator.validate_signature(&is_lock).is_ok());
    }

    #[test]
    fn test_edge_case_many_inputs() {
        let validator = InstantLockValidator::new();

        // Create lock with many inputs
        let many_inputs: Vec<(sha256d::Hash, u32)> =
            (0..100u32).map(|i| (sha256d::Hash::hash(&i.to_le_bytes()), i % 10)).collect();

        let lock =
            create_instant_lock_with_inputs(sha256d::Hash::hash(&[100, 101, 102]), many_inputs);

        assert!(validator.validate(&lock).is_ok());
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
