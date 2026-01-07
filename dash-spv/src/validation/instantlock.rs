//! InstantLock validation functionality.

use dashcore::InstantLock;
use dashcore_hashes::Hash;

use crate::error::{ValidationError, ValidationResult};

/// Validates InstantLock messages.
#[derive(Default)]
pub struct InstantLockValidator {
    // Quorum manager is now passed as parameter to validate_signature
    // to avoid circular dependencies and allow flexible usage
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
    fn validate_structure(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
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
    fn validate_signature(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore_hashes::{sha256d, Hash};

    #[test]
    fn test_valid_instantlock() {
        let validator = InstantLockValidator::new();
        let is_lock = InstantLock::dummy();

        // Structural validation only (for testing)
        assert!(validator.validate_structure(&is_lock).is_ok());
    }

    #[test]
    fn test_empty_inputs() {
        let validator = InstantLockValidator::new();
        let mut is_lock = InstantLock::dummy();
        is_lock.inputs.clear();

        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one input"));
    }

    #[test]
    fn test_empty_signature() {
        let validator = InstantLockValidator::new();
        let mut is_lock = InstantLock::dummy();
        is_lock.signature = dashcore::bls_sig_utils::BLSSignature::from([0; 96]);

        // Zero signatures should be rejected as invalid structure
        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature cannot be zero"));
    }

    #[test]
    fn test_null_txid() {
        let validator = InstantLockValidator::new();
        let mut is_lock = InstantLock::dummy();
        is_lock.txid = dashcore::Txid::all_zeros();

        // Null txid should be rejected as invalid structure
        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("transaction ID cannot be zero"));
    }

    #[test]
    fn test_null_input_txid() {
        let validator = InstantLockValidator::new();
        let mut is_lock = InstantLock::dummy();
        // Set the second input to have a null txid
        is_lock.inputs[1].txid = dashcore::Txid::all_zeros();

        // Null input txid should be rejected as invalid structure
        let result = validator.validate_structure(&is_lock);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("input") && err_str.contains("null transaction ID"));
    }

    // Note: test_signature_validation_without_quorum has been removed as BLS signature
    // verification now requires MasternodeListEngine, not the simplified QuorumManager.

    // Note: test_signature_validation_with_quorum_invalid_signature has been removed
    // as BLS signature verification now requires MasternodeListEngine with properly
    // populated rotated quorums implementing DIP 24 quorum selection.

    #[test]
    fn test_request_id_computation() {
        let is_lock = InstantLock::dummy();

        // Verify request ID can be computed
        let request_id = is_lock.request_id();
        assert!(request_id.is_ok());

        // Same inputs should produce same request ID
        let is_lock2 = InstantLock::dummy();
        let request_id2 = is_lock2.request_id();
        assert!(request_id2.is_ok());
        assert_eq!(request_id.unwrap(), request_id2.unwrap());
    }

    #[test]
    fn test_edge_case_many_inputs() {
        let validator = InstantLockValidator::new();

        // Create lock with many inputs
        let many_inputs: Vec<sha256d::Hash> =
            (0..100u32).map(|i| sha256d::Hash::hash(&i.to_le_bytes())).collect();

        let lock = InstantLock::dummy_with_inputs(many_inputs);

        assert!(validator.validate_structure(&lock).is_ok());
    }
}
