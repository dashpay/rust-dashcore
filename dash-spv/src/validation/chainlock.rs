//! ChainLock validation functionality.

use dashcore::ChainLock;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore_hashes::{Hash, sha256d};
use tracing::{debug, warn, info};
use blsful;

use crate::error::{ValidationError, ValidationResult};

/// Validates ChainLock messages according to DIP8.
pub struct ChainLockValidator {
    /// Minimum number of quorum members required to sign (240 out of 400)
    min_quorum_signatures: u32,
    /// Total quorum size
    quorum_size: u32,
}

impl ChainLockValidator {
    /// Create a new ChainLock validator with default DIP8 parameters.
    pub fn new() -> Self {
        Self {
            min_quorum_signatures: 240,  // 60% of 400
            quorum_size: 400,
        }
    }

    /// Validate a ChainLock.
    pub fn validate(&self, chain_lock: &ChainLock) -> ValidationResult<()> {
        // Basic structural validation
        self.validate_structure(chain_lock)?;

        // TODO: Validate signature using masternode list
        // For now, we just do basic validation
        tracing::debug!("ChainLock validation passed for height {}", chain_lock.block_height);

        Ok(())
    }

    /// Validate ChainLock structure.
    fn validate_structure(&self, chain_lock: &ChainLock) -> ValidationResult<()> {
        // Check height is reasonable
        if chain_lock.block_height == 0 {
            return Err(ValidationError::InvalidChainLock(
                "ChainLock height cannot be zero".to_string(),
            ));
        }

        // Check block hash is not zero (we'll skip this check for now)
        // TODO: Implement proper null hash check

        // Check signature is not empty
        if chain_lock.signature.as_bytes().is_empty() {
            return Err(ValidationError::InvalidChainLock(
                "ChainLock signature cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate ChainLock signature (requires masternode quorum info).
    pub fn validate_signature(
        &self,
        chain_lock: &ChainLock,
        quorum_public_key: &[u8],
    ) -> ValidationResult<()> {
        // Get the message that should have been signed
        let message = self.get_signing_message(
            chain_lock.block_height,
            &chain_lock.block_hash,
        );

        // Hash the message to get the digest
        let message_digest = sha256d::Hash::hash(&message);

        // Verify BLS signature
        self.verify_bls_signature(
            &chain_lock.signature,
            message_digest.as_byte_array(),
            quorum_public_key,
        )?;

        Ok(())
    }

    /// Check if ChainLock supersedes another ChainLock.
    pub fn supersedes(&self, new_lock: &ChainLock, old_lock: &ChainLock) -> bool {
        // Higher height always supersedes
        if new_lock.block_height > old_lock.block_height {
            return true;
        }

        // Same height but different hash - this shouldn't happen in normal operation
        if new_lock.block_height == old_lock.block_height
            && new_lock.block_hash != old_lock.block_hash
        {
            tracing::warn!(
                "Conflicting ChainLocks at height {}: {} vs {}",
                new_lock.block_height,
                new_lock.block_hash,
                old_lock.block_hash
            );
            // In case of conflict, we could implement additional logic
            // For now, we keep the existing one
            return false;
        }

        false
    }

    /// Get the message to be signed for a ChainLock
    pub fn get_signing_message(
        &self,
        block_height: u32,
        block_hash: &dashcore::BlockHash,
    ) -> Vec<u8> {
        // According to DIP8, the message signed is:
        // "clsig" + blockHeight + blockHash
        let mut message = Vec::new();
        
        // Add message prefix
        message.extend_from_slice(b"clsig");
        
        // Add block height (little-endian)
        message.extend_from_slice(&block_height.to_le_bytes());
        
        // Add block hash
        message.extend_from_slice(block_hash.as_byte_array());
        
        message
    }

    /// Validate ChainLock with masternode quorum information
    pub fn validate_with_quorum(
        &self,
        chain_lock: &ChainLock,
        quorum_public_key: &[u8],
        quorum_height: u32,
    ) -> ValidationResult<()> {
        info!(
            "Validating ChainLock for height {} with quorum at height {}",
            chain_lock.block_height, quorum_height
        );

        // Basic validation first
        self.validate(chain_lock)?;

        // Validate that the quorum is recent enough
        // ChainLocks should be signed by a quorum from a recent block
        let max_quorum_age = 24; // blocks
        if chain_lock.block_height > quorum_height + max_quorum_age {
            return Err(ValidationError::InvalidChainLock(
                format!(
                    "Quorum at height {} is too old for ChainLock at height {}",
                    quorum_height, chain_lock.block_height
                )
            ));
        }

        // Get the message that should have been signed
        let message = self.get_signing_message(
            chain_lock.block_height,
            &chain_lock.block_hash,
        );

        // Hash the message to get the digest
        let message_digest = sha256d::Hash::hash(&message);

        // Verify BLS signature
        self.verify_bls_signature(
            &chain_lock.signature,
            message_digest.as_byte_array(),
            quorum_public_key,
        )?;

        info!(
            "ChainLock BLS signature verified successfully for height {}",
            chain_lock.block_height
        );

        Ok(())
    }

    /// Check if a ChainLock is for a future block
    pub fn is_future_chainlock(&self, chain_lock: &ChainLock, current_height: u32) -> bool {
        chain_lock.block_height > current_height
    }

    /// Validate ChainLock timing constraints
    pub fn validate_timing(&self, chain_lock: &ChainLock, current_height: u32) -> ValidationResult<()> {
        // ChainLocks shouldn't be too far in the future
        let max_future_blocks = 10;
        if chain_lock.block_height > current_height + max_future_blocks {
            return Err(ValidationError::InvalidChainLock(
                format!(
                    "ChainLock height {} is too far in the future (current height: {})",
                    chain_lock.block_height, current_height
                )
            ));
        }

        // ChainLocks shouldn't be too old
        let max_age = 576; // ~1 day worth of blocks
        if current_height > chain_lock.block_height + max_age {
            warn!(
                "ChainLock at height {} is old (current height: {})",
                chain_lock.block_height, current_height
            );
        }

        Ok(())
    }

    /// Verify BLS signature for ChainLock
    fn verify_bls_signature(
        &self,
        signature: &BLSSignature,
        message_digest: &[u8; 32],
        quorum_public_key_bytes: &[u8],
    ) -> ValidationResult<()> {
        use blsful::Bls12381G2Impl;
        
        // Validate public key length
        if quorum_public_key_bytes.len() != 48 {
            return Err(ValidationError::InvalidChainLock(
                format!(
                    "Invalid quorum public key length: expected 48, got {}",
                    quorum_public_key_bytes.len()
                )
            ));
        }

        // Create BLS public key from bytes
        let public_key = blsful::PublicKey::<Bls12381G2Impl>::try_from(quorum_public_key_bytes)
            .map_err(|e| ValidationError::InvalidChainLock(
                format!("Failed to parse quorum public key: {:?}", e)
            ))?;

        // Convert signature to blsful type
        let sig_bytes = signature.to_bytes();
        let bls_signature = blsful::Signature::<Bls12381G2Impl>::try_from(sig_bytes.as_slice())
            .map_err(|e| ValidationError::InvalidChainLock(
                format!("Failed to parse BLS signature: {:?}", e)
            ))?;

        // Verify the signature
        bls_signature
            .verify(&public_key, *message_digest)
            .map_err(|e| ValidationError::InvalidChainLock(
                format!("BLS signature verification failed: {}", e)
            ))?;

        debug!("BLS signature verified successfully");
        Ok(())
    }
}
