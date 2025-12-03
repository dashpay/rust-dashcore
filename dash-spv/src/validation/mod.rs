//! Validation functionality for the Dash SPV client.

pub mod headers;
pub mod instantlock;
pub mod quorum;

use dashcore::{block::Header as BlockHeader, InstantLock, Network};

use crate::error::ValidationResult;
use crate::types::ValidationMode;

pub use headers::HeaderValidator;
pub use instantlock::InstantLockValidator;
pub use quorum::{QuorumInfo, QuorumManager, QuorumType};

/// Manages all validation operations.
pub struct ValidationManager {
    mode: ValidationMode,
    header_validator: HeaderValidator,
    instantlock_validator: InstantLockValidator,
}

impl ValidationManager {
    /// Create a new validation manager.
    pub fn new(mode: ValidationMode, network: Network) -> Self {
        Self {
            mode,
            header_validator: HeaderValidator::new(mode, network),
            instantlock_validator: InstantLockValidator::new(),
        }
    }

    /// Validate a block header.
    pub fn validate_header(
        &self,
        header: &BlockHeader,
        prev_header: Option<&BlockHeader>,
    ) -> ValidationResult<()> {
        self.header_validator.validate(header, prev_header)
    }

    /// Validate a chain of headers.
    pub fn validate_headers(&self, headers: &[BlockHeader]) -> ValidationResult<()> {
        self.header_validator.validate_headers(headers)
    }

    /// Validate an InstantLock (structural validation only).
    ///
    /// **WARNING**: This only performs structural validation without BLS signature
    /// verification. For network messages, the caller must use the InstantLockValidator
    /// directly with a masternode engine to ensure full security.
    pub fn validate_instantlock(&self, instantlock: &InstantLock) -> ValidationResult<()> {
        match self.mode {
            ValidationMode::None => Ok(()),
            ValidationMode::Basic | ValidationMode::Full => {
                // Only structural validation - signature verification requires masternode engine
                // which should be passed by the caller when processing network messages
                self.instantlock_validator.validate_structure(instantlock)
            }
        }
    }

    /// Get current validation mode.
    pub fn mode(&self) -> ValidationMode {
        self.mode
    }

    /// Set validation mode.
    pub fn set_mode(&mut self, mode: ValidationMode) {
        self.mode = mode;
        self.header_validator.set_mode(mode);
    }
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod manager_test;
