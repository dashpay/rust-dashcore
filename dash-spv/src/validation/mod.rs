//! Validation functionality for the Dash SPV client.

pub mod headers;
pub mod chainlock;
pub mod instantlock;

use dashcore::{
    block::Header as BlockHeader,
    ChainLock, InstantLock,
};

use crate::error::{ValidationError, ValidationResult};
use crate::types::ValidationMode;

pub use headers::HeaderValidator;
pub use chainlock::ChainLockValidator;
pub use instantlock::InstantLockValidator;

/// Manages all validation operations.
pub struct ValidationManager {
    mode: ValidationMode,
    header_validator: HeaderValidator,
    chainlock_validator: ChainLockValidator,
    instantlock_validator: InstantLockValidator,
}

impl ValidationManager {
    /// Create a new validation manager.
    pub fn new(mode: ValidationMode) -> Self {
        Self {
            mode,
            header_validator: HeaderValidator::new(mode),
            chainlock_validator: ChainLockValidator::new(),
            instantlock_validator: InstantLockValidator::new(),
        }
    }
    
    /// Validate a block header.
    pub fn validate_header(
        &self,
        header: &BlockHeader,
        prev_header: Option<&BlockHeader>,
    ) -> ValidationResult<()> {
        match self.mode {
            ValidationMode::None => Ok(()),
            ValidationMode::Basic | ValidationMode::Full => {
                self.header_validator.validate(header, prev_header)
            }
        }
    }
    
    /// Validate a chain of headers.
    pub fn validate_header_chain(
        &self,
        headers: &[BlockHeader],
        validate_pow: bool,
    ) -> ValidationResult<()> {
        match self.mode {
            ValidationMode::None => Ok(()),
            ValidationMode::Basic => {
                self.header_validator.validate_chain_basic(headers)
            }
            ValidationMode::Full => {
                self.header_validator.validate_chain_full(headers, validate_pow)
            }
        }
    }
    
    /// Validate a ChainLock.
    pub fn validate_chainlock(&self, chainlock: &ChainLock) -> ValidationResult<()> {
        match self.mode {
            ValidationMode::None => Ok(()),
            ValidationMode::Basic | ValidationMode::Full => {
                self.chainlock_validator.validate(chainlock)
            }
        }
    }
    
    /// Validate an InstantLock.
    pub fn validate_instantlock(&self, instantlock: &InstantLock) -> ValidationResult<()> {
        match self.mode {
            ValidationMode::None => Ok(()),
            ValidationMode::Basic | ValidationMode::Full => {
                self.instantlock_validator.validate(instantlock)
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