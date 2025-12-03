//! Header validation functionality.

use dashcore::{
    block::Header as BlockHeader, error::Error as DashError, network::constants::NetworkExt,
    Network,
};

use crate::error::{ValidationError, ValidationResult};
use crate::types::ValidationMode;

/// Validates block headers.
pub struct HeaderValidator {
    mode: ValidationMode,
    network: Network,
}

impl HeaderValidator {
    /// Create a new header validator.
    pub fn new(mode: ValidationMode, network: Network) -> Self {
        Self {
            mode,
            network,
        }
    }

    /// Set validation mode.
    pub fn set_mode(&mut self, mode: ValidationMode) {
        self.mode = mode;
    }

    /// Validate a single header.
    pub fn validate(
        &self,
        header: &BlockHeader,
        prev_header: Option<&BlockHeader>,
    ) -> ValidationResult<()> {
        match self.mode {
            ValidationMode::None => Ok(()),
            ValidationMode::Basic => self.validate_basic(header, prev_header),
            ValidationMode::Full => self.validate_full(header, prev_header),
        }
    }

    /// Basic header validation (structure and chain continuity).
    fn validate_basic(
        &self,
        header: &BlockHeader,
        prev_header: Option<&BlockHeader>,
    ) -> ValidationResult<()> {
        // Check chain continuity if we have previous header
        if let Some(prev) = prev_header {
            if header.prev_blockhash != prev.block_hash() {
                return Err(ValidationError::InvalidHeaderChain(
                    "Header does not connect to previous header".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Full header validation (includes PoW verification).
    fn validate_full(
        &self,
        header: &BlockHeader,
        prev_header: Option<&BlockHeader>,
    ) -> ValidationResult<()> {
        // First do basic validation
        self.validate_basic(header, prev_header)?;

        // Validate proof of work with X11 hashing (now enabled with core-block-hash-use-x11 feature)
        let target = header.target();
        if let Err(e) = header.validate_pow(target) {
            return match e {
                DashError::BlockBadProofOfWork => Err(ValidationError::InvalidProofOfWork),
                DashError::BlockBadTarget => {
                    Err(ValidationError::InvalidHeaderChain("Invalid target".to_string()))
                }
                _ => Err(ValidationError::InvalidHeaderChain(format!(
                    "PoW validation error: {:?}",
                    e
                ))),
            };
        }

        Ok(())
    }

    /// Validate a chain of headers considering the validation mode.
    pub fn validate_headers(&self, headers: &[BlockHeader]) -> ValidationResult<()> {
        if self.mode == ValidationMode::None {
            return Ok(());
        }

        if headers.is_empty() {
            return Ok(());
        }

        // For the first header, we might need to check it connects to genesis or our existing chain
        // For now, we'll just validate internal chain continuity

        // Validate each header in the chain
        for i in 0..headers.len() {
            let header = &headers[i];
            let prev_header = if i > 0 {
                Some(&headers[i - 1])
            } else {
                None
            };

            self.validate(header, prev_header)?;
        }

        tracing::debug!(
            "Header chain validation passed for {} headers in mode: {:?}",
            headers.len(),
            self.mode
        );
        Ok(())
    }

    /// Validate headers connect to genesis block.
    pub fn validate_connects_to_genesis(&self, headers: &[BlockHeader]) -> ValidationResult<()> {
        if headers.is_empty() {
            return Ok(());
        }

        let genesis_hash = self.network.known_genesis_block_hash().ok_or_else(|| {
            ValidationError::Consensus("No known genesis hash for network".to_string())
        })?;

        if headers[0].prev_blockhash != genesis_hash {
            return Err(ValidationError::InvalidHeaderChain(
                "First header doesn't connect to genesis".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "headers_test.rs"]
mod headers_test;

#[cfg(test)]
#[path = "headers_edge_test.rs"]
mod headers_edge_test;
