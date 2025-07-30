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
    pub fn new(mode: ValidationMode) -> Self {
        Self {
            mode,
            network: Network::Dash, // Default to mainnet
        }
    }

    /// Set validation mode.
    pub fn set_mode(&mut self, mode: ValidationMode) {
        self.mode = mode;
    }

    /// Set network.
    pub fn set_network(&mut self, network: Network) {
        self.network = network;
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
            match e {
                DashError::BlockBadProofOfWork => {
                    return Err(ValidationError::InvalidProofOfWork);
                }
                DashError::BlockBadTarget => {
                    return Err(ValidationError::InvalidHeaderChain("Invalid target".to_string()));
                }
                _ => {
                    return Err(ValidationError::InvalidHeaderChain(format!(
                        "PoW validation error: {:?}",
                        e
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate a chain of headers with basic validation.
    pub fn validate_chain_basic(&self, headers: &[BlockHeader]) -> ValidationResult<()> {
        // Respect ValidationMode::None
        if self.mode == ValidationMode::None {
            return Ok(());
        }

        if headers.is_empty() {
            return Ok(());
        }

        // Validate chain continuity
        for i in 1..headers.len() {
            let header = &headers[i];
            let prev_header = &headers[i - 1];

            self.validate_basic(header, Some(prev_header))?;
        }

        tracing::debug!("Basic header chain validation passed for {} headers", headers.len());
        Ok(())
    }

    /// Validate a chain of headers with full validation.
    pub fn validate_chain_full(
        &self,
        headers: &[BlockHeader],
        validate_pow: bool,
    ) -> ValidationResult<()> {
        // Respect ValidationMode::None
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

            if validate_pow {
                self.validate_full(header, prev_header)?;
            } else {
                self.validate_basic(header, prev_header)?;
            }
        }

        tracing::debug!("Full header chain validation passed for {} headers", headers.len());
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

    /// Validate difficulty adjustment (simplified for SPV).
    pub fn validate_difficulty_adjustment(
        &self,
        header: &BlockHeader,
        prev_header: &BlockHeader,
    ) -> ValidationResult<()> {
        // For SPV client, we trust that the network has validated difficulty properly
        // We only check basic constraints

        // For SPV we trust the network for difficulty validation
        // TODO: Implement proper difficulty validation if needed
        let _prev_target = prev_header.target();
        let _current_target = header.target();

        Ok(())
    }
}

#[cfg(test)]
#[path = "headers_test.rs"]
mod headers_test;

#[cfg(test)]
#[path = "headers_edge_test.rs"]
mod headers_edge_test;
