//! Header validation functionality.

use dashcore::{block::Header as BlockHeader, error::Error as DashError};
use std::time::Instant;

use crate::error::{ValidationError, ValidationResult};
use crate::types::ValidationMode;

/// Validate a chain of headers considering the validation mode.
pub fn validate_headers(headers: &[BlockHeader], mode: ValidationMode) -> ValidationResult<()> {
    if mode == ValidationMode::None {
        tracing::debug!("Skipping header validation: disabled");
        return Ok(());
    }

    let start = Instant::now();

    let mut prev_block_hash = None;
    for header in headers {
        // Check chain continuity if we have previous header
        if let Some(prev) = prev_block_hash {
            if header.prev_blockhash != prev {
                return Err(ValidationError::InvalidHeaderChain(
                    "Header does not connect to previous header".to_string(),
                ));
            }
        }

        if mode == ValidationMode::Full {
            // Validate proof of work with X11 hashing
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
        }

        prev_block_hash = Some(header.block_hash());
    }

    tracing::debug!(
        "Header chain validation passed for {} headers in mode: {:?}, duration: {:?}",
        headers.len(),
        mode,
        start.elapsed(),
    );
    Ok(())
}

#[cfg(test)]
#[path = "headers_test.rs"]
mod headers_test;

#[cfg(test)]
#[path = "headers_edge_test.rs"]
mod headers_edge_test;
