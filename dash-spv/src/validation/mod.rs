//! Validation functionality for the Dash SPV client.

mod filter;
mod header;

pub use filter::{FilterValidationInput, FilterValidator};
pub use header::BlockHeaderValidator;

use crate::error::ValidationResult;

pub trait Validator<T> {
    fn validate(&self, data: T) -> ValidationResult<()>;
}
