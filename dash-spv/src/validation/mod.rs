//! Validation functionality for the Dash SPV client.

mod header;
mod instantlock;

pub use header::BlockHeaderValidator;
pub use instantlock::InstantLockValidator;

use crate::error::ValidationResult;

pub trait Validator<T> {
    fn validate(&self, data: T) -> ValidationResult<()>;
}
