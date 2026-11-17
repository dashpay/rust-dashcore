//! Validation functionality for the Dash SPV client.

mod block;
mod chainlock;
mod filter;
mod header;
mod instantlock;
mod masternode_list;

pub use block::BlockValidator;
pub use chainlock::ChainLockValidator;
pub use filter::{FilterValidationInput, FilterValidator};
pub use header::BlockHeaderValidator;
pub(crate) use instantlock::verify_against_cycle;
pub use instantlock::InstantLockStructureValidator;
#[cfg(test)]
pub(crate) use instantlock::MAX_INSTANT_LOCK_INPUTS;
pub use masternode_list::MasternodeListValidator;

use crate::error::ValidationResult;

pub trait Validator<T> {
    fn validate(&self, data: T) -> ValidationResult<()>;
}
