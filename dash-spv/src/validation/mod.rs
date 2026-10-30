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
pub use instantlock::{InstantLockStructureValidator, InstantLockValidator};
pub use masternode_list::MasternodeListValidator;

use crate::error::ValidationResult;

pub trait Validator<T> {
    fn validate(&self, data: T) -> ValidationResult<()>;
}
