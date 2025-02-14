use thiserror::Error;

#[derive(Debug, Error, Clone, Ord, PartialOrd, PartialEq, Hash,  Eq)]
pub enum QuorumValidationError {

}