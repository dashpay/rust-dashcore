//! Error types for the key-wallet library

use core::fmt;

#[cfg(feature = "std")]
use std::error;

/// Result type alias for key-wallet operations
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur in key-wallet operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// BIP32 related error
    Bip32(crate::bip32::Error),
    /// Invalid mnemonic phrase
    InvalidMnemonic(String),
    /// Invalid derivation path
    InvalidDerivationPath(String),
    /// Invalid address
    InvalidAddress(String),
    /// Secp256k1 error
    Secp256k1(secp256k1::Error),
    /// Base58 decoding error
    Base58,
    /// Invalid network
    InvalidNetwork,
    /// Key error
    KeyError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Bip32(e) => write!(f, "BIP32 error: {}", e),
            Error::InvalidMnemonic(s) => write!(f, "Invalid mnemonic: {}", s),
            Error::InvalidDerivationPath(s) => write!(f, "Invalid derivation path: {}", s),
            Error::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            Error::Secp256k1(e) => write!(f, "Secp256k1 error: {}", e),
            Error::Base58 => write!(f, "Base58 decoding error"),
            Error::InvalidNetwork => write!(f, "Invalid network"),
            Error::KeyError(s) => write!(f, "Key error: {}", s),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Bip32(e) => Some(e),
            Error::Secp256k1(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::bip32::Error> for Error {
    fn from(e: crate::bip32::Error) -> Self {
        Error::Bip32(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp256k1(e)
    }
}
