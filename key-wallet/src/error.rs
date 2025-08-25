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
    /// SLIP-0010 Ed25519 derivation error
    #[cfg(feature = "eddsa")]
    Slip10(crate::derivation_slip10::Error),
    /// BLS HD derivation error
    #[cfg(feature = "bls")]
    BLS(crate::derivation_bls_bip32::Error),
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
    /// CoinJoin not enabled
    CoinJoinNotEnabled,
    /// Serialization error
    Serialization(String),
    /// Invalid parameter
    InvalidParameter(String),
    /// Watch-only wallet (no private keys available)
    WatchOnly,
    /// No key source available for address derivation
    NoKeySource,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Bip32(e) => write!(f, "BIP32 error: {}", e),
            #[cfg(feature = "eddsa")]
            Error::Slip10(e) => write!(f, "SLIP-0010 error: {}", e),
            #[cfg(feature = "bls")]
            Error::BLS(e) => write!(f, "BLS error: {}", e),
            Error::InvalidMnemonic(s) => write!(f, "Invalid mnemonic: {}", s),
            Error::InvalidDerivationPath(s) => write!(f, "Invalid derivation path: {}", s),
            Error::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            Error::Secp256k1(e) => write!(f, "Secp256k1 error: {}", e),
            Error::Base58 => write!(f, "Base58 decoding error"),
            Error::InvalidNetwork => write!(f, "Invalid network"),
            Error::KeyError(s) => write!(f, "Key error: {}", s),
            Error::CoinJoinNotEnabled => write!(f, "CoinJoin not enabled for this account"),
            Error::Serialization(s) => write!(f, "Serialization error: {}", s),
            Error::InvalidParameter(s) => write!(f, "Invalid parameter: {}", s),
            Error::WatchOnly => write!(f, "Watch-only wallet: private keys not available"),
            Error::NoKeySource => write!(f, "No key source available for address derivation"),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Bip32(e) => Some(e),
            #[cfg(feature = "eddsa")]
            Error::Slip10(e) => Some(e),
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

#[cfg(feature = "eddsa")]
impl From<crate::derivation_slip10::Error> for Error {
    fn from(e: crate::derivation_slip10::Error) -> Self {
        Error::Slip10(e)
    }
}

#[cfg(feature = "bls")]
impl From<crate::derivation_bls_bip32::Error> for Error {
    fn from(e: crate::derivation_bls_bip32::Error) -> Self {
        Error::BLS(e)
    }
}
