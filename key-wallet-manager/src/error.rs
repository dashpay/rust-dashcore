//! Error types for the wallet manager.

use crate::WalletId;

/// Wallet manager errors
#[derive(Debug)]
pub enum WalletError {
    /// Wallet creation failed
    WalletCreation(String),
    /// Wallet not found
    WalletNotFound(WalletId),
    /// Wallet already exists
    WalletExists(WalletId),
    /// Invalid mnemonic
    InvalidMnemonic(String),
    /// Account creation failed
    AccountCreation(String),
    /// Account not found
    AccountNotFound(u32),
    /// Address generation failed
    AddressGeneration(String),
    /// Invalid network
    InvalidNetwork,
    /// Invalid parameter
    InvalidParameter(String),
    /// Transaction building failed
    TransactionBuild(String),
    /// Insufficient funds
    InsufficientFunds,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::WalletCreation(msg) => write!(f, "Wallet creation failed: {}", msg),
            WalletError::WalletNotFound(id) => {
                write!(f, "Wallet not found: ")?;
                for byte in id.iter() {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
            WalletError::WalletExists(id) => {
                write!(f, "Wallet already exists: ")?;
                for byte in id.iter() {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
            WalletError::InvalidMnemonic(msg) => write!(f, "Invalid mnemonic: {}", msg),
            WalletError::AccountCreation(msg) => write!(f, "Account creation failed: {}", msg),
            WalletError::AccountNotFound(idx) => write!(f, "Account not found: {}", idx),
            WalletError::AddressGeneration(msg) => write!(f, "Address generation failed: {}", msg),
            WalletError::InvalidNetwork => write!(f, "Invalid network"),
            WalletError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            WalletError::TransactionBuild(err) => write!(f, "Transaction build failed: {}", err),
            WalletError::InsufficientFunds => write!(f, "Insufficient funds"),
        }
    }
}

impl std::error::Error for WalletError {}

/// Conversion from key_wallet::Error to WalletError
impl From<key_wallet::Error> for WalletError {
    fn from(err: key_wallet::Error) -> Self {
        use key_wallet::Error;

        match err {
            Error::InvalidMnemonic(msg) => WalletError::InvalidMnemonic(msg),
            Error::InvalidDerivationPath(msg) => {
                WalletError::InvalidParameter(format!("Invalid derivation path: {}", msg))
            }
            Error::InvalidAddress(msg) => {
                WalletError::AddressGeneration(format!("Invalid address: {}", msg))
            }
            Error::InvalidNetwork => WalletError::InvalidNetwork,
            Error::InvalidParameter(msg) => WalletError::InvalidParameter(msg),
            Error::WatchOnly => WalletError::InvalidParameter(
                "Operation not supported on watch-only wallet".to_string(),
            ),
            Error::CoinJoinNotEnabled => {
                WalletError::InvalidParameter("CoinJoin not enabled".to_string())
            }
            Error::KeyError(msg) => WalletError::AccountCreation(format!("Key error: {}", msg)),
            Error::Serialization(msg) => {
                WalletError::InvalidParameter(format!("Serialization error: {}", msg))
            }
            Error::Bip32(e) => WalletError::AccountCreation(format!("BIP32 error: {}", e)),
            Error::Secp256k1(e) => WalletError::AccountCreation(format!("Secp256k1 error: {}", e)),
            Error::Base58 => WalletError::InvalidParameter("Base58 decoding error".to_string()),
            Error::NoKeySource => {
                WalletError::InvalidParameter("No key source available".to_string())
            }
            #[allow(unreachable_patterns)]
            _ => WalletError::InvalidParameter(format!("Key wallet error: {}", err)),
        }
    }
}
