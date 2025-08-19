//! Common types for FFI interface

use key_wallet::{Network, Wallet};
use std::sync::Arc;

/// FFI Network type
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFINetwork {
    Dash = 0,
    Testnet = 1,
    Regtest = 2,
    Devnet = 3,
}

impl From<FFINetwork> for Network {
    fn from(n: FFINetwork) -> Self {
        match n {
            FFINetwork::Dash => Network::Dash,
            FFINetwork::Testnet => Network::Testnet,
            FFINetwork::Regtest => Network::Regtest,
            FFINetwork::Devnet => Network::Devnet,
        }
    }
}

impl From<Network> for FFINetwork {
    fn from(n: Network) -> Self {
        match n {
            Network::Dash => FFINetwork::Dash,
            Network::Testnet => FFINetwork::Testnet,
            Network::Regtest => FFINetwork::Regtest,
            Network::Devnet => FFINetwork::Devnet,
            _ => FFINetwork::Dash, // Default to Dash for unknown networks
        }
    }
}

/// Opaque wallet handle
pub struct FFIWallet {
    pub(crate) wallet: Arc<Wallet>,
}

impl FFIWallet {
    /// Create a new FFI wallet handle
    pub fn new(wallet: Wallet) -> Self {
        FFIWallet {
            wallet: Arc::new(wallet),
        }
    }

    /// Get a reference to the inner wallet
    pub fn inner(&self) -> &Wallet {
        &self.wallet
    }

    /// Get a mutable reference to the inner wallet (requires Arc::get_mut)
    pub fn inner_mut(&mut self) -> Option<&mut Wallet> {
        Arc::get_mut(&mut self.wallet)
    }
}

/// Account type enumeration
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIAccountType {
    Standard = 0,
    CoinJoin = 1,
    Identity = 2,
}

impl FFIAccountType {
    /// Convert to AccountType with an index
    pub fn to_account_type(self, index: u32) -> key_wallet::AccountType {
        use key_wallet::account::types::StandardAccountType;
        match self {
            FFIAccountType::Standard => key_wallet::AccountType::Standard {
                index,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            FFIAccountType::CoinJoin => key_wallet::AccountType::CoinJoin {
                index,
            },
            FFIAccountType::Identity => key_wallet::AccountType::IdentityRegistration,
        }
    }
}

/// Address type enumeration
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIAddressType {
    P2PKH = 0,
    P2SH = 1,
}

impl From<key_wallet::AddressType> for FFIAddressType {
    fn from(t: key_wallet::AddressType) -> Self {
        match t {
            key_wallet::AddressType::P2pkh => FFIAddressType::P2PKH,
            key_wallet::AddressType::P2sh => FFIAddressType::P2SH,
            _ => FFIAddressType::P2PKH, // Default
        }
    }
}

impl From<FFIAddressType> for key_wallet::AddressType {
    fn from(t: FFIAddressType) -> Self {
        match t {
            FFIAddressType::P2PKH => key_wallet::AddressType::P2pkh,
            FFIAddressType::P2SH => key_wallet::AddressType::P2sh,
        }
    }
}
