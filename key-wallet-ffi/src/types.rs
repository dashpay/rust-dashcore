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

/// FFI Account Creation Option Type
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIAccountCreationOptionType {
    /// Create default accounts (BIP44 account 0, CoinJoin account 0, and special accounts)
    Default = 0,
    /// Create all specified accounts plus all special purpose accounts
    AllAccounts = 1,
    /// Create only BIP44 accounts (no CoinJoin or special accounts)
    BIP44AccountsOnly = 2,
    /// Create specific accounts with full control
    SpecificAccounts = 3,
    /// Create no accounts at all
    None = 4,
}

/// FFI structure for wallet account creation options
/// This single struct represents all possible account creation configurations
#[repr(C)]
pub struct FFIWalletAccountCreationOptions {
    /// The type of account creation option
    pub option_type: FFIAccountCreationOptionType,

    /// Array of BIP44 account indices to create
    pub bip44_indices: *const u32,
    pub bip44_count: usize,

    /// Array of BIP32 account indices to create
    pub bip32_indices: *const u32,
    pub bip32_count: usize,

    /// Array of CoinJoin account indices to create
    pub coinjoin_indices: *const u32,
    pub coinjoin_count: usize,

    /// Array of identity top-up registration indices to create
    pub topup_indices: *const u32,
    pub topup_count: usize,

    /// For SpecificAccounts: Additional special account types to create
    /// (e.g., IdentityRegistration, ProviderKeys, etc.)
    /// This is an array of FFIAccountType values
    pub special_account_types: *const FFIAccountType,
    pub special_account_types_count: usize,
}

impl FFIWalletAccountCreationOptions {
    /// Create default options
    pub fn default_options() -> Self {
        FFIWalletAccountCreationOptions {
            option_type: FFIAccountCreationOptionType::Default,
            bip44_indices: std::ptr::null(),
            bip44_count: 0,
            bip32_indices: std::ptr::null(),
            bip32_count: 0,
            coinjoin_indices: std::ptr::null(),
            coinjoin_count: 0,
            topup_indices: std::ptr::null(),
            topup_count: 0,
            special_account_types: std::ptr::null(),
            special_account_types_count: 0,
        }
    }

    /// Convert FFI options to Rust WalletAccountCreationOptions
    pub unsafe fn to_wallet_options(
        &self,
    ) -> key_wallet::wallet::initialization::WalletAccountCreationOptions {
        use key_wallet::wallet::initialization::WalletAccountCreationOptions;
        use std::collections::BTreeSet;

        match self.option_type {
            FFIAccountCreationOptionType::Default => WalletAccountCreationOptions::Default,
            FFIAccountCreationOptionType::None => WalletAccountCreationOptions::None,
            FFIAccountCreationOptionType::BIP44AccountsOnly => {
                let mut bip44_set = BTreeSet::new();
                if !self.bip44_indices.is_null() && self.bip44_count > 0 {
                    let slice = std::slice::from_raw_parts(self.bip44_indices, self.bip44_count);
                    bip44_set.extend(slice.iter().copied());
                } else {
                    // Default to account 0 if no indices provided
                    bip44_set.insert(0);
                }
                WalletAccountCreationOptions::BIP44AccountsOnly(bip44_set)
            }
            FFIAccountCreationOptionType::AllAccounts => {
                let mut bip44_set = BTreeSet::new();
                if !self.bip44_indices.is_null() && self.bip44_count > 0 {
                    let slice = std::slice::from_raw_parts(self.bip44_indices, self.bip44_count);
                    bip44_set.extend(slice.iter().copied());
                }

                let mut bip32_set = BTreeSet::new();
                if !self.bip32_indices.is_null() && self.bip32_count > 0 {
                    let slice = std::slice::from_raw_parts(self.bip32_indices, self.bip32_count);
                    bip32_set.extend(slice.iter().copied());
                }

                let mut coinjoin_set = BTreeSet::new();
                if !self.coinjoin_indices.is_null() && self.coinjoin_count > 0 {
                    let slice =
                        std::slice::from_raw_parts(self.coinjoin_indices, self.coinjoin_count);
                    coinjoin_set.extend(slice.iter().copied());
                }

                let mut topup_set = BTreeSet::new();
                if !self.topup_indices.is_null() && self.topup_count > 0 {
                    let slice = std::slice::from_raw_parts(self.topup_indices, self.topup_count);
                    topup_set.extend(slice.iter().copied());
                }

                WalletAccountCreationOptions::AllAccounts(
                    bip44_set,
                    bip32_set,
                    coinjoin_set,
                    topup_set,
                )
            }
            FFIAccountCreationOptionType::SpecificAccounts => {
                let mut bip44_set = BTreeSet::new();
                if !self.bip44_indices.is_null() && self.bip44_count > 0 {
                    let slice = std::slice::from_raw_parts(self.bip44_indices, self.bip44_count);
                    bip44_set.extend(slice.iter().copied());
                }

                let mut coinjoin_set = BTreeSet::new();
                if !self.coinjoin_indices.is_null() && self.coinjoin_count > 0 {
                    let slice =
                        std::slice::from_raw_parts(self.coinjoin_indices, self.coinjoin_count);
                    coinjoin_set.extend(slice.iter().copied());
                }

                let mut topup_set = BTreeSet::new();
                if !self.topup_indices.is_null() && self.topup_count > 0 {
                    let slice = std::slice::from_raw_parts(self.topup_indices, self.topup_count);
                    topup_set.extend(slice.iter().copied());
                }

                // Convert special account types if provided
                let special_accounts = if !self.special_account_types.is_null()
                    && self.special_account_types_count > 0
                {
                    let slice = std::slice::from_raw_parts(
                        self.special_account_types,
                        self.special_account_types_count,
                    );
                    let mut accounts = Vec::new();
                    for &ffi_type in slice {
                        // Use a dummy index for special accounts that don't need one
                        accounts.push(ffi_type.to_account_type(0));
                    }
                    Some(accounts)
                } else {
                    None
                };

                WalletAccountCreationOptions::SpecificAccounts(
                    bip44_set,
                    coinjoin_set,
                    topup_set,
                    special_accounts,
                )
            }
        }
    }
}
