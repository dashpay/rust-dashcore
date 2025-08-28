//! Common types for FFI interface

use key_wallet::{Network, Wallet};
use std::os::raw::c_uint;
use std::sync::Arc;

/// FFI Network type (bit flags for multiple networks)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFINetwork {
    NoNetworks = 0,
    Dash = 1,
    Testnet = 2,
    Regtest = 4,
    Devnet = 8,
    AllNetworks = 15, // Dash | Testnet | Regtest | Devnet
}

impl FFINetwork {
    /// Parse bit flags into a vector of networks
    pub fn parse_networks(&self) -> Vec<Network> {
        let flags = *self as c_uint;

        // Handle special cases
        if flags == FFINetwork::NoNetworks as c_uint || flags == 0 {
            // If no networks specified, default to testnet
            return vec![Network::Testnet];
        }

        let mut networks = Vec::new();

        if flags & (FFINetwork::Dash as c_uint) != 0 {
            networks.push(Network::Dash);
        }
        if flags & (FFINetwork::Testnet as c_uint) != 0 {
            networks.push(Network::Testnet);
        }
        if flags & (FFINetwork::Regtest as c_uint) != 0 {
            networks.push(Network::Regtest);
        }
        if flags & (FFINetwork::Devnet as c_uint) != 0 {
            networks.push(Network::Devnet);
        }

        networks
    }
}

impl FFINetwork {
    /// Try to convert to a single Network
    /// Returns None if multiple networks are set or if NoNetworks is set
    pub fn try_into_single_network(&self) -> Option<Network> {
        let flags = *self as c_uint;

        // Check if it's a single network
        match flags {
            x if x == FFINetwork::Dash as c_uint => Some(Network::Dash),
            x if x == FFINetwork::Testnet as c_uint => Some(Network::Testnet),
            x if x == FFINetwork::Regtest as c_uint => Some(Network::Regtest),
            x if x == FFINetwork::Devnet as c_uint => Some(Network::Devnet),
            _ => None, // Multiple networks or NoNetworks
        }
    }
}

use std::convert::TryFrom;

impl TryFrom<FFINetwork> for Network {
    type Error = &'static str;

    fn try_from(value: FFINetwork) -> Result<Self, Self::Error> {
        match value.try_into_single_network() {
            Some(network) => Ok(network),
            None => Err("FFINetwork must represent exactly one network"),
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

/// FFI Balance type for representing wallet balances
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FFIBalance {
    /// Confirmed balance in satoshis
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis
    pub unconfirmed: u64,
    /// Immature balance in satoshis (e.g., mining rewards)
    pub immature: u64,
    /// Total balance (confirmed + unconfirmed) in satoshis
    pub total: u64,
}


impl From<key_wallet::WalletBalance> for FFIBalance {
    fn from(balance: key_wallet::WalletBalance) -> Self {
        FFIBalance {
            confirmed: balance.confirmed,
            unconfirmed: balance.unconfirmed,
            immature: balance.locked, // Map locked to immature for now
            total: balance.total,
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
        self.wallet.as_ref()
    }

    /// Get a mutable reference to the inner wallet (requires Arc::get_mut)
    pub fn inner_mut(&mut self) -> Option<&mut Wallet> {
        Arc::get_mut(&mut self.wallet)
    }
}

/// FFI Result type for Account operations
#[repr(C)]
pub struct FFIAccountResult {
    /// The account handle if successful, NULL if error
    pub account: *mut FFIAccount,
    /// Error code (0 = success)
    pub error_code: i32,
    /// Error message (NULL if success, must be freed by caller if not NULL)
    pub error_message: *mut std::os::raw::c_char,
}

impl FFIAccountResult {
    /// Create a success result
    pub fn success(account: *mut FFIAccount) -> Self {
        FFIAccountResult {
            account,
            error_code: 0,
            error_message: std::ptr::null_mut(),
        }
    }

    /// Create an error result
    pub fn error(code: crate::error::FFIErrorCode, message: String) -> Self {
        use std::ffi::CString;
        let c_message = CString::new(message).unwrap_or_else(|_| {
            // Fallback to a safe literal that cannot fail
            CString::new("Unknown error").expect("Hardcoded string should never fail")
        });
        FFIAccountResult {
            account: std::ptr::null_mut(),
            error_code: code as i32,
            error_message: c_message.into_raw(),
        }
    }
}

/// Opaque account handle
pub struct FFIAccount {
    pub(crate) account: Arc<key_wallet::Account>,
}

impl FFIAccount {
    /// Create a new FFI account handle
    pub fn new(account: &key_wallet::Account) -> Self {
        FFIAccount {
            account: Arc::new(account.clone()),
        }
    }

    /// Get a reference to the inner account
    pub fn inner(&self) -> &key_wallet::Account {
        self.account.as_ref()
    }
}

/// Standard account subtype
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIStandardAccountType {
    BIP44 = 0,
    BIP32 = 1,
}

/// Account type enumeration matching all key_wallet AccountType variants
///
/// This enum provides a complete FFI representation of all account types
/// supported by the key_wallet library:
///
/// - Standard accounts: BIP44 and BIP32 variants for regular transactions
/// - CoinJoin: Privacy-enhanced transactions
/// - Identity accounts: Registration, top-up, and invitation funding
/// - Provider accounts: Various masternode provider key types (voting, owner, operator, platform)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIAccountType {
    /// Standard BIP44 account (m/44'/coin_type'/account'/x/x)
    StandardBIP44 = 0,
    /// Standard BIP32 account (m/account'/x/x)
    StandardBIP32 = 1,
    /// CoinJoin account for private transactions
    CoinJoin = 2,
    /// Identity registration funding
    IdentityRegistration = 3,
    /// Identity top-up funding (requires registration_index)
    IdentityTopUp = 4,
    /// Identity top-up funding not bound to a specific identity
    IdentityTopUpNotBoundToIdentity = 5,
    /// Identity invitation funding
    IdentityInvitation = 6,
    /// Provider voting keys (DIP-3) - Path: m/9'/5'/3'/1'/[key_index]
    ProviderVotingKeys = 7,
    /// Provider owner keys (DIP-3) - Path: m/9'/5'/3'/2'/[key_index]
    ProviderOwnerKeys = 8,
    /// Provider operator keys (DIP-3) - Path: m/9'/5'/3'/3'/[key_index]
    ProviderOperatorKeys = 9,
    /// Provider platform P2P keys (DIP-3, ED25519) - Path: m/9'/5'/3'/4'/[key_index]
    ProviderPlatformKeys = 10,
}

impl FFIAccountType {
    /// Convert to AccountType with optional indices
    /// Returns None if required parameters are missing (e.g., registration_index for IdentityTopUp)
    pub fn to_account_type(self, index: u32) -> key_wallet::AccountType {
        use key_wallet::account::account_type::StandardAccountType;
        match self {
            FFIAccountType::StandardBIP44 => key_wallet::AccountType::Standard {
                index,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            FFIAccountType::StandardBIP32 => key_wallet::AccountType::Standard {
                index,
                standard_account_type: StandardAccountType::BIP32Account,
            },
            FFIAccountType::CoinJoin => key_wallet::AccountType::CoinJoin {
                index,
            },
            FFIAccountType::IdentityRegistration => key_wallet::AccountType::IdentityRegistration,
            FFIAccountType::IdentityTopUp => {
                // IdentityTopUp requires a registration_index
                key_wallet::AccountType::IdentityTopUp {
                    registration_index: index,
                }
            }
            FFIAccountType::IdentityTopUpNotBoundToIdentity => {
                key_wallet::AccountType::IdentityTopUpNotBoundToIdentity
            }
            FFIAccountType::IdentityInvitation => key_wallet::AccountType::IdentityInvitation,
            FFIAccountType::ProviderVotingKeys => key_wallet::AccountType::ProviderVotingKeys,
            FFIAccountType::ProviderOwnerKeys => key_wallet::AccountType::ProviderOwnerKeys,
            FFIAccountType::ProviderOperatorKeys => key_wallet::AccountType::ProviderOperatorKeys,
            FFIAccountType::ProviderPlatformKeys => key_wallet::AccountType::ProviderPlatformKeys,
        }
    }

    /// Convert from AccountType
    pub fn from_account_type(account_type: &key_wallet::AccountType) -> (Self, u32, Option<u32>) {
        use key_wallet::account::account_type::StandardAccountType;
        match account_type {
            key_wallet::AccountType::Standard {
                index,
                standard_account_type,
            } => match standard_account_type {
                StandardAccountType::BIP44Account => (FFIAccountType::StandardBIP44, *index, None),
                StandardAccountType::BIP32Account => (FFIAccountType::StandardBIP32, *index, None),
            },
            key_wallet::AccountType::CoinJoin {
                index,
            } => (FFIAccountType::CoinJoin, *index, None),
            key_wallet::AccountType::IdentityRegistration => {
                (FFIAccountType::IdentityRegistration, 0, None)
            }
            key_wallet::AccountType::IdentityTopUp {
                registration_index,
            } => (FFIAccountType::IdentityTopUp, 0, Some(*registration_index)),
            key_wallet::AccountType::IdentityTopUpNotBoundToIdentity => {
                (FFIAccountType::IdentityTopUpNotBoundToIdentity, 0, None)
            }
            key_wallet::AccountType::IdentityInvitation => {
                (FFIAccountType::IdentityInvitation, 0, None)
            }
            key_wallet::AccountType::ProviderVotingKeys => {
                (FFIAccountType::ProviderVotingKeys, 0, None)
            }
            key_wallet::AccountType::ProviderOwnerKeys => {
                (FFIAccountType::ProviderOwnerKeys, 0, None)
            }
            key_wallet::AccountType::ProviderOperatorKeys => {
                (FFIAccountType::ProviderOperatorKeys, 0, None)
            }
            key_wallet::AccountType::ProviderPlatformKeys => {
                (FFIAccountType::ProviderPlatformKeys, 0, None)
            }
        }
    }
}

/// Address type enumeration
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIAddressType {
    P2PKH = 0,
    P2SH = 1,
    Unknown = 255,
}

impl From<key_wallet::AddressType> for FFIAddressType {
    fn from(t: key_wallet::AddressType) -> Self {
        match t {
            key_wallet::AddressType::P2pkh => FFIAddressType::P2PKH,
            key_wallet::AddressType::P2sh => FFIAddressType::P2SH,
            // SegWit and Taproot address types are not supported yet in Dash
            key_wallet::AddressType::P2wpkh => FFIAddressType::Unknown,
            key_wallet::AddressType::P2wsh => FFIAddressType::Unknown,
            key_wallet::AddressType::P2tr => FFIAddressType::Unknown,
            // Handle any future address types
            _ => FFIAddressType::Unknown,
        }
    }
}

impl From<FFIAddressType> for key_wallet::AddressType {
    fn from(t: FFIAddressType) -> Self {
        match t {
            FFIAddressType::P2PKH => key_wallet::AddressType::P2pkh,
            FFIAddressType::P2SH => key_wallet::AddressType::P2sh,
            FFIAddressType::Unknown => key_wallet::AddressType::P2pkh, // Default to P2PKH for unknown types
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
    ///
    /// # Safety
    ///
    /// - If `account_indices` is not null, it must point to a valid array of at least `account_indices_count` elements
    /// - The indices in the array must be valid u32 values
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
                        accounts.push(ffi_type.to_account_type(0));
                    }
                    Some(accounts)
                } else {
                    None
                };

                WalletAccountCreationOptions::SpecificAccounts(
                    bip44_set,
                    bip32_set,
                    coinjoin_set,
                    topup_set,
                    special_accounts,
                )
            }
        }
    }
}

/// FFI-compatible transaction context
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFITransactionContext {
    /// Transaction is in the mempool (unconfirmed)
    Mempool = 0,
    /// Transaction is in a block at the given height
    InBlock = 1,
    /// Transaction is in a chain-locked block at the given height
    InChainLockedBlock = 2,
}

/// FFI-compatible transaction context details
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FFITransactionContextDetails {
    /// The context type
    pub context_type: FFITransactionContext,
    /// Block height (0 for mempool)
    pub height: c_uint,
    /// Block hash (32 bytes, null for mempool or if unknown)
    pub block_hash: *const u8,
    /// Timestamp (0 if unknown)
    pub timestamp: c_uint,
}

impl FFITransactionContextDetails {
    /// Create a mempool context
    pub fn mempool() -> Self {
        FFITransactionContextDetails {
            context_type: FFITransactionContext::Mempool,
            height: 0,
            block_hash: std::ptr::null(),
            timestamp: 0,
        }
    }

    /// Create an in-block context
    pub fn in_block(height: c_uint, block_hash: *const u8, timestamp: c_uint) -> Self {
        FFITransactionContextDetails {
            context_type: FFITransactionContext::InBlock,
            height,
            block_hash,
            timestamp,
        }
    }

    /// Create a chain-locked block context
    pub fn in_chain_locked_block(height: c_uint, block_hash: *const u8, timestamp: c_uint) -> Self {
        FFITransactionContextDetails {
            context_type: FFITransactionContext::InChainLockedBlock,
            height,
            block_hash,
            timestamp,
        }
    }

    /// Convert to the native TransactionContext
    pub fn to_transaction_context(&self) -> key_wallet::transaction_checking::TransactionContext {
        use key_wallet::transaction_checking::TransactionContext;

        match self.context_type {
            FFITransactionContext::Mempool => TransactionContext::Mempool,
            FFITransactionContext::InBlock => {
                let block_hash = if self.block_hash.is_null() {
                    None
                } else {
                    // Convert the 32-byte hash to BlockHash
                    let mut hash_bytes = [0u8; 32];
                    unsafe {
                        std::ptr::copy_nonoverlapping(self.block_hash, hash_bytes.as_mut_ptr(), 32);
                    }
                    use dashcore::hashes::Hash;
                    Some(dashcore::BlockHash::from_byte_array(hash_bytes))
                };

                TransactionContext::InBlock {
                    height: self.height,
                    block_hash,
                    timestamp: if self.timestamp == 0 {
                        None
                    } else {
                        Some(self.timestamp)
                    },
                }
            }
            FFITransactionContext::InChainLockedBlock => {
                let block_hash = if self.block_hash.is_null() {
                    None
                } else {
                    // Convert the 32-byte hash to BlockHash
                    let mut hash_bytes = [0u8; 32];
                    unsafe {
                        std::ptr::copy_nonoverlapping(self.block_hash, hash_bytes.as_mut_ptr(), 32);
                    }
                    use dashcore::hashes::Hash;
                    Some(dashcore::BlockHash::from_byte_array(hash_bytes))
                };

                TransactionContext::InChainLockedBlock {
                    height: self.height,
                    block_hash,
                    timestamp: if self.timestamp == 0 {
                        None
                    } else {
                        Some(self.timestamp)
                    },
                }
            }
        }
    }
}
