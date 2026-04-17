//! Common types for FFI interface

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use key_wallet::managed_account::transaction_record::{OutputRole, TransactionDirection};
use key_wallet::transaction_checking::transaction_router::TransactionType;
use key_wallet::transaction_checking::{BlockInfo, TransactionContext};
use key_wallet::Wallet;
use std::os::raw::c_char;
use std::sync::Arc;

/// FFI-compatible block metadata (height, hash, timestamp).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FFIBlockInfo {
    /// Block height
    pub height: u32,
    /// Block hash (32 bytes)
    pub block_hash: [u8; 32],
    /// Unix timestamp
    pub timestamp: u32,
}

impl FFIBlockInfo {
    /// All-zeros placeholder used for unconfirmed contexts.
    pub fn empty() -> Self {
        Self {
            height: 0,
            block_hash: [0u8; 32],
            timestamp: 0,
        }
    }

    /// Convert to native `BlockInfo`.
    pub fn to_block_info(&self) -> BlockInfo {
        let block_hash = dashcore::BlockHash::from_byte_array(self.block_hash);
        BlockInfo::new(self.height, block_hash, self.timestamp)
    }
}

impl From<BlockInfo> for FFIBlockInfo {
    fn from(info: BlockInfo) -> Self {
        Self {
            height: info.height(),
            block_hash: info.block_hash().to_byte_array(),
            timestamp: info.timestamp(),
        }
    }
}

/// Convert an `FFIBlockInfo` and context type to a native `TransactionContext`.
///
/// Returns `None` when:
/// - Block info is all-zeros for confirmed contexts (`InBlock`, `InChainLockedBlock`)
/// - IS lock data is null/empty for `InstantSend` contexts
/// - IS lock data fails deserialization
pub(crate) fn transaction_context_from_ffi(
    context_type: FFITransactionContextType,
    block_info: &FFIBlockInfo,
    islock_data: *const u8,
    islock_len: usize,
) -> Option<TransactionContext> {
    match context_type {
        FFITransactionContextType::Mempool => Some(TransactionContext::Mempool),
        FFITransactionContextType::InstantSend => {
            if islock_data.is_null() || islock_len == 0 {
                return None;
            }
            let bytes = unsafe { std::slice::from_raw_parts(islock_data, islock_len) };
            let lock = match dashcore::consensus::deserialize::<InstantLock>(bytes) {
                Ok(lock) => lock,
                Err(_) => return None,
            };
            Some(TransactionContext::InstantSend(lock))
        }
        FFITransactionContextType::InBlock => {
            if block_info.block_hash == [0u8; 32] && block_info.timestamp == 0 {
                return None;
            }
            Some(TransactionContext::InBlock(block_info.to_block_info()))
        }
        FFITransactionContextType::InChainLockedBlock => {
            if block_info.block_hash == [0u8; 32] && block_info.timestamp == 0 {
                return None;
            }
            Some(TransactionContext::InChainLockedBlock(block_info.to_block_info()))
        }
    }
}

/// FFI Balance type for representing wallet balances
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FFIBalance {
    /// Confirmed balance in duffs
    pub confirmed: u64,
    /// Unconfirmed balance in duffs
    pub unconfirmed: u64,
    /// Immature balance in duffs (e.g., mining rewards not yet mature)
    pub immature: u64,
    /// Locked balance in duffs (e.g., CoinJoin reserves)
    pub locked: u64,
    /// Total balance in duffs
    pub total: u64,
}

impl From<key_wallet::WalletCoreBalance> for FFIBalance {
    fn from(balance: key_wallet::WalletCoreBalance) -> Self {
        FFIBalance {
            confirmed: balance.confirmed(),
            unconfirmed: balance.unconfirmed(),
            immature: balance.immature(),
            locked: balance.locked(),
            total: balance.total(),
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
    pub error_message: *mut c_char,
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

/// Forward declaration for FFIAccount (defined in account.rs)
pub use crate::account::FFIAccount;
#[cfg(feature = "bls")]
pub use crate::account::FFIBLSAccount;
#[cfg(feature = "eddsa")]
pub use crate::account::FFIEdDSAAccount;

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
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// Provider voting keys (DIP-3) - Path: m/9'/5'/3'/1'/\[key_index\]
    ProviderVotingKeys = 7,
    /// Provider owner keys (DIP-3) - Path: m/9'/5'/3'/2'/\[key_index\]
    ProviderOwnerKeys = 8,
    /// Provider operator keys (DIP-3) - Path: m/9'/5'/3'/3'/\[key_index\]
    ProviderOperatorKeys = 9,
    /// Provider platform P2P keys (DIP-3, ED25519) - Path: m/9'/5'/3'/4'/\[key_index\]
    ProviderPlatformKeys = 10,
    /// DashPay incoming funds account using 256-bit derivation
    DashpayReceivingFunds = 11,
    /// DashPay external (watch-only) account using 256-bit derivation
    DashpayExternalAccount = 12,
    /// Platform Payment address (DIP-17) - Path: m/9'/5'/17'/account'/key_class'/index
    PlatformPayment = 13,
    /// Asset lock address top-up funding (subfeature 4)
    AssetLockAddressTopUp = 14,
    /// Asset lock shielded address top-up funding (subfeature 5)
    AssetLockShieldedAddressTopUp = 15,
}

impl FFIAccountType {
    /// Convert to AccountType with the provided index (used where applicable).
    /// For types needing an index (e.g., IdentityTopUp.registration_index), the provided index is used.
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
            FFIAccountType::AssetLockAddressTopUp => key_wallet::AccountType::AssetLockAddressTopUp,
            FFIAccountType::AssetLockShieldedAddressTopUp => {
                key_wallet::AccountType::AssetLockShieldedAddressTopUp
            }
            FFIAccountType::ProviderVotingKeys => key_wallet::AccountType::ProviderVotingKeys,
            FFIAccountType::ProviderOwnerKeys => key_wallet::AccountType::ProviderOwnerKeys,
            FFIAccountType::ProviderOperatorKeys => key_wallet::AccountType::ProviderOperatorKeys,
            FFIAccountType::ProviderPlatformKeys => key_wallet::AccountType::ProviderPlatformKeys,
            // DashPay variants require additional identity IDs (user_identity_id and friend_identity_id)
            // that are not part of the current FFI API. These types cannot be constructed via this
            // conversion path. Attempting to use them is a programming error.
            //
            // TODO: Extend the FFI API to accept identity IDs for DashPay account creation:
            //   - Add new FFI functions like:
            //     * ffi_account_type_to_dashpay_receiving_funds(index, user_id[32], friend_id[32])
            //     * ffi_account_type_to_dashpay_external_account(index, user_id[32], friend_id[32])
            //   - Or extend to_account_type to accept optional identity ID parameters
            //
            // Until then, attempting to convert these variants will panic to prevent silent misrouting.
            FFIAccountType::DashpayReceivingFunds => {
                panic!(
                    "FFIAccountType::DashpayReceivingFunds cannot be converted to AccountType \
                     without user_identity_id and friend_identity_id. The FFI API does not yet \
                     support passing these 32-byte identity IDs. This is a programming error - \
                     DashPay account creation must use a different API path."
                );
            }
            FFIAccountType::DashpayExternalAccount => {
                panic!(
                    "FFIAccountType::DashpayExternalAccount cannot be converted to AccountType \
                     without user_identity_id and friend_identity_id. The FFI API does not yet \
                     support passing these 32-byte identity IDs. This is a programming error - \
                     DashPay account creation must use a different API path."
                );
            }
            FFIAccountType::PlatformPayment => {
                panic!(
                    "FFIAccountType::PlatformPayment cannot be converted to AccountType \
                     without account and key_class indices. The FFI API does not yet \
                     support passing these values. This is a programming error - \
                     Platform Payment account creation must use a different API path."
                );
            }
        }
    }

    /// Convert from AccountType to FFI representation
    ///
    /// Returns: (FFIAccountType, primary_index, optional_secondary_index)
    ///
    /// # Panics
    ///
    /// Panics when attempting to convert DashPay account types (DashpayReceivingFunds,
    /// DashpayExternalAccount) because they contain 32-byte identity IDs that cannot be
    /// represented in the current FFI tuple format. This prevents silent data loss.
    ///
    /// TODO: Extend the return type or create separate FFI functions that can return
    ///       the full DashPay account information including identity IDs.
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
            key_wallet::AccountType::AssetLockAddressTopUp => {
                (FFIAccountType::AssetLockAddressTopUp, 0, None)
            }
            key_wallet::AccountType::AssetLockShieldedAddressTopUp => {
                (FFIAccountType::AssetLockShieldedAddressTopUp, 0, None)
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
            key_wallet::AccountType::DashpayReceivingFunds {
                index,
                user_identity_id,
                friend_identity_id,
            } => {
                // Cannot convert DashPay accounts to FFI without losing identity ID information
                panic!(
                    "Cannot convert AccountType::DashpayReceivingFunds (index={}, user_id={:?}, friend_id={:?}) \
                     to FFI representation. The current FFI tuple format (FFIAccountType, u32, Option<u32>) \
                     cannot represent the two 32-byte identity IDs required by DashPay accounts. \
                     This would result in silent data loss. A dedicated FFI API for DashPay accounts is needed.",
                    index,
                    &user_identity_id[..8], // Show first 8 bytes for debugging
                    &friend_identity_id[..8]
                );
            }
            key_wallet::AccountType::DashpayExternalAccount {
                index,
                user_identity_id,
                friend_identity_id,
            } => {
                // Cannot convert DashPay accounts to FFI without losing identity ID information
                panic!(
                    "Cannot convert AccountType::DashpayExternalAccount (index={}, user_id={:?}, friend_id={:?}) \
                     to FFI representation. The current FFI tuple format (FFIAccountType, u32, Option<u32>) \
                     cannot represent the two 32-byte identity IDs required by DashPay accounts. \
                     This would result in silent data loss. A dedicated FFI API for DashPay accounts is needed.",
                    index,
                    &user_identity_id[..8], // Show first 8 bytes for debugging
                    &friend_identity_id[..8]
                );
            }
            key_wallet::AccountType::PlatformPayment {
                account,
                key_class,
            } => (FFIAccountType::PlatformPayment, *account, Some(*key_class)),
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

/// FFI specification for a PlatformPayment account to create
///
/// PlatformPayment accounts (DIP-17) use the derivation path:
/// `m/9'/coin_type'/17'/account'/key_class'/index`
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FFIPlatformPaymentAccountSpec {
    /// Account index (hardened) - the account' level in the derivation path
    pub account: u32,
    /// Key class (hardened) - defaults to 0', 1' is reserved for change-like segregation
    pub key_class: u32,
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
    NoAccounts = 4,
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

    /// Array of PlatformPayment account specs to create
    pub platform_payment_specs: *const FFIPlatformPaymentAccountSpec,
    pub platform_payment_count: usize,

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
            platform_payment_specs: std::ptr::null(),
            platform_payment_count: 0,
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
            FFIAccountCreationOptionType::NoAccounts => WalletAccountCreationOptions::None,
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
                use key_wallet::wallet::initialization::PlatformPaymentAccountSpec;

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

                let mut platform_payment_set = BTreeSet::new();
                if !self.platform_payment_specs.is_null() && self.platform_payment_count > 0 {
                    let slice = std::slice::from_raw_parts(
                        self.platform_payment_specs,
                        self.platform_payment_count,
                    );
                    for spec in slice {
                        platform_payment_set.insert(PlatformPaymentAccountSpec {
                            account: spec.account,
                            key_class: spec.key_class,
                        });
                    }
                }

                WalletAccountCreationOptions::AllAccounts(
                    bip44_set,
                    bip32_set,
                    coinjoin_set,
                    topup_set,
                    platform_payment_set,
                )
            }
            FFIAccountCreationOptionType::SpecificAccounts => {
                use key_wallet::wallet::initialization::PlatformPaymentAccountSpec;

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

                let mut platform_payment_set = BTreeSet::new();
                if !self.platform_payment_specs.is_null() && self.platform_payment_count > 0 {
                    let slice = std::slice::from_raw_parts(
                        self.platform_payment_specs,
                        self.platform_payment_count,
                    );
                    for spec in slice {
                        platform_payment_set.insert(PlatformPaymentAccountSpec {
                            account: spec.account,
                            key_class: spec.key_class,
                        });
                    }
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
                    platform_payment_set,
                    special_accounts,
                )
            }
        }
    }
}

/// FFI-compatible transaction context type
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFITransactionContextType {
    /// Transaction is in the mempool (unconfirmed)
    Mempool = 0,
    /// Transaction is in the mempool with an InstantSend lock
    InstantSend = 1,
    /// Transaction is in a block at the given height
    InBlock = 2,
    /// Transaction is in a chain-locked block at the given height
    InChainLockedBlock = 3,
}

impl From<TransactionContext> for FFITransactionContextType {
    fn from(ctx: TransactionContext) -> Self {
        match ctx {
            TransactionContext::Mempool => FFITransactionContextType::Mempool,
            TransactionContext::InstantSend(_) => FFITransactionContextType::InstantSend,
            TransactionContext::InBlock(_) => FFITransactionContextType::InBlock,
            TransactionContext::InChainLockedBlock(_) => {
                FFITransactionContextType::InChainLockedBlock
            }
        }
    }
}

/// FFI-compatible transaction context (type + optional block info + optional IS lock)
#[repr(C)]
#[derive(Debug)]
pub struct FFITransactionContext {
    /// The context type
    pub context_type: FFITransactionContextType,
    /// Block info (zeroed for mempool/instant-send contexts)
    pub block_info: FFIBlockInfo,
    /// Consensus-serialized `InstantLock` bytes (null for non-IS contexts)
    pub islock_data: *const u8,
    /// Length of the `islock_data` buffer
    pub islock_len: usize,
}

impl FFITransactionContext {
    /// Create a mempool context
    pub fn mempool() -> Self {
        Self {
            context_type: FFITransactionContextType::Mempool,
            block_info: FFIBlockInfo::empty(),
            islock_data: std::ptr::null(),
            islock_len: 0,
        }
    }

    /// Create an in-block context
    pub fn in_block(block_info: FFIBlockInfo) -> Self {
        Self {
            context_type: FFITransactionContextType::InBlock,
            block_info,
            islock_data: std::ptr::null(),
            islock_len: 0,
        }
    }

    /// Create a chain-locked block context
    pub fn in_chain_locked_block(block_info: FFIBlockInfo) -> Self {
        Self {
            context_type: FFITransactionContextType::InChainLockedBlock,
            block_info,
            islock_data: std::ptr::null(),
            islock_len: 0,
        }
    }

    /// Convert to the native `TransactionContext`.
    ///
    /// Returns `None` when block info is all-zeros for confirmed contexts.
    pub fn to_transaction_context(&self) -> Option<TransactionContext> {
        transaction_context_from_ffi(
            self.context_type,
            &self.block_info,
            self.islock_data,
            self.islock_len,
        )
    }

    /// Free the heap-allocated `islock_data` buffer, if present.
    ///
    /// # Safety
    ///
    /// Must only be called once per instance. The pointer must have been
    /// produced by `Box::into_raw` in the `From<TransactionContext>` impl.
    pub unsafe fn free_islock_data(&mut self) {
        if !self.islock_data.is_null() && self.islock_len > 0 {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.islock_data as *mut u8,
                self.islock_len,
            )));
            self.islock_data = std::ptr::null();
            self.islock_len = 0;
        }
    }
}

impl From<TransactionContext> for FFITransactionContext {
    fn from(ctx: TransactionContext) -> Self {
        let block_info = ctx
            .block_info()
            .map(|info| FFIBlockInfo::from(*info))
            .unwrap_or_else(FFIBlockInfo::empty);

        let (islock_data, islock_len) = if let TransactionContext::InstantSend(ref lock) = ctx {
            let bytes = dashcore::consensus::serialize(lock).into_boxed_slice();
            let len = bytes.len();
            let ptr = Box::into_raw(bytes) as *const u8;
            (ptr, len)
        } else {
            (std::ptr::null(), 0)
        };

        let context_type = FFITransactionContextType::from(ctx);
        Self {
            context_type,
            block_info,
            islock_data,
            islock_len,
        }
    }
}

/// FFI-compatible transaction direction
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFITransactionDirection {
    Incoming = 0,
    Outgoing = 1,
    Internal = 2,
    CoinJoin = 3,
}

impl From<TransactionDirection> for FFITransactionDirection {
    fn from(dir: TransactionDirection) -> Self {
        match dir {
            TransactionDirection::Incoming => Self::Incoming,
            TransactionDirection::Outgoing => Self::Outgoing,
            TransactionDirection::Internal => Self::Internal,
            TransactionDirection::CoinJoin => Self::CoinJoin,
        }
    }
}

/// FFI-compatible transaction type classification
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFITransactionType {
    Standard = 0,
    CoinJoin = 1,
    ProviderRegistration = 2,
    ProviderUpdateRegistrar = 3,
    ProviderUpdateService = 4,
    ProviderUpdateRevocation = 5,
    AssetLock = 6,
    AssetUnlock = 7,
    Coinbase = 8,
    Ignored = 9,
}

impl From<TransactionType> for FFITransactionType {
    fn from(tt: TransactionType) -> Self {
        match tt {
            TransactionType::Standard => Self::Standard,
            TransactionType::CoinJoin => Self::CoinJoin,
            TransactionType::ProviderRegistration => Self::ProviderRegistration,
            TransactionType::ProviderUpdateRegistrar => Self::ProviderUpdateRegistrar,
            TransactionType::ProviderUpdateService => Self::ProviderUpdateService,
            TransactionType::ProviderUpdateRevocation => Self::ProviderUpdateRevocation,
            TransactionType::AssetLock => Self::AssetLock,
            TransactionType::AssetUnlock => Self::AssetUnlock,
            TransactionType::Coinbase => Self::Coinbase,
            TransactionType::Ignored => Self::Ignored,
        }
    }
}

/// FFI-compatible output role
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIOutputRole {
    Received = 0,
    Change = 1,
    Sent = 2,
    Unspendable = 3,
}

impl From<OutputRole> for FFIOutputRole {
    fn from(role: OutputRole) -> Self {
        match role {
            OutputRole::Received => Self::Received,
            OutputRole::Change => Self::Change,
            OutputRole::Sent => Self::Sent,
            OutputRole::Unspendable => Self::Unspendable,
        }
    }
}

/// FFI-compatible input detail
#[repr(C)]
pub struct FFIInputDetail {
    pub index: u32,
    pub value: u64,
    pub address: *mut std::os::raw::c_char,
}

/// FFI-compatible output detail
#[repr(C)]
pub struct FFIOutputDetail {
    pub index: u32,
    pub role: FFIOutputRole,
    pub value: u64,
    pub address: *mut c_char,
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use dashcore::consensus::serialize;
    use dashcore::ephemerealdata::instant_lock::InstantLock;
    use key_wallet::transaction_checking::BlockInfo;

    use super::*;

    fn valid_block_info() -> FFIBlockInfo {
        FFIBlockInfo {
            height: 1000,
            block_hash: [0xab; 32],
            timestamp: 1700000000,
        }
    }

    #[test]
    #[should_panic(expected = "DashpayReceivingFunds cannot be converted to AccountType")]
    fn test_dashpay_receiving_funds_to_account_type_panics() {
        // This should panic because we cannot construct a DashPay account without identity IDs
        let _ = FFIAccountType::DashpayReceivingFunds.to_account_type(0);
    }

    #[test]
    #[should_panic(expected = "DashpayExternalAccount cannot be converted to AccountType")]
    fn test_dashpay_external_account_to_account_type_panics() {
        // This should panic because we cannot construct a DashPay account without identity IDs
        let _ = FFIAccountType::DashpayExternalAccount.to_account_type(0);
    }

    #[test]
    #[should_panic(expected = "PlatformPayment cannot be converted to AccountType")]
    fn test_platform_payment_to_account_type_panics() {
        // This should panic because we cannot construct a Platform Payment account without indices
        let _ = FFIAccountType::PlatformPayment.to_account_type(0);
    }

    #[test]
    #[should_panic(expected = "Cannot convert AccountType::DashpayReceivingFunds")]
    fn test_dashpay_receiving_funds_from_account_type_panics() {
        // This should panic because we cannot represent identity IDs in the FFI tuple
        let account_type = key_wallet::AccountType::DashpayReceivingFunds {
            index: 0,
            user_identity_id: [1u8; 32],
            friend_identity_id: [2u8; 32],
        };
        let _ = FFIAccountType::from_account_type(&account_type);
    }

    #[test]
    #[should_panic(expected = "Cannot convert AccountType::DashpayExternalAccount")]
    fn test_dashpay_external_account_from_account_type_panics() {
        // This should panic because we cannot represent identity IDs in the FFI tuple
        let account_type = key_wallet::AccountType::DashpayExternalAccount {
            index: 0,
            user_identity_id: [1u8; 32],
            friend_identity_id: [2u8; 32],
        };
        let _ = FFIAccountType::from_account_type(&account_type);
    }

    #[test]
    fn test_non_dashpay_conversions_work() {
        // Verify that non-DashPay types still convert correctly
        let standard_bip44 = FFIAccountType::StandardBIP44.to_account_type(5);
        assert!(matches!(
            standard_bip44,
            key_wallet::AccountType::Standard {
                index: 5,
                ..
            }
        ));

        let coinjoin = FFIAccountType::CoinJoin.to_account_type(3);
        assert!(matches!(
            coinjoin,
            key_wallet::AccountType::CoinJoin {
                index: 3
            }
        ));

        // Test reverse conversion
        let (ffi_type, index, _) = FFIAccountType::from_account_type(&standard_bip44);
        assert_eq!(ffi_type, FFIAccountType::StandardBIP44);
        assert_eq!(index, 5);
    }

    #[test]
    fn transaction_context_from_ffi_mempool_with_empty_block_info() {
        let result = transaction_context_from_ffi(
            FFITransactionContextType::Mempool,
            &FFIBlockInfo::empty(),
            ptr::null(),
            0,
        );
        assert!(matches!(result, Some(TransactionContext::Mempool)));
    }

    #[test]
    fn transaction_context_from_ffi_instant_send_with_null_islock() {
        let result = transaction_context_from_ffi(
            FFITransactionContextType::InstantSend,
            &FFIBlockInfo::empty(),
            ptr::null(),
            0,
        );
        assert!(result.is_none());
    }

    #[test]
    fn transaction_context_from_ffi_instant_send_with_valid_islock() {
        let islock = InstantLock::default();
        let bytes = serialize(&islock);
        let result = transaction_context_from_ffi(
            FFITransactionContextType::InstantSend,
            &FFIBlockInfo::empty(),
            bytes.as_ptr(),
            bytes.len(),
        );
        assert!(matches!(result, Some(TransactionContext::InstantSend(_))));
    }

    #[test]
    fn transaction_context_from_ffi_in_block_with_empty_block_info() {
        let result = transaction_context_from_ffi(
            FFITransactionContextType::InBlock,
            &FFIBlockInfo::empty(),
            ptr::null(),
            0,
        );
        assert!(result.is_none());
    }

    #[test]
    fn transaction_context_from_ffi_in_chain_locked_block_with_empty_block_info() {
        let result = transaction_context_from_ffi(
            FFITransactionContextType::InChainLockedBlock,
            &FFIBlockInfo::empty(),
            ptr::null(),
            0,
        );
        assert!(result.is_none());
    }

    #[test]
    fn transaction_context_from_ffi_in_block_with_valid_block_info() {
        let block_info = valid_block_info();
        let result = transaction_context_from_ffi(
            FFITransactionContextType::InBlock,
            &block_info,
            ptr::null(),
            0,
        );
        let ctx = result.expect("should return Some for InBlock with valid block info");
        assert!(matches!(ctx, TransactionContext::InBlock(info) if info.height() == 1000));
    }

    #[test]
    fn transaction_context_from_ffi_in_chain_locked_block_with_valid_block_info() {
        let block_info = valid_block_info();
        let result = transaction_context_from_ffi(
            FFITransactionContextType::InChainLockedBlock,
            &block_info,
            ptr::null(),
            0,
        );
        let ctx = result.expect("should return Some for InChainLockedBlock with valid block info");
        assert!(
            matches!(ctx, TransactionContext::InChainLockedBlock(info) if info.height() == 1000)
        );
    }

    #[test]
    fn test_ffi_transaction_direction_from() {
        assert!(matches!(
            FFITransactionDirection::from(TransactionDirection::Incoming),
            FFITransactionDirection::Incoming
        ));
        assert!(matches!(
            FFITransactionDirection::from(TransactionDirection::Outgoing),
            FFITransactionDirection::Outgoing
        ));
        assert!(matches!(
            FFITransactionDirection::from(TransactionDirection::Internal),
            FFITransactionDirection::Internal
        ));
        assert!(matches!(
            FFITransactionDirection::from(TransactionDirection::CoinJoin),
            FFITransactionDirection::CoinJoin
        ));
    }

    #[test]
    fn test_ffi_transaction_type_from() {
        assert!(matches!(
            FFITransactionType::from(TransactionType::Standard),
            FFITransactionType::Standard
        ));
        assert!(matches!(
            FFITransactionType::from(TransactionType::CoinJoin),
            FFITransactionType::CoinJoin
        ));
        assert!(matches!(
            FFITransactionType::from(TransactionType::ProviderRegistration),
            FFITransactionType::ProviderRegistration
        ));
        assert!(matches!(
            FFITransactionType::from(TransactionType::AssetLock),
            FFITransactionType::AssetLock
        ));
        assert!(matches!(
            FFITransactionType::from(TransactionType::Coinbase),
            FFITransactionType::Coinbase
        ));
        assert!(matches!(
            FFITransactionType::from(TransactionType::Ignored),
            FFITransactionType::Ignored
        ));
    }

    #[test]
    fn test_ffi_transaction_context_from_in_block() {
        let hash = dashcore::BlockHash::from_byte_array([0xab; 32]);
        let block_info = BlockInfo::new(1000, hash, 1700000000);
        let ctx = FFITransactionContext::from(TransactionContext::InBlock(block_info));
        assert!(matches!(ctx.context_type, FFITransactionContextType::InBlock));
        assert_eq!(ctx.block_info.height, 1000);
        assert_eq!(ctx.block_info.block_hash, [0xab; 32]);
        assert_eq!(ctx.block_info.timestamp, 1700000000);
    }

    #[test]
    fn test_ffi_transaction_context_from_mempool() {
        let ctx = FFITransactionContext::from(TransactionContext::Mempool);
        assert!(matches!(ctx.context_type, FFITransactionContextType::Mempool));
        assert_eq!(ctx.block_info.block_hash, [0u8; 32]);
    }

    #[test]
    fn test_ffi_output_role_from() {
        assert!(matches!(FFIOutputRole::from(OutputRole::Received), FFIOutputRole::Received));
        assert!(matches!(FFIOutputRole::from(OutputRole::Change), FFIOutputRole::Change));
        assert!(matches!(FFIOutputRole::from(OutputRole::Sent), FFIOutputRole::Sent));
        assert!(matches!(FFIOutputRole::from(OutputRole::Unspendable), FFIOutputRole::Unspendable));
    }
}
