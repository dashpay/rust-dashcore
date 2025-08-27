use crate::client::FFIDashSpvClient;
use crate::types::FFINetwork;
use crate::{null_check, FFIArray};
use crate::{set_last_error, FFIString};
use dash_spv::FilterMatch;
use dashcore::{OutPoint, ScriptBuf, Txid};
use key_wallet::account::StandardAccountType;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use key_wallet::AccountType;
use key_wallet::Utxo as KWUtxo;
use key_wallet::WalletBalance;
use key_wallet_manager::wallet_manager::{AccountTypeUsed, WalletId};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::str::FromStr;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIWatchItemType {
    Address = 0,
    Script = 1,
    Outpoint = 2,
}

#[repr(C)]
pub struct FFIWatchItem {
    pub item_type: FFIWatchItemType,
    pub data: FFIString,
}

impl FFIWatchItem {
    pub unsafe fn to_watch_item(&self) -> Result<(), String> {
        // Note: This method uses NetworkUnchecked for backward compatibility.
        // Consider using to_watch_item_with_network for proper network validation.
        let data_str = FFIString::from_ptr(self.data.ptr)?;

        match self.item_type {
            FFIWatchItemType::Address => {
                let _addr =
                    dashcore::Address::<dashcore::address::NetworkUnchecked>::from_str(&data_str)
                        .map_err(|e| format!("Invalid address: {}", e))?
                        .assume_checked();
                Ok(())
            }
            FFIWatchItemType::Script => {
                let script_bytes =
                    hex::decode(&data_str).map_err(|e| format!("Invalid script hex: {}", e))?;
                let _script = ScriptBuf::from(script_bytes);
                Ok(())
            }
            FFIWatchItemType::Outpoint => {
                let parts: Vec<&str> = data_str.split(':').collect();
                if parts.len() != 2 {
                    return Err("Invalid outpoint format (expected txid:vout)".to_string());
                }
                let txid: Txid = parts[0].parse().map_err(|e| format!("Invalid txid: {}", e))?;
                let vout: u32 = parts[1].parse().map_err(|e| format!("Invalid vout: {}", e))?;
                let _ = OutPoint::new(txid, vout);
                Ok(())
            }
        }
    }

    /// Convert FFIWatchItem to WatchItem with network validation
    pub unsafe fn to_watch_item_with_network(
        &self,
        network: dashcore::Network,
    ) -> Result<(), String> {
        let data_str = FFIString::from_ptr(self.data.ptr)?;

        match self.item_type {
            FFIWatchItemType::Address => {
                let addr =
                    dashcore::Address::<dashcore::address::NetworkUnchecked>::from_str(&data_str)
                        .map_err(|e| format!("Invalid address: {}", e))?;

                // Validate that the address belongs to the expected network
                let _checked_addr = addr.require_network(network).map_err(|_| {
                    format!("Address {} is not valid for network {:?}", data_str, network)
                })?;
                Ok(())
            }
            FFIWatchItemType::Script => {
                let script_bytes =
                    hex::decode(&data_str).map_err(|e| format!("Invalid script hex: {}", e))?;
                let _script = ScriptBuf::from(script_bytes);
                Ok(())
            }
            FFIWatchItemType::Outpoint => {
                let _outpoint = OutPoint::from_str(&data_str)
                    .map_err(|e| format!("Invalid outpoint: {}", e))?;
                Ok(())
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FFIBalance {
    pub confirmed: u64,
    pub pending: u64,
    pub instantlocked: u64,
    pub mempool: u64,
    pub mempool_instant: u64,
    pub total: u64,
}

// Balance struct removed from dash-spv public API; use AddressBalance conversion below

impl From<dash_spv::types::AddressBalance> for FFIBalance {
    fn from(balance: dash_spv::types::AddressBalance) -> Self {
        FFIBalance {
            confirmed: balance.confirmed.to_sat(),
            pending: balance.unconfirmed.to_sat(),
            instantlocked: 0, // AddressBalance doesn't have instantlocked
            mempool: balance.pending.to_sat(),
            mempool_instant: balance.pending_instant.to_sat(),
            total: balance.total().to_sat(),
        }
    }
}

#[repr(C)]
pub struct FFIUtxo {
    pub txid: FFIString,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: FFIString,
    pub address: FFIString,
    pub height: u32,
    pub is_coinbase: bool,
    pub is_confirmed: bool,
    pub is_instantlocked: bool,
}

impl From<KWUtxo> for FFIUtxo {
    fn from(utxo: KWUtxo) -> Self {
        FFIUtxo {
            txid: FFIString::new(&utxo.outpoint.txid.to_string()),
            vout: utxo.outpoint.vout,
            amount: utxo.txout.value,
            script_pubkey: FFIString::new(&hex::encode(utxo.txout.script_pubkey.to_bytes())),
            address: FFIString::new(&utxo.address.to_string()),
            height: utxo.height,
            is_coinbase: utxo.is_coinbase,
            is_confirmed: utxo.is_confirmed,
            is_instantlocked: utxo.is_instantlocked,
        }
    }
}

#[repr(C)]
pub struct FFITransactionResult {
    pub txid: FFIString,
    pub version: i32,
    pub locktime: u32,
    pub size: u32,
    pub weight: u32,
    pub fee: u64,
    pub confirmation_time: u64,
    pub confirmation_height: u32,
}

// TransactionResult no longer available from dash-spv; conversion removed

#[repr(C)]
pub struct FFIBlockResult {
    pub hash: FFIString,
    pub height: u32,
    pub time: u32,
    pub tx_count: u32,
}

// BlockResult no longer available from dash-spv; conversion removed

#[repr(C)]
pub struct FFIFilterMatch {
    pub block_hash: FFIString,
    pub height: u32,
    pub block_requested: bool,
}

impl From<FilterMatch> for FFIFilterMatch {
    fn from(filter_match: FilterMatch) -> Self {
        FFIFilterMatch {
            block_hash: FFIString::new(&filter_match.block_hash.to_string()),
            height: filter_match.height,
            block_requested: filter_match.block_requested,
        }
    }
}

#[repr(C)]
pub struct FFIAddressStats {
    pub address: FFIString,
    pub utxo_count: u32,
    pub total_value: u64,
    pub confirmed_value: u64,
    pub pending_value: u64,
    pub spendable_count: u32,
    pub coinbase_count: u32,
}

// AddressStats no longer available from dash-spv; conversion removed

impl From<WalletBalance> for FFIBalance {
    fn from(bal: WalletBalance) -> Self {
        // Map confirmed/unconfirmed/locked; mempool fields are not tracked here
        let confirmed = bal.confirmed;
        let unconfirmed = bal.unconfirmed;
        // "locked" is not exposed in FFIBalance directly; keep in total implicitly
        FFIBalance {
            confirmed,
            pending: unconfirmed,
            instantlocked: 0,
            mempool: 0,
            mempool_instant: 0,
            total: bal.total,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_watch_item_address(
    address: *const c_char,
) -> *mut FFIWatchItem {
    if address.is_null() {
        set_last_error("Null address pointer");
        return std::ptr::null_mut();
    }

    match CStr::from_ptr(address).to_str() {
        Ok(addr_str) => {
            let item = FFIWatchItem {
                item_type: FFIWatchItemType::Address,
                data: FFIString::new(addr_str),
            };
            Box::into_raw(Box::new(item))
        }
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_watch_item_script(
    script_hex: *const c_char,
) -> *mut FFIWatchItem {
    if script_hex.is_null() {
        set_last_error("Null script pointer");
        return std::ptr::null_mut();
    }

    match CStr::from_ptr(script_hex).to_str() {
        Ok(script_str) => {
            let item = FFIWatchItem {
                item_type: FFIWatchItemType::Script,
                data: FFIString::new(script_str),
            };
            Box::into_raw(Box::new(item))
        }
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in script: {}", e));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_watch_item_outpoint(
    txid: *const c_char,
    vout: u32,
) -> *mut FFIWatchItem {
    if txid.is_null() {
        set_last_error("Null txid pointer");
        return std::ptr::null_mut();
    }

    match CStr::from_ptr(txid).to_str() {
        Ok(txid_str) => {
            let outpoint_str = format!("{}:{}", txid_str, vout);
            let item = FFIWatchItem {
                item_type: FFIWatchItemType::Outpoint,
                data: FFIString::new(&outpoint_str),
            };
            Box::into_raw(Box::new(item))
        }
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in txid: {}", e));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_watch_item_destroy(item: *mut FFIWatchItem) {
    if !item.is_null() {
        let item = Box::from_raw(item);
        dash_spv_ffi_string_destroy(item.data);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_balance_destroy(balance: *mut FFIBalance) {
    if !balance.is_null() {
        let _ = Box::from_raw(balance);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_utxo_destroy(utxo: *mut FFIUtxo) {
    if !utxo.is_null() {
        let utxo = Box::from_raw(utxo);
        dash_spv_ffi_string_destroy(utxo.txid);
        dash_spv_ffi_string_destroy(utxo.script_pubkey);
        dash_spv_ffi_string_destroy(utxo.address);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_transaction_result_destroy(tx: *mut FFITransactionResult) {
    if !tx.is_null() {
        let tx = Box::from_raw(tx);
        dash_spv_ffi_string_destroy(tx.txid);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_block_result_destroy(block: *mut FFIBlockResult) {
    if !block.is_null() {
        let block = Box::from_raw(block);
        dash_spv_ffi_string_destroy(block.hash);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_filter_match_destroy(filter_match: *mut FFIFilterMatch) {
    if !filter_match.is_null() {
        let filter_match = Box::from_raw(filter_match);
        dash_spv_ffi_string_destroy(filter_match.block_hash);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_address_stats_destroy(stats: *mut FFIAddressStats) {
    if !stats.is_null() {
        let stats = Box::from_raw(stats);
        dash_spv_ffi_string_destroy(stats.address);
    }
}

use crate::types::dash_spv_ffi_string_destroy;

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_validate_address(
    address: *const c_char,
    network: FFINetwork,
) -> i32 {
    if address.is_null() {
        return 0;
    }

    let addr_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Convert FFI network to dashcore network
    let net: dashcore::Network = network.into();

    // Try to parse the address as unchecked first
    match dashcore::Address::<dashcore::address::NetworkUnchecked>::from_str(addr_str) {
        Ok(addr_unchecked) => {
            // Check if the address is valid for the given network
            match addr_unchecked.require_network(net) {
                Ok(_) => 1,  // Address is valid for the specified network
                Err(_) => 0, // Address is for a different network
            }
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_get_monitored_addresses(
    client: *mut FFIDashSpvClient,
    network: FFINetwork,
) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<FFIArray, String> = client.run_async(|| async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            let wallet = spv_client.wallet().clone();
            let wallet = wallet.read().await;
            let net: dashcore::Network = network.into();
            let addrs = wallet.base.monitored_addresses(net);
            let ffi: Vec<FFIString> =
                addrs.into_iter().map(|a| FFIString::new(&a.to_string())).collect();
            Ok(FFIArray::new(ffi))
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(arr) => arr,
        Err(e) => {
            set_last_error(&e);
            FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_get_balance(
    client: *mut FFIDashSpvClient,
    wallet_id_ptr: *const c_char,
) -> *mut crate::FFIBalance {
    null_check!(client, std::ptr::null_mut());
    null_check!(wallet_id_ptr, std::ptr::null_mut());

    // Parse wallet id as 64-char hex string
    let wallet_id_hex = match CStr::from_ptr(wallet_id_ptr).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in wallet id: {}", e));
            return std::ptr::null_mut();
        }
    };

    let mut id: [u8; 32] = [0u8; 32];
    let bytes = hex::decode(wallet_id_hex).unwrap_or_default();
    if bytes.len() != 32 {
        set_last_error("Wallet ID must be 32 bytes hex");
        return std::ptr::null_mut();
    }
    id.copy_from_slice(&bytes);

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<crate::FFIBalance, String> = client.run_async(|| async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            let wallet = spv_client.wallet().clone();
            let wallet = wallet.read().await;
            match wallet.base.get_wallet_balance(&id) {
                Ok(b) => Ok(crate::FFIBalance::from(b)),
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(bal) => Box::into_raw(Box::new(bal)),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_get_utxos(
    client: *mut FFIDashSpvClient,
    wallet_id_ptr: *const c_char,
) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );
    null_check!(
        wallet_id_ptr,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    let wallet_id_hex = match CStr::from_ptr(wallet_id_ptr).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in wallet id: {}", e));
            return FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            };
        }
    };

    let mut id: [u8; 32] = [0u8; 32];
    let bytes = hex::decode(wallet_id_hex).unwrap_or_default();
    if bytes.len() != 32 {
        set_last_error("Wallet ID must be 32 bytes hex");
        return FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
    }
    id.copy_from_slice(&bytes);

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<FFIArray, String> = client.run_async(|| async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            let wallet = spv_client.wallet().clone();
            let wallet = wallet.read().await;
            match wallet.base.wallet_utxos(&id) {
                Ok(set) => {
                    let ffi: Vec<crate::FFIUtxo> =
                        set.into_iter().cloned().map(crate::FFIUtxo::from).collect();
                    Ok(FFIArray::new(ffi))
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(arr) => arr,
        Err(e) => {
            set_last_error(&e);
            FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIWalletAccountCreationOptions {
    /// Default account creation: Creates account 0 for BIP44, account 0 for CoinJoin,
    /// and all special purpose accounts (Identity Registration, Identity Invitation,
    /// Provider keys, etc.)
    Default = 0,
    /// Create only BIP44 accounts (no CoinJoin or special accounts)
    BIP44AccountsOnly = 1,
    /// Create no accounts at all - useful for tests that want to manually control account creation
    None = 2,
}

impl From<FFIWalletAccountCreationOptions> for WalletAccountCreationOptions {
    fn from(options: FFIWalletAccountCreationOptions) -> Self {
        match options {
            FFIWalletAccountCreationOptions::Default => WalletAccountCreationOptions::Default,
            FFIWalletAccountCreationOptions::BIP44AccountsOnly => {
                WalletAccountCreationOptions::BIP44AccountsOnly(Default::default())
            }
            FFIWalletAccountCreationOptions::None => WalletAccountCreationOptions::None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIAccountType {
    /// Standard BIP44 account for regular transactions
    BIP44 = 0,
    /// Standard BIP32 account for regular transactions
    BIP32 = 1,
    /// CoinJoin account for private transactions
    CoinJoin = 2,
    /// Identity registration funding
    IdentityRegistration = 3,
    /// Identity top-up funding
    IdentityTopUp = 4,
    /// Identity invitation funding
    IdentityInvitation = 5,
    /// Provider voting keys (DIP-3)
    ProviderVotingKeys = 6,
    /// Provider owner keys (DIP-3)
    ProviderOwnerKeys = 7,
    /// Provider operator keys (DIP-3)
    ProviderOperatorKeys = 8,
    /// Provider platform P2P keys (DIP-3, ED25519)
    ProviderPlatformKeys = 9,
}

impl FFIAccountType {
    /// Convert FFI account type to internal AccountType
    ///
    /// # Arguments
    /// * `account_index` - Required for BIP44, BIP32, and CoinJoin account types
    /// * `registration_index` - Required for IdentityTopUp account type
    pub fn to_account_type(
        self,
        account_index: Option<u32>,
        registration_index: Option<u32>,
    ) -> Result<AccountType, String> {
        use key_wallet::AccountType::*;

        match self {
            FFIAccountType::BIP44 => {
                let index = account_index.ok_or("Account index required for BIP44 accounts")?;
                Ok(Standard {
                    index,
                    standard_account_type: StandardAccountType::BIP44Account,
                })
            }
            FFIAccountType::BIP32 => {
                let index = account_index.ok_or("Account index required for BIP32 accounts")?;
                Ok(Standard {
                    index,
                    standard_account_type: StandardAccountType::BIP32Account,
                })
            }
            FFIAccountType::CoinJoin => {
                let index = account_index.ok_or("Account index required for CoinJoin accounts")?;
                Ok(CoinJoin {
                    index,
                })
            }
            FFIAccountType::IdentityRegistration => Ok(IdentityRegistration),
            FFIAccountType::IdentityTopUp => {
                let registration_index = registration_index
                    .ok_or("Registration index required for IdentityTopUp accounts")?;
                Ok(IdentityTopUp {
                    registration_index,
                })
            }
            FFIAccountType::IdentityInvitation => Ok(IdentityInvitation),
            FFIAccountType::ProviderVotingKeys => Ok(ProviderVotingKeys),
            FFIAccountType::ProviderOwnerKeys => Ok(ProviderOwnerKeys),
            FFIAccountType::ProviderOperatorKeys => Ok(ProviderOperatorKeys),
            FFIAccountType::ProviderPlatformKeys => Ok(ProviderPlatformKeys),
        }
    }
}

/// Create a new wallet from mnemonic phrase
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
/// * `mnemonic` - The mnemonic phrase as null-terminated C string
/// * `passphrase` - Optional BIP39 passphrase (can be null/empty)
/// * `network` - The network to use
/// * `account_options` - Account creation options
/// * `name` - Wallet name as null-terminated C string
/// * `birth_height` - Optional birth height (can be 0 for none)
///
/// # Returns
/// * Pointer to FFIString containing hex-encoded WalletId (32 bytes as 64-char hex)
/// * Returns null on error (check last_error)
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_create_from_mnemonic(
    client: *mut FFIDashSpvClient,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    network: FFINetwork,
    account_options: FFIWalletAccountCreationOptions,
    name: *const c_char,
    birth_height: u32,
) -> *mut FFIString {
    null_check!(client, std::ptr::null_mut());
    null_check!(mnemonic, std::ptr::null_mut());
    null_check!(name, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let mnemonic_str = match CStr::from_ptr(mnemonic).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in mnemonic: {}", e));
            return std::ptr::null_mut();
        }
    };

    let passphrase_str = if passphrase.is_null() {
        ""
    } else {
        match CStr::from_ptr(passphrase).to_str() {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("Invalid UTF-8 in passphrase: {}", e));
                return std::ptr::null_mut();
            }
        }
    };

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in name: {}", e));
            return std::ptr::null_mut();
        }
    };

    let result = client.run_async(|| async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            let wallet_manager = &mut spv_client.wallet().write().await.base;

            // Generate a random WalletId
            let wallet_id = WalletId::from(rand::random::<[u8; 32]>());

            let network = network.into();
            let account_creation_options: WalletAccountCreationOptions = account_options.into();
            let birth_height_opt = if birth_height == 0 {
                None
            } else {
                Some(birth_height)
            };

            match wallet_manager.create_wallet_from_mnemonic(
                wallet_id,
                name_str.to_string(),
                mnemonic_str,
                passphrase_str,
                Some(network),
                birth_height_opt,
                account_creation_options,
            ) {
                Ok(_) => {
                    // Convert WalletId to hex string
                    Ok(hex::encode(wallet_id))
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(wallet_id_hex) => Box::into_raw(Box::new(FFIString::new(&wallet_id_hex))),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Create a new empty wallet (test wallet with fixed mnemonic)
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
/// * `network` - The network to use
/// * `account_options` - Account creation options
/// * `name` - Wallet name as null-terminated C string
///
/// # Returns
/// * Pointer to FFIString containing hex-encoded WalletId (32 bytes as 64-char hex)
/// * Returns null on error (check last_error)
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_create(
    client: *mut FFIDashSpvClient,
    network: FFINetwork,
    account_options: FFIWalletAccountCreationOptions,
    name: *const c_char,
) -> *mut FFIString {
    null_check!(client, std::ptr::null_mut());
    null_check!(name, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in name: {}", e));
            return std::ptr::null_mut();
        }
    };

    let result = client.run_async(|| async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            let wallet_manager = &mut spv_client.wallet().write().await.base;

            // Generate a random WalletId
            let wallet_id = WalletId::from(rand::random::<[u8; 32]>());

            let network = network.into();
            let account_creation_options: WalletAccountCreationOptions = account_options.into();

            match wallet_manager.create_wallet(
                wallet_id,
                name_str.to_string(),
                account_creation_options,
                network,
            ) {
                Ok(_) => {
                    // Convert WalletId to hex string
                    Ok(hex::encode(wallet_id))
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(wallet_id_hex) => Box::into_raw(Box::new(FFIString::new(&wallet_id_hex))),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Get a list of all wallet IDs
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
///
/// # Returns
/// * FFIArray of FFIString objects containing hex-encoded WalletIds
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_list(client: *mut FFIDashSpvClient) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<FFIArray, String> = client.run_async(|| async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            let wallet_manager = &spv_client.wallet().read().await.base;
            let wallet_ids: Vec<FFIString> = wallet_manager
                .list_wallets()
                .iter()
                .map(|id| FFIString::new(&hex::encode(id)))
                .collect();

            Ok(FFIArray::new(wallet_ids))
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(arr) => arr,
        Err(e) => {
            set_last_error(&e);
            FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            }
        }
    }
}

/// Import a wallet from an extended private key
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
/// * `xprv` - The extended private key string (base58check encoded)
/// * `network` - The network to use
/// * `account_options` - Account creation options
/// * `name` - Wallet name as null-terminated C string
///
/// # Returns
/// * Pointer to FFIString containing hex-encoded WalletId (32 bytes as 64-char hex)
/// * Returns null on error (check last_error)
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_import_from_xprv(
    client: *mut FFIDashSpvClient,
    xprv: *const c_char,
    network: FFINetwork,
    account_options: FFIWalletAccountCreationOptions,
    name: *const c_char,
) -> *mut FFIString {
    null_check!(client, std::ptr::null_mut());
    null_check!(xprv, std::ptr::null_mut());
    null_check!(name, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let xprv_str = match CStr::from_ptr(xprv).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in xprv: {}", e));
            return std::ptr::null_mut();
        }
    };

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in name: {}", e));
            return std::ptr::null_mut();
        }
    };

    let result = client.run_async(|| async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            let wallet_manager = &mut spv_client.wallet().write().await.base;

            // Generate a random WalletId
            let wallet_id = WalletId::from(rand::random::<[u8; 32]>());

            let network = network.into();
            let account_creation_options: WalletAccountCreationOptions = account_options.into();

            match wallet_manager.import_wallet_from_extended_priv_key(
                wallet_id,
                name_str.to_string(),
                xprv_str,
                network,
                account_creation_options,
            ) {
                Ok(_) => {
                    // Convert WalletId to hex string
                    Ok(hex::encode(wallet_id))
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(wallet_id_hex) => Box::into_raw(Box::new(FFIString::new(&wallet_id_hex))),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Import a watch-only wallet from an extended public key
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
/// * `xpub` - The extended public key string (base58check encoded)
/// * `network` - The network to use
/// * `name` - Wallet name as null-terminated C string
///
/// # Returns
/// * Pointer to FFIString containing hex-encoded WalletId (32 bytes as 64-char hex)
/// * Returns null on error (check last_error)
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_import_from_xpub(
    client: *mut FFIDashSpvClient,
    xpub: *const c_char,
    network: FFINetwork,
    name: *const c_char,
) -> *mut FFIString {
    null_check!(client, std::ptr::null_mut());
    null_check!(xpub, std::ptr::null_mut());
    null_check!(name, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let xpub_str = match CStr::from_ptr(xpub).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in xpub: {}", e));
            return std::ptr::null_mut();
        }
    };

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in name: {}", e));
            return std::ptr::null_mut();
        }
    };

    let result = client.run_async(|| async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            let wallet_manager = &mut spv_client.wallet().write().await.base;

            // Generate a random WalletId
            let wallet_id = WalletId::from(rand::random::<[u8; 32]>());

            let network = network.into();

            match wallet_manager.import_wallet_from_xpub(
                wallet_id,
                name_str.to_string(),
                xpub_str,
                network,
            ) {
                Ok(_) => {
                    // Convert WalletId to hex string
                    Ok(hex::encode(wallet_id))
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(wallet_id_hex) => Box::into_raw(Box::new(FFIString::new(&wallet_id_hex))),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIAccountTypePreference {
    /// Use BIP44 account only
    BIP44 = 0,
    /// Use BIP32 account only
    BIP32 = 1,
    /// Prefer BIP44, fallback to BIP32
    PreferBIP44 = 2,
    /// Prefer BIP32, fallback to BIP44
    PreferBIP32 = 3,
}

impl From<FFIAccountTypePreference> for AccountTypePreference {
    fn from(pref: FFIAccountTypePreference) -> Self {
        match pref {
            FFIAccountTypePreference::BIP44 => AccountTypePreference::BIP44,
            FFIAccountTypePreference::BIP32 => AccountTypePreference::BIP32,
            FFIAccountTypePreference::PreferBIP44 => AccountTypePreference::PreferBIP44,
            FFIAccountTypePreference::PreferBIP32 => AccountTypePreference::PreferBIP32,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIAccountTypeUsed {
    /// BIP44 account was used
    BIP44 = 0,
    /// BIP32 account was used
    BIP32 = 1,
}

#[repr(C)]
pub struct FFIAddressGenerationResult {
    pub address: *mut FFIString,
    pub account_type_used: FFIAccountTypeUsed,
}

/// Add a new account to an existing wallet from an extended public key
///
/// This creates a watch-only account that can monitor addresses and transactions
/// but cannot sign them.
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
/// * `wallet_id_hex` - Hex-encoded wallet ID (64 characters)
/// * `xpub` - The extended public key string (base58check encoded)
/// * `account_type` - The type of account to create
/// * `network` - The network for the account
/// * `account_index` - Account index (required for BIP44, BIP32, CoinJoin)
/// * `registration_index` - Registration index (required for IdentityTopUp)
///
/// # Returns
/// * FFIErrorCode::Success on success
/// * FFIErrorCode::InvalidArgument on error (check last_error)
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_add_account_from_xpub(
    client: *mut FFIDashSpvClient,
    wallet_id_hex: *const c_char,
    xpub: *const c_char,
    account_type: FFIAccountType,
    network: FFINetwork,
    account_index: u32,
    registration_index: u32,
) -> i32 {
    null_check!(client, crate::FFIErrorCode::InvalidArgument as i32);
    null_check!(wallet_id_hex, crate::FFIErrorCode::InvalidArgument as i32);
    null_check!(xpub, crate::FFIErrorCode::InvalidArgument as i32);

    let client = &(*client);
    let inner = client.inner.clone();

    let wallet_id_hex_str = match CStr::from_ptr(wallet_id_hex).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in wallet ID: {}", e));
            return crate::FFIErrorCode::InvalidArgument as i32;
        }
    };

    let xpub_str = match CStr::from_ptr(xpub).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in xpub: {}", e));
            return crate::FFIErrorCode::InvalidArgument as i32;
        }
    };

    // Parse wallet ID
    let mut wallet_id: [u8; 32] = [0u8; 32];
    let bytes = match hex::decode(wallet_id_hex_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("Invalid hex wallet ID: {}", e));
            return crate::FFIErrorCode::InvalidArgument as i32;
        }
    };
    if bytes.len() != 32 {
        set_last_error("Wallet ID must be 32 bytes hex");
        return crate::FFIErrorCode::InvalidArgument as i32;
    }
    wallet_id.copy_from_slice(&bytes);

    // Convert account type with parameters
    let account_index_opt = if matches!(
        account_type,
        FFIAccountType::BIP44 | FFIAccountType::BIP32 | FFIAccountType::CoinJoin
    ) {
        Some(account_index)
    } else {
        None
    };

    let registration_index_opt = if matches!(account_type, FFIAccountType::IdentityTopUp) {
        Some(registration_index)
    } else {
        None
    };

    let account_type_internal =
        match account_type.to_account_type(account_index_opt, registration_index_opt) {
            Ok(at) => at,
            Err(e) => {
                set_last_error(&e);
                return crate::FFIErrorCode::InvalidArgument as i32;
            }
        };

    let result: Result<(), String> = client.run_async(|| async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            let wallet_manager = &mut spv_client.wallet().write().await.base;

            // Parse the extended public key
            let extended_pub_key = key_wallet::ExtendedPubKey::from_str(xpub_str)
                .map_err(|e| format!("Invalid xpub: {}", e))?;

            match wallet_manager.create_account(
                &wallet_id,
                account_type_internal,
                network.into(),
                Some(extended_pub_key),
            ) {
                Ok(()) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(()) => crate::FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e);
            crate::FFIErrorCode::InvalidArgument as i32
        }
    }
}

/// Get a receive address from a specific wallet and account
///
/// This generates a new unused receive address (external chain) for the specified
/// wallet and account. The address will be marked as used if mark_as_used is true.
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
/// * `wallet_id_hex` - Hex-encoded wallet ID (64 characters)
/// * `network` - The network for the address
/// * `account_index` - Account index (0 for first account)
/// * `account_type_pref` - Account type preference (BIP44, BIP32, or preference)
/// * `mark_as_used` - Whether to mark the address as used after generation
///
/// # Returns
/// * Pointer to FFIAddressGenerationResult containing the address and account type used
/// * Returns null if address generation fails (check last_error)
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_get_receive_address(
    client: *mut FFIDashSpvClient,
    wallet_id_hex: *const c_char,
    network: FFINetwork,
    account_index: u32,
    account_type_pref: FFIAccountTypePreference,
    mark_as_used: bool,
) -> *mut FFIAddressGenerationResult {
    null_check!(client, std::ptr::null_mut());
    null_check!(wallet_id_hex, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let wallet_id_hex_str = match CStr::from_ptr(wallet_id_hex).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in wallet ID: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Parse wallet ID
    let mut wallet_id: [u8; 32] = [0u8; 32];
    let bytes = match hex::decode(wallet_id_hex_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("Invalid hex wallet ID: {}", e));
            return std::ptr::null_mut();
        }
    };
    if bytes.len() != 32 {
        set_last_error("Wallet ID must be 32 bytes hex");
        return std::ptr::null_mut();
    }
    wallet_id.copy_from_slice(&bytes);

    let result: Result<FFIAddressGenerationResult, String> = client.run_async(|| async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            let wallet_manager = &mut spv_client.wallet().write().await.base;

            match wallet_manager.get_receive_address(
                &wallet_id,
                network.into(),
                account_index,
                account_type_pref.into(),
                mark_as_used,
            ) {
                Ok(addr_result) => {
                    if let (Some(address), Some(account_type_used)) =
                        (addr_result.address, addr_result.account_type_used)
                    {
                        let ffi_account_type = match account_type_used {
                            AccountTypeUsed::BIP44 => FFIAccountTypeUsed::BIP44,
                            AccountTypeUsed::BIP32 => FFIAccountTypeUsed::BIP32,
                        };

                        Ok(FFIAddressGenerationResult {
                            address: Box::into_raw(Box::new(FFIString::new(&address.to_string()))),
                            account_type_used: ffi_account_type,
                        })
                    } else {
                        Err("No address could be generated".to_string())
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Get a change address from a specific wallet and account
///
/// This generates a new unused change address (internal chain) for the specified
/// wallet and account. The address will be marked as used if mark_as_used is true.
///
/// # Arguments
/// * `client` - Pointer to FFIDashSpvClient
/// * `wallet_id_hex` - Hex-encoded wallet ID (64 characters)
/// * `network` - The network for the address
/// * `account_index` - Account index (0 for first account)
/// * `account_type_pref` - Account type preference (BIP44, BIP32, or preference)
/// * `mark_as_used` - Whether to mark the address as used after generation
///
/// # Returns
/// * Pointer to FFIAddressGenerationResult containing the address and account type used
/// * Returns null if address generation fails (check last_error)
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_get_change_address(
    client: *mut FFIDashSpvClient,
    wallet_id_hex: *const c_char,
    network: FFINetwork,
    account_index: u32,
    account_type_pref: FFIAccountTypePreference,
    mark_as_used: bool,
) -> *mut FFIAddressGenerationResult {
    null_check!(client, std::ptr::null_mut());
    null_check!(wallet_id_hex, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let wallet_id_hex_str = match CStr::from_ptr(wallet_id_hex).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in wallet ID: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Parse wallet ID
    let mut wallet_id: [u8; 32] = [0u8; 32];
    let bytes = match hex::decode(wallet_id_hex_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("Invalid hex wallet ID: {}", e));
            return std::ptr::null_mut();
        }
    };
    if bytes.len() != 32 {
        set_last_error("Wallet ID must be 32 bytes hex");
        return std::ptr::null_mut();
    }
    wallet_id.copy_from_slice(&bytes);

    let result: Result<FFIAddressGenerationResult, String> = client.run_async(|| async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            let wallet_manager = &mut spv_client.wallet().write().await.base;

            match wallet_manager.get_change_address(
                &wallet_id,
                network.into(),
                account_index,
                account_type_pref.into(),
                mark_as_used,
            ) {
                Ok(addr_result) => {
                    if let (Some(address), Some(account_type_used)) =
                        (addr_result.address, addr_result.account_type_used)
                    {
                        let ffi_account_type = match account_type_used {
                            AccountTypeUsed::BIP44 => FFIAccountTypeUsed::BIP44,
                            AccountTypeUsed::BIP32 => FFIAccountTypeUsed::BIP32,
                        };

                        Ok(FFIAddressGenerationResult {
                            address: Box::into_raw(Box::new(FFIString::new(&address.to_string()))),
                            account_type_used: ffi_account_type,
                        })
                    } else {
                        Err("No address could be generated".to_string())
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Client not initialized".to_string())
        }
    });

    match result {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Free an FFIAddressGenerationResult and its associated resources
///
/// # Safety
/// * `result` must be a valid pointer to an FFIAddressGenerationResult
/// * The pointer must not be used after this function is called
/// * This function should only be called once per FFIAddressGenerationResult
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_address_generation_result_destroy(
    result: *mut FFIAddressGenerationResult,
) {
    if !result.is_null() {
        let result = Box::from_raw(result);
        if !result.address.is_null() {
            let addr_ptr = result.address;
            // Read the FFIString from the raw pointer and destroy it
            let addr_string = unsafe { *Box::from_raw(addr_ptr) };
            dash_spv_ffi_string_destroy(addr_string);
        }
    }
}
