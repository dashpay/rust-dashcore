use crate::client::FFIDashSpvClient;
use crate::types::FFINetwork;
use crate::{null_check, FFIArray};
use crate::{set_last_error, FFIString};
use dash_spv::FilterMatch;
use dashcore::{OutPoint, ScriptBuf, Txid};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::Utxo as KWUtxo;
use key_wallet::WalletBalance;
use key_wallet_manager::wallet_manager::WalletId;
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
