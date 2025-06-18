use crate::{set_last_error, FFIString};
use dash_spv::{
    AddressStats, Balance, BlockResult, FilterMatch, TransactionResult, Utxo, WatchItem,
};
use dashcore::{OutPoint, ScriptBuf, Txid};
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
    pub unsafe fn to_watch_item(&self) -> Result<WatchItem, String> {
        // Note: This method uses NetworkUnchecked for backward compatibility.
        // Consider using to_watch_item_with_network for proper network validation.
        let data_str = FFIString::from_ptr(self.data.ptr)?;

        match self.item_type {
            FFIWatchItemType::Address => {
                let addr =
                    dashcore::Address::<dashcore::address::NetworkUnchecked>::from_str(&data_str)
                        .map_err(|e| format!("Invalid address: {}", e))?
                        .assume_checked();
                Ok(WatchItem::Address {
                    address: addr,
                    earliest_height: None,
                })
            }
            FFIWatchItemType::Script => {
                let script_bytes =
                    hex::decode(&data_str).map_err(|e| format!("Invalid script hex: {}", e))?;
                let script = ScriptBuf::from(script_bytes);
                Ok(WatchItem::Script(script))
            }
            FFIWatchItemType::Outpoint => {
                let parts: Vec<&str> = data_str.split(':').collect();
                if parts.len() != 2 {
                    return Err("Invalid outpoint format (expected txid:vout)".to_string());
                }
                let txid: Txid = parts[0].parse().map_err(|e| format!("Invalid txid: {}", e))?;
                let vout: u32 = parts[1].parse().map_err(|e| format!("Invalid vout: {}", e))?;
                Ok(WatchItem::Outpoint(OutPoint::new(txid, vout)))
            }
        }
    }

    /// Convert FFIWatchItem to WatchItem with network validation
    pub unsafe fn to_watch_item_with_network(
        &self,
        network: dashcore::Network,
    ) -> Result<WatchItem, String> {
        let data_str = FFIString::from_ptr(self.data.ptr)?;

        match self.item_type {
            FFIWatchItemType::Address => {
                let addr =
                    dashcore::Address::<dashcore::address::NetworkUnchecked>::from_str(&data_str)
                        .map_err(|e| format!("Invalid address: {}", e))?;

                // Validate that the address belongs to the expected network
                let checked_addr = addr.require_network(network).map_err(|_| {
                    format!("Address {} is not valid for network {:?}", data_str, network)
                })?;

                Ok(WatchItem::Address {
                    address: checked_addr,
                    earliest_height: None,
                })
            }
            FFIWatchItemType::Script => {
                let script_bytes =
                    hex::decode(&data_str).map_err(|e| format!("Invalid script hex: {}", e))?;
                let script = ScriptBuf::from(script_bytes);
                Ok(WatchItem::Script(script))
            }
            FFIWatchItemType::Outpoint => {
                let outpoint = OutPoint::from_str(&data_str)
                    .map_err(|e| format!("Invalid outpoint: {}", e))?;
                Ok(WatchItem::Outpoint(outpoint))
            }
        }
    }
}

#[repr(C)]
pub struct FFIBalance {
    pub confirmed: u64,
    pub pending: u64,
    pub instantlocked: u64,
    pub total: u64,
}

impl From<Balance> for FFIBalance {
    fn from(balance: Balance) -> Self {
        FFIBalance {
            confirmed: balance.confirmed.to_sat(),
            pending: balance.pending.to_sat(),
            instantlocked: balance.instantlocked.to_sat(),
            total: balance.total().to_sat(),
        }
    }
}

impl From<dash_spv::types::AddressBalance> for FFIBalance {
    fn from(balance: dash_spv::types::AddressBalance) -> Self {
        FFIBalance {
            confirmed: balance.confirmed.to_sat(),
            pending: balance.unconfirmed.to_sat(),
            instantlocked: 0, // AddressBalance doesn't have instantlocked
            total: (balance.confirmed + balance.unconfirmed).to_sat(),
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

impl From<Utxo> for FFIUtxo {
    fn from(utxo: Utxo) -> Self {
        FFIUtxo {
            txid: FFIString::new(&utxo.outpoint.txid.to_string()),
            vout: utxo.outpoint.vout,
            amount: utxo.value().to_sat(),
            script_pubkey: FFIString::new(&hex::encode(utxo.script_pubkey().to_bytes())),
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

impl From<TransactionResult> for FFITransactionResult {
    fn from(tx: TransactionResult) -> Self {
        FFITransactionResult {
            txid: FFIString::new(&tx.transaction.txid().to_string()),
            version: tx.transaction.version as i32,
            locktime: tx.transaction.lock_time,
            size: tx.transaction.size() as u32,
            weight: tx.transaction.weight().to_wu() as u32,
            fee: 0,                 // fee not available in TransactionResult
            confirmation_time: 0,   // not available in TransactionResult
            confirmation_height: 0, // not available in TransactionResult
        }
    }
}

#[repr(C)]
pub struct FFIBlockResult {
    pub hash: FFIString,
    pub height: u32,
    pub time: u32,
    pub tx_count: u32,
}

impl From<BlockResult> for FFIBlockResult {
    fn from(block: BlockResult) -> Self {
        FFIBlockResult {
            hash: FFIString::new(&block.block_hash.to_string()),
            height: block.height,
            time: 0, // not available in BlockResult
            tx_count: block.transactions.len() as u32,
        }
    }
}

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

impl From<AddressStats> for FFIAddressStats {
    fn from(stats: AddressStats) -> Self {
        FFIAddressStats {
            address: FFIString::new(&stats.address.to_string()),
            utxo_count: stats.utxo_count as u32,
            total_value: stats.total_value.to_sat(),
            confirmed_value: stats.confirmed_value.to_sat(),
            pending_value: stats.pending_value.to_sat(),
            spendable_count: stats.spendable_count as u32,
            coinbase_count: stats.coinbase_count as u32,
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
use crate::FFINetwork;

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
