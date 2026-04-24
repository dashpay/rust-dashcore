use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;

use clap::{Arg, ArgAction, Command};
use dash_network::ffi::FFINetwork;
use dash_spv_ffi::*;
use key_wallet_ffi::managed_account::FFITransactionRecord;
use key_wallet_ffi::types::FFITransactionContext;
use key_wallet_ffi::wallet_manager::wallet_manager_add_wallet_from_mnemonic;
use key_wallet_ffi::FFIError;

fn ffi_string_to_rust(s: *const c_char) -> String {
    if s.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(s) }.to_str().unwrap_or_default().to_owned()
}

// ============================================================================
// Sync Event Callbacks
// ============================================================================

extern "C" fn on_sync_start(manager_id: FFIManagerId, _user_data: *mut c_void) {
    let manager_name = match manager_id {
        FFIManagerId::Headers => "Headers",
        FFIManagerId::FilterHeaders => "FilterHeaders",
        FFIManagerId::Filters => "Filters",
        FFIManagerId::Blocks => "Blocks",
        FFIManagerId::Masternodes => "Masternodes",
        FFIManagerId::ChainLocks => "ChainLocks",
        FFIManagerId::InstantSend => "InstantSend",
        FFIManagerId::Mempool => "Mempool",
    };
    println!("[Sync] Manager started: {}", manager_name);
}

extern "C" fn on_block_headers_stored(tip_height: u32, _user_data: *mut c_void) {
    println!("[Sync] Block headers stored, tip: {}", tip_height);
}

extern "C" fn on_block_header_sync_complete(tip_height: u32, _user_data: *mut c_void) {
    println!("[Sync] Block header sync complete at height: {}", tip_height);
}

extern "C" fn on_filter_headers_stored(
    start_height: u32,
    end_height: u32,
    tip_height: u32,
    _user_data: *mut c_void,
) {
    println!("[Sync] Filter headers stored: {}-{}, tip: {}", start_height, end_height, tip_height);
}

extern "C" fn on_filter_headers_sync_complete(tip_height: u32, _user_data: *mut c_void) {
    println!("[Sync] Filter headers sync complete at height: {}", tip_height);
}

extern "C" fn on_filters_stored(start_height: u32, end_height: u32, _user_data: *mut c_void) {
    println!("[Sync] Filters stored: {}-{}", start_height, end_height);
}

extern "C" fn on_filters_sync_complete(tip_height: u32, _user_data: *mut c_void) {
    println!("[Sync] Filters sync complete at height: {}", tip_height);
}

extern "C" fn on_blocks_needed(blocks: *const FFIBlockNeeded, count: u32, _user_data: *mut c_void) {
    println!("[Sync] Blocks needed: {}", count);
    if !blocks.is_null() && count > 0 {
        let blocks_slice = unsafe { std::slice::from_raw_parts(blocks, count as usize) };
        for block in blocks_slice.iter() {
            println!("  - height: {}, hash: {}", block.height, hex::encode(block.hash));
        }
    }
}

extern "C" fn on_block_processed(
    height: u32,
    _hash: *const [u8; 32],
    new_address_count: u32,
    _confirmed_txids: *const [u8; 32],
    confirmed_txid_count: u32,
    _user_data: *mut c_void,
) {
    println!(
        "[Sync] Block processed: height={}, new_addresses={}, confirmed_txs={}",
        height, new_address_count, confirmed_txid_count
    );
}

extern "C" fn on_masternode_state_updated(height: u32, _user_data: *mut c_void) {
    println!("[Sync] Masternode state updated at height: {}", height);
}

extern "C" fn on_chainlock_received(
    height: u32,
    hash: *const [u8; 32],
    signature: *const [u8; 96],
    validated: bool,
    _user_data: *mut c_void,
) {
    let hash_hex = unsafe { hex::encode(*hash) };
    let signature_hex = unsafe { hex::encode(*signature) };
    println!(
        "[Sync] ChainLock received: height={}, hash={}, signature={}, validated={}",
        height, hash_hex, signature_hex, validated
    );
}

extern "C" fn on_instantlock_received(
    txid: *const [u8; 32],
    _instantlock_data: *const u8,
    instantlock_len: usize,
    validated: bool,
    _user_data: *mut c_void,
) {
    let txid_hex = unsafe { hex::encode(*txid) };
    println!(
        "[Sync] InstantLock received: txid={}, validated={}, data_len={}",
        txid_hex, validated, instantlock_len
    );
}

extern "C" fn on_manager_error(
    manager_id: FFIManagerId,
    error: *const c_char,
    _user_data: *mut c_void,
) {
    let error_str = ffi_string_to_rust(error);
    println!("[Sync] Manager error: {:?} - {}", manager_id, error_str);
}

extern "C" fn on_sync_complete(header_tip: u32, cycle: u32, _user_data: *mut c_void) {
    println!("[Sync] Sync complete at height: {} (cycle {})", header_tip, cycle);
}

// ============================================================================
// Network Event Callbacks
// ============================================================================

extern "C" fn on_peer_connected(address: *const c_char, _user_data: *mut c_void) {
    let addr = ffi_string_to_rust(address);
    println!("[Network] Peer connected: {}", addr);
}

extern "C" fn on_peer_disconnected(address: *const c_char, _user_data: *mut c_void) {
    let addr = ffi_string_to_rust(address);
    println!("[Network] Peer disconnected: {}", addr);
}

extern "C" fn on_peers_updated(connected_count: u32, best_height: u32, _user_data: *mut c_void) {
    println!("[Network] Peers: {} connected, best height: {}", connected_count, best_height);
}

// ============================================================================
// Wallet Event Callbacks
// ============================================================================

extern "C" fn on_transaction_received(
    wallet_id: *const c_char,
    account_index: u32,
    record: *const FFITransactionRecord,
    _user_data: *mut c_void,
) {
    let wallet_str = ffi_string_to_rust(wallet_id);
    let wallet_short = if wallet_str.len() > 8 {
        &wallet_str[..8]
    } else {
        &wallet_str
    };
    if record.is_null() {
        println!(
            "[Wallet] TX received: wallet={}..., account={}, record=null",
            wallet_short, account_index
        );
        return;
    }
    let r = unsafe { &*record };
    let txid_hex = hex::encode(r.txid);
    println!(
        "[Wallet] TX received: wallet={}..., txid={}, account={}, amount={} duffs, tx_size={}",
        wallet_short, txid_hex, account_index, r.net_amount, r.tx_len
    );
}

extern "C" fn on_transaction_status_changed(
    _wallet_id: *const c_char,
    txid: *const [u8; 32],
    status: FFITransactionContext,
    _user_data: *mut c_void,
) {
    let txid_hex = unsafe { hex::encode(*txid) };
    println!("[Wallet] TX status changed: txid={}, status={:?}", txid_hex, status);
}

extern "C" fn on_balance_updated(
    wallet_id: *const c_char,
    spendable: u64,
    unconfirmed: u64,
    immature: u64,
    locked: u64,
    _user_data: *mut c_void,
) {
    let wallet_str = ffi_string_to_rust(wallet_id);
    let wallet_short = if wallet_str.len() > 8 {
        &wallet_str[..8]
    } else {
        &wallet_str
    };
    println!(
        "[Wallet] Balance updated: wallet={}..., spendable={}, unconfirmed={}, immature={}, locked={}",
        wallet_short, spendable, unconfirmed, immature, locked
    );
}

// ============================================================================
// Progress Callback
// ============================================================================

extern "C" fn on_progress_update(progress: *const FFISyncProgress, _user_data: *mut c_void) {
    if progress.is_null() {
        return;
    }
    let p = unsafe { &*progress };

    let state_str = match p.state {
        FFISyncState::WaitForEvents => "WaitForEvents",
        FFISyncState::WaitingForConnections => "WaitingForConnections",
        FFISyncState::Syncing => "Syncing",
        FFISyncState::Synced => "Synced",
        FFISyncState::Error => "Error",
    };

    print!("[Progress] {:.1}% {} ", p.percentage * 100.0, state_str);

    if !p.headers.is_null() {
        let h = unsafe { &*p.headers };
        print!("headers:{}/{} ", h.tip_height + h.buffered, h.target_height);
    }
    if !p.filter_headers.is_null() {
        let fh = unsafe { &*p.filter_headers };
        print!("filter headers:{}/{} ", fh.current_height, fh.target_height);
    }
    if !p.filters.is_null() {
        let f = unsafe { &*p.filters };
        print!("filters:{}/{} stored: {} ", f.committed_height, f.target_height, f.stored_height);
    }
    if !p.blocks.is_null() {
        let f = unsafe { &*p.blocks };
        print!("blocks: last: {}, transactions: {} ", f.last_processed, f.transactions);
    }
    if !p.masternodes.is_null() {
        let mn = unsafe { &*p.masternodes };
        print!("masternodes:{}/{} ", mn.current_height, mn.target_height);
    }

    println!();
}

// ============================================================================
// Error Callback
// ============================================================================

extern "C" fn on_error(error: *const c_char, _user_data: *mut c_void) {
    let msg = if error.is_null() {
        "unknown error".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(error) }
            .to_str()
            .unwrap_or("invalid error string")
            .to_string()
    };
    eprintln!("[FATAL] {}", msg);
    std::process::exit(1);
}

fn main() {
    let matches = Command::new("dash-spv-ffi")
        .about("Run SPV sync via FFI using event callbacks")
        .arg(
            Arg::new("network")
                .long("network")
                .short('n')
                .value_parser(clap::builder::PossibleValuesParser::new([
                    "mainnet", "testnet", "regtest",
                ]))
                .default_value("mainnet"),
        )
        .arg(
            Arg::new("peer")
                .long("peer")
                .short('p')
                .action(ArgAction::Append)
                .help("Peer address host:port (repeatable)"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Tracing log level"),
        )
        .arg(
            Arg::new("start-height")
                .long("start-height")
                .value_parser(clap::value_parser!(u32))
                .help("Start syncing from nearest checkpoint at height"),
        )
        .arg(
            Arg::new("no-masternodes")
                .long("no-masternodes")
                .action(ArgAction::SetTrue)
                .help("Disable masternode list synchronization"),
        )
        .arg(
            Arg::new("data-dir")
                .short('d')
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for storage (default: unique directory in /tmp)"),
        )
        .arg(
            Arg::new("mnemonic-file")
                .long("mnemonic-file")
                .value_name("PATH")
                .help("Path to file containing BIP39 mnemonic phrase"),
        )
        .get_matches();

    // Map network
    let network = match matches.get_one::<String>("network").map(|s| s.as_str()) {
        Some("mainnet") => FFINetwork::Mainnet,
        Some("testnet") => FFINetwork::Testnet,
        Some("regtest") => FFINetwork::Regtest,
        _ => FFINetwork::Mainnet,
    };

    unsafe {
        // Build config
        let cfg = dash_spv_ffi_config_new(network);
        if cfg.is_null() {
            eprintln!(
                "Failed to allocate config: {}",
                ffi_string_to_rust(dash_spv_ffi_get_last_error())
            );
            std::process::exit(1);
        }

        // Determine and set data directory
        let data_dir = matches
            .get_one::<String>("data-dir")
            .map(|s| s.to_string())
            .unwrap_or_else(|| ".tmp/ffi-cli".to_string());

        let storage_dir_c = CString::new(data_dir.as_str()).unwrap();
        let rc = dash_spv_ffi_config_set_data_dir(cfg, storage_dir_c.as_ptr());
        if rc != FFIErrorCode::Success as i32 {
            eprintln!(
                "Failed to set data dir: {}",
                ffi_string_to_rust(dash_spv_ffi_get_last_error())
            );
            std::process::exit(1);
        }
        println!("Storage directory: {}", data_dir);

        // Initialize tracing/logging via FFI with file logging to data_dir/logs
        let level = matches.get_one::<String>("log-level").map(String::as_str).unwrap_or("info");
        let level_c = CString::new(level).unwrap();
        let log_dir = format!("{}/logs", data_dir);
        let log_dir_c = CString::new(log_dir.as_str()).unwrap();
        let _ = dash_spv_ffi_init_logging(level_c.as_ptr(), false, log_dir_c.as_ptr(), 5);
        println!("Log directory: {}", log_dir);

        if let Some(height) = matches.get_one::<u32>("start-height") {
            let _ = dash_spv_ffi_config_set_start_from_height(cfg, *height);
        }

        if matches.get_flag("no-masternodes") {
            let _ = dash_spv_ffi_config_set_masternode_sync_enabled(cfg, false);
        }

        if let Some(peers) = matches.get_many::<String>("peer") {
            for p in peers {
                let c = CString::new(p.as_str()).unwrap();
                let rc = dash_spv_ffi_config_add_peer(cfg, c.as_ptr());
                if rc != FFIErrorCode::Success as i32 {
                    eprintln!(
                        "Invalid peer {}: {}",
                        p,
                        ffi_string_to_rust(dash_spv_ffi_get_last_error())
                    );
                }
            }
        }

        // Read mnemonic file if provided
        let mnemonic_phrase = matches.get_one::<String>("mnemonic-file").map(|path| {
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to read mnemonic file '{}': {}", path, e);
                    std::process::exit(1);
                })
                .trim()
                .to_string()
        });

        // Build all event callbacks in a single struct
        let callbacks = FFIEventCallbacks {
            sync: FFISyncEventCallbacks {
                on_sync_start: Some(on_sync_start),
                on_block_headers_stored: Some(on_block_headers_stored),
                on_block_header_sync_complete: Some(on_block_header_sync_complete),
                on_filter_headers_stored: Some(on_filter_headers_stored),
                on_filter_headers_sync_complete: Some(on_filter_headers_sync_complete),
                on_filters_stored: Some(on_filters_stored),
                on_filters_sync_complete: Some(on_filters_sync_complete),
                on_blocks_needed: Some(on_blocks_needed),
                on_block_processed: Some(on_block_processed),
                on_masternode_state_updated: Some(on_masternode_state_updated),
                on_chainlock_received: Some(on_chainlock_received),
                on_instantlock_received: Some(on_instantlock_received),
                on_manager_error: Some(on_manager_error),
                on_sync_complete: Some(on_sync_complete),
                user_data: ptr::null_mut(),
            },
            network: FFINetworkEventCallbacks {
                on_peer_connected: Some(on_peer_connected),
                on_peer_disconnected: Some(on_peer_disconnected),
                on_peers_updated: Some(on_peers_updated),
                user_data: ptr::null_mut(),
            },
            progress: FFIProgressCallback {
                on_progress: Some(on_progress_update),
                user_data: ptr::null_mut(),
            },
            wallet: FFIWalletEventCallbacks {
                on_transaction_received: Some(on_transaction_received),
                on_transaction_status_changed: Some(on_transaction_status_changed),
                on_balance_updated: Some(on_balance_updated),
                user_data: ptr::null_mut(),
            },
            error: FFIClientErrorCallback {
                on_error: Some(on_error),
                user_data: ptr::null_mut(),
            },
        };

        // Create client with event callbacks
        let client = dash_spv_ffi_client_new(cfg, callbacks);
        if client.is_null() {
            eprintln!(
                "Client create failed: {}",
                ffi_string_to_rust(dash_spv_ffi_get_last_error())
            );
            std::process::exit(1);
        }

        // Add wallet from mnemonic if provided
        if let Some(ref mnemonic) = mnemonic_phrase {
            let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
            if wallet_manager.is_null() {
                eprintln!(
                    "Failed to get wallet manager: {}",
                    ffi_string_to_rust(dash_spv_ffi_get_last_error())
                );
                std::process::exit(1);
            }

            let mnemonic_c = CString::new(mnemonic.as_str()).unwrap();
            let mut error = FFIError::default();
            let success = wallet_manager_add_wallet_from_mnemonic(
                wallet_manager as *mut _,
                mnemonic_c.as_ptr(),
                ptr::null(), // no passphrase
                &mut error,
            );

            if !success {
                eprintln!("Failed to add wallet from mnemonic: {:?}", error);
                std::process::exit(1);
            }

            println!("Wallet created from mnemonic");
            dash_spv_ffi_wallet_manager_free(wallet_manager);
        }

        println!("Event and progress callbacks configured, starting sync...");

        // Run client - starts sync in background and returns immediately
        let rc = dash_spv_ffi_client_run(client);
        if rc != FFIErrorCode::Success as i32 {
            eprintln!("Client run failed: {}", ffi_string_to_rust(dash_spv_ffi_get_last_error()));
            std::process::exit(1);
        }

        println!("Client running. Press Ctrl+C to shutdown...");

        // Wait for Ctrl+C signal using tokio
        tokio::runtime::Runtime::new()
            .expect("Failed to create tokio runtime")
            .block_on(tokio::signal::ctrl_c())
            .expect("Failed to listen for Ctrl+C");

        println!("Shutting down...");

        // Cleanup
        dash_spv_ffi_client_stop(client);
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(cfg);

        println!("Done.");
    }
}
