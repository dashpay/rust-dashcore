use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use clap::{Arg, ArgAction, Command, ValueEnum};

use dash_spv_ffi::*;
use key_wallet_ffi::wallet_manager::wallet_manager_add_wallet_from_mnemonic;
use key_wallet_ffi::{FFIError, FFINetwork};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum NetworkOpt {
    Mainnet,
    Testnet,
    Regtest,
}

static SYNC_COMPLETED: AtomicBool = AtomicBool::new(false);

fn ffi_string_to_rust(s: *const c_char) -> String {
    if s.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(s) }.to_str().unwrap_or_default().to_owned()
}

extern "C" fn on_detailed_progress(progress: *const FFIDetailedSyncProgress, _ud: *mut c_void) {
    if progress.is_null() {
        return;
    }
    unsafe {
        let p = &*progress;
        println!(
            "height {}/{} {:.2}% peers {} hps {:.1}",
            p.overview.header_height,
            p.total_height,
            p.percentage,
            p.overview.peer_count,
            p.headers_per_second
        );
    }
}

extern "C" fn on_completion(success: bool, msg: *const c_char, _ud: *mut c_void) {
    let m = ffi_string_to_rust(msg);
    if success {
        println!("Completed: {}", m);
        SYNC_COMPLETED.store(true, Ordering::SeqCst);
    } else {
        eprintln!("Failed: {}", m);
    }
}

fn main() {
    env_logger::init();

    let matches = Command::new("dash-spv-ffi")
        .about("Run SPV sync via FFI")
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
        .get_matches();

    // Map network
    let network = match matches.get_one::<String>("network").map(|s| s.as_str()) {
        Some("mainnet") => FFINetwork::Dash,
        Some("testnet") => FFINetwork::Testnet,
        Some("regtest") => FFINetwork::Regtest,
        _ => FFINetwork::Dash,
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

        // Create client
        let client = dash_spv_ffi_client_new(cfg);
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
            let mut error = FFIError::success();
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

        // Set minimal event callbacks
        let callbacks = FFIEventCallbacks {
            on_block: None,
            on_transaction: None,
            on_balance_update: None,
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_compact_filter_matched: None,
            on_wallet_transaction: None,
            user_data: ptr::null_mut(),
        };
        let _ = dash_spv_ffi_client_set_event_callbacks(client, callbacks);

        // Start client
        let rc = dash_spv_ffi_client_start(client);
        if rc != FFIErrorCode::Success as i32 {
            eprintln!("Start failed: {}", ffi_string_to_rust(dash_spv_ffi_get_last_error()));
            std::process::exit(1);
        }

        // Ensure completion flag is reset before starting sync
        SYNC_COMPLETED.store(false, Ordering::SeqCst);

        // Run sync on this thread; detailed progress will print via callback
        let rc = dash_spv_ffi_client_sync_to_tip_with_progress(
            client,
            Some(on_detailed_progress),
            Some(on_completion),
            ptr::null_mut(),
        );
        if rc != FFIErrorCode::Success as i32 {
            eprintln!("Sync failed: {}", ffi_string_to_rust(dash_spv_ffi_get_last_error()));
            std::process::exit(1);
        }

        // Wait for sync completion by polling basic progress flags; drain events meanwhile
        loop {
            let _ = dash_spv_ffi_client_drain_events(client);
            let prog_ptr = dash_spv_ffi_client_get_sync_progress(client);
            if !prog_ptr.is_null() {
                let prog = &*prog_ptr;
                let headers_done = SYNC_COMPLETED.load(Ordering::SeqCst);
                let filters_complete = prog.filter_header_height >= prog.header_height
                    && prog.last_synced_filter_height >= prog.filter_header_height;
                if headers_done && filters_complete {
                    dash_spv_ffi_sync_progress_destroy(prog_ptr);
                    break;
                }
                dash_spv_ffi_sync_progress_destroy(prog_ptr);
            }
            thread::sleep(Duration::from_millis(300));
        }

        // Cleanup
        dash_spv_ffi_client_stop(client);
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(cfg);
    }
}
