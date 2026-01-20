use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use clap::{Arg, ArgAction, Command, ValueEnum};

use dash_spv_ffi::*;

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
            Arg::new("workers")
                .long("workers")
                .value_parser(clap::value_parser!(u32))
                .help("Tokio worker threads (0=auto)"),
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
            Arg::new("no-filters")
                .long("no-filters")
                .action(ArgAction::SetTrue)
                .help("Disable compact filter synchronization"),
        )
        .get_matches();

    // Map network
    let cfg_builder = match matches.get_one::<String>("network").map(|s| s.as_str()) {
        Some("mainnet") => dash_spv_ffi_config_builder_mainnet(),
        Some("testnet") => dash_spv_ffi_config_builder_testnet(),
        Some("regtest") => dash_spv_ffi_config_builder_regtest(),
        _ => dash_spv_ffi_config_builder_mainnet(),
    };

    if cfg_builder.is_null() {
        eprintln!(
            "Failed to allocate config: {}",
            ffi_string_to_rust(dash_spv_ffi_get_last_error())
        );
        std::process::exit(1);
    }

    let disable_filter_sync = matches.get_flag("no-filters");

    unsafe {
        // Initialize tracing/logging via FFI so `tracing::info!` emits output
        let level = matches.get_one::<String>("log-level").map(String::as_str).unwrap_or("info");
        let level_c = CString::new(level).unwrap();
        let _ = dash_spv_ffi_init_logging(level_c.as_ptr(), true, std::ptr::null(), 0);

        // Build config
        let _ = dash_spv_ffi_config_builder_set_filter_load(cfg_builder, !disable_filter_sync);

        if let Some(workers) = matches.get_one::<u32>("workers") {
            let _ = dash_spv_ffi_config_builder_set_worker_threads(cfg_builder, *workers);
        }

        if let Some(height) = matches.get_one::<u32>("start-height") {
            let _ = dash_spv_ffi_config_builder_set_start_from_height(cfg_builder, *height);
        }

        if matches.get_flag("no-masternodes") {
            let _ = dash_spv_ffi_config_builder_set_masternode_sync_enabled(cfg_builder, false);
        }

        let cfg = dash_spv_ffi_config_builder_build(cfg_builder);

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

        // Create client
        let client = dash_spv_ffi_client_new(cfg);
        if client.is_null() {
            eprintln!(
                "Client create failed: {}",
                ffi_string_to_rust(dash_spv_ffi_get_last_error())
            );
            std::process::exit(1);
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
                let filters_complete = if disable_filter_sync || !prog.filter_sync_available {
                    false
                } else {
                    prog.filter_header_height >= prog.header_height
                        && prog.last_synced_filter_height >= prog.filter_header_height
                };
                if headers_done && (filters_complete || disable_filter_sync) {
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
