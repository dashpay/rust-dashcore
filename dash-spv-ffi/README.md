# Dash SPV FFI

This crate provides C-compatible FFI bindings for the Dash SPV client library.

## Features

- Complete FFI wrapper for DashSpvClient
- Configuration management
- Wallet operations (watch addresses, balance queries, UTXO management)
- Async operation support via callbacks
- Comprehensive error handling
- Memory-safe abstractions

## Building

```bash
cargo build --release
```

This will generate:
- Static library: `target/release/libdash_spv_ffi.a`
- Dynamic library: `target/release/libdash_spv_ffi.so` (or `.dylib` on macOS)
- C header: `include/dash_spv_ffi.h`

## Usage

See `examples/basic_usage.c` for a simple example of using the FFI bindings.

### Basic Example

```c
#include "dash_spv_ffi.h"

// Initialize logging
dash_spv_ffi_init_logging("info");

// Create configuration
FFIClientConfig* config = dash_spv_ffi_config_testnet();
dash_spv_ffi_config_set_data_dir(config, "/path/to/data");

// Create client
FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
if (client == NULL) {
    const char* error = dash_spv_ffi_get_last_error();
    // Handle error
}

// Start the client
if (dash_spv_ffi_client_start(client) != 0) {
    // Handle error
}

// ... use the client ...

// Clean up
dash_spv_ffi_client_destroy(client);
dash_spv_ffi_config_destroy(config);
```

## API Documentation

### Configuration

- `dash_spv_ffi_config_new(network)` - Create new config
- `dash_spv_ffi_config_mainnet()` - Create mainnet config
- `dash_spv_ffi_config_testnet()` - Create testnet config
- `dash_spv_ffi_config_set_data_dir(config, path)` - Set data directory
- `dash_spv_ffi_config_set_validation_mode(config, mode)` - Set validation mode
- `dash_spv_ffi_config_set_max_peers(config, max)` - Set maximum peers
- `dash_spv_ffi_config_add_peer(config, addr)` - Add a peer address
- `dash_spv_ffi_config_destroy(config)` - Free config memory

### Client Operations

- `dash_spv_ffi_client_new(config)` - Create new client
- `dash_spv_ffi_client_start(client)` - Start the client
- `dash_spv_ffi_client_stop(client)` - Stop the client
- `dash_spv_ffi_client_sync_to_tip(client, callbacks)` - Sync to chain tip
- `dash_spv_ffi_client_get_sync_progress(client)` - Get sync progress
- `dash_spv_ffi_client_get_stats(client)` - Get client statistics
- `dash_spv_ffi_client_destroy(client)` - Free client memory

### Wallet Operations

- `dash_spv_ffi_client_add_watch_item(client, item)` - Add address/script to watch
- `dash_spv_ffi_client_remove_watch_item(client, item)` - Remove watch item
- `dash_spv_ffi_client_get_address_balance(client, address)` - Get address balance
- `dash_spv_ffi_client_get_utxos(client)` - Get all UTXOs
- `dash_spv_ffi_client_get_utxos_for_address(client, address)` - Get UTXOs for address

### Watch Items

- `dash_spv_ffi_watch_item_address(address)` - Create address watch item
- `dash_spv_ffi_watch_item_script(script_hex)` - Create script watch item
- `dash_spv_ffi_watch_item_outpoint(txid, vout)` - Create outpoint watch item
- `dash_spv_ffi_watch_item_destroy(item)` - Free watch item memory

### Error Handling

- `dash_spv_ffi_get_last_error()` - Get last error message
- `dash_spv_ffi_clear_error()` - Clear last error

### Memory Management

All created objects must be explicitly destroyed:
- Config: `dash_spv_ffi_config_destroy()`
- Client: `dash_spv_ffi_client_destroy()`
- Progress: `dash_spv_ffi_sync_progress_destroy()`
- Stats: `dash_spv_ffi_spv_stats_destroy()`
- Balance: `dash_spv_ffi_balance_destroy()`
- Arrays: `dash_spv_ffi_array_destroy()`
- Strings: `dash_spv_ffi_string_destroy()`

## Thread Safety

The FFI bindings are thread-safe. The client uses internal synchronization to ensure safe concurrent access.

## License

MIT