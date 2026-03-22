# Dash SPV FFI API Documentation

This document provides a comprehensive reference for all FFI (Foreign Function Interface) functions available in the dash-spv-ffi library.

**Auto-generated**: This documentation is automatically generated from the source code. Do not edit manually.

**Total Functions**: 39

## Table of Contents

- [Client Management](#client-management)
- [Configuration](#configuration)
- [Synchronization](#synchronization)
- [Transaction Management](#transaction-management)
- [Platform Integration](#platform-integration)
- [Error Handling](#error-handling)
- [Utility Functions](#utility-functions)

## Function Reference

### Client Management

Functions: 3

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_destroy` | Destroy the client and free associated resources | client |
| `dash_spv_ffi_client_new` | Create a new SPV client and return an opaque pointer | client |
| `dash_spv_ffi_client_stop` | Stop the SPV client | client |

### Configuration

Functions: 16

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_update_config` | Update the running client's configuration | client |
| `dash_spv_ffi_config_add_peer` | Adds a peer address to the configuration  Accepts socket addresses with or... | config |
| `dash_spv_ffi_config_destroy` | Destroys an FFIClientConfig and frees its memory  # Safety - `config` must... | config |
| `dash_spv_ffi_config_get_network` | Gets the network type from the configuration  # Safety - `config` must be a... | config |
| `dash_spv_ffi_config_mainnet` | No description | config |
| `dash_spv_ffi_config_new` | No description | config |
| `dash_spv_ffi_config_set_data_dir` | Sets the data directory for storing blockchain data  # Safety - `config`... | config |
| `dash_spv_ffi_config_set_fetch_mempool_transactions` | Sets whether to fetch full mempool transaction data  # Safety - `config`... | config |
| `dash_spv_ffi_config_set_masternode_sync_enabled` | Enables or disables masternode synchronization  # Safety - `config` must be... | config |
| `dash_spv_ffi_config_set_mempool_strategy` | Sets the mempool synchronization strategy  # Safety - `config` must be a... | config |
| `dash_spv_ffi_config_set_mempool_tracking` | Enables or disables mempool tracking  # Safety - `config` must be a valid... | config |
| `dash_spv_ffi_config_set_persist_mempool` | Sets whether to persist mempool state to disk  # Safety - `config` must be a... | config |
| `dash_spv_ffi_config_set_restrict_to_configured_peers` | Restrict connections strictly to configured peers (disable DNS discovery and... | config |
| `dash_spv_ffi_config_set_start_from_height` | Sets the starting block height for synchronization  # Safety - `config` must... | config |
| `dash_spv_ffi_config_set_user_agent` | Sets the user agent string to advertise in the P2P handshake  # Safety -... | config |
| `dash_spv_ffi_config_testnet` | No description | config |

### Synchronization

Functions: 3

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_get_manager_sync_progress` | Get the current manager-based sync progress | client |
| `dash_spv_ffi_client_get_sync_progress` | Get the current sync progress snapshot | client |
| `dash_spv_ffi_sync_progress_destroy` | Destroy an `FFISyncProgress` object and all its nested pointers | types |

### Transaction Management

Functions: 1

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_broadcast_transaction` | Broadcasts a transaction to the Dash network via connected peers | client |

### Platform Integration

Functions: 2

| Function | Description | Module |
|----------|-------------|--------|
| `ffi_dash_spv_get_platform_activation_height` | Gets the platform activation height from the Core chain  # Safety  This... | platform_integration |
| `ffi_dash_spv_get_quorum_public_key` | Gets a quorum public key from the Core chain  # Safety  This function is... | platform_integration |

### Error Handling

Functions: 1

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_get_last_error` | No description | error |

### Utility Functions

Functions: 13

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_block_headers_progress_destroy` | Destroy an `FFIBlockHeadersProgress` object | types |
| `dash_spv_ffi_blocks_progress_destroy` | Destroy an `FFIBlocksProgress` object | types |
| `dash_spv_ffi_chainlock_progress_destroy` | Destroy an `FFIChainLockProgress` object | types |
| `dash_spv_ffi_client_clear_storage` | Clear all persisted SPV storage (headers, filters, metadata, sync state) | client |
| `dash_spv_ffi_client_get_wallet_manager` | Get the wallet manager from the SPV client  Returns a pointer to an... | client |
| `dash_spv_ffi_client_run` | Start the SPV client and begin syncing in the background | client |
| `dash_spv_ffi_filter_headers_progress_destroy` | Destroy an `FFIFilterHeadersProgress` object | types |
| `dash_spv_ffi_filters_progress_destroy` | Destroy an `FFIFiltersProgress` object | types |
| `dash_spv_ffi_init_logging` | Initialize logging for the SPV library | utils |
| `dash_spv_ffi_instantsend_progress_destroy` | Destroy an `FFIInstantSendProgress` object | types |
| `dash_spv_ffi_masternode_progress_destroy` | Destroy an `FFIMasternodesProgress` object | types |
| `dash_spv_ffi_version` | No description | utils |
| `dash_spv_ffi_wallet_manager_free` | Release a wallet manager obtained from `dash_spv_ffi_client_get_wallet_manager` | client |

## Detailed Function Documentation

### Client Management - Detailed

#### `dash_spv_ffi_client_destroy`

```c
dash_spv_ffi_client_destroy(client: *mut FFIDashSpvClient) -> ()
```

**Description:**
Destroy the client and free associated resources.  # Safety - `client` must be either null or a pointer obtained from `dash_spv_ffi_client_new`.

**Safety:**
- `client` must be either null or a pointer obtained from `dash_spv_ffi_client_new`.

**Module:** `client`

---

#### `dash_spv_ffi_client_new`

```c
dash_spv_ffi_client_new(config: *const FFIClientConfig, callbacks: FFIEventCallbacks,) -> *mut FFIDashSpvClient
```

**Description:**
Create a new SPV client and return an opaque pointer.  # Safety - `config` must be a valid, non-null pointer for the duration of the call. - `callbacks` is taken by value (function pointers and `user_data` pointers are copied internally). The struct itself may be dropped after the call, but all `user_data` pointer targets must remain valid until `dash_spv_ffi_client_stop` or `dash_spv_ffi_client_destroy` is called. - Callback functions and `user_data` pointees must be safe to use from background threads; different callback groups may be invoked concurrently. - The returned pointer must be freed with `dash_spv_ffi_client_destroy`.

**Safety:**
- `config` must be a valid, non-null pointer for the duration of the call. - `callbacks` is taken by value (function pointers and `user_data` pointers are copied internally). The struct itself may be dropped after the call, but all `user_data` pointer targets must remain valid until `dash_spv_ffi_client_stop` or `dash_spv_ffi_client_destroy` is called. - Callback functions and `user_data` pointees must be safe to use from background threads; different callback groups may be invoked concurrently. - The returned pointer must be freed with `dash_spv_ffi_client_destroy`.

**Module:** `client`

---

#### `dash_spv_ffi_client_stop`

```c
dash_spv_ffi_client_stop(client: *mut FFIDashSpvClient) -> i32
```

**Description:**
Stop the SPV client.  # Safety - `client` must be a valid, non-null pointer to a created client.

**Safety:**
- `client` must be a valid, non-null pointer to a created client.

**Module:** `client`

---

### Configuration - Detailed

#### `dash_spv_ffi_client_update_config`

```c
dash_spv_ffi_client_update_config(client: *mut FFIDashSpvClient, config: *const FFIClientConfig,) -> i32
```

**Description:**
Update the running client's configuration.  # Safety - `client` must be a valid pointer to an `FFIDashSpvClient`. - `config` must be a valid pointer to an `FFIClientConfig`. - The network in `config` must match the client's network; changing networks at runtime is not supported.

**Safety:**
- `client` must be a valid pointer to an `FFIDashSpvClient`. - `config` must be a valid pointer to an `FFIClientConfig`. - The network in `config` must match the client's network; changing networks at runtime is not supported.

**Module:** `client`

---

#### `dash_spv_ffi_config_add_peer`

```c
dash_spv_ffi_config_add_peer(config: *mut FFIClientConfig, addr: *const c_char,) -> i32
```

**Description:**
Adds a peer address to the configuration  Accepts socket addresses with or without port. When no port is specified, the default P2P port for the configured network is used.  Supported formats: - IP with port: `192.168.1.1:9999`, `[::1]:19999` - IP without port: `127.0.0.1`, `2001:db8::1` - Hostname with port: `node.example.com:9999` - Hostname without port: `node.example.com`  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - `addr` must be a valid null-terminated C string containing a socket address or IP-only string - The caller must ensure both pointers remain valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - `addr` must be a valid null-terminated C string containing a socket address or IP-only string - The caller must ensure both pointers remain valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_destroy`

```c
dash_spv_ffi_config_destroy(config: *mut FFIClientConfig) -> ()
```

**Description:**
Destroys an FFIClientConfig and frees its memory  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet, or null - After calling this function, the config pointer becomes invalid and must not be used - This function should only be called once per config instance

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet, or null - After calling this function, the config pointer becomes invalid and must not be used - This function should only be called once per config instance

**Module:** `config`

---

#### `dash_spv_ffi_config_get_network`

```c
dash_spv_ffi_config_get_network(config: *const FFIClientConfig,) -> FFINetwork
```

**Description:**
Gets the network type from the configuration  # Safety - `config` must be a valid pointer to an FFIClientConfig or null - If null, returns FFINetwork::Mainnet as default

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig or null - If null, returns FFINetwork::Mainnet as default

**Module:** `config`

---

#### `dash_spv_ffi_config_mainnet`

```c
dash_spv_ffi_config_mainnet() -> *mut FFIClientConfig
```

**Module:** `config`

---

#### `dash_spv_ffi_config_new`

```c
dash_spv_ffi_config_new(network: FFINetwork) -> *mut FFIClientConfig
```

**Module:** `config`

---

#### `dash_spv_ffi_config_set_data_dir`

```c
dash_spv_ffi_config_set_data_dir(config: *mut FFIClientConfig, path: *const c_char,) -> i32
```

**Description:**
Sets the data directory for storing blockchain data  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - `path` must be a valid null-terminated C string - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - `path` must be a valid null-terminated C string - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_fetch_mempool_transactions`

```c
dash_spv_ffi_config_set_fetch_mempool_transactions(config: *mut FFIClientConfig, fetch: bool,) -> i32
```

**Description:**
Sets whether to fetch full mempool transaction data  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_masternode_sync_enabled`

```c
dash_spv_ffi_config_set_masternode_sync_enabled(config: *mut FFIClientConfig, enable: bool,) -> i32
```

**Description:**
Enables or disables masternode synchronization  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_mempool_strategy`

```c
dash_spv_ffi_config_set_mempool_strategy(config: *mut FFIClientConfig, strategy: FFIMempoolStrategy,) -> i32
```

**Description:**
Sets the mempool synchronization strategy  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_mempool_tracking`

```c
dash_spv_ffi_config_set_mempool_tracking(config: *mut FFIClientConfig, enable: bool,) -> i32
```

**Description:**
Enables or disables mempool tracking  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_persist_mempool`

```c
dash_spv_ffi_config_set_persist_mempool(config: *mut FFIClientConfig, persist: bool,) -> i32
```

**Description:**
Sets whether to persist mempool state to disk  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_restrict_to_configured_peers`

```c
dash_spv_ffi_config_set_restrict_to_configured_peers(config: *mut FFIClientConfig, restrict_peers: bool,) -> i32
```

**Description:**
Restrict connections strictly to configured peers (disable DNS discovery and peer store)  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet

**Module:** `config`

---

#### `dash_spv_ffi_config_set_start_from_height`

```c
dash_spv_ffi_config_set_start_from_height(config: *mut FFIClientConfig, height: u32,) -> i32
```

**Description:**
Sets the starting block height for synchronization  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_user_agent`

```c
dash_spv_ffi_config_set_user_agent(config: *mut FFIClientConfig, user_agent: *const c_char,) -> i32
```

**Description:**
Sets the user agent string to advertise in the P2P handshake  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - `user_agent` must be a valid null-terminated C string - The caller must ensure both pointers remain valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - `user_agent` must be a valid null-terminated C string - The caller must ensure both pointers remain valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_testnet`

```c
dash_spv_ffi_config_testnet() -> *mut FFIClientConfig
```

**Module:** `config`

---

### Synchronization - Detailed

#### `dash_spv_ffi_client_get_manager_sync_progress`

```c
dash_spv_ffi_client_get_manager_sync_progress(client: *mut FFIDashSpvClient,) -> *mut FFISyncProgress
```

**Description:**
Get the current manager-based sync progress.  Returns the new parallel sync system's progress with per-manager details. Use `dash_spv_ffi_sync_progress_destroy` to free the returned struct.  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

#### `dash_spv_ffi_client_get_sync_progress`

```c
dash_spv_ffi_client_get_sync_progress(client: *mut FFIDashSpvClient,) -> *mut FFISyncProgress
```

**Description:**
Get the current sync progress snapshot.  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

#### `dash_spv_ffi_sync_progress_destroy`

```c
dash_spv_ffi_sync_progress_destroy(progress: *mut FFISyncProgress) -> ()
```

**Description:**
Destroy an `FFISyncProgress` object and all its nested pointers.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

### Transaction Management - Detailed

#### `dash_spv_ffi_client_broadcast_transaction`

```c
dash_spv_ffi_client_broadcast_transaction(client: *mut FFIDashSpvClient, tx_bytes: *const u8, length: usize,) -> i32
```

**Description:**
Broadcasts a transaction to the Dash network via connected peers.  # Safety  - `client` must be a valid, non-null pointer to an initialized FFIDashSpvClient - `tx_bytes` must be a valid, non-null pointer to the transaction data - `length` must be the length of the transaction data in bytes

**Safety:**
- `client` must be a valid, non-null pointer to an initialized FFIDashSpvClient - `tx_bytes` must be a valid, non-null pointer to the transaction data - `length` must be the length of the transaction data in bytes

**Module:** `client`

---

### Platform Integration - Detailed

#### `ffi_dash_spv_get_platform_activation_height`

```c
ffi_dash_spv_get_platform_activation_height(client: *mut FFIDashSpvClient, out_height: *mut u32,) -> FFIResult
```

**Description:**
Gets the platform activation height from the Core chain  # Safety  This function is unsafe because: - The caller must ensure all pointers are valid - out_height must point to a valid u32

**Safety:**
This function is unsafe because: - The caller must ensure all pointers are valid - out_height must point to a valid u32

**Module:** `platform_integration`

---

#### `ffi_dash_spv_get_quorum_public_key`

```c
ffi_dash_spv_get_quorum_public_key(client: *mut FFIDashSpvClient, quorum_type: u32, quorum_hash: *const u8, core_chain_locked_height: u32, out_pubkey: *mut u8, out_pubkey_size: usize,) -> FFIResult
```

**Description:**
Gets a quorum public key from the Core chain  # Safety  This function is unsafe because: - The caller must ensure all pointers are valid - quorum_hash must point to a 32-byte array - out_pubkey must point to a buffer of at least out_pubkey_size bytes - out_pubkey_size must be at least 48 bytes

**Safety:**
This function is unsafe because: - The caller must ensure all pointers are valid - quorum_hash must point to a 32-byte array - out_pubkey must point to a buffer of at least out_pubkey_size bytes - out_pubkey_size must be at least 48 bytes

**Module:** `platform_integration`

---

### Error Handling - Detailed

#### `dash_spv_ffi_get_last_error`

```c
dash_spv_ffi_get_last_error() -> *const c_char
```

**Module:** `error`

---

### Utility Functions - Detailed

#### `dash_spv_ffi_block_headers_progress_destroy`

```c
dash_spv_ffi_block_headers_progress_destroy(progress: *mut FFIBlockHeadersProgress,) -> ()
```

**Description:**
Destroy an `FFIBlockHeadersProgress` object.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

#### `dash_spv_ffi_blocks_progress_destroy`

```c
dash_spv_ffi_blocks_progress_destroy(progress: *mut FFIBlocksProgress) -> ()
```

**Description:**
Destroy an `FFIBlocksProgress` object.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

#### `dash_spv_ffi_chainlock_progress_destroy`

```c
dash_spv_ffi_chainlock_progress_destroy(progress: *mut FFIChainLockProgress,) -> ()
```

**Description:**
Destroy an `FFIChainLockProgress` object.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

#### `dash_spv_ffi_client_clear_storage`

```c
dash_spv_ffi_client_clear_storage(client: *mut FFIDashSpvClient) -> i32
```

**Description:**
Clear all persisted SPV storage (headers, filters, metadata, sync state).  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

#### `dash_spv_ffi_client_get_wallet_manager`

```c
dash_spv_ffi_client_get_wallet_manager(client: *mut FFIDashSpvClient,) -> *mut FFIWalletManager
```

**Description:**
Get the wallet manager from the SPV client  Returns a pointer to an `FFIWalletManager` wrapper that clones the underlying `Arc<RwLock<WalletManager>>`. This allows direct interaction with the wallet manager without going back through the client for each call.  # Safety  The caller must ensure that: - The client pointer is valid - The returned pointer is released exactly once using `dash_spv_ffi_wallet_manager_free`  # Returns  A pointer to the wallet manager wrapper, or NULL if the client is not initialized.

**Safety:**
The caller must ensure that: - The client pointer is valid - The returned pointer is released exactly once using `dash_spv_ffi_wallet_manager_free`

**Module:** `client`

---

#### `dash_spv_ffi_client_run`

```c
dash_spv_ffi_client_run(client: *mut FFIDashSpvClient) -> i32
```

**Description:**
Start the SPV client and begin syncing in the background.  Uses the event callbacks provided at client creation time. Returns immediately after spawning the sync task.  # Safety - `client` must be a valid, non-null pointer to a created client.  # Returns 0 on success, error code on failure.

**Safety:**
- `client` must be a valid, non-null pointer to a created client.

**Module:** `client`

---

#### `dash_spv_ffi_filter_headers_progress_destroy`

```c
dash_spv_ffi_filter_headers_progress_destroy(progress: *mut FFIFilterHeadersProgress,) -> ()
```

**Description:**
Destroy an `FFIFilterHeadersProgress` object.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

#### `dash_spv_ffi_filters_progress_destroy`

```c
dash_spv_ffi_filters_progress_destroy(progress: *mut FFIFiltersProgress) -> ()
```

**Description:**
Destroy an `FFIFiltersProgress` object.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

#### `dash_spv_ffi_init_logging`

```c
dash_spv_ffi_init_logging(level: *const c_char, enable_console: bool, log_dir: *const c_char, max_files: usize,) -> i32
```

**Description:**
Initialize logging for the SPV library.  # Arguments - `level`: Log level string (null uses RUST_LOG env var or defaults to INFO). Valid values: "error", "warn", "info", "debug", "trace" - `enable_console`: Whether to output logs to console (stderr) - `log_dir`: Directory for log files (null to disable file logging) - `max_files`: Maximum archived log files to retain (ignored if log_dir is null)  # Safety - `level` and `log_dir` may be null or point to valid, NUL-terminated C strings.

**Safety:**
- `level` and `log_dir` may be null or point to valid, NUL-terminated C strings.

**Module:** `utils`

---

#### `dash_spv_ffi_instantsend_progress_destroy`

```c
dash_spv_ffi_instantsend_progress_destroy(progress: *mut FFIInstantSendProgress,) -> ()
```

**Description:**
Destroy an `FFIInstantSendProgress` object.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

#### `dash_spv_ffi_masternode_progress_destroy`

```c
dash_spv_ffi_masternode_progress_destroy(progress: *mut FFIMasternodesProgress,) -> ()
```

**Description:**
Destroy an `FFIMasternodesProgress` object.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `types`

---

#### `dash_spv_ffi_version`

```c
dash_spv_ffi_version() -> *const c_char
```

**Module:** `utils`

---

#### `dash_spv_ffi_wallet_manager_free`

```c
dash_spv_ffi_wallet_manager_free(manager: *mut FFIWalletManager) -> ()
```

**Description:**
Release a wallet manager obtained from `dash_spv_ffi_client_get_wallet_manager`.  This simply forwards to `wallet_manager_free` in key-wallet-ffi so that lifetime management is consistent between direct key-wallet usage and the SPV client pathway.  # Safety - `manager` must either be null or a pointer previously returned by `dash_spv_ffi_client_get_wallet_manager`.

**Safety:**
- `manager` must either be null or a pointer previously returned by `dash_spv_ffi_client_get_wallet_manager`.

**Module:** `client`

---

## Type Definitions

### Core Types

- `FFIDashSpvClient` - SPV client handle
- `FFIClientConfig` - Client configuration
- `FFISyncProgress` - Synchronization progress
- `FFIDetailedSyncProgress` - Detailed sync progress
- `FFITransaction` - Transaction information
- `FFIUnconfirmedTransaction` - Unconfirmed transaction
- `FFIEventCallbacks` - Event callback structure
- `CoreSDKHandle` - Platform SDK integration handle

### Enumerations

- `FFINetwork` - Network type (Mainnet, Testnet, Regtest, Devnet)
- `FFIValidationMode` - Validation mode (None, Basic, Full)
- `FFIMempoolStrategy` - Mempool strategy (FetchAll, BloomFilter, Selective)

## Memory Management

### Important Rules

1. **Ownership Transfer**: Functions returning pointers transfer ownership to the caller
2. **Cleanup Required**: All returned pointers must be freed using the appropriate `_destroy` function
3. **Thread Safety**: The SPV client is thread-safe
4. **Error Handling**: Check return codes and use `dash_spv_ffi_get_last_error()` for details
5. **Shared Ownership**: `dash_spv_ffi_client_get_wallet_manager()` returns `FFIWalletManager*` that must be released with `dash_spv_ffi_wallet_manager_free()`

## Usage Examples

### Basic SPV Client Usage

```c
// Create configuration
FFIClientConfig* config = dash_spv_ffi_config_testnet();

// Build event callbacks (zero-init for no-op defaults)
FFIEventCallbacks callbacks = { 0 };

// Create client with callbacks
FFIDashSpvClient* client = dash_spv_ffi_client_new(config, callbacks);

// Start syncing (uses callbacks provided at creation)
int32_t result = dash_spv_ffi_client_run(client);
if (result != 0) {
    const char* error = dash_spv_ffi_get_last_error();
    // Handle error
}

// Get wallet manager (shares ownership with the client)
FFIWalletManager* wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);

// Clean up
dash_spv_ffi_client_destroy(client);
dash_spv_ffi_config_destroy(config);
```

### Event Callbacks

```c
void on_headers(uint32_t tip_height, void* user_data) {
    printf("Headers stored up to height %u\n", tip_height);
}

void on_tx(const char* wallet_id, uint32_t account_index,
           const uint8_t (*txid)[32], int64_t amount,
           const char* addresses, void* user_data) {
    printf("Transaction: %lld duffs\n", (long long)amount);
}

// Build callbacks struct and pass to client_new()
FFIEventCallbacks callbacks = { 0 };
callbacks.sync.on_block_headers_stored = on_headers;
callbacks.wallet.on_transaction_received = on_tx;
FFIDashSpvClient* client = dash_spv_ffi_client_new(config, callbacks);

// Start syncing (uses callbacks provided at creation)
dash_spv_ffi_client_run(client);
```
