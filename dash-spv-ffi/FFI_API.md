# Dash SPV FFI API Documentation

This document provides a comprehensive reference for all FFI (Foreign Function Interface) functions available in the dash-spv-ffi library.

**Auto-generated**: This documentation is automatically generated from the source code. Do not edit manually.

**Total Functions**: 64

## Table of Contents

- [Client Management](#client-management)
- [Configuration](#configuration)
- [Synchronization](#synchronization)
- [Address Monitoring](#address-monitoring)
- [Transaction Management](#transaction-management)
- [Mempool Operations](#mempool-operations)
- [Platform Integration](#platform-integration)
- [Event Callbacks](#event-callbacks)
- [Error Handling](#error-handling)
- [Utility Functions](#utility-functions)

## Function Reference

### Client Management

Functions: 4

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_destroy` | Destroy the client and free associated resources | client |
| `dash_spv_ffi_client_new` | Create a new SPV client and return an opaque pointer | client |
| `dash_spv_ffi_client_start` | Start the SPV client | client |
| `dash_spv_ffi_client_stop` | Stop the SPV client | client |

### Configuration

Functions: 26

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_update_config` | Update the running client's configuration | client |
| `dash_spv_ffi_config_add_peer` | Adds a peer address to the configuration  Accepts either a full socket addres... | config |
| `dash_spv_ffi_config_destroy` | Destroys an FFIClientConfig and frees its memory  # Safety - `config` must be... | config |
| `dash_spv_ffi_config_get_data_dir` | Gets the data directory path from the configuration  # Safety - `config` must... | config |
| `dash_spv_ffi_config_get_mempool_strategy` | Gets the mempool synchronization strategy  # Safety - `config` must be a vali... | config |
| `dash_spv_ffi_config_get_mempool_tracking` | Gets whether mempool tracking is enabled  # Safety - `config` must be a valid... | config |
| `dash_spv_ffi_config_get_network` | Gets the network type from the configuration  # Safety - `config` must be a v... | config |
| `dash_spv_ffi_config_mainnet` | No description | config |
| `dash_spv_ffi_config_new` | No description | config |
| `dash_spv_ffi_config_set_data_dir` | Sets the data directory for storing blockchain data  # Safety - `config` must... | config |
| `dash_spv_ffi_config_set_fetch_mempool_transactions` | Sets whether to fetch full mempool transaction data  # Safety - `config` must... | config |
| `dash_spv_ffi_config_set_filter_load` | Sets whether to load bloom filters  # Safety - `config` must be a valid point... | config |
| `dash_spv_ffi_config_set_masternode_sync_enabled` | Enables or disables masternode synchronization  # Safety - `config` must be a... | config |
| `dash_spv_ffi_config_set_max_mempool_transactions` | Sets the maximum number of mempool transactions to track  # Safety - `config`... | config |
| `dash_spv_ffi_config_set_max_peers` | Sets the maximum number of peers to connect to  # Safety - `config` must be a... | config |
| `dash_spv_ffi_config_set_mempool_strategy` | Sets the mempool synchronization strategy  # Safety - `config` must be a vali... | config |
| `dash_spv_ffi_config_set_mempool_timeout` | Sets the mempool transaction timeout in seconds  # Safety - `config` must be ... | config |
| `dash_spv_ffi_config_set_mempool_tracking` | Enables or disables mempool tracking  # Safety - `config` must be a valid poi... | config |
| `dash_spv_ffi_config_set_persist_mempool` | Sets whether to persist mempool state to disk  # Safety - `config` must be a ... | config |
| `dash_spv_ffi_config_set_relay_transactions` | Sets whether to relay transactions (currently a no-op)  # Safety - `config` m... | config |
| `dash_spv_ffi_config_set_restrict_to_configured_peers` | Restrict connections strictly to configured peers (disable DNS discovery and ... | config |
| `dash_spv_ffi_config_set_start_from_height` | Sets the starting block height for synchronization  # Safety - `config` must ... | config |
| `dash_spv_ffi_config_set_user_agent` | Sets the user agent string to advertise in the P2P handshake  # Safety - `con... | config |
| `dash_spv_ffi_config_set_validation_mode` | Sets the validation mode for the SPV client  # Safety - `config` must be a va... | config |
| `dash_spv_ffi_config_set_wallet_creation_time` | Sets the wallet creation timestamp for synchronization optimization  # Safety... | config |
| `dash_spv_ffi_config_testnet` | No description | config |

### Synchronization

Functions: 7

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_cancel_sync` | Cancels the sync operation | client |
| `dash_spv_ffi_client_get_sync_progress` | Get the current sync progress snapshot | client |
| `dash_spv_ffi_client_is_filter_sync_available` | Check if compact filter sync is currently available | client |
| `dash_spv_ffi_client_sync_to_tip` | Sync the SPV client to the chain tip | client |
| `dash_spv_ffi_client_sync_to_tip_with_progress` | Sync the SPV client to the chain tip with detailed progress updates | client |
| `dash_spv_ffi_client_test_sync` | Performs a test synchronization of the SPV client  # Parameters - `client`: P... | client |
| `dash_spv_ffi_sync_progress_destroy` | Destroy a `FFISyncProgress` object returned by this crate | client |

### Address Monitoring

Functions: 1

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_unconfirmed_transaction_destroy_addresses` | Destroys the addresses array allocated for an FFIUnconfirmedTransaction  # Sa... | types |

### Transaction Management

Functions: 3

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_broadcast_transaction` | No description | broadcast |
| `dash_spv_ffi_unconfirmed_transaction_destroy` | Destroys an FFIUnconfirmedTransaction and all its associated resources  # Saf... | types |
| `dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx` | Destroys the raw transaction bytes allocated for an FFIUnconfirmedTransaction... | types |

### Mempool Operations

Functions: 1

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_enable_mempool_tracking` | Enable mempool tracking with a given strategy | client |

### Platform Integration

Functions: 4

| Function | Description | Module |
|----------|-------------|--------|
| `ffi_dash_spv_get_core_handle` | Creates a CoreSDKHandle from an FFIDashSpvClient  # Safety  This function is ... | platform_integration |
| `ffi_dash_spv_get_platform_activation_height` | Gets the platform activation height from the Core chain  # Safety  This funct... | platform_integration |
| `ffi_dash_spv_get_quorum_public_key` | Gets a quorum public key from the Core chain  # Safety  This function is unsa... | platform_integration |
| `ffi_dash_spv_release_core_handle` | Releases a CoreSDKHandle  # Safety  This function is unsafe because: - The ca... | platform_integration |

### Event Callbacks

Functions: 1

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_client_set_event_callbacks` | Set event callbacks for the client | client |

### Error Handling

Functions: 2

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_clear_error` | No description | error |
| `dash_spv_ffi_get_last_error` | No description | error |

### Utility Functions

Functions: 15

| Function | Description | Module |
|----------|-------------|--------|
| `dash_spv_ffi_array_destroy` | No description | types |
| `dash_spv_ffi_checkpoint_before_height` | Get the last checkpoint at or before a given height | checkpoints |
| `dash_spv_ffi_checkpoint_before_timestamp` | Get the last checkpoint at or before a given UNIX timestamp (seconds) | checkpoints |
| `dash_spv_ffi_checkpoint_latest` | Get the latest checkpoint for the given network | checkpoints |
| `dash_spv_ffi_checkpoints_between_heights` | Get all checkpoints between two heights (inclusive) | checkpoints |
| `dash_spv_ffi_client_get_stats` | Get current runtime statistics for the SPV client | client |
| `dash_spv_ffi_client_get_wallet_manager` | Get the wallet manager from the SPV client  Returns an opaque pointer to FFIW... | client |
| `dash_spv_ffi_client_record_send` | Record that we attempted to send a transaction by its txid | client |
| `dash_spv_ffi_client_rescan_blockchain` | Request a rescan of the blockchain from a given height (not yet implemented) | client |
| `dash_spv_ffi_enable_test_mode` | No description | utils |
| `dash_spv_ffi_init_logging` | Initialize logging for the SPV library | utils |
| `dash_spv_ffi_spv_stats_destroy` | Destroy an `FFISpvStats` object returned by this crate | client |
| `dash_spv_ffi_string_array_destroy` | Destroy an array of FFIString pointers (Vec<*mut FFIString>) and their contents | types |
| `dash_spv_ffi_string_destroy` | No description | types |
| `dash_spv_ffi_version` | No description | utils |

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
dash_spv_ffi_client_new(config: *const FFIClientConfig,) -> *mut FFIDashSpvClient
```

**Description:**
Create a new SPV client and return an opaque pointer.  # Safety - `config` must be a valid, non-null pointer for the duration of the call. - The returned pointer must be freed with `dash_spv_ffi_client_destroy`.

**Safety:**
- `config` must be a valid, non-null pointer for the duration of the call. - The returned pointer must be freed with `dash_spv_ffi_client_destroy`.

**Module:** `client`

---

#### `dash_spv_ffi_client_start`

```c
dash_spv_ffi_client_start(client: *mut FFIDashSpvClient) -> i32
```

**Description:**
Start the SPV client.  # Safety - `client` must be a valid, non-null pointer to a created client.

**Safety:**
- `client` must be a valid, non-null pointer to a created client.

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
Adds a peer address to the configuration  Accepts either a full socket address (e.g., "192.168.1.1:9999" or "[::1]:19999") or an IP-only string (e.g., "127.0.0.1" or "2001:db8::1"). When an IP-only string is given, the default P2P port for the configured network is used.  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - `addr` must be a valid null-terminated C string containing a socket address or IP-only string - The caller must ensure both pointers remain valid for the duration of this call

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

#### `dash_spv_ffi_config_get_data_dir`

```c
dash_spv_ffi_config_get_data_dir(config: *const FFIClientConfig,) -> FFIString
```

**Description:**
Gets the data directory path from the configuration  # Safety - `config` must be a valid pointer to an FFIClientConfig or null - If null or no data directory is set, returns an FFIString with null pointer - The returned FFIString must be freed by the caller using `dash_spv_ffi_string_destroy`

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig or null - If null or no data directory is set, returns an FFIString with null pointer - The returned FFIString must be freed by the caller using `dash_spv_ffi_string_destroy`

**Module:** `config`

---

#### `dash_spv_ffi_config_get_mempool_strategy`

```c
dash_spv_ffi_config_get_mempool_strategy(config: *const FFIClientConfig,) -> FFIMempoolStrategy
```

**Description:**
Gets the mempool synchronization strategy  # Safety - `config` must be a valid pointer to an FFIClientConfig or null - If null, returns FFIMempoolStrategy::Selective as default

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig or null - If null, returns FFIMempoolStrategy::Selective as default

**Module:** `config`

---

#### `dash_spv_ffi_config_get_mempool_tracking`

```c
dash_spv_ffi_config_get_mempool_tracking(config: *const FFIClientConfig,) -> bool
```

**Description:**
Gets whether mempool tracking is enabled  # Safety - `config` must be a valid pointer to an FFIClientConfig or null - If null, returns false as default

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig or null - If null, returns false as default

**Module:** `config`

---

#### `dash_spv_ffi_config_get_network`

```c
dash_spv_ffi_config_get_network(config: *const FFIClientConfig,) -> FFINetwork
```

**Description:**
Gets the network type from the configuration  # Safety - `config` must be a valid pointer to an FFIClientConfig or null - If null, returns FFINetwork::Dash as default

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig or null - If null, returns FFINetwork::Dash as default

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

#### `dash_spv_ffi_config_set_filter_load`

```c
dash_spv_ffi_config_set_filter_load(config: *mut FFIClientConfig, load_filters: bool,) -> i32
```

**Description:**
Sets whether to load bloom filters  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

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

#### `dash_spv_ffi_config_set_max_mempool_transactions`

```c
dash_spv_ffi_config_set_max_mempool_transactions(config: *mut FFIClientConfig, max_transactions: u32,) -> i32
```

**Description:**
Sets the maximum number of mempool transactions to track  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_max_peers`

```c
dash_spv_ffi_config_set_max_peers(config: *mut FFIClientConfig, max_peers: u32,) -> i32
```

**Description:**
Sets the maximum number of peers to connect to  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

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

#### `dash_spv_ffi_config_set_mempool_timeout`

```c
dash_spv_ffi_config_set_mempool_timeout(config: *mut FFIClientConfig, timeout_secs: u64,) -> i32
```

**Description:**
Sets the mempool transaction timeout in seconds  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

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

#### `dash_spv_ffi_config_set_relay_transactions`

```c
dash_spv_ffi_config_set_relay_transactions(config: *mut FFIClientConfig, _relay: bool,) -> i32
```

**Description:**
Sets whether to relay transactions (currently a no-op)  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

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

#### `dash_spv_ffi_config_set_validation_mode`

```c
dash_spv_ffi_config_set_validation_mode(config: *mut FFIClientConfig, mode: FFIValidationMode,) -> i32
```

**Description:**
Sets the validation mode for the SPV client  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_set_wallet_creation_time`

```c
dash_spv_ffi_config_set_wallet_creation_time(config: *mut FFIClientConfig, timestamp: u32,) -> i32
```

**Description:**
Sets the wallet creation timestamp for synchronization optimization  # Safety - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Safety:**
- `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet - The caller must ensure the config pointer remains valid for the duration of this call

**Module:** `config`

---

#### `dash_spv_ffi_config_testnet`

```c
dash_spv_ffi_config_testnet() -> *mut FFIClientConfig
```

**Module:** `config`

---

### Synchronization - Detailed

#### `dash_spv_ffi_client_cancel_sync`

```c
dash_spv_ffi_client_cancel_sync(client: *mut FFIDashSpvClient) -> i32
```

**Description:**
Cancels the sync operation.  **Note**: This function currently only stops the SPV client and clears sync callbacks, but does not fully abort the ongoing sync process. The sync operation may continue running in the background until it completes naturally. Full sync cancellation with proper task abortion is not yet implemented.  # Safety The client pointer must be valid and non-null.  # Returns Returns 0 on success, or an error code on failure.

**Safety:**
The client pointer must be valid and non-null.

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

#### `dash_spv_ffi_client_is_filter_sync_available`

```c
dash_spv_ffi_client_is_filter_sync_available(client: *mut FFIDashSpvClient,) -> bool
```

**Description:**
Check if compact filter sync is currently available.  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

#### `dash_spv_ffi_client_sync_to_tip`

```c
dash_spv_ffi_client_sync_to_tip(client: *mut FFIDashSpvClient, completion_callback: Option<extern "C" fn(bool, *const c_char, *mut c_void)>, user_data: *mut c_void,) -> i32
```

**Description:**
Sync the SPV client to the chain tip.  # Safety  This function is unsafe because: - `client` must be a valid pointer to an initialized `FFIDashSpvClient` - `user_data` must satisfy thread safety requirements: - If non-null, it must point to data that is safe to access from multiple threads - The caller must ensure proper synchronization if the data is mutable - The data must remain valid for the entire duration of the sync operation - `completion_callback` must be thread-safe and can be called from any thread  # Parameters  - `client`: Pointer to the SPV client - `completion_callback`: Optional callback invoked on completion - `user_data`: Optional user data pointer passed to callbacks  # Returns  0 on success, error code on failure

**Safety:**
This function is unsafe because: - `client` must be a valid pointer to an initialized `FFIDashSpvClient` - `user_data` must satisfy thread safety requirements: - If non-null, it must point to data that is safe to access from multiple threads - The caller must ensure proper synchronization if the data is mutable - The data must remain valid for the entire duration of the sync operation - `completion_callback` must be thread-safe and can be called from any thread

**Module:** `client`

---

#### `dash_spv_ffi_client_sync_to_tip_with_progress`

```c
dash_spv_ffi_client_sync_to_tip_with_progress(client: *mut FFIDashSpvClient, progress_callback: Option<extern "C" fn(*const FFIDetailedSyncProgress, *mut c_void)>, completion_callback: Option<extern "C" fn(bool, *const c_char, *mut c_void)>, user_data: *mut c_void,) -> i32
```

**Description:**
Sync the SPV client to the chain tip with detailed progress updates.  # Safety  This function is unsafe because: - `client` must be a valid pointer to an initialized `FFIDashSpvClient` - `user_data` must satisfy thread safety requirements: - If non-null, it must point to data that is safe to access from multiple threads - The caller must ensure proper synchronization if the data is mutable - The data must remain valid for the entire duration of the sync operation - Both `progress_callback` and `completion_callback` must be thread-safe and can be called from any thread  # Parameters  - `client`: Pointer to the SPV client - `progress_callback`: Optional callback invoked periodically with sync progress - `completion_callback`: Optional callback invoked on completion - `user_data`: Optional user data pointer passed to all callbacks  # Returns  0 on success, error code on failure

**Safety:**
This function is unsafe because: - `client` must be a valid pointer to an initialized `FFIDashSpvClient` - `user_data` must satisfy thread safety requirements: - If non-null, it must point to data that is safe to access from multiple threads - The caller must ensure proper synchronization if the data is mutable - The data must remain valid for the entire duration of the sync operation - Both `progress_callback` and `completion_callback` must be thread-safe and can be called from any thread

**Module:** `client`

---

#### `dash_spv_ffi_client_test_sync`

```c
dash_spv_ffi_client_test_sync(client: *mut FFIDashSpvClient) -> i32
```

**Description:**
Performs a test synchronization of the SPV client  # Parameters - `client`: Pointer to an FFIDashSpvClient instance  # Returns - `0` on success - Negative error code on failure  # Safety This function is unsafe because it dereferences a raw pointer. The caller must ensure that the client pointer is valid.

**Safety:**
This function is unsafe because it dereferences a raw pointer. The caller must ensure that the client pointer is valid.

**Module:** `client`

---

#### `dash_spv_ffi_sync_progress_destroy`

```c
dash_spv_ffi_sync_progress_destroy(progress: *mut FFISyncProgress) -> ()
```

**Description:**
Destroy a `FFISyncProgress` object returned by this crate.  # Safety - `progress` must be a pointer returned from this crate, or null.

**Safety:**
- `progress` must be a pointer returned from this crate, or null.

**Module:** `client`

---

### Address Monitoring - Detailed

#### `dash_spv_ffi_unconfirmed_transaction_destroy_addresses`

```c
dash_spv_ffi_unconfirmed_transaction_destroy_addresses(addresses: *mut FFIString, addresses_len: usize,) -> ()
```

**Description:**
Destroys the addresses array allocated for an FFIUnconfirmedTransaction  # Safety  - `addresses` must be a valid pointer to an array of FFIString objects - `addresses_len` must be the correct length of the array - Each FFIString in the array must be destroyed separately using `dash_spv_ffi_string_destroy` - The pointer must not be used after this function is called - This function should only be called once per allocation

**Safety:**
- `addresses` must be a valid pointer to an array of FFIString objects - `addresses_len` must be the correct length of the array - Each FFIString in the array must be destroyed separately using `dash_spv_ffi_string_destroy` - The pointer must not be used after this function is called - This function should only be called once per allocation

**Module:** `types`

---

### Transaction Management - Detailed

#### `dash_spv_ffi_client_broadcast_transaction`

```c
dash_spv_ffi_client_broadcast_transaction(client: *mut FFIDashSpvClient, tx_hex: *const c_char,) -> i32
```

**Module:** `broadcast`

---

#### `dash_spv_ffi_unconfirmed_transaction_destroy`

```c
dash_spv_ffi_unconfirmed_transaction_destroy(tx: *mut FFIUnconfirmedTransaction,) -> ()
```

**Description:**
Destroys an FFIUnconfirmedTransaction and all its associated resources  # Safety  - `tx` must be a valid pointer to an FFIUnconfirmedTransaction - All resources (raw_tx, addresses array, and individual FFIStrings) will be freed - The pointer must not be used after this function is called - This function should only be called once per FFIUnconfirmedTransaction

**Safety:**
- `tx` must be a valid pointer to an FFIUnconfirmedTransaction - All resources (raw_tx, addresses array, and individual FFIStrings) will be freed - The pointer must not be used after this function is called - This function should only be called once per FFIUnconfirmedTransaction

**Module:** `types`

---

#### `dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx`

```c
dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx(raw_tx: *mut u8, raw_tx_len: usize,) -> ()
```

**Description:**
Destroys the raw transaction bytes allocated for an FFIUnconfirmedTransaction  # Safety  - `raw_tx` must be a valid pointer to memory allocated by the caller - `raw_tx_len` must be the correct length of the allocated memory - The pointer must not be used after this function is called - This function should only be called once per allocation

**Safety:**
- `raw_tx` must be a valid pointer to memory allocated by the caller - `raw_tx_len` must be the correct length of the allocated memory - The pointer must not be used after this function is called - This function should only be called once per allocation

**Module:** `types`

---

### Mempool Operations - Detailed

#### `dash_spv_ffi_client_enable_mempool_tracking`

```c
dash_spv_ffi_client_enable_mempool_tracking(client: *mut FFIDashSpvClient, strategy: FFIMempoolStrategy,) -> i32
```

**Description:**
Enable mempool tracking with a given strategy.  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

### Platform Integration - Detailed

#### `ffi_dash_spv_get_core_handle`

```c
ffi_dash_spv_get_core_handle(client: *mut FFIDashSpvClient,) -> *mut CoreSDKHandle
```

**Description:**
Creates a CoreSDKHandle from an FFIDashSpvClient  # Safety  This function is unsafe because: - The caller must ensure the client pointer is valid - The returned handle must be properly released with ffi_dash_spv_release_core_handle

**Safety:**
This function is unsafe because: - The caller must ensure the client pointer is valid - The returned handle must be properly released with ffi_dash_spv_release_core_handle

**Module:** `platform_integration`

---

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

#### `ffi_dash_spv_release_core_handle`

```c
ffi_dash_spv_release_core_handle(handle: *mut CoreSDKHandle) -> ()
```

**Description:**
Releases a CoreSDKHandle  # Safety  This function is unsafe because: - The caller must ensure the handle pointer is valid - The handle must not be used after this call

**Safety:**
This function is unsafe because: - The caller must ensure the handle pointer is valid - The handle must not be used after this call

**Module:** `platform_integration`

---

### Event Callbacks - Detailed

#### `dash_spv_ffi_client_set_event_callbacks`

```c
dash_spv_ffi_client_set_event_callbacks(client: *mut FFIDashSpvClient, callbacks: FFIEventCallbacks,) -> i32
```

**Description:**
Set event callbacks for the client.  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

### Error Handling - Detailed

#### `dash_spv_ffi_clear_error`

```c
dash_spv_ffi_clear_error() -> ()
```

**Module:** `error`

---

#### `dash_spv_ffi_get_last_error`

```c
dash_spv_ffi_get_last_error() -> *const c_char
```

**Module:** `error`

---

### Utility Functions - Detailed

#### `dash_spv_ffi_array_destroy`

```c
dash_spv_ffi_array_destroy(arr: *mut FFIArray) -> ()
```

**Module:** `types`

---

#### `dash_spv_ffi_checkpoint_before_height`

```c
dash_spv_ffi_checkpoint_before_height(network: FFINetwork, height: u32, out_height: *mut u32, out_hash: *mut u8, // expects at least 32 bytes) -> i32
```

**Description:**
Get the last checkpoint at or before a given height.  # Safety - `out_height` must be a valid pointer to a `u32`. - `out_hash` must point to at least 32 writable bytes.

**Safety:**
- `out_height` must be a valid pointer to a `u32`. - `out_hash` must point to at least 32 writable bytes.

**Module:** `checkpoints`

---

#### `dash_spv_ffi_checkpoint_before_timestamp`

```c
dash_spv_ffi_checkpoint_before_timestamp(network: FFINetwork, timestamp: u32, out_height: *mut u32, out_hash: *mut u8, // expects at least 32 bytes) -> i32
```

**Description:**
Get the last checkpoint at or before a given UNIX timestamp (seconds).  # Safety - `out_height` must be a valid pointer to a `u32`. - `out_hash` must point to at least 32 writable bytes.

**Safety:**
- `out_height` must be a valid pointer to a `u32`. - `out_hash` must point to at least 32 writable bytes.

**Module:** `checkpoints`

---

#### `dash_spv_ffi_checkpoint_latest`

```c
dash_spv_ffi_checkpoint_latest(network: FFINetwork, out_height: *mut u32, out_hash: *mut u8, // expects at least 32 bytes) -> i32
```

**Description:**
Get the latest checkpoint for the given network.  # Safety - `out_height` must be a valid pointer to a `u32`. - `out_hash` must point to at least 32 writable bytes.

**Safety:**
- `out_height` must be a valid pointer to a `u32`. - `out_hash` must point to at least 32 writable bytes.

**Module:** `checkpoints`

---

#### `dash_spv_ffi_checkpoints_between_heights`

```c
dash_spv_ffi_checkpoints_between_heights(network: FFINetwork, start_height: u32, end_height: u32,) -> FFIArray
```

**Description:**
Get all checkpoints between two heights (inclusive).  Returns an `FFIArray` of `FFICheckpoint` items. The caller owns the memory and must free the array buffer using `dash_spv_ffi_array_destroy` when done.

**Module:** `checkpoints`

---

#### `dash_spv_ffi_client_get_stats`

```c
dash_spv_ffi_client_get_stats(client: *mut FFIDashSpvClient,) -> *mut FFISpvStats
```

**Description:**
Get current runtime statistics for the SPV client.  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

#### `dash_spv_ffi_client_get_wallet_manager`

```c
dash_spv_ffi_client_get_wallet_manager(client: *mut FFIDashSpvClient,) -> *mut c_void
```

**Description:**
Get the wallet manager from the SPV client  Returns an opaque pointer to FFIWalletManager that contains a cloned Arc reference to the wallet manager. This allows direct interaction with the wallet manager without going through the client.  # Safety  The caller must ensure that: - The client pointer is valid - The returned pointer is freed using `wallet_manager_free` from key-wallet-ffi  # Returns  An opaque pointer (void*) to the wallet manager, or NULL if the client is not initialized. Swift should treat this as an OpaquePointer. Get a handle to the wallet manager owned by this client.  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
The caller must ensure that: - The client pointer is valid - The returned pointer is freed using `wallet_manager_free` from key-wallet-ffi

**Module:** `client`

---

#### `dash_spv_ffi_client_record_send`

```c
dash_spv_ffi_client_record_send(client: *mut FFIDashSpvClient, txid: *const c_char,) -> i32
```

**Description:**
Record that we attempted to send a transaction by its txid.  # Safety - `client` and `txid` must be valid, non-null pointers.

**Safety:**
- `client` and `txid` must be valid, non-null pointers.

**Module:** `client`

---

#### `dash_spv_ffi_client_rescan_blockchain`

```c
dash_spv_ffi_client_rescan_blockchain(client: *mut FFIDashSpvClient, _from_height: u32,) -> i32
```

**Description:**
Request a rescan of the blockchain from a given height (not yet implemented).  # Safety - `client` must be a valid, non-null pointer.

**Safety:**
- `client` must be a valid, non-null pointer.

**Module:** `client`

---

#### `dash_spv_ffi_enable_test_mode`

```c
dash_spv_ffi_enable_test_mode() -> ()
```

**Module:** `utils`

---

#### `dash_spv_ffi_init_logging`

```c
dash_spv_ffi_init_logging(level: *const c_char) -> i32
```

**Description:**
Initialize logging for the SPV library.  # Safety - `level` may be null or point to a valid, NUL-terminated C string. - If non-null, the pointer must remain valid for the duration of this call.

**Safety:**
- `level` may be null or point to a valid, NUL-terminated C string. - If non-null, the pointer must remain valid for the duration of this call.

**Module:** `utils`

---

#### `dash_spv_ffi_spv_stats_destroy`

```c
dash_spv_ffi_spv_stats_destroy(stats: *mut FFISpvStats) -> ()
```

**Description:**
Destroy an `FFISpvStats` object returned by this crate.  # Safety - `stats` must be a pointer returned from this crate, or null.

**Safety:**
- `stats` must be a pointer returned from this crate, or null.

**Module:** `client`

---

#### `dash_spv_ffi_string_array_destroy`

```c
dash_spv_ffi_string_array_destroy(arr: *mut FFIArray) -> ()
```

**Description:**
Destroy an array of FFIString pointers (Vec<*mut FFIString>) and their contents.  This function: - Iterates the array elements as pointers to FFIString and destroys each via dash_spv_ffi_string_destroy - Frees the underlying vector buffer stored in FFIArray - Does not free the FFIArray struct itself (safe for both stack- and heap-allocated structs)

**Module:** `types`

---

#### `dash_spv_ffi_string_destroy`

```c
dash_spv_ffi_string_destroy(s: FFIString) -> ()
```

**Module:** `types`

---

#### `dash_spv_ffi_version`

```c
dash_spv_ffi_version() -> *const c_char
```

**Module:** `utils`

---

## Type Definitions

### Core Types

- `FFIDashSpvClient` - SPV client handle
- `FFIClientConfig` - Client configuration
- `FFISyncProgress` - Synchronization progress
- `FFIDetailedSyncProgress` - Detailed sync progress
- `FFISpvStats` - SPV statistics
- `FFITransaction` - Transaction information
- `FFIUnconfirmedTransaction` - Unconfirmed transaction
- `FFIEventCallbacks` - Event callback structure
- `CoreSDKHandle` - Platform SDK integration handle

### Enumerations

- `FFINetwork` - Network type (Dash, Testnet, Regtest, Devnet)
- `FFIValidationMode` - Validation mode (None, Basic, Full)
- `FFIMempoolStrategy` - Mempool strategy (FetchAll, BloomFilter, Selective)
- `FFISyncStage` - Synchronization stage

## Memory Management

### Important Rules

1. **Ownership Transfer**: Functions returning pointers transfer ownership to the caller
2. **Cleanup Required**: All returned pointers must be freed using the appropriate `_destroy` function
3. **Thread Safety**: The SPV client is thread-safe
4. **Error Handling**: Check return codes and use `dash_spv_ffi_get_last_error()` for details
5. **Opaque Pointers**: `dash_spv_ffi_client_get_wallet_manager()` returns `void*` for Swift compatibility

## Usage Examples

### Basic SPV Client Usage

```c
// Create configuration
FFIClientConfig* config = dash_spv_ffi_config_testnet();

// Create client
FFIDashSpvClient* client = dash_spv_ffi_client_new(config);

// Start the client
int32_t result = dash_spv_ffi_client_start(client);
if (result != 0) {
    const char* error = dash_spv_ffi_get_last_error();
    // Handle error
}

// Sync to chain tip
dash_spv_ffi_client_sync_to_tip(client, NULL, NULL);

// Get wallet manager (returns void* for Swift)
void* wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);

// Clean up
dash_spv_ffi_client_destroy(client);
dash_spv_ffi_config_destroy(config);
```

### Event Callbacks

```c
void on_block(uint32_t height, const uint8_t (*hash)[32], void* user_data) {
    printf("New block at height %u\n", height);
}

void on_transaction(const uint8_t (*txid)[32], bool confirmed, 
                    int64_t amount, const char* addresses, 
                    uint32_t block_height, void* user_data) {
    printf("Transaction: %lld duffs\n", amount);
}

// Set up callbacks
FFIEventCallbacks callbacks = {
    .on_block = on_block,
    .on_transaction = on_transaction,
    .user_data = NULL
};

dash_spv_ffi_client_set_event_callbacks(client, callbacks);
```
