#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum FFIMempoolStrategy {
  FetchAll = 0,
  BloomFilter = 1,
  Selective = 2,
} FFIMempoolStrategy;

typedef enum FFISyncStage {
  Connecting = 0,
  QueryingHeight = 1,
  Downloading = 2,
  Validating = 3,
  Storing = 4,
  Complete = 5,
  Failed = 6,
} FFISyncStage;

typedef enum FFIValidationMode {
  None = 0,
  Basic = 1,
  Full = 2,
} FFIValidationMode;

typedef struct FFIDashSpvClient FFIDashSpvClient;

/**
 * FFI-safe array that transfers ownership of memory to the C caller.
 *
 * # Safety
 *
 * This struct represents memory that has been allocated by Rust but ownership
 * has been transferred to the C caller. The caller is responsible for:
 * - Not accessing the memory after it has been freed
 * - Calling `dash_spv_ffi_array_destroy` to properly deallocate the memory
 * - Ensuring the data, len, and capacity fields remain consistent
 */
typedef struct FFIArray {
  void *data;
  uintptr_t len;
  uintptr_t capacity;
  uintptr_t elem_size;
  uintptr_t elem_align;
} FFIArray;

typedef ClientConfig FFIClientConfig;

typedef struct FFIString {
  char *ptr;
  uintptr_t length;
} FFIString;

typedef struct FFIDetailedSyncProgress {
  uint32_t current_height;
  uint32_t total_height;
  double percentage;
  double headers_per_second;
  int64_t estimated_seconds_remaining;
  enum FFISyncStage stage;
  struct FFIString stage_message;
  uint32_t connected_peers;
  uint64_t total_headers;
  int64_t sync_start_timestamp;
} FFIDetailedSyncProgress;

typedef struct FFISyncProgress {
  uint32_t header_height;
  uint32_t filter_header_height;
  uint32_t masternode_height;
  uint32_t peer_count;
  bool headers_synced;
  bool filter_headers_synced;
  bool masternodes_synced;
  bool filter_sync_available;
  uint32_t filters_downloaded;
  uint32_t last_synced_filter_height;
} FFISyncProgress;

typedef struct FFISpvStats {
  uint32_t connected_peers;
  uint32_t total_peers;
  uint32_t header_height;
  uint32_t filter_height;
  uint64_t headers_downloaded;
  uint64_t filter_headers_downloaded;
  uint64_t filters_downloaded;
  uint64_t filters_matched;
  uint64_t blocks_processed;
  uint64_t bytes_received;
  uint64_t bytes_sent;
  uint64_t uptime;
} FFISpvStats;

typedef void (*BlockCallback)(uint32_t height, const uint8_t (*hash)[32], void *user_data);

typedef void (*TransactionCallback)(const uint8_t (*txid)[32],
                                    bool confirmed,
                                    int64_t amount,
                                    const char *addresses,
                                    uint32_t block_height,
                                    void *user_data);

typedef void (*BalanceCallback)(uint64_t confirmed, uint64_t unconfirmed, void *user_data);

typedef void (*MempoolTransactionCallback)(const uint8_t (*txid)[32],
                                           int64_t amount,
                                           const char *addresses,
                                           bool is_instant_send,
                                           void *user_data);

typedef void (*MempoolConfirmedCallback)(const uint8_t (*txid)[32],
                                         uint32_t block_height,
                                         const uint8_t (*block_hash)[32],
                                         void *user_data);

typedef void (*MempoolRemovedCallback)(const uint8_t (*txid)[32], uint8_t reason, void *user_data);

typedef void (*CompactFilterMatchedCallback)(const uint8_t (*block_hash)[32],
                                             const char *matched_scripts,
                                             const char *wallet_id,
                                             void *user_data);

typedef void (*WalletTransactionCallback)(const char *wallet_id,
                                          uint32_t account_index,
                                          const uint8_t (*txid)[32],
                                          bool confirmed,
                                          int64_t amount,
                                          const char *addresses,
                                          uint32_t block_height,
                                          bool is_ours,
                                          void *user_data);

typedef struct FFIEventCallbacks {
  BlockCallback on_block;
  TransactionCallback on_transaction;
  BalanceCallback on_balance_update;
  MempoolTransactionCallback on_mempool_transaction_added;
  MempoolConfirmedCallback on_mempool_transaction_confirmed;
  MempoolRemovedCallback on_mempool_transaction_removed;
  CompactFilterMatchedCallback on_compact_filter_matched;
  WalletTransactionCallback on_wallet_transaction;
  void *user_data;
} FFIEventCallbacks;

/**
 * Handle for Core SDK that can be passed to Platform SDK
 */
typedef struct CoreSDKHandle {
  struct FFIDashSpvClient *client;
} CoreSDKHandle;

/**
 * FFIResult type for error handling
 */
typedef struct FFIResult {
  int32_t error_code;
  const char *error_message;
} FFIResult;

/**
 * FFI-safe representation of an unconfirmed transaction
 *
 * # Safety
 *
 * This struct contains raw pointers that must be properly managed:
 *
 * - `raw_tx`: A pointer to the raw transaction bytes. The caller is responsible for:
 *   - Allocating this memory before passing it to Rust
 *   - Ensuring the pointer remains valid for the lifetime of this struct
 *   - Freeing the memory after use with `dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx`
 *
 * - `addresses`: A pointer to an array of FFIString objects. The caller is responsible for:
 *   - Allocating this array before passing it to Rust
 *   - Ensuring the pointer remains valid for the lifetime of this struct
 *   - Freeing each FFIString in the array with `dash_spv_ffi_string_destroy`
 *   - Freeing the array itself after use with `dash_spv_ffi_unconfirmed_transaction_destroy_addresses`
 *
 * Use `dash_spv_ffi_unconfirmed_transaction_destroy` to safely clean up all resources
 * associated with this struct.
 */
typedef struct FFIUnconfirmedTransaction {
  struct FFIString txid;
  uint8_t *raw_tx;
  uintptr_t raw_tx_len;
  int64_t amount;
  uint64_t fee;
  bool is_instant_send;
  bool is_outgoing;
  struct FFIString *addresses;
  uintptr_t addresses_len;
} FFIUnconfirmedTransaction;

/**
 * Get the latest checkpoint for the given network.
 *
 * # Safety
 * - `out_height` must be a valid pointer to a `u32`.
 * - `out_hash` must point to at least 32 writable bytes.
 */
int32_t dash_spv_ffi_checkpoint_latest(FFINetwork network, uint32_t *out_height, uint8_t *out_hash);

/**
 * Get the last checkpoint at or before a given height.
 *
 * # Safety
 * - `out_height` must be a valid pointer to a `u32`.
 * - `out_hash` must point to at least 32 writable bytes.
 */
int32_t dash_spv_ffi_checkpoint_before_height(FFINetwork network,
                                              uint32_t height,
                                              uint32_t *out_height,
                                              uint8_t *out_hash);

/**
 * Get the last checkpoint at or before a given UNIX timestamp (seconds).
 *
 * # Safety
 * - `out_height` must be a valid pointer to a `u32`.
 * - `out_hash` must point to at least 32 writable bytes.
 */
int32_t dash_spv_ffi_checkpoint_before_timestamp(FFINetwork network,
                                                 uint32_t timestamp,
                                                 uint32_t *out_height,
                                                 uint8_t *out_hash);

/**
 * Get all checkpoints between two heights (inclusive).
 *
 * Returns an `FFIArray` of `FFICheckpoint` items. The caller owns the memory and
 * must free the array buffer using `dash_spv_ffi_array_destroy` when done.
 */
struct FFIArray dash_spv_ffi_checkpoints_between_heights(FFINetwork network,
                                                         uint32_t start_height,
                                                         uint32_t end_height);

/**
 * Create a new SPV client and return an opaque pointer.
 *
 * # Safety
 * - `config` must be a valid, non-null pointer for the duration of the call.
 * - The returned pointer must be freed with `dash_spv_ffi_client_destroy`.
 */
struct FFIDashSpvClient *dash_spv_ffi_client_new(const FFIClientConfig *config);

/**
 * Update the running client's configuration.
 *
 * # Safety
 * - `client` must be a valid pointer to an `FFIDashSpvClient`.
 * - `config` must be a valid pointer to an `FFIClientConfig`.
 * - The network in `config` must match the client's network; changing networks at runtime is not supported.
 */
int32_t dash_spv_ffi_client_update_config(struct FFIDashSpvClient *client,
                                          const FFIClientConfig *config);

/**
 * Start the SPV client.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer to a created client.
 */
int32_t dash_spv_ffi_client_start(struct FFIDashSpvClient *client);

/**
 * Stop the SPV client.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer to a created client.
 */
int32_t dash_spv_ffi_client_stop(struct FFIDashSpvClient *client);

/**
 * Sync the SPV client to the chain tip.
 *
 * # Safety
 *
 * This function is unsafe because:
 * - `client` must be a valid pointer to an initialized `FFIDashSpvClient`
 * - `user_data` must satisfy thread safety requirements:
 *   - If non-null, it must point to data that is safe to access from multiple threads
 *   - The caller must ensure proper synchronization if the data is mutable
 *   - The data must remain valid for the entire duration of the sync operation
 * - `completion_callback` must be thread-safe and can be called from any thread
 *
 * # Parameters
 *
 * - `client`: Pointer to the SPV client
 * - `completion_callback`: Optional callback invoked on completion
 * - `user_data`: Optional user data pointer passed to callbacks
 *
 * # Returns
 *
 * 0 on success, error code on failure
 */
int32_t dash_spv_ffi_client_sync_to_tip(struct FFIDashSpvClient *client,
                                        void (*completion_callback)(bool, const char*, void*),
                                        void *user_data);

/**
 * Performs a test synchronization of the SPV client
 *
 * # Parameters
 * - `client`: Pointer to an FFIDashSpvClient instance
 *
 * # Returns
 * - `0` on success
 * - Negative error code on failure
 *
 * # Safety
 * This function is unsafe because it dereferences a raw pointer.
 * The caller must ensure that the client pointer is valid.
 */
int32_t dash_spv_ffi_client_test_sync(struct FFIDashSpvClient *client);

/**
 * Sync the SPV client to the chain tip with detailed progress updates.
 *
 * # Safety
 *
 * This function is unsafe because:
 * - `client` must be a valid pointer to an initialized `FFIDashSpvClient`
 * - `user_data` must satisfy thread safety requirements:
 *   - If non-null, it must point to data that is safe to access from multiple threads
 *   - The caller must ensure proper synchronization if the data is mutable
 *   - The data must remain valid for the entire duration of the sync operation
 * - Both `progress_callback` and `completion_callback` must be thread-safe and can be called from any thread
 *
 * # Parameters
 *
 * - `client`: Pointer to the SPV client
 * - `progress_callback`: Optional callback invoked periodically with sync progress
 * - `completion_callback`: Optional callback invoked on completion
 * - `user_data`: Optional user data pointer passed to all callbacks
 *
 * # Returns
 *
 * 0 on success, error code on failure
 */
int32_t dash_spv_ffi_client_sync_to_tip_with_progress(struct FFIDashSpvClient *client,
                                                      void (*progress_callback)(const struct FFIDetailedSyncProgress*,
                                                                                void*),
                                                      void (*completion_callback)(bool,
                                                                                  const char*,
                                                                                  void*),
                                                      void *user_data);

/**
 * Cancels the sync operation.
 *
 * **Note**: This function currently only stops the SPV client and clears sync callbacks,
 * but does not fully abort the ongoing sync process. The sync operation may continue
 * running in the background until it completes naturally. Full sync cancellation with
 * proper task abortion is not yet implemented.
 *
 * # Safety
 * The client pointer must be valid and non-null.
 *
 * # Returns
 * Returns 0 on success, or an error code on failure.
 */
int32_t dash_spv_ffi_client_cancel_sync(struct FFIDashSpvClient *client);

/**
 * Get the current sync progress snapshot.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer.
 */
struct FFISyncProgress *dash_spv_ffi_client_get_sync_progress(struct FFIDashSpvClient *client);

/**
 * Get current runtime statistics for the SPV client.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer.
 */
struct FFISpvStats *dash_spv_ffi_client_get_stats(struct FFIDashSpvClient *client);

/**
 * Check if compact filter sync is currently available.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer.
 */
bool dash_spv_ffi_client_is_filter_sync_available(struct FFIDashSpvClient *client);

/**
 * Set event callbacks for the client.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer.
 */
int32_t dash_spv_ffi_client_set_event_callbacks(struct FFIDashSpvClient *client,
                                                struct FFIEventCallbacks callbacks);

/**
 * Destroy the client and free associated resources.
 *
 * # Safety
 * - `client` must be either null or a pointer obtained from `dash_spv_ffi_client_new`.
 */
void dash_spv_ffi_client_destroy(struct FFIDashSpvClient *client);

/**
 * Destroy a `FFISyncProgress` object returned by this crate.
 *
 * # Safety
 * - `progress` must be a pointer returned from this crate, or null.
 */
void dash_spv_ffi_sync_progress_destroy(struct FFISyncProgress *progress);

/**
 * Destroy an `FFISpvStats` object returned by this crate.
 *
 * # Safety
 * - `stats` must be a pointer returned from this crate, or null.
 */
void dash_spv_ffi_spv_stats_destroy(struct FFISpvStats *stats);

/**
 * Request a rescan of the blockchain from a given height (not yet implemented).
 *
 * # Safety
 * - `client` must be a valid, non-null pointer.
 */
int32_t dash_spv_ffi_client_rescan_blockchain(struct FFIDashSpvClient *client,
                                              uint32_t _from_height);

/**
 * Enable mempool tracking with a given strategy.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer.
 */
int32_t dash_spv_ffi_client_enable_mempool_tracking(struct FFIDashSpvClient *client,
                                                    enum FFIMempoolStrategy strategy);

/**
 * Record that we attempted to send a transaction by its txid.
 *
 * # Safety
 * - `client` and `txid` must be valid, non-null pointers.
 */
int32_t dash_spv_ffi_client_record_send(struct FFIDashSpvClient *client, const char *txid);

/**
 * Get the wallet manager from the SPV client
 *
 * Returns an opaque pointer to FFIWalletManager that contains a cloned Arc reference to the wallet manager.
 * This allows direct interaction with the wallet manager without going through the client.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - The client pointer is valid
 * - The returned pointer is freed using `wallet_manager_free` from key-wallet-ffi
 *
 * # Returns
 *
 * An opaque pointer (void*) to the wallet manager, or NULL if the client is not initialized.
 * Swift should treat this as an OpaquePointer.
 * Get a handle to the wallet manager owned by this client.
 *
 * # Safety
 * - `client` must be a valid, non-null pointer.
 */
void *dash_spv_ffi_client_get_wallet_manager(struct FFIDashSpvClient *client);

FFIClientConfig *dash_spv_ffi_config_new(FFINetwork network);

FFIClientConfig *dash_spv_ffi_config_mainnet(void);

FFIClientConfig *dash_spv_ffi_config_testnet(void);

/**
 * Sets the data directory for storing blockchain data
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - `path` must be a valid null-terminated C string
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_data_dir(FFIClientConfig *config,
                                         const char *path);

/**
 * Sets the validation mode for the SPV client
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_validation_mode(FFIClientConfig *config,
                                                enum FFIValidationMode mode);

/**
 * Sets the maximum number of peers to connect to
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_max_peers(FFIClientConfig *config,
                                          uint32_t max_peers);

/**
 * Adds a peer address to the configuration
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - `addr` must be a valid null-terminated C string containing a socket address (e.g., "192.168.1.1:9999")
 * - The caller must ensure both pointers remain valid for the duration of this call
 */
int32_t dash_spv_ffi_config_add_peer(FFIClientConfig *config,
                                     const char *addr);

/**
 * Sets the user agent string to advertise in the P2P handshake
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - `user_agent` must be a valid null-terminated C string
 * - The caller must ensure both pointers remain valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_user_agent(FFIClientConfig *config,
                                           const char *user_agent);

/**
 * Sets whether to relay transactions (currently a no-op)
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_relay_transactions(FFIClientConfig *config,
                                                   bool _relay);

/**
 * Sets whether to load bloom filters
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_filter_load(FFIClientConfig *config,
                                            bool load_filters);

/**
 * Enables or disables masternode synchronization
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_masternode_sync_enabled(FFIClientConfig *config,
                                                        bool enable);

/**
 * Gets the network type from the configuration
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig or null
 * - If null, returns FFINetwork::Dash as default
 */
FFINetwork dash_spv_ffi_config_get_network(const FFIClientConfig *config);

/**
 * Gets the data directory path from the configuration
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig or null
 * - If null or no data directory is set, returns an FFIString with null pointer
 * - The returned FFIString must be freed by the caller using `dash_spv_ffi_string_destroy`
 */
struct FFIString dash_spv_ffi_config_get_data_dir(const FFIClientConfig *config);

/**
 * Destroys an FFIClientConfig and frees its memory
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet, or null
 * - After calling this function, the config pointer becomes invalid and must not be used
 * - This function should only be called once per config instance
 */
void dash_spv_ffi_config_destroy(FFIClientConfig *config);

/**
 * Enables or disables mempool tracking
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_mempool_tracking(FFIClientConfig *config,
                                                 bool enable);

/**
 * Sets the mempool synchronization strategy
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_mempool_strategy(FFIClientConfig *config,
                                                 enum FFIMempoolStrategy strategy);

/**
 * Sets the maximum number of mempool transactions to track
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_max_mempool_transactions(FFIClientConfig *config,
                                                         uint32_t max_transactions);

/**
 * Sets the mempool transaction timeout in seconds
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_mempool_timeout(FFIClientConfig *config,
                                                uint64_t timeout_secs);

/**
 * Sets whether to fetch full mempool transaction data
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_fetch_mempool_transactions(FFIClientConfig *config,
                                                           bool fetch);

/**
 * Sets whether to persist mempool state to disk
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_persist_mempool(FFIClientConfig *config,
                                                bool persist);

/**
 * Gets whether mempool tracking is enabled
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig or null
 * - If null, returns false as default
 */
bool dash_spv_ffi_config_get_mempool_tracking(const FFIClientConfig *config);

/**
 * Gets the mempool synchronization strategy
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig or null
 * - If null, returns FFIMempoolStrategy::Selective as default
 */
enum FFIMempoolStrategy dash_spv_ffi_config_get_mempool_strategy(const FFIClientConfig *config);

/**
 * Sets the starting block height for synchronization
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_start_from_height(FFIClientConfig *config,
                                                  uint32_t height);

/**
 * Sets the wallet creation timestamp for synchronization optimization
 *
 * # Safety
 * - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
 * - The caller must ensure the config pointer remains valid for the duration of this call
 */
int32_t dash_spv_ffi_config_set_wallet_creation_time(FFIClientConfig *config,
                                                     uint32_t timestamp);

const char *dash_spv_ffi_get_last_error(void);

void dash_spv_ffi_clear_error(void);

/**
 * Creates a CoreSDKHandle from an FFIDashSpvClient
 *
 * # Safety
 *
 * This function is unsafe because:
 * - The caller must ensure the client pointer is valid
 * - The returned handle must be properly released with ffi_dash_spv_release_core_handle
 */
struct CoreSDKHandle *ffi_dash_spv_get_core_handle(struct FFIDashSpvClient *client);

/**
 * Releases a CoreSDKHandle
 *
 * # Safety
 *
 * This function is unsafe because:
 * - The caller must ensure the handle pointer is valid
 * - The handle must not be used after this call
 */
void ffi_dash_spv_release_core_handle(struct CoreSDKHandle *handle);

/**
 * Gets a quorum public key from the Core chain
 *
 * # Safety
 *
 * This function is unsafe because:
 * - The caller must ensure all pointers are valid
 * - quorum_hash must point to a 32-byte array
 * - out_pubkey must point to a buffer of at least out_pubkey_size bytes
 * - out_pubkey_size must be at least 48 bytes
 */
struct FFIResult ffi_dash_spv_get_quorum_public_key(struct FFIDashSpvClient *client,
                                                    uint32_t quorum_type,
                                                    const uint8_t *quorum_hash,
                                                    uint32_t core_chain_locked_height,
                                                    uint8_t *out_pubkey,
                                                    uintptr_t out_pubkey_size);

/**
 * Gets the platform activation height from the Core chain
 *
 * # Safety
 *
 * This function is unsafe because:
 * - The caller must ensure all pointers are valid
 * - out_height must point to a valid u32
 */
struct FFIResult ffi_dash_spv_get_platform_activation_height(struct FFIDashSpvClient *client,
                                                             uint32_t *out_height);

/**
 * # Safety
 * - `s.ptr` must be a pointer previously returned by `FFIString::new` or compatible.
 * - It must not be used after this call.
 */
void dash_spv_ffi_string_destroy(struct FFIString s);

/**
 * # Safety
 * - `arr` must be either null or a valid pointer to an `FFIArray` previously constructed in Rust.
 * - The memory referenced by `arr.data` must not be used after this call.
 */
void dash_spv_ffi_array_destroy(struct FFIArray *arr);

/**
 * Destroy an array of FFIString pointers (Vec<*mut FFIString>) and their contents.
 *
 * This function:
 * - Iterates the array elements as pointers to FFIString and destroys each via dash_spv_ffi_string_destroy
 * - Frees the underlying vector buffer stored in FFIArray
 * - Does not free the FFIArray struct itself (safe for both stack- and heap-allocated structs)
 * # Safety
 * - `arr` must be either null or a valid pointer to an `FFIArray` whose elements are `*mut FFIString`.
 * - Each element pointer must be valid or null; non-null entries are freed.
 * - The memory referenced by `arr.data` must not be used after this call.
 */
void dash_spv_ffi_string_array_destroy(struct FFIArray *arr);

/**
 * Destroys the raw transaction bytes allocated for an FFIUnconfirmedTransaction
 *
 * # Safety
 *
 * - `raw_tx` must be a valid pointer to memory allocated by the caller
 * - `raw_tx_len` must be the correct length of the allocated memory
 * - The pointer must not be used after this function is called
 * - This function should only be called once per allocation
 */
void dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx(uint8_t *raw_tx, uintptr_t raw_tx_len);

/**
 * Destroys the addresses array allocated for an FFIUnconfirmedTransaction
 *
 * # Safety
 *
 * - `addresses` must be a valid pointer to an array of FFIString objects
 * - `addresses_len` must be the correct length of the array
 * - Each FFIString in the array must be destroyed separately using `dash_spv_ffi_string_destroy`
 * - The pointer must not be used after this function is called
 * - This function should only be called once per allocation
 */
void dash_spv_ffi_unconfirmed_transaction_destroy_addresses(struct FFIString *addresses,
                                                            uintptr_t addresses_len);

/**
 * Destroys an FFIUnconfirmedTransaction and all its associated resources
 *
 * # Safety
 *
 * - `tx` must be a valid pointer to an FFIUnconfirmedTransaction
 * - All resources (raw_tx, addresses array, and individual FFIStrings) will be freed
 * - The pointer must not be used after this function is called
 * - This function should only be called once per FFIUnconfirmedTransaction
 */
void dash_spv_ffi_unconfirmed_transaction_destroy(struct FFIUnconfirmedTransaction *tx);

/**
 * Initialize logging for the SPV library.
 *
 * # Safety
 * - `level` may be null or point to a valid, NUL-terminated C string.
 * - If non-null, the pointer must remain valid for the duration of this call.
 */
int32_t dash_spv_ffi_init_logging(const char *level);

const char *dash_spv_ffi_version(void);

void dash_spv_ffi_enable_test_mode(void);

int32_t dash_spv_ffi_client_broadcast_transaction(struct FFIDashSpvClient *client,
                                                  const char *tx_hex);
