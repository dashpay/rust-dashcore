#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum FFIMempoolStrategy {
  FetchAll = 0,
  BloomFilter = 1,
  Selective = 2,
} FFIMempoolStrategy;

typedef enum FFINetwork {
  Dash = 0,
  Testnet = 1,
  Regtest = 2,
  Devnet = 3,
} FFINetwork;

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

typedef enum FFIWatchItemType {
  Address = 0,
  Script = 1,
  Outpoint = 2,
} FFIWatchItemType;

typedef struct FFIClientConfig FFIClientConfig;

/**
 * FFIDashSpvClient structure
 */
typedef struct FFIDashSpvClient FFIDashSpvClient;

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

typedef struct FFIWatchItem {
  enum FFIWatchItemType item_type;
  struct FFIString data;
} FFIWatchItem;

typedef struct FFIBalance {
  uint64_t confirmed;
  uint64_t pending;
  uint64_t instantlocked;
  uint64_t mempool;
  uint64_t mempool_instant;
  uint64_t total;
} FFIBalance;

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
} FFIArray;

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

typedef struct FFIEventCallbacks {
  BlockCallback on_block;
  TransactionCallback on_transaction;
  BalanceCallback on_balance_update;
  MempoolTransactionCallback on_mempool_transaction_added;
  MempoolConfirmedCallback on_mempool_transaction_confirmed;
  MempoolRemovedCallback on_mempool_transaction_removed;
  void *user_data;
} FFIEventCallbacks;

typedef struct FFITransaction {
  struct FFIString txid;
  int32_t version;
  uint32_t locktime;
  uint32_t size;
  uint32_t weight;
} FFITransaction;

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

typedef struct FFIUtxo {
  struct FFIString txid;
  uint32_t vout;
  uint64_t amount;
  struct FFIString script_pubkey;
  struct FFIString address;
  uint32_t height;
  bool is_coinbase;
  bool is_confirmed;
  bool is_instantlocked;
} FFIUtxo;

typedef struct FFITransactionResult {
  struct FFIString txid;
  int32_t version;
  uint32_t locktime;
  uint32_t size;
  uint32_t weight;
  uint64_t fee;
  uint64_t confirmation_time;
  uint32_t confirmation_height;
} FFITransactionResult;

typedef struct FFIBlockResult {
  struct FFIString hash;
  uint32_t height;
  uint32_t time;
  uint32_t tx_count;
} FFIBlockResult;

typedef struct FFIFilterMatch {
  struct FFIString block_hash;
  uint32_t height;
  bool block_requested;
} FFIFilterMatch;

typedef struct FFIAddressStats {
  struct FFIString address;
  uint32_t utxo_count;
  uint64_t total_value;
  uint64_t confirmed_value;
  uint64_t pending_value;
  uint32_t spendable_count;
  uint32_t coinbase_count;
} FFIAddressStats;

struct FFIDashSpvClient *dash_spv_ffi_client_new(const struct FFIClientConfig *config);

int32_t dash_spv_ffi_client_start(struct FFIDashSpvClient *client);

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

struct FFISyncProgress *dash_spv_ffi_client_get_sync_progress(struct FFIDashSpvClient *client);

struct FFISpvStats *dash_spv_ffi_client_get_stats(struct FFIDashSpvClient *client);

bool dash_spv_ffi_client_is_filter_sync_available(struct FFIDashSpvClient *client);

int32_t dash_spv_ffi_client_add_watch_item(struct FFIDashSpvClient *client,
                                           const struct FFIWatchItem *item);

int32_t dash_spv_ffi_client_remove_watch_item(struct FFIDashSpvClient *client,
                                              const struct FFIWatchItem *item);

struct FFIBalance *dash_spv_ffi_client_get_address_balance(struct FFIDashSpvClient *client,
                                                           const char *address);

struct FFIArray dash_spv_ffi_client_get_utxos(struct FFIDashSpvClient *client);

struct FFIArray dash_spv_ffi_client_get_utxos_for_address(struct FFIDashSpvClient *client,
                                                          const char *address);

int32_t dash_spv_ffi_client_set_event_callbacks(struct FFIDashSpvClient *client,
                                                struct FFIEventCallbacks callbacks);

void dash_spv_ffi_client_destroy(struct FFIDashSpvClient *client);

void dash_spv_ffi_sync_progress_destroy(struct FFISyncProgress *progress);

void dash_spv_ffi_spv_stats_destroy(struct FFISpvStats *stats);

int32_t dash_spv_ffi_client_watch_address(struct FFIDashSpvClient *client, const char *address);

int32_t dash_spv_ffi_client_unwatch_address(struct FFIDashSpvClient *client, const char *address);

int32_t dash_spv_ffi_client_watch_script(struct FFIDashSpvClient *client, const char *script_hex);

int32_t dash_spv_ffi_client_unwatch_script(struct FFIDashSpvClient *client, const char *script_hex);

struct FFIArray dash_spv_ffi_client_get_address_history(struct FFIDashSpvClient *client,
                                                        const char *address);

struct FFITransaction *dash_spv_ffi_client_get_transaction(struct FFIDashSpvClient *client,
                                                           const char *txid);

int32_t dash_spv_ffi_client_broadcast_transaction(struct FFIDashSpvClient *client,
                                                  const char *tx_hex);

struct FFIArray dash_spv_ffi_client_get_watched_addresses(struct FFIDashSpvClient *client);

struct FFIArray dash_spv_ffi_client_get_watched_scripts(struct FFIDashSpvClient *client);

struct FFIBalance *dash_spv_ffi_client_get_total_balance(struct FFIDashSpvClient *client);

int32_t dash_spv_ffi_client_rescan_blockchain(struct FFIDashSpvClient *client,
                                              uint32_t _from_height);

int32_t dash_spv_ffi_client_get_transaction_confirmations(struct FFIDashSpvClient *client,
                                                          const char *txid);

int32_t dash_spv_ffi_client_is_transaction_confirmed(struct FFIDashSpvClient *client,
                                                     const char *txid);

void dash_spv_ffi_transaction_destroy(struct FFITransaction *tx);

struct FFIArray dash_spv_ffi_client_get_address_utxos(struct FFIDashSpvClient *client,
                                                      const char *address);

int32_t dash_spv_ffi_client_enable_mempool_tracking(struct FFIDashSpvClient *client,
                                                    enum FFIMempoolStrategy strategy);

struct FFIBalance *dash_spv_ffi_client_get_balance_with_mempool(struct FFIDashSpvClient *client);

int32_t dash_spv_ffi_client_get_mempool_transaction_count(struct FFIDashSpvClient *client);

int32_t dash_spv_ffi_client_record_send(struct FFIDashSpvClient *client, const char *txid);

struct FFIBalance *dash_spv_ffi_client_get_mempool_balance(struct FFIDashSpvClient *client,
                                                           const char *address);

struct FFIClientConfig *dash_spv_ffi_config_new(enum FFINetwork network);

struct FFIClientConfig *dash_spv_ffi_config_mainnet(void);

struct FFIClientConfig *dash_spv_ffi_config_testnet(void);

int32_t dash_spv_ffi_config_set_data_dir(struct FFIClientConfig *config, const char *path);

int32_t dash_spv_ffi_config_set_validation_mode(struct FFIClientConfig *config,
                                                enum FFIValidationMode mode);

int32_t dash_spv_ffi_config_set_max_peers(struct FFIClientConfig *config, uint32_t max_peers);

int32_t dash_spv_ffi_config_add_peer(struct FFIClientConfig *config, const char *addr);

int32_t dash_spv_ffi_config_set_user_agent(struct FFIClientConfig *config, const char *user_agent);

int32_t dash_spv_ffi_config_set_relay_transactions(struct FFIClientConfig *config, bool _relay);

int32_t dash_spv_ffi_config_set_filter_load(struct FFIClientConfig *config, bool load_filters);

enum FFINetwork dash_spv_ffi_config_get_network(const struct FFIClientConfig *config);

struct FFIString dash_spv_ffi_config_get_data_dir(const struct FFIClientConfig *config);

void dash_spv_ffi_config_destroy(struct FFIClientConfig *config);

int32_t dash_spv_ffi_config_set_mempool_tracking(struct FFIClientConfig *config, bool enable);

int32_t dash_spv_ffi_config_set_mempool_strategy(struct FFIClientConfig *config,
                                                 enum FFIMempoolStrategy strategy);

int32_t dash_spv_ffi_config_set_max_mempool_transactions(struct FFIClientConfig *config,
                                                         uint32_t max_transactions);

int32_t dash_spv_ffi_config_set_mempool_timeout(struct FFIClientConfig *config,
                                                uint64_t timeout_secs);

int32_t dash_spv_ffi_config_set_fetch_mempool_transactions(struct FFIClientConfig *config,
                                                           bool fetch);

int32_t dash_spv_ffi_config_set_persist_mempool(struct FFIClientConfig *config, bool persist);

bool dash_spv_ffi_config_get_mempool_tracking(const struct FFIClientConfig *config);

enum FFIMempoolStrategy dash_spv_ffi_config_get_mempool_strategy(const struct FFIClientConfig *config);

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
                                                    uint32_t _quorum_type,
                                                    const uint8_t *quorum_hash,
                                                    uint32_t _core_chain_locked_height,
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

void dash_spv_ffi_string_destroy(struct FFIString s);

void dash_spv_ffi_array_destroy(struct FFIArray *arr);

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

int32_t dash_spv_ffi_init_logging(const char *level);

const char *dash_spv_ffi_version(void);

const char *dash_spv_ffi_get_network_name(enum FFINetwork network);

void dash_spv_ffi_enable_test_mode(void);

struct FFIWatchItem *dash_spv_ffi_watch_item_address(const char *address);

struct FFIWatchItem *dash_spv_ffi_watch_item_script(const char *script_hex);

struct FFIWatchItem *dash_spv_ffi_watch_item_outpoint(const char *txid, uint32_t vout);

void dash_spv_ffi_watch_item_destroy(struct FFIWatchItem *item);

void dash_spv_ffi_balance_destroy(struct FFIBalance *balance);

void dash_spv_ffi_utxo_destroy(struct FFIUtxo *utxo);

void dash_spv_ffi_transaction_result_destroy(struct FFITransactionResult *tx);

void dash_spv_ffi_block_result_destroy(struct FFIBlockResult *block);

void dash_spv_ffi_filter_match_destroy(struct FFIFilterMatch *filter_match);

void dash_spv_ffi_address_stats_destroy(struct FFIAddressStats *stats);

int32_t dash_spv_ffi_validate_address(const char *address, enum FFINetwork network);
