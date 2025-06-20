#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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

typedef struct FFIDashSpvClient FFIDashSpvClient;

typedef struct FFIString {
  char *ptr;
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
  uint64_t total;
} FFIBalance;

typedef struct FFIArray {
  void *data;
  uintptr_t len;
  uintptr_t capacity;
} FFIArray;

typedef void (*BlockCallback)(uint32_t height, const char *hash, void *user_data);

typedef void (*TransactionCallback)(const char *txid, bool confirmed, void *user_data);

typedef void (*BalanceCallback)(uint64_t confirmed, uint64_t unconfirmed, void *user_data);

typedef struct FFIEventCallbacks {
  BlockCallback on_block;
  TransactionCallback on_transaction;
  BalanceCallback on_balance_update;
  void *user_data;
} FFIEventCallbacks;

typedef struct FFITransaction {
  struct FFIString txid;
  int32_t version;
  uint32_t locktime;
  uint32_t size;
  uint32_t weight;
} FFITransaction;

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

int32_t dash_spv_ffi_client_sync_to_tip(struct FFIDashSpvClient *client,
                                        void (*progress_callback)(double, const char*, void*),
                                        void (*completion_callback)(bool, const char*, void*),
                                        void *user_data);

int32_t dash_spv_ffi_client_test_sync(struct FFIDashSpvClient *client);

int32_t dash_spv_ffi_client_sync_to_tip_with_progress(struct FFIDashSpvClient *client,
                                                      void (*progress_callback)(const struct FFIDetailedSyncProgress*,
                                                                                void*),
                                                      void (*completion_callback)(bool,
                                                                                  const char*,
                                                                                  void*),
                                                      void *user_data);

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

const char *dash_spv_ffi_get_last_error(void);

void dash_spv_ffi_clear_error(void);

void dash_spv_ffi_string_destroy(struct FFIString s);

void dash_spv_ffi_array_destroy(struct FFIArray *arr);

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
