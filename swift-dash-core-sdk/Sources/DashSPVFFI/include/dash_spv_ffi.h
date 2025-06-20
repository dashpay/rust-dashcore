#ifndef DASH_SPV_FFI_H
#define DASH_SPV_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Mock FFI types for compilation
typedef struct {
    char* data;
    size_t len;
    size_t capacity;
} dash_spv_ffi_string;

typedef struct {
    void* data;
    size_t len;
    size_t capacity;
} dash_spv_ffi_array;

typedef struct {
    uint64_t confirmed;
    uint64_t pending;
    uint64_t instant_locked;
    uint64_t total;
} dash_spv_ffi_balance;

typedef struct {
    const char* txid;
    uint32_t vout;
    const char* address;
    const uint8_t* script;
    size_t script_len;
    uint64_t value;
    uint32_t height;
    uint32_t confirmations;
    bool is_instant_locked;
} dash_spv_ffi_utxo;

typedef struct {
    const char* txid;
    uint32_t height;
    uint64_t timestamp;
    uint64_t amount;
    uint64_t fee;
    uint32_t confirmations;
    bool is_instant_locked;
    const uint8_t* raw_tx;
    size_t raw_tx_len;
    uint32_t size;
    uint32_t version;
} dash_spv_ffi_transaction;

typedef struct {
    dash_spv_ffi_transaction tx;
    const char* block_hash;
    uint32_t block_time;
} dash_spv_ffi_transaction_result;

typedef struct {
    uint32_t current_height;
    uint32_t total_height;
    double progress;
    uint32_t status;
    uint64_t eta;
    dash_spv_ffi_string* message;
} dash_spv_ffi_sync_progress;

typedef struct {
    uint32_t connected_peers;
    uint32_t total_peers;
    uint32_t header_height;
    uint32_t filter_height;
    uint32_t scanned_height;
    uint64_t total_headers;
    uint64_t total_filters;
    uint64_t total_transactions;
    uint64_t start_time;
    uint64_t bytes_received;
    uint64_t bytes_sent;
} dash_spv_ffi_spv_stats;

typedef struct {
    uint32_t item_type;
    const uint8_t* data;
    size_t data_len;
} dash_spv_ffi_watch_item;

typedef struct {
    const char* address;
    uint64_t total_received;
    uint64_t total_sent;
    uint64_t balance;
    uint32_t tx_count;
} dash_spv_ffi_address_stats;

// Callback types
typedef void (*dash_spv_ffi_progress_callback)(double progress, const char* message, void* user_data);
typedef void (*dash_spv_ffi_completion_callback)(bool success, const char* error, void* user_data);
typedef void (*dash_spv_ffi_data_callback)(const void* data, size_t len, void* user_data);
typedef void (*dash_spv_ffi_block_callback)(uint32_t height, const char* hash, void* user_data);
typedef void (*dash_spv_ffi_transaction_callback)(const char* txid, bool confirmed, void* user_data);
typedef void (*dash_spv_ffi_balance_callback)(uint64_t confirmed, uint64_t unconfirmed, void* user_data);

typedef struct {
    dash_spv_ffi_block_callback on_block;
    dash_spv_ffi_transaction_callback on_transaction;
    dash_spv_ffi_balance_callback on_balance;
    void* user_data;
} dash_spv_ffi_event_callbacks;

// Opaque types
typedef void* FFIClientConfig;
typedef void* FFIClient;

// Function declarations (extern for linking)
#ifdef __cplusplus
extern "C" {
#endif

// Memory management
void dash_spv_ffi_string_destroy(dash_spv_ffi_string* s);
void dash_spv_ffi_array_destroy(dash_spv_ffi_array* a);
void dash_spv_ffi_sync_progress_destroy(dash_spv_ffi_sync_progress* p);
void dash_spv_ffi_spv_stats_destroy(dash_spv_ffi_spv_stats* s);

// Error handling
const char* dash_spv_ffi_get_last_error();
void dash_spv_ffi_clear_error();

// Configuration
FFIClientConfig dash_spv_ffi_config_new(uint32_t network);
void dash_spv_ffi_config_destroy(FFIClientConfig config);
int32_t dash_spv_ffi_config_set_data_dir(FFIClientConfig config, const char* path);
int32_t dash_spv_ffi_config_set_validation_mode(FFIClientConfig config, uint32_t mode);
int32_t dash_spv_ffi_config_set_max_peers(FFIClientConfig config, uint32_t max_peers);
int32_t dash_spv_ffi_config_set_user_agent(FFIClientConfig config, const char* agent);
int32_t dash_spv_ffi_config_set_filter_load(FFIClientConfig config, bool enable);
int32_t dash_spv_ffi_config_add_peer(FFIClientConfig config, const char* peer);

// Client operations
FFIClient dash_spv_ffi_client_new(FFIClientConfig config);
void dash_spv_ffi_client_destroy(FFIClient client);
int32_t dash_spv_ffi_client_start(FFIClient client);
int32_t dash_spv_ffi_client_stop(FFIClient client);
int32_t dash_spv_ffi_client_sync_to_tip(FFIClient client, dash_spv_ffi_progress_callback progress, dash_spv_ffi_completion_callback completion, void* user_data);
dash_spv_ffi_sync_progress* dash_spv_ffi_client_get_sync_progress(FFIClient client);
dash_spv_ffi_spv_stats* dash_spv_ffi_client_get_stats(FFIClient client);
dash_spv_ffi_string* dash_spv_ffi_client_broadcast_transaction(FFIClient client, const uint8_t* tx, size_t len);
void dash_spv_ffi_client_set_event_callbacks(FFIClient client, const dash_spv_ffi_event_callbacks* callbacks);
int32_t dash_spv_ffi_client_rescan_blockchain(FFIClient client, uint32_t from_height, dash_spv_ffi_completion_callback completion, void* user_data);

#ifdef __cplusplus
}
#endif

#endif // DASH_SPV_FFI_H