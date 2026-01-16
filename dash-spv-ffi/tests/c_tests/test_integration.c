#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include "../../dash_spv_ffi.h"

#define TEST_ASSERT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "Assertion failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

#define TEST_SUCCESS(name) printf("✓ %s\n", name)
#define TEST_START(name) printf("Running %s...\n", name)

// Integration test context
typedef struct {
    FFIDashSpvClient* client;
    FFIClientConfig* config;
    int sync_completed;
    int block_count;
    int tx_count;
    uint64_t total_balance;
} IntegrationContext;

// Event callbacks
void on_block_event(uint32_t height, const char* hash, void* user_data) {
    IntegrationContext* ctx = (IntegrationContext*)user_data;
    ctx->block_count++;
    printf("New block at height %u: %s\n", height, hash ? hash : "null");
}

void on_transaction_event(const char* txid, int confirmed, void* user_data) {
    IntegrationContext* ctx = (IntegrationContext*)user_data;
    ctx->tx_count++;
    printf("Transaction %s: confirmed=%d\n", txid ? txid : "null", confirmed);
}

void on_balance_update_event(uint64_t confirmed, uint64_t unconfirmed, void* user_data) {
    IntegrationContext* ctx = (IntegrationContext*)user_data;
    ctx->total_balance = confirmed + unconfirmed;
    printf("Balance update: confirmed=%llu, unconfirmed=%llu\n",
           (unsigned long long)confirmed, (unsigned long long)unconfirmed);
}

// Test full workflow
void test_full_workflow() {
    TEST_START("test_full_workflow");

    IntegrationContext ctx = {0};

    // Create configuration
    ctx.config = dash_spv_ffi_config_new(FFINetwork_Regtest);
    TEST_ASSERT(ctx.config != NULL);

    // Configure client
    dash_spv_ffi_config_set_data_dir(ctx.config, "/tmp/dash-spv-integration");
    dash_spv_ffi_config_builder_set_validation_mode(ctx.config, FFIValidationMode_Basic);
    dash_spv_ffi_config_builder_set_max_peers(ctx.config, 8);

    // Add some test peers
    dash_spv_ffi_config_add_peer(ctx.config, "127.0.0.1:19999");
    dash_spv_ffi_config_add_peer(ctx.config, "127.0.0.1:19998");

    // Create client
    ctx.client = dash_spv_ffi_client_new(ctx.config);
    TEST_ASSERT(ctx.client != NULL);

    // Set up event callbacks
    FFIEventCallbacks event_callbacks = {0};
    event_callbacks.on_block = on_block_event;
    event_callbacks.on_transaction = on_transaction_event;
    event_callbacks.on_balance_update = on_balance_update_event;
    event_callbacks.user_data = &ctx;

    int32_t result = dash_spv_ffi_client_set_event_callbacks(ctx.client, event_callbacks);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Add addresses to watch
    const char* addresses[] = {
        "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E",
        "XuQQkwA4FYkq2XERzMY2CiAZhJTEkgZ6uN",
        "XpAy3DUNod14KdJJh3XUjtkAiUkD2kd4JT"
    };

    for (int i = 0; i < 3; i++) {
        result = dash_spv_ffi_client_watch_address(ctx.client, addresses[i]);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    // Start the client
    result = dash_spv_ffi_client_start(ctx.client);
    printf("Client start result: %d\n", result);

    // Monitor for a while
    time_t start_time = time(NULL);
    time_t monitor_duration = 5; // 5 seconds

    while (time(NULL) - start_time < monitor_duration) {
        // Check sync progress
        FFISyncProgress* progress = dash_spv_ffi_client_get_sync_progress(ctx.client);
        if (progress != NULL) {
            printf("Sync progress: headers=%u, filters=%u, peers=%u\n",
                   progress->header_height,
                   progress->filter_header_height,
                   progress->peer_count);
            dash_spv_ffi_sync_progress_destroy(progress);
        }

        // Check stats
        FFISpvStats* stats = dash_spv_ffi_client_get_stats(ctx.client);
        if (stats != NULL) {
            printf("Stats: headers=%llu, filters=%llu, bytes_received=%llu\n",
                   (unsigned long long)stats->headers_downloaded,
                   (unsigned long long)stats->filters_downloaded,
                   (unsigned long long)stats->bytes_received);
            dash_spv_ffi_spv_stats_destroy(stats);
        }

        sleep(1);
    }

    // Stop the client
    result = dash_spv_ffi_client_stop(ctx.client);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Print summary
    printf("\nWorkflow summary:\n");
    printf("  Blocks received: %d\n", ctx.block_count);
    printf("  Transactions: %d\n", ctx.tx_count);
    printf("  Total balance: %llu\n", (unsigned long long)ctx.total_balance);

    // Clean up
    dash_spv_ffi_client_destroy(ctx.client);
    dash_spv_ffi_config_destroy(ctx.config);

    TEST_SUCCESS("test_full_workflow");
}

// Test persistence
void test_persistence() {
    TEST_START("test_persistence");

    const char* data_dir = "/tmp/dash-spv-persistence";

    // Phase 1: Create client and add data
    {
        FFIClientConfig* config = dash_spv_ffi_config_new(FFINetwork_Regtest);
        dash_spv_ffi_config_set_data_dir(config, data_dir);

        FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
        TEST_ASSERT(client != NULL);

        // Add watched addresses
        dash_spv_ffi_client_watch_address(client, "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E");
        dash_spv_ffi_client_watch_address(client, "XuQQkwA4FYkq2XERzMY2CiAZhJTEkgZ6uN");

        // Start and sync for a bit
        dash_spv_ffi_client_start(client);
        sleep(2);

        // Get current state
        FFISyncProgress* progress = dash_spv_ffi_client_get_sync_progress(client);
        uint32_t height1 = 0;
        if (progress != NULL) {
            height1 = progress->header_height;
            dash_spv_ffi_sync_progress_destroy(progress);
        }

        printf("Phase 1 height: %u\n", height1);

        dash_spv_ffi_client_stop(client);
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }

    // Phase 2: Create new client with same data directory
    {
        FFIClientConfig* config = dash_spv_ffi_config_new(FFINetwork_Regtest);
        dash_spv_ffi_config_set_data_dir(config, data_dir);

        FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
        TEST_ASSERT(client != NULL);

        // Check if state was persisted
        FFISyncProgress* progress = dash_spv_ffi_client_get_sync_progress(client);
        if (progress != NULL) {
            printf("Phase 2 height: %u\n", progress->header_height);
            dash_spv_ffi_sync_progress_destroy(progress);
        }

        // Check watched addresses
        FFIArray* watched = dash_spv_ffi_client_get_watched_addresses(client);
        if (watched != NULL) {
            printf("Persisted watched addresses: %zu\n", watched->len);
            dash_spv_ffi_array_destroy(*watched);
        }

        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }

    TEST_SUCCESS("test_persistence");
}

// Test transaction handling
void test_transaction_handling() {
    TEST_START("test_transaction_handling");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-tx-test");

    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Test transaction validation (minimal tx for testing)
    const char* test_tx_hex = "01000000000100000000000000001976a914000000000000000000000000000000000000000088ac00000000";

    // Try to broadcast (will likely fail, but tests the API)
    int32_t result = dash_spv_ffi_client_broadcast_transaction(client, test_tx_hex);
    printf("Broadcast result: %d\n", result);

    // If failed, check error
    if (result != FFIErrorCode_Success) {
        const char* error = dash_spv_ffi_get_last_error();
        if (error != NULL) {
            printf("Broadcast error: %s\n", error);
        }
        dash_spv_ffi_clear_error();
    }

    // Test transaction query
    const char* test_txid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    FFITransaction* tx = dash_spv_ffi_client_get_transaction(client, test_txid);
    if (tx == NULL) {
        printf("Transaction not found (expected)\n");
    } else {
        dash_spv_ffi_transaction_destroy(tx);
    }

    // Test confirmation status
    int32_t confirmations = dash_spv_ffi_client_get_transaction_confirmations(client, test_txid);
    printf("Transaction confirmations: %d\n", confirmations);

    int32_t is_confirmed = dash_spv_ffi_client_is_transaction_confirmed(client, test_txid);
    printf("Transaction confirmed: %d\n", is_confirmed);

    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_transaction_handling");
}

// Test rescan functionality
void test_rescan() {
    TEST_START("test_rescan");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-rescan-test");

    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Add addresses to watch
    dash_spv_ffi_client_watch_address(client, "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E");
    dash_spv_ffi_client_watch_address(client, "XuQQkwA4FYkq2XERzMY2CiAZhJTEkgZ6uN");

    // Start rescan from height 0
    int32_t result = dash_spv_ffi_client_rescan_blockchain(client, 0);
    printf("Rescan from height 0 result: %d\n", result);

    // Start rescan from specific height
    result = dash_spv_ffi_client_rescan_blockchain(client, 100000);
    printf("Rescan from height 100000 result: %d\n", result);

    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_rescan");
}

// Main test runner
int main() {
    printf("Running Dash SPV FFI Integration C Tests\n");
    printf("========================================\n\n");

    test_full_workflow();
    test_persistence();
    test_transaction_handling();
    test_rescan();

    printf("\n========================================\n");
    printf("All integration tests completed!\n");

    return 0;
}
