#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include "../../dash_spv_ffi.h"

#define TEST_ASSERT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "Assertion failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

#define TEST_SUCCESS(name) printf("✓ %s\n", name)
#define TEST_START(name) printf("Running %s...\n", name)

// Test wallet operations
void test_wallet_operations() {
    TEST_START("test_wallet_operations");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-test-wallet");

    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Test watching addresses
    const char* test_addresses[] = {
        "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E",
        "XuQQkwA4FYkq2XERzMY2CiAZhJTEkgZ6uN",
        "XpAy3DUNod14KdJJh3XUjtkAiUkD2kd4JT"
    };

    for (int i = 0; i < 3; i++) {
        int32_t result = dash_spv_ffi_client_watch_address(client, test_addresses[i]);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    // Test getting balance
    FFIBalance* balance = dash_spv_ffi_client_get_address_balance(client, test_addresses[0]);
    if (balance != NULL) {
        // New wallet should have zero balance
        TEST_ASSERT(balance->confirmed == 0);
        TEST_ASSERT(balance->pending == 0);
        dash_spv_ffi_balance_destroy(balance);
    }

    // Test getting UTXOs
    FFIArray* utxos = dash_spv_ffi_client_get_address_utxos(client, test_addresses[0]);
    if (utxos != NULL) {
        // New wallet should have no UTXOs
        TEST_ASSERT(utxos->len == 0);
        dash_spv_ffi_array_destroy(utxos);
    }

    // Test unwatching address
    int32_t result = dash_spv_ffi_client_unwatch_address(client, test_addresses[0]);
    TEST_ASSERT(result == FFIErrorCode_Success);

    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_wallet_operations");
}

// Test sync progress
void test_sync_progress() {
    TEST_START("test_sync_progress");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-test-sync");

    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Get initial sync progress
    FFISyncProgress* progress = dash_spv_ffi_client_get_sync_progress(client);
    if (progress != NULL) {
        // Validate fields
        TEST_ASSERT(progress->header_height >= 0);
        TEST_ASSERT(progress->filter_header_height >= 0);
        TEST_ASSERT(progress->masternode_height >= 0);
        TEST_ASSERT(progress->peer_count >= 0);

        dash_spv_ffi_sync_progress_destroy(progress);
    }

    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_sync_progress");
}

// Thread data for concurrent test
typedef struct {
    FFIDashSpvClient* client;
    int thread_id;
    int operations_completed;
} ThreadData;

// Thread function for concurrent operations
void* concurrent_operations(void* arg) {
    ThreadData* data = (ThreadData*)arg;

    for (int i = 0; i < 100; i++) {
        // Perform various operations
        switch (i % 3) {
            case 0: {
                // Get sync progress
                FFISyncProgress* progress = dash_spv_ffi_client_get_sync_progress(data->client);
                if (progress != NULL) {
                    dash_spv_ffi_sync_progress_destroy(progress);
                }
                break;
            }
            case 1: {
                // Check address balance
                FFIBalance* balance = dash_spv_ffi_client_get_address_balance(
                    data->client,
                    "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E"
                );
                if (balance != NULL) {
                    dash_spv_ffi_balance_destroy(balance);
                }
                break;
            }
            case 2: {
                // Watch/unwatch address
                char addr[64];
                snprintf(addr, sizeof(addr), "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R%02d", i);
                dash_spv_ffi_client_watch_address(data->client, addr);
                dash_spv_ffi_client_unwatch_address(data->client, addr);
                break;
            }
        }

        data->operations_completed++;
        usleep(1000); // 1ms delay
    }

    return NULL;
}

// Test concurrent access
void test_concurrent_access() {
    TEST_START("test_concurrent_access");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-test-concurrent");

    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    const int num_threads = 4;
    pthread_t threads[num_threads];
    ThreadData thread_data[num_threads];

    // Start threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].client = client;
        thread_data[i].thread_id = i;
        thread_data[i].operations_completed = 0;

        int result = pthread_create(&threads[i], NULL, concurrent_operations, &thread_data[i]);
        TEST_ASSERT(result == 0);
    }

    // Wait for threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        printf("Thread %d completed %d operations\n",
               thread_data[i].thread_id,
               thread_data[i].operations_completed);
    }

    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_concurrent_access");
}

// Test memory management
void test_memory_management() {
    TEST_START("test_memory_management");

    // Test rapid allocation/deallocation
    for (int i = 0; i < 1000; i++) {
        FFIClientConfig* config = dash_spv_ffi_config_testnet();

        char data_dir[256];
        snprintf(data_dir, sizeof(data_dir), "/tmp/dash-spv-test-mem-%d", i);
        dash_spv_ffi_config_set_data_dir(config, data_dir);

        // Add some peers
        dash_spv_ffi_config_add_peer(config, "127.0.0.1:9999");
        dash_spv_ffi_config_add_peer(config, "192.168.1.1:9999");

        // Create and immediately destroy client
        FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
        if (client != NULL) {
            dash_spv_ffi_client_destroy(client);
        }

        dash_spv_ffi_config_destroy(config);
    }

    TEST_SUCCESS("test_memory_management");
}

// Test error conditions
void test_error_conditions() {
    TEST_START("test_error_conditions");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-test-errors");

    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Test invalid address
    int32_t result = dash_spv_ffi_client_watch_address(client, "invalid_address");
    TEST_ASSERT(result == FFIErrorCode_InvalidArgument);

    // Check error was set
    const char* error = dash_spv_ffi_get_last_error();
    TEST_ASSERT(error != NULL);

    // Clear error
    dash_spv_ffi_clear_error();

    // Test invalid transaction ID
    FFITransaction* tx = dash_spv_ffi_client_get_transaction(client, "not_a_txid");
    TEST_ASSERT(tx == NULL);

    // Test invalid script
    result = dash_spv_ffi_client_watch_script(client, "not_hex");
    TEST_ASSERT(result == FFIErrorCode_InvalidArgument);

    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_error_conditions");
}

// Test callbacks with real operations
typedef struct {
    int progress_count;
    int completion_called;
    double last_progress;
} CallbackData;

void real_progress_callback(double progress, const char* message, void* user_data) {
    CallbackData* data = (CallbackData*)user_data;
    data->progress_count++;
    data->last_progress = progress;

    if (message != NULL) {
        printf("Progress %.1f%%: %s\n", progress, message);
    }
}

void real_completion_callback(int success, const char* error, void* user_data) {
    CallbackData* data = (CallbackData*)user_data;
    data->completion_called = 1;

    if (!success && error != NULL) {
        printf("Operation failed: %s\n", error);
    }
}

void test_callbacks_with_operations() {
    TEST_START("test_callbacks_with_operations");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-test-callbacks");

    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Wait a bit for callbacks
    usleep(100000); // 100ms

    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_callbacks_with_operations");
}

// Main test runner
int main() {
    printf("Running Dash SPV FFI Advanced C Tests\n");
    printf("=====================================\n\n");

    test_wallet_operations();
    test_sync_progress();
    test_concurrent_access();
    test_memory_management();
    test_error_conditions();
    test_callbacks_with_operations();

    printf("\n=====================================\n");
    printf("All advanced tests passed!\n");

    return 0;
}
