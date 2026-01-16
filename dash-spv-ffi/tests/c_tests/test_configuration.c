#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include "../../../key-wallet-ffi/include/key_wallet_ffi.h"
#include "../../dash_spv_ffi.h"

// Define constants for better readability
#define FFIErrorCode_Success 0
#define FFIErrorCode_NullPointer 1
#define FFIValidationMode_None 0
#define FFIValidationMode_Basic 1

// Test helper macros
#define TEST_ASSERT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "Assertion failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

#define TEST_SUCCESS(name) printf("✓ %s\n", name)
#define TEST_START(name) printf("Running %s...\n", name)

void test_worker_threads_basic() {
    TEST_START("test_worker_threads_basic");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    TEST_ASSERT(config != NULL);

    // Test setting worker threads to 0 (auto mode)
    int result = dash_spv_ffi_config_builder_set_worker_threads(config, 0);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test setting specific worker thread counts
    uint32_t thread_counts[] = {1, 2, 4, 8, 16, 32};
    size_t num_counts = sizeof(thread_counts) / sizeof(thread_counts[0]);

    for (size_t i = 0; i < num_counts; i++) {
        result = dash_spv_ffi_config_builder_set_worker_threads(config, thread_counts[i]);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    dash_spv_ffi_config_destroy(config);
    TEST_SUCCESS("test_worker_threads_basic");
}

void test_worker_threads_null_config() {
    TEST_START("test_worker_threads_null_config");

    // Test with null config pointer
    int result = dash_spv_ffi_config_builder_set_worker_threads(NULL, 4);
    TEST_ASSERT(result == FFIErrorCode_NullPointer);

    // Check error was set
    const char* error = dash_spv_ffi_get_last_error();
    TEST_ASSERT(error != NULL);
    TEST_ASSERT(strstr(error, "Null") != NULL || strstr(error, "null") != NULL || strstr(error, "invalid") != NULL);

    TEST_SUCCESS("test_worker_threads_null_config");
}

void test_worker_threads_extreme_values() {
    TEST_START("test_worker_threads_extreme_values");

    FFIClientConfig* config = dash_spv_ffi_config_mainnet();
    TEST_ASSERT(config != NULL);

    // Test large worker thread count
    int result = dash_spv_ffi_config_builder_set_worker_threads(config, 1000);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test maximum value
    result = dash_spv_ffi_config_builder_set_worker_threads(config, UINT32_MAX);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test back to reasonable value
    result = dash_spv_ffi_config_builder_set_worker_threads(config, 4);
    TEST_ASSERT(result == FFIErrorCode_Success);

    dash_spv_ffi_config_destroy(config);
    TEST_SUCCESS("test_worker_threads_extreme_values");
}

void test_worker_threads_with_client_creation() {
    TEST_START("test_worker_threads_with_client_creation");

    // Test that worker thread setting is used when creating client
    uint32_t thread_counts[] = {0, 1, 4, 8};
    size_t num_counts = sizeof(thread_counts) / sizeof(thread_counts[0]);

    for (size_t i = 0; i < num_counts; i++) {
        FFIClientConfig* config = dash_spv_ffi_config_new(REGTEST);
        TEST_ASSERT(config != NULL);

        // Set worker threads
        int result = dash_spv_ffi_config_builder_set_worker_threads(config, thread_counts[i]);
        TEST_ASSERT(result == FFIErrorCode_Success);

        // Set up config for client creation
        char temp_path[256];
        snprintf(temp_path, sizeof(temp_path), "/tmp/dash_spv_worker_test_%d_%zu", getpid(), i);
        result = dash_spv_ffi_config_set_data_dir(config, temp_path);
        TEST_ASSERT(result == FFIErrorCode_Success);

        result = dash_spv_ffi_config_builder_set_validation_mode(config, FFIValidationMode_None);
        TEST_ASSERT(result == FFIErrorCode_Success);

        // Create client - should succeed regardless of worker thread count
        FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
        TEST_ASSERT(client != NULL);

        printf("Created client successfully with %u worker threads\n", thread_counts[i]);

        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }

    TEST_SUCCESS("test_worker_threads_with_client_creation");
}

void test_worker_threads_multiple_configs() {
    TEST_START("test_worker_threads_multiple_configs");

    // Test that different configs can have different worker thread counts
    typedef struct {
        FFIClientConfig* config;
        uint32_t thread_count;
    } ConfigThreadPair;

    ConfigThreadPair pairs[] = {
        {dash_spv_ffi_config_testnet(), 1},
        {dash_spv_ffi_config_mainnet(), 4},
        {dash_spv_ffi_config_new(REGTEST), 8}
    };
    size_t num_pairs = sizeof(pairs) / sizeof(pairs[0]);

    for (size_t i = 0; i < num_pairs; i++) {
        TEST_ASSERT(pairs[i].config != NULL);
        int result = dash_spv_ffi_config_builder_set_worker_threads(pairs[i].config, pairs[i].thread_count);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    // Clean up all configs
    for (size_t i = 0; i < num_pairs; i++) {
        dash_spv_ffi_config_destroy(pairs[i].config);
    }

    TEST_SUCCESS("test_worker_threads_multiple_configs");
}

void test_worker_threads_repeated_setting() {
    TEST_START("test_worker_threads_repeated_setting");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    TEST_ASSERT(config != NULL);

    // Test repeated setting of worker threads
    for (int i = 0; i < 10; i++) {
        int result = dash_spv_ffi_config_builder_set_worker_threads(config, 4);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    // Test setting different values in sequence
    uint32_t sequence[] = {0, 1, 0, 8, 0, 16, 0};
    size_t sequence_len = sizeof(sequence) / sizeof(sequence[0]);

    for (size_t i = 0; i < sequence_len; i++) {
        int result = dash_spv_ffi_config_builder_set_worker_threads(config, sequence[i]);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    dash_spv_ffi_config_destroy(config);
    TEST_SUCCESS("test_worker_threads_repeated_setting");
}

void test_worker_threads_performance() {
    TEST_START("test_worker_threads_performance");

    FFIClientConfig* config = dash_spv_ffi_config_new(REGTEST);
    TEST_ASSERT(config != NULL);

    // Test performance of setting worker threads many times
    const int num_calls = 1000;
    clock_t start = clock();

    for (int i = 0; i < num_calls; i++) {
        uint32_t thread_count = (i % 8) + 1; // 1-8 threads
        int result = dash_spv_ffi_config_builder_set_worker_threads(config, thread_count);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("Performance: %d worker thread settings took %.3f seconds (%.1f μs per call)\n",
           num_calls, elapsed, (elapsed * 1000000) / num_calls);

    // Should be very fast
    TEST_ASSERT(elapsed < 0.01);

    dash_spv_ffi_config_destroy(config);
    TEST_SUCCESS("test_worker_threads_performance");
}

void test_worker_threads_edge_cases() {
    TEST_START("test_worker_threads_edge_cases");

    // Test with different network configs
    FFINetwork networks[] = {DASH, TESTNET, REGTEST, DEVNET};
    size_t num_networks = sizeof(networks) / sizeof(networks[0]);

    for (size_t i = 0; i < num_networks; i++) {
        FFIClientConfig* config = dash_spv_ffi_config_new(networks[i]);
        TEST_ASSERT(config != NULL);

        // Set worker threads
        int result = dash_spv_ffi_config_builder_set_worker_threads(config, 2);
        TEST_ASSERT(result == FFIErrorCode_Success);

        // Test setting to 0 (auto)
        result = dash_spv_ffi_config_builder_set_worker_threads(config, 0);
        TEST_ASSERT(result == FFIErrorCode_Success);

        dash_spv_ffi_config_destroy(config);
    }

    TEST_SUCCESS("test_worker_threads_edge_cases");
}

void test_worker_threads_memory_safety() {
    TEST_START("test_worker_threads_memory_safety");

    // Test that repeated config creation/destruction doesn't leak
    for (int iteration = 0; iteration < 10; iteration++) {
        FFIClientConfig* config = dash_spv_ffi_config_testnet();
        TEST_ASSERT(config != NULL);

        // Set various worker thread counts
        uint32_t counts[] = {0, 1, 2, 4, 8, 0};
        size_t num_counts = sizeof(counts) / sizeof(counts[0]);

        for (size_t i = 0; i < num_counts; i++) {
            int result = dash_spv_ffi_config_builder_set_worker_threads(config, counts[i]);
            TEST_ASSERT(result == FFIErrorCode_Success);
        }

        dash_spv_ffi_config_destroy(config);
    }

    TEST_SUCCESS("test_worker_threads_memory_safety");
}

int main() {
    printf("=== C Tests for dash_spv_ffi_config_builder_set_worker_threads ===\n");

    test_worker_threads_basic();
    test_worker_threads_null_config();
    test_worker_threads_extreme_values();
    test_worker_threads_with_client_creation();
    test_worker_threads_multiple_configs();
    test_worker_threads_repeated_setting();
    test_worker_threads_performance();
    test_worker_threads_edge_cases();
    test_worker_threads_memory_safety();

    printf("\n=== All worker thread configuration tests passed! ===\n");
    return 0;
}
