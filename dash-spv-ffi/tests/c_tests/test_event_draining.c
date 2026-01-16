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

// Test helper macros
#define TEST_ASSERT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "Assertion failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

#define TEST_SUCCESS(name) printf("✓ %s\n", name)
#define TEST_START(name) printf("Running %s...\n", name)

FFIDashSpvClient* create_simple_test_client() {
    // Create config
    FFIClientConfig* config = dash_spv_ffi_config_new(REGTEST);
    TEST_ASSERT(config != NULL);

    // Set data directory to temporary location
    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "/tmp/dash_spv_test_%d", getpid());
    int result = dash_spv_ffi_config_set_data_dir(config, temp_path);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Set validation mode to none for faster testing
    result = dash_spv_ffi_config_builder_set_validation_mode(config, FFIValidationMode_None);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Create client
    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Clean up config
    dash_spv_ffi_config_destroy(config);

    return client;
}

void test_drain_events_null_client() {
    TEST_START("test_drain_events_null_client");

    // Test with null client pointer
    int result = dash_spv_ffi_client_drain_events(NULL);
    TEST_ASSERT(result == FFIErrorCode_NullPointer);

    // Check error was set
    const char* error = dash_spv_ffi_get_last_error();
    TEST_ASSERT(error != NULL);
    TEST_ASSERT(strstr(error, "Null") != NULL || strstr(error, "null") != NULL || strstr(error, "invalid") != NULL);

    TEST_SUCCESS("test_drain_events_null_client");
}

void test_drain_events_no_events() {
    TEST_START("test_drain_events_no_events");

    FFIDashSpvClient* client = create_simple_test_client();

    // Call drain events - should succeed with no events
    int result = dash_spv_ffi_client_drain_events(client);
    TEST_ASSERT(result == FFIErrorCode_Success);

    dash_spv_ffi_client_destroy(client);
    TEST_SUCCESS("test_drain_events_no_events");
}

void test_drain_events_multiple_calls() {
    TEST_START("test_drain_events_multiple_calls");

    FFIDashSpvClient* client = create_simple_test_client();

    // Make multiple drain calls - should be idempotent
    for (int i = 0; i < 10; i++) {
        int result = dash_spv_ffi_client_drain_events(client);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    dash_spv_ffi_client_destroy(client);
    TEST_SUCCESS("test_drain_events_multiple_calls");
}

void test_drain_events_performance() {
    TEST_START("test_drain_events_performance");

    FFIDashSpvClient* client = create_simple_test_client();

    // Test performance with many calls
    const int num_calls = 1000;
    clock_t start = clock();

    for (int i = 0; i < num_calls; i++) {
        int result = dash_spv_ffi_client_drain_events(client);
        TEST_ASSERT(result == FFIErrorCode_Success);
    }

    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("Performance: %d drain_events calls took %.3f seconds (%.1f μs per call)\n",
           num_calls, elapsed, (elapsed * 1000000) / num_calls);

    // Should be very fast - less than 100ms for 1000 calls
    TEST_ASSERT(elapsed < 0.1);

    dash_spv_ffi_client_destroy(client);
    TEST_SUCCESS("test_drain_events_performance");
}

void test_drain_events_memory_safety() {
    TEST_START("test_drain_events_memory_safety");

    // Test that repeated client creation/destruction with drain events doesn't leak
    for (int iteration = 0; iteration < 5; iteration++) {
        FFIDashSpvClient* client = create_simple_test_client();

        // Multiple rapid drain calls
        for (int i = 0; i < 20; i++) {
            int result = dash_spv_ffi_client_drain_events(client);
            TEST_ASSERT(result == FFIErrorCode_Success);
        }

        dash_spv_ffi_client_destroy(client);
    }

    TEST_SUCCESS("test_drain_events_memory_safety");
}

int main() {
    printf("=== C Tests for dash_spv_ffi_client_drain_events ===\n");

    test_drain_events_null_client();
    test_drain_events_no_events();
    test_drain_events_multiple_calls();
    test_drain_events_performance();
    test_drain_events_memory_safety();

    printf("\n=== All event draining tests passed! ===\n");
    return 0;
}
