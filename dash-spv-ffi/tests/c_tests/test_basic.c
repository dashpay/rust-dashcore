#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "../../dash_spv_ffi.h"

// Test helper macros
#define TEST_ASSERT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "Assertion failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

#define TEST_SUCCESS(name) printf("✓ %s\n", name)
#define TEST_START(name) printf("Running %s...\n", name)

// Test basic configuration
void test_config_creation() {
    TEST_START("test_config_creation");

    // Test creating config for each network
    FFIClientConfig* config_mainnet = dash_spv_ffi_config_new(FFINetwork_Dash);
    TEST_ASSERT(config_mainnet != NULL);

    FFIClientConfig* config_testnet = dash_spv_ffi_config_new(FFINetwork_Testnet);
    TEST_ASSERT(config_testnet != NULL);

    FFIClientConfig* config_regtest = dash_spv_ffi_config_new(FFINetwork_Regtest);
    TEST_ASSERT(config_regtest != NULL);

    // Test convenience constructors
    FFIClientConfig* config_testnet2 = dash_spv_ffi_config_testnet();
    TEST_ASSERT(config_testnet2 != NULL);

    // Clean up
    dash_spv_ffi_config_destroy(config_mainnet);
    dash_spv_ffi_config_destroy(config_testnet);
    dash_spv_ffi_config_destroy(config_regtest);
    dash_spv_ffi_config_destroy(config_testnet2);

    TEST_SUCCESS("test_config_creation");
}

// Test configuration setters
void test_config_setters() {
    TEST_START("test_config_setters");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    TEST_ASSERT(config != NULL);

    // Test setting data directory
    int32_t result = dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-test");
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test setting validation mode
    result = dash_spv_ffi_config_builder_set_validation_mode(config, FFIValidationMode_Basic);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test setting max peers
    result = dash_spv_ffi_config_builder_set_max_peers(config, 16);
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test adding peers
    result = dash_spv_ffi_config_add_peer(config, "127.0.0.1:9999");
    TEST_ASSERT(result == FFIErrorCode_Success);

    result = dash_spv_ffi_config_add_peer(config, "192.168.1.1:9999");
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test setting user agent
    result = dash_spv_ffi_config_set_user_agent(config, "TestClient/1.0");
    TEST_ASSERT(result == FFIErrorCode_Success);

    // Test boolean setters
    result = dash_spv_ffi_config_set_relay_transactions(config, 1);
    TEST_ASSERT(result == FFIErrorCode_Success);

    result = dash_spv_ffi_config_set_filter_load(config, 1);
    TEST_ASSERT(result == FFIErrorCode_Success);

    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_config_setters");
}

// Test configuration getters
void test_config_getters() {
    TEST_START("test_config_getters");

    FFIClientConfig* config = dash_spv_ffi_config_new(FFINetwork_Testnet);
    TEST_ASSERT(config != NULL);

    // Set some values
    dash_spv_ffi_config_set_data_dir(config, "/tmp/test-dir");

    // Test getting network
    FFINetwork network = dash_spv_ffi_config_get_network(config);
    TEST_ASSERT(network == FFINetwork_Testnet);

    // Test getting data directory
    FFIString data_dir = dash_spv_ffi_config_get_storage_path(config);
    if (data_dir.ptr != NULL) {
        TEST_ASSERT(strcmp(data_dir.ptr, "/tmp/test-dir") == 0);
        dash_spv_ffi_string_destroy(data_dir);
    }

    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_config_getters");
}

// Test error handling
void test_error_handling() {
    TEST_START("test_error_handling");

    // Clear any existing error
    dash_spv_ffi_clear_error();

    // Test that no error is set initially
    const char* error = dash_spv_ffi_get_last_error();
    TEST_ASSERT(error == NULL);

    // Trigger an error by using NULL config
    int32_t result = dash_spv_ffi_config_set_data_dir(NULL, "/tmp");
    TEST_ASSERT(result == FFIErrorCode_NullPointer);

    // Check error was set
    error = dash_spv_ffi_get_last_error();
    TEST_ASSERT(error != NULL);
    TEST_ASSERT(strlen(error) > 0);

    // Clear error
    dash_spv_ffi_clear_error();
    error = dash_spv_ffi_get_last_error();
    TEST_ASSERT(error == NULL);

    TEST_SUCCESS("test_error_handling");
}

// Test client creation
void test_client_creation() {
    TEST_START("test_client_creation");

    FFIClientConfig* config = dash_spv_ffi_config_testnet();
    TEST_ASSERT(config != NULL);

    // Set required configuration
    dash_spv_ffi_config_set_data_dir(config, "/tmp/dash-spv-test");

    // Create client
    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    TEST_ASSERT(client != NULL);

    // Clean up
    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    TEST_SUCCESS("test_client_creation");
}

// Test string operations
void test_string_operations() {
    TEST_START("test_string_operations");

    // Test creating and destroying strings
    FFIString str = {0};
    str.ptr = strdup("Hello, FFI!");
    TEST_ASSERT(str.ptr != NULL);

    // Note: In real usage, strings would come from FFI functions
    free(str.ptr); // Using free instead of dash_spv_ffi_string_destroy for test string

    TEST_SUCCESS("test_string_operations");
}

// Test array operations
void test_array_operations() {
    TEST_START("test_array_operations");

    // Arrays would typically come from FFI functions
    // Here we just test the structure
    FFIArray array = {0};
    array.data = NULL;
    array.len = 0;

    // Test destroying empty array
    dash_spv_ffi_array_destroy(array);

    TEST_SUCCESS("test_array_operations");
}

// Test address validation
void test_address_validation() {
    TEST_START("test_address_validation");

    // Test valid mainnet address
    int32_t valid = dash_spv_ffi_validate_address("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E", FFINetwork_Dash);
    TEST_ASSERT(valid == 1);

    // Test invalid address
    valid = dash_spv_ffi_validate_address("invalid_address", FFINetwork_Dash);
    TEST_ASSERT(valid == 0);

    // Test empty address
    valid = dash_spv_ffi_validate_address("", FFINetwork_Dash);
    TEST_ASSERT(valid == 0);

    // Test Bitcoin address (should be invalid for Dash)
    valid = dash_spv_ffi_validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", FFINetwork_Dash);
    TEST_ASSERT(valid == 0);

    TEST_SUCCESS("test_address_validation");
}

// Test null pointer handling
void test_null_pointer_handling() {
    TEST_START("test_null_pointer_handling");

    // Test all functions with NULL pointers

    // Config functions
    TEST_ASSERT(dash_spv_ffi_config_set_data_dir(NULL, NULL) == FFIErrorCode_NullPointer);
    TEST_ASSERT(dash_spv_ffi_config_builder_set_validation_mode(NULL, FFIValidationMode_Basic) == FFIErrorCode_NullPointer);
    TEST_ASSERT(dash_spv_ffi_config_builder_set_max_peers(NULL, 10) == FFIErrorCode_NullPointer);
    TEST_ASSERT(dash_spv_ffi_config_add_peer(NULL, NULL) == FFIErrorCode_NullPointer);

    // Client functions
    TEST_ASSERT(dash_spv_ffi_client_new(NULL) == NULL);
    TEST_ASSERT(dash_spv_ffi_client_start(NULL) == FFIErrorCode_NullPointer);
    TEST_ASSERT(dash_spv_ffi_client_stop(NULL) == FFIErrorCode_NullPointer);

    // Destruction functions (should handle NULL gracefully)
    dash_spv_ffi_client_destroy(NULL);
    dash_spv_ffi_config_destroy(NULL);

    FFIString null_string = {0};
    dash_spv_ffi_string_destroy(null_string);

    FFIArray null_array = {0};
    dash_spv_ffi_array_destroy(null_array);

    TEST_SUCCESS("test_null_pointer_handling");
}

// Test callbacks
void progress_callback(double progress, const char* message, void* user_data) {
    int* called = (int*)user_data;
    *called = 1;

    TEST_ASSERT(progress >= 0.0 && progress <= 100.0);
    // Message can be NULL
}

void completion_callback(int success, const char* error, void* user_data) {
    int* called = (int*)user_data;
    *called = 1;

    // Error should be NULL on success, non-NULL on failure
    if (success) {
        TEST_ASSERT(error == NULL);
    }
}

void test_callbacks() {
    TEST_START("test_callbacks");

    int progress_called = 0;
    int completion_called = 0;

    FFICallbacks callbacks = {0};
    callbacks.on_progress = progress_callback;
    callbacks.on_completion = completion_callback;
    callbacks.on_data = NULL;
    callbacks.user_data = &progress_called; // Simplified for test

    // In a real test, these callbacks would be invoked by FFI functions
    // Here we just test the structure

    TEST_SUCCESS("test_callbacks");
}

// Main test runner
int main() {
    printf("Running Dash SPV FFI C Tests\n");
    printf("=============================\n\n");

    test_config_creation();
    test_config_setters();
    test_config_getters();
    test_error_handling();
    test_client_creation();
    test_string_operations();
    test_array_operations();
    test_address_validation();
    test_null_pointer_handling();
    test_callbacks();

    printf("\n=============================\n");
    printf("All tests passed!\n");

    return 0;
}
