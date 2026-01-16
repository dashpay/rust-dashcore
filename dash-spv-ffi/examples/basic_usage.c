#include <stdio.h>
#include <stdlib.h>
#include "../include/dash_spv_ffi.h"

int main() {
    // Initialize logging
    if (dash_spv_ffi_init_logging("info", true, NULL, 0) != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }

    // Create a configuration for testnet
    FFIConfig* builder = dash_spv_ffi_config_builder_testnet();
    if (builder == NULL) {
        fprintf(stderr, "Failed to create config builder\n");
        return 1;
    }

    // Set data directory
    if (dash_spv_ffi_config_builder_set_storage_path(builder, "/tmp/dash-spv-test") != 0) {
        fprintf(stderr, "Failed to set data dir\n");
        dash_spv_ffi_config_builder_destroy(builder);
        return 1;
    }

    FFIConfig* config = dash_spv_ffi_config_builder_build(builder);

    // Create the client
    FFIDashSpvClient* client = dash_spv_ffi_client_new(config);
    if (client == NULL) {
        const char* error = dash_spv_ffi_get_last_error();
        fprintf(stderr, "Failed to create client: %s\n", error);
        dash_spv_ffi_config_destroy(config);
        return 1;
    }

    printf("Successfully created Dash SPV client!\n");

    // Clean up
    dash_spv_ffi_client_destroy(client);
    dash_spv_ffi_config_destroy(config);

    return 0;
}
