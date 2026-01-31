# Wallet Import FFI Binding

## Overview

The `wallet_manager_import_wallet_from_bytes` FFI function allows importing a previously serialized wallet from bincode bytes into a wallet manager instance.

## Function Signature

```c
bool wallet_manager_import_wallet_from_bytes(
    FFIWalletManager *manager,
    const uint8_t *wallet_bytes,
    size_t wallet_bytes_len,
    uint8_t *wallet_id_out,
    FFIError *error
);
```

## Parameters

- `manager`: Pointer to an FFIWalletManager instance
- `wallet_bytes`: Pointer to bincode-serialized wallet bytes
- `wallet_bytes_len`: Length of the wallet bytes
- `wallet_id_out`: Pointer to a 32-byte buffer that will receive the wallet ID
- `error`: Pointer to an FFIError structure for error reporting (can be NULL)

## Return Value

- `true`: Wallet imported successfully
- `false`: Import failed (check error for details)

## Error Codes

The function may set the following error codes:

- `InvalidInput` (1): Null pointer or invalid length provided
- `SerializationError` (9): Failed to deserialize wallet from bincode
- `InvalidState` (11): Wallet already exists in the manager
- `WalletError` (8): Other wallet-related errors

## Usage Example

```c
#include "key_wallet_ffi.h"

// Load wallet bytes from file or network
uint8_t *wallet_bytes = load_wallet_bytes();
size_t bytes_len = get_wallet_bytes_length();

// Prepare output buffer for wallet ID
uint8_t wallet_id[32];

// Import the wallet
FFIError error = {0};
bool success = wallet_manager_import_wallet_from_bytes(
    manager,
    wallet_bytes,
    bytes_len,
    wallet_id,
    &error
);

if (success) {
    printf("Wallet imported with ID: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", wallet_id[i]);
    }
    printf("\n");
} else {
    printf("Import failed: %s\n", error.message);
    if (error.message) {
        error_message_free(error.message);
    }
}
```

## Building with Bincode Support

To use this function, the FFI library must be built with the `bincode` feature enabled:

```bash
cargo build --features bincode
```

## Serialization Format

The wallet bytes must be in bincode format (version 2.0). The serialization includes:
- Wallet seed and key material
- Account information
- Address pools and indices
- Transaction history
- Other wallet metadata

## Safety Considerations

1. The `wallet_bytes` pointer must remain valid for the duration of the function call
2. The `wallet_id_out` buffer must be at least 32 bytes
3. Do not use the wallet_id_out buffer if the function returns false
4. Always free error messages using `error_message_free()` when done
5. The imported wallet must not already exist in the manager (will fail with InvalidState)

## Thread Safety

The wallet manager uses internal locking, so this function is thread-safe with respect to other wallet manager operations on the same instance.
