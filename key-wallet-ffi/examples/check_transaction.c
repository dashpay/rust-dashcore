// Example of using wallet_check_transaction FFI function

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// FFI type definitions (normally these would be in a header file)
typedef enum {
    Dash = 0,
    Testnet = 1,
    Regtest = 2,
    Devnet = 3
} FFINetwork;

typedef enum {
    Mempool = 0,
    InBlock = 1,
    InChainLockedBlock = 2
} FFITransactionContext;

typedef struct {
    bool is_relevant;
    uint64_t total_received;
    uint64_t total_sent;
    uint32_t affected_accounts_count;
} FFITransactionCheckResult;

typedef struct {
    int32_t code;
    char* message;
} FFIError;

// External function declarations
extern void* wallet_create_from_mnemonic(
    const char* mnemonic,
    const char* passphrase,
    FFINetwork network,
    FFIError* error
);

extern bool wallet_check_transaction(
    void* wallet,
    FFINetwork network,
    const uint8_t* tx_bytes,
    size_t tx_len,
    FFITransactionContext context_type,
    uint32_t block_height,
    const uint8_t* block_hash,  // 32 bytes if not null
    uint64_t timestamp,
    bool update_state,
    FFITransactionCheckResult* result_out,
    FFIError* error
);

extern void wallet_free(void* wallet);

int main() {
    // Example mnemonic (DO NOT USE IN PRODUCTION)
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    FFIError error = {0};
    FFINetwork network = Testnet;

    // Create wallet
    void* wallet = wallet_create_from_mnemonic(mnemonic, NULL, network, &error);
    if (!wallet) {
        printf("Failed to create wallet: %s\n", error.message);
        return 1;
    }

    printf("Wallet created successfully\n");

    // Example transaction bytes (this would be a real transaction in practice)
    uint8_t tx_bytes[] = { /* ... transaction data ... */ };
    size_t tx_len = sizeof(tx_bytes);

    // Check if transaction belongs to wallet
    FFITransactionCheckResult result = {0};
    bool success = wallet_check_transaction(
        wallet,
        network,
        tx_bytes,
        tx_len,
        Mempool,  // Transaction is in mempool
        0,        // No block height for mempool tx
        NULL,     // No block hash for mempool tx
        0,        // No timestamp
        false,    // Don't update wallet state
        &result,
        &error
    );

    if (success) {
        if (result.is_relevant) {
            printf("Transaction belongs to wallet!\n");
            printf("  Total received: %llu\n", (unsigned long long)result.total_received);
            printf("  Total sent: %llu\n", (unsigned long long)result.total_sent);
            printf("  Affected accounts: %u\n", result.affected_accounts_count);
        } else {
            printf("Transaction does not belong to wallet\n");
        }
    } else {
        printf("Failed to check transaction: %s\n", error.message);
    }

    // Check a confirmed transaction
    uint8_t block_hash[32] = { /* ... block hash ... */ };
    success = wallet_check_transaction(
        wallet,
        network,
        tx_bytes,
        tx_len,
        InBlock,      // Transaction is in a block
        650000,       // Block height
        block_hash,   // Block hash
        1234567890,   // Unix timestamp
        true,         // Update wallet state
        &result,
        &error
    );

    if (success && result.is_relevant) {
        printf("Confirmed transaction processed and wallet state updated\n");
    }

    // Clean up
    wallet_free(wallet);

    return 0;
}
