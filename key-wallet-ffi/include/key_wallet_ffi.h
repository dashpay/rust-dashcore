/**
 * Key Wallet FFI - C Header File
 * 
 * This header provides C-compatible function declarations for the key-wallet
 * Rust library FFI bindings.
 */

#ifndef KEY_WALLET_FFI_H
#define KEY_WALLET_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * Error codes returned by FFI functions
 */
typedef enum FFIErrorCode {
    FFI_SUCCESS = 0,
    FFI_INVALID_INPUT = 1,
    FFI_ALLOCATION_FAILED = 2,
    FFI_INVALID_MNEMONIC = 3,
    FFI_INVALID_DERIVATION_PATH = 4,
    FFI_INVALID_NETWORK = 5,
    FFI_INVALID_ADDRESS = 6,
    FFI_INVALID_TRANSACTION = 7,
    FFI_WALLET_ERROR = 8,
    FFI_SERIALIZATION_ERROR = 9,
    FFI_NOT_FOUND = 10,
    FFI_INVALID_STATE = 11,
} FFIErrorCode;

/**
 * Error structure containing error code and message
 */
typedef struct FFIError {
    FFIErrorCode code;
    char* message;
} FFIError;

/* ============================================================================
 * Network Types
 * ============================================================================ */

/**
 * Network type enumeration
 */
typedef enum FFINetwork {
    NETWORK_DASH = 0,
    NETWORK_TESTNET = 1,
    NETWORK_REGTEST = 2,
    NETWORK_DEVNET = 3,
} FFINetwork;

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

/**
 * Opaque wallet handle
 */
typedef struct FFIWallet FFIWallet;

/**
 * UTXO structure
 */
typedef struct FFIUTXO {
    uint8_t txid[32];
    uint32_t vout;
    uint64_t amount;
    char* address;
    uint8_t* script_pubkey;
    size_t script_len;
    uint32_t height;
    uint32_t confirmations;
} FFIUTXO;

/**
 * Balance structure
 */
typedef struct FFIBalance {
    uint64_t confirmed;
    uint64_t unconfirmed;
    uint64_t immature;
    uint64_t total;
} FFIBalance;

/**
 * Transaction output for building
 */
typedef struct FFITxOutput {
    const char* address;
    uint64_t amount;
} FFITxOutput;

/* ============================================================================
 * Mnemonic Functions
 * ============================================================================ */

/**
 * Generate a new mnemonic with specified word count (12, 15, 18, 21, or 24)
 * 
 * @param word_count Number of words in the mnemonic
 * @param error Pointer to error structure
 * @return Mnemonic string (must be freed with mnemonic_free) or NULL on error
 */
char* mnemonic_generate(uint32_t word_count, FFIError* error);

/**
 * Validate a mnemonic phrase
 * 
 * @param mnemonic The mnemonic phrase to validate
 * @param error Pointer to error structure
 * @return true if valid, false otherwise
 */
bool mnemonic_validate(const char* mnemonic, FFIError* error);

/**
 * Convert mnemonic to seed with optional passphrase
 * 
 * @param mnemonic The mnemonic phrase
 * @param passphrase Optional passphrase (can be NULL)
 * @param seed_out Buffer to receive seed (must be at least 64 bytes)
 * @param seed_len Pointer to receive seed length
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool mnemonic_to_seed(
    const char* mnemonic,
    const char* passphrase,
    uint8_t* seed_out,
    size_t* seed_len,
    FFIError* error
);

/**
 * Free a mnemonic string
 * 
 * @param mnemonic The mnemonic string to free
 */
void mnemonic_free(char* mnemonic);

/* ============================================================================
 * Wallet Creation and Management
 * ============================================================================ */

/**
 * Create a new wallet from mnemonic
 * 
 * @param mnemonic The mnemonic phrase
 * @param passphrase Optional passphrase (can be NULL)
 * @param network The network type
 * @param error Pointer to error structure
 * @return Wallet handle or NULL on error
 */
FFIWallet* wallet_create_from_mnemonic(
    const char* mnemonic,
    const char* passphrase,
    FFINetwork network,
    FFIError* error
);

/**
 * Create a new wallet from seed
 * 
 * @param seed The seed bytes
 * @param seed_len Length of seed
 * @param network The network type
 * @param error Pointer to error structure
 * @return Wallet handle or NULL on error
 */
FFIWallet* wallet_create_from_seed(
    const uint8_t* seed,
    size_t seed_len,
    FFINetwork network,
    FFIError* error
);

/**
 * Create a watch-only wallet from extended public key
 * 
 * @param xpub The extended public key string
 * @param network The network type
 * @param error Pointer to error structure
 * @return Wallet handle or NULL on error
 */
FFIWallet* wallet_create_watch_only(
    const char* xpub,
    FFINetwork network,
    FFIError* error
);

/**
 * Get wallet ID (32-byte hash)
 * 
 * @param wallet The wallet handle
 * @param id_out Buffer to receive ID (must be 32 bytes)
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_get_id(
    const FFIWallet* wallet,
    uint8_t* id_out,
    FFIError* error
);

/**
 * Get wallet mnemonic (if available)
 * 
 * @param wallet The wallet handle
 * @param error Pointer to error structure
 * @return Mnemonic string (must be freed) or NULL if not available/error
 */
char* wallet_get_mnemonic(
    const FFIWallet* wallet,
    FFIError* error
);

/**
 * Free a wallet
 * 
 * @param wallet The wallet handle to free
 */
void wallet_free(FFIWallet* wallet);

/* ============================================================================
 * Account Management
 * ============================================================================ */

/**
 * Create or get an account
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param account_type Account type (0=standard, 1=coinjoin, 2=identity)
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_get_account(
    FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    uint32_t account_type,
    FFIError* error
);

/**
 * Get number of accounts
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param error Pointer to error structure
 * @return Number of accounts
 */
uint32_t wallet_get_account_count(
    const FFIWallet* wallet,
    FFINetwork network,
    FFIError* error
);

/* ============================================================================
 * Address Derivation
 * ============================================================================ */

/**
 * Derive a new receive address
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param error Pointer to error structure
 * @return Address string (must be freed) or NULL on error
 */
char* wallet_derive_receive_address(
    FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    FFIError* error
);

/**
 * Derive a new change address
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param error Pointer to error structure
 * @return Address string (must be freed) or NULL on error
 */
char* wallet_derive_change_address(
    FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    FFIError* error
);

/**
 * Get address at specific index
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param is_change Whether this is a change address
 * @param address_index The address index
 * @param error Pointer to error structure
 * @return Address string (must be freed) or NULL on error
 */
char* wallet_get_address_at_index(
    const FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    bool is_change,
    uint32_t address_index,
    FFIError* error
);

/**
 * Mark address as used
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param address The address to mark as used
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_mark_address_used(
    FFIWallet* wallet,
    FFINetwork network,
    const char* address,
    FFIError* error
);

/**
 * Get all addresses for an account
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param addresses_out Pointer to receive address array
 * @param count_out Pointer to receive address count
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_get_all_addresses(
    const FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    char*** addresses_out,
    size_t* count_out,
    FFIError* error
);

/**
 * Free address string
 * 
 * @param address The address string to free
 */
void address_free(char* address);

/**
 * Free address array
 * 
 * @param addresses The address array to free
 * @param count Number of addresses
 */
void address_array_free(char** addresses, size_t count);

/* ============================================================================
 * Key Derivation
 * ============================================================================ */

/**
 * Get extended private key for account
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param error Pointer to error structure
 * @return Extended private key string (must be freed) or NULL on error
 */
char* wallet_get_account_xpriv(
    const FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    FFIError* error
);

/**
 * Get extended public key for account
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param error Pointer to error structure
 * @return Extended public key string (must be freed) or NULL on error
 */
char* wallet_get_account_xpub(
    const FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    FFIError* error
);

/**
 * Derive private key for address
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param derivation_path The derivation path string
 * @param error Pointer to error structure
 * @return Private key string (must be freed) or NULL on error
 */
char* wallet_derive_private_key(
    const FFIWallet* wallet,
    FFINetwork network,
    const char* derivation_path,
    FFIError* error
);

/**
 * Derive public key for address
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param derivation_path The derivation path string
 * @param key_out Buffer to receive public key (33 bytes)
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_derive_public_key(
    const FFIWallet* wallet,
    FFINetwork network,
    const char* derivation_path,
    uint8_t* key_out,
    FFIError* error
);

/* ============================================================================
 * UTXO Management
 * ============================================================================ */

/**
 * Add UTXO to wallet
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param txid Transaction ID (32 bytes)
 * @param vout Output index
 * @param amount Amount in satoshis
 * @param address The address
 * @param script_pubkey The script public key
 * @param script_len Length of script
 * @param height Block height
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_add_utxo(
    FFIWallet* wallet,
    FFINetwork network,
    const uint8_t* txid,
    uint32_t vout,
    uint64_t amount,
    const char* address,
    const uint8_t* script_pubkey,
    size_t script_len,
    uint32_t height,
    FFIError* error
);

/**
 * Remove UTXO from wallet
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param txid Transaction ID (32 bytes)
 * @param vout Output index
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_remove_utxo(
    FFIWallet* wallet,
    FFINetwork network,
    const uint8_t* txid,
    uint32_t vout,
    FFIError* error
);

/**
 * Get all UTXOs
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param utxos_out Pointer to receive UTXO array
 * @param count_out Pointer to receive UTXO count
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_get_utxos(
    const FFIWallet* wallet,
    FFINetwork network,
    FFIUTXO** utxos_out,
    size_t* count_out,
    FFIError* error
);

/**
 * Free UTXO array
 * 
 * @param utxos The UTXO array to free
 * @param count Number of UTXOs
 */
void utxo_array_free(FFIUTXO** utxos, size_t count);

/* ============================================================================
 * Balance
 * ============================================================================ */

/**
 * Get wallet balance
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param balance_out Pointer to receive balance
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_get_balance(
    const FFIWallet* wallet,
    FFINetwork network,
    FFIBalance* balance_out,
    FFIError* error
);

/**
 * Get account balance
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param balance_out Pointer to receive balance
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_get_account_balance(
    const FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    FFIBalance* balance_out,
    FFIError* error
);

/* ============================================================================
 * Transaction Building
 * ============================================================================ */

/**
 * Build a transaction
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param outputs Array of transaction outputs
 * @param outputs_count Number of outputs
 * @param fee_per_kb Fee per kilobyte in satoshis
 * @param tx_bytes_out Pointer to receive transaction bytes
 * @param tx_len_out Pointer to receive transaction length
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_build_transaction(
    FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    const FFITxOutput* outputs,
    size_t outputs_count,
    uint64_t fee_per_kb,
    uint8_t** tx_bytes_out,
    size_t* tx_len_out,
    FFIError* error
);

/**
 * Sign a transaction
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param tx_bytes Transaction bytes
 * @param tx_len Transaction length
 * @param signed_tx_out Pointer to receive signed transaction bytes
 * @param signed_len_out Pointer to receive signed transaction length
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_sign_transaction(
    const FFIWallet* wallet,
    FFINetwork network,
    const uint8_t* tx_bytes,
    size_t tx_len,
    uint8_t** signed_tx_out,
    size_t* signed_len_out,
    FFIError* error
);

/**
 * Free transaction bytes
 * 
 * @param tx_bytes The transaction bytes to free
 */
void transaction_bytes_free(uint8_t* tx_bytes);

/* ============================================================================
 * Transaction Checking
 * ============================================================================ */

/**
 * Check if a transaction belongs to the wallet
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param tx_bytes Transaction bytes
 * @param tx_len Transaction length
 * @param block_height Block height
 * @param is_confirmed Whether the transaction is confirmed
 * @param belongs_to_wallet Pointer to receive result
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_check_transaction(
    FFIWallet* wallet,
    FFINetwork network,
    const uint8_t* tx_bytes,
    size_t tx_len,
    uint32_t block_height,
    bool is_confirmed,
    bool* belongs_to_wallet,
    FFIError* error
);

/* ============================================================================
 * Gap Limit Management
 * ============================================================================ */

/**
 * Set gap limit for account
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param gap_limit The gap limit
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool wallet_set_gap_limit(
    FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    uint32_t gap_limit,
    FFIError* error
);

/**
 * Get gap limit for account
 * 
 * @param wallet The wallet handle
 * @param network The network type
 * @param account_index The account index
 * @param error Pointer to error structure
 * @return Gap limit value
 */
uint32_t wallet_get_gap_limit(
    const FFIWallet* wallet,
    FFINetwork network,
    uint32_t account_index,
    FFIError* error
);

/* ============================================================================
 * Wallet Backup and Restore
 * ============================================================================ */

/**
 * Export wallet to JSON
 * 
 * @param wallet The wallet handle
 * @param include_private_keys Whether to include private keys
 * @param error Pointer to error structure
 * @return JSON string (must be freed) or NULL on error
 */
char* wallet_export_json(
    const FFIWallet* wallet,
    bool include_private_keys,
    FFIError* error
);

/**
 * Import wallet from JSON
 * 
 * @param json The JSON string
 * @param error Pointer to error structure
 * @return Wallet handle or NULL on error
 */
FFIWallet* wallet_import_json(
    const char* json,
    FFIError* error
);

/* ============================================================================
 * BIP38 Support
 * ============================================================================ */

#ifdef KEY_WALLET_FFI_BIP38_ENABLED

/**
 * Encrypt a private key with BIP38
 * 
 * @param private_key The private key string
 * @param passphrase The passphrase
 * @param network The network type
 * @param error Pointer to error structure
 * @return Encrypted key string (must be freed) or NULL on error
 */
char* bip38_encrypt_private_key(
    const char* private_key,
    const char* passphrase,
    FFINetwork network,
    FFIError* error
);

/**
 * Decrypt a BIP38 encrypted private key
 * 
 * @param encrypted_key The encrypted key string
 * @param passphrase The passphrase
 * @param error Pointer to error structure
 * @return Private key string (must be freed) or NULL on error
 */
char* bip38_decrypt_private_key(
    const char* encrypted_key,
    const char* passphrase,
    FFIError* error
);

#endif /* KEY_WALLET_FFI_BIP38_ENABLED */

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Validate an address
 * 
 * @param address The address string
 * @param network The network type
 * @param error Pointer to error structure
 * @return true if valid, false otherwise
 */
bool address_validate(
    const char* address,
    FFINetwork network,
    FFIError* error
);

/**
 * Get address type
 * 
 * @param address The address string
 * @param network The network type
 * @param error Pointer to error structure
 * @return Address type (0=P2PKH, 1=P2SH, etc.) or -1 on error
 */
uint32_t address_get_type(
    const char* address,
    FFINetwork network,
    FFIError* error
);

/**
 * Parse derivation path
 * 
 * @param path The derivation path string
 * @param indices_out Pointer to receive indices array
 * @param hardened_out Pointer to receive hardened flags array
 * @param count_out Pointer to receive count
 * @param error Pointer to error structure
 * @return true on success, false on error
 */
bool derivation_path_parse(
    const char* path,
    uint32_t** indices_out,
    bool** hardened_out,
    size_t* count_out,
    FFIError* error
);

/**
 * Free derivation path arrays
 * 
 * @param indices The indices array
 * @param hardened The hardened flags array
 */
void derivation_path_free(
    uint32_t* indices,
    bool* hardened
);

/* ============================================================================
 * Memory Management
 * ============================================================================ */

/**
 * Free an error message
 * 
 * @param message The error message to free
 */
void error_message_free(char* message);

/**
 * Free a string
 * 
 * @param s The string to free
 */
void string_free(char* s);

/* ============================================================================
 * Initialization and Version
 * ============================================================================ */

/**
 * Initialize the library
 * 
 * @return true on success, false on error
 */
bool key_wallet_ffi_initialize(void);

/**
 * Get library version
 * 
 * @return Version string (do not free)
 */
const char* key_wallet_ffi_version(void);

#ifdef __cplusplus
}
#endif

#endif /* KEY_WALLET_FFI_H */