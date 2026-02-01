# Key-Wallet FFI API Documentation

This document provides a comprehensive reference for all FFI (Foreign Function Interface) functions available in the key-wallet-ffi library.

**Auto-generated**: This documentation is automatically generated from the source code. Do not edit manually.

**Total Functions**: 261

## Table of Contents

- [Initialization](#initialization)
- [Error Handling](#error-handling)
- [Wallet Manager](#wallet-manager)
- [Wallet Operations](#wallet-operations)
- [Account Management](#account-management)
- [Address Management](#address-management)
- [Transaction Management](#transaction-management)
- [Key Management](#key-management)
- [Mnemonic Operations](#mnemonic-operations)
- [Utility Functions](#utility-functions)

## Function Reference

### Initialization

Functions: 2

| Function | Description | Module |
|----------|-------------|--------|
| `key_wallet_ffi_initialize` | Initialize the library | lib |
| `key_wallet_ffi_version` | Get library version  Returns a static string that should NOT be freed by the... | lib |

### Error Handling

Functions: 4

| Function | Description | Module |
|----------|-------------|--------|
| `account_result_free_error` | Free an account result's error message (if any) Note: This does NOT free the... | account |
| `error_message_free` | Free an error message  # Safety  - `message` must be a valid pointer to a C... | error |
| `managed_account_result_free_error` | Free a managed account result's error message (if any) Note: This does NOT... | managed_account |
| `managed_platform_account_result_free_error` | Free a managed platform account result's error message (if any) Note: This... | managed_account |

### Wallet Manager

Functions: 19

| Function | Description | Module |
|----------|-------------|--------|
| `wallet_manager_add_wallet_from_mnemonic` | Add a wallet from mnemonic to the manager (backward compatibility)  # Safety... | wallet_manager |
| `wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes` | No description | wallet_manager |
| `wallet_manager_add_wallet_from_mnemonic_with_options` | Add a wallet from mnemonic to the manager with options  # Safety  -... | wallet_manager |
| `wallet_manager_create` | Create a new wallet manager | wallet_manager |
| `wallet_manager_current_height` | Get current height for a network  # Safety  - `manager` must be a valid... | wallet_manager |
| `wallet_manager_describe` | Describe the wallet manager for a given network and return a newly allocated... | wallet_manager |
| `wallet_manager_free` | Free wallet manager  # Safety  - `manager` must be a valid pointer to an... | wallet_manager |
| `wallet_manager_free_addresses` | Free address array  # Safety  - `addresses` must be a valid pointer to an... | wallet_manager |
| `wallet_manager_free_string` | Free a string previously returned by wallet manager APIs | wallet_manager |
| `wallet_manager_free_wallet_bytes` | No description | wallet_manager |
| `wallet_manager_free_wallet_ids` | Free wallet IDs buffer  # Safety  - `wallet_ids` must be a valid pointer to... | wallet_manager |
| `wallet_manager_get_managed_wallet_info` | Get managed wallet info from the manager  Returns a reference to the managed... | wallet_manager |
| `wallet_manager_get_wallet` | Get a wallet from the manager  Returns a reference to the wallet if found  #... | wallet_manager |
| `wallet_manager_get_wallet_balance` | Get wallet balance  Returns the confirmed and unconfirmed balance for a... | wallet_manager |
| `wallet_manager_get_wallet_ids` | Get wallet IDs  # Safety  - `manager` must be a valid pointer to an... | wallet_manager |
| `wallet_manager_import_wallet_from_bytes` | No description | wallet_manager |
| `wallet_manager_network` | Get the network for this wallet manager  # Safety  - `manager` must be a... | wallet_manager |
| `wallet_manager_process_transaction` | Process a transaction through all wallets  Checks a transaction against all... | wallet_manager |
| `wallet_manager_wallet_count` | Get wallet count  # Safety  - `manager` must be a valid pointer to an... | wallet_manager |

### Wallet Operations

Functions: 65

| Function | Description | Module |
|----------|-------------|--------|
| `account_get_parent_wallet_id` | Get the parent wallet ID of an account  # Safety  - `account` must be a... | account |
| `bls_account_get_parent_wallet_id` | No description | account |
| `eddsa_account_get_parent_wallet_id` | No description | account |
| `ffi_managed_wallet_free` | Free a managed wallet (FFIManagedWalletInfo type)  # Safety  -... | transaction_checking |
| `key_wallet_derive_address_from_key` | Derive an address from a private key  # Safety - `private_key` must be a... | derivation |
| `key_wallet_derive_address_from_seed` | Derive an address from a seed at a specific derivation path  # Safety -... | derivation |
| `key_wallet_derive_private_key_from_seed` | Derive a private key from a seed at a specific derivation path  # Safety -... | derivation |
| `managed_account_get_parent_wallet_id` | Get the parent wallet ID of a managed account  Note: ManagedAccount doesn't... | managed_account |
| `managed_wallet_check_transaction` | Check if a transaction belongs to the wallet  This function checks a... | transaction_checking |
| `managed_wallet_free` | Free managed wallet info  # Safety  - `managed_wallet` must be a valid... | managed_wallet |
| `managed_wallet_generate_addresses_to_index` | Generate addresses up to a specific index in a pool  This ensures that... | address_pool |
| `managed_wallet_get_account` | Get a managed account from a managed wallet  This function gets a... | managed_account |
| `managed_wallet_get_account_collection` | Get managed account collection for a specific network from wallet manager  #... | managed_account_collection |
| `managed_wallet_get_account_count` | Get number of accounts in a managed wallet  # Safety  - `manager` must be a... | managed_account |
| `managed_wallet_get_address_pool_info` | Get address pool information for an account  # Safety  - `managed_wallet`... | address_pool |
| `managed_wallet_get_balance` | Get wallet balance from managed wallet info  Returns the balance breakdown... | managed_wallet |
| `managed_wallet_get_bip_44_external_address_range` | Get BIP44 external (receive) addresses in the specified range  Returns... | managed_wallet |
| `managed_wallet_get_bip_44_internal_address_range` | Get BIP44 internal (change) addresses in the specified range  Returns... | managed_wallet |
| `managed_wallet_get_dashpay_external_account` | Get a managed DashPay external account by composite key  # Safety - Pointers... | managed_account |
| `managed_wallet_get_dashpay_receiving_account` | Get a managed DashPay receiving funds account by composite key  # Safety -... | managed_account |
| `managed_wallet_get_next_bip44_change_address` | Get the next unused change address  Generates the next unused change address... | managed_wallet |
| `managed_wallet_get_next_bip44_receive_address` | Get the next unused receive address  Generates the next unused receive... | managed_wallet |
| `managed_wallet_get_platform_payment_account` | Get a managed platform payment account from a managed wallet  Platform... | managed_account |
| `managed_wallet_get_top_up_account_with_registration_index` | Get a managed IdentityTopUp account with a specific registration index  This... | managed_account |
| `managed_wallet_get_utxos` | Get all UTXOs from managed wallet info  # Safety  - `managed_info` must be a... | utxo |
| `managed_wallet_info_free` | Free managed wallet info returned by wallet_manager_get_managed_wallet_info ... | managed_wallet |
| `managed_wallet_mark_address_used` | Mark an address as used in the pool  This updates the pool's tracking of... | address_pool |
| `managed_wallet_set_gap_limit` | Set the gap limit for an address pool  The gap limit determines how many... | address_pool |
| `managed_wallet_synced_height` | Get current synced height from wallet info  # Safety  - `managed_wallet`... | managed_wallet |
| `wallet_add_account` | Add an account to the wallet without xpub  # Safety  This function... | wallet |
| `wallet_add_account_with_string_xpub` | Add an account to the wallet with xpub as string  # Safety  This function... | wallet |
| `wallet_add_account_with_xpub_bytes` | Add an account to the wallet with xpub as byte array  # Safety  This... | wallet |
| `wallet_add_dashpay_external_account_with_xpub_bytes` | Add a DashPay external (watch-only) account with xpub bytes  # Safety -... | wallet |
| `wallet_add_dashpay_receiving_account` | Add a DashPay receiving funds account  # Safety - `wallet` must be a valid... | wallet |
| `wallet_add_platform_payment_account` | Add a Platform Payment account (DIP-17) to the wallet  Platform Payment... | wallet |
| `wallet_build_and_sign_transaction` | Build and sign a transaction using the wallet's managed info  This is the... | transaction |
| `wallet_build_transaction` | Build a transaction (unsigned)  This creates an unsigned transaction | transaction |
| `wallet_check_transaction` | Check if a transaction belongs to the wallet using ManagedWalletInfo  #... | transaction |
| `wallet_create_from_mnemonic` | Create a new wallet from mnemonic (backward compatibility - single network) ... | wallet |
| `wallet_create_from_mnemonic_with_options` | Create a new wallet from mnemonic with options  # Safety  - `mnemonic` must... | wallet |
| `wallet_create_from_seed` | Create a new wallet from seed (backward compatibility)  # Safety  - `seed`... | wallet |
| `wallet_create_from_seed_with_options` | Create a new wallet from seed with options  # Safety  - `seed` must be a... | wallet |
| `wallet_create_managed_wallet` | Create a managed wallet from a regular wallet  This creates a... | transaction_checking |
| `wallet_create_random` | Create a new random wallet (backward compatibility)  # Safety  - `error`... | wallet |
| `wallet_create_random_with_options` | Create a new random wallet with options  # Safety  - `account_options` must... | wallet |
| `wallet_derive_extended_private_key` | Derive extended private key at a specific path Returns an opaque... | keys |
| `wallet_derive_extended_public_key` | Derive extended public key at a specific path Returns an opaque... | keys |
| `wallet_derive_private_key` | Derive private key at a specific path Returns an opaque FFIPrivateKey... | keys |
| `wallet_derive_private_key_as_wif` | Derive private key at a specific path and return as WIF string  # Safety  -... | keys |
| `wallet_derive_public_key` | Derive public key at a specific path Returns an opaque FFIPublicKey pointer... | keys |
| `wallet_derive_public_key_as_hex` | Derive public key at a specific path and return as hex string  # Safety  -... | keys |
| `wallet_free` | Free a wallet  # Safety  - `wallet` must be a valid pointer to an FFIWallet... | wallet |
| `wallet_free_const` | Free a const wallet handle  This is a const-safe wrapper for wallet_free()... | wallet |
| `wallet_get_account` | Get an account handle for a specific account type Returns a result... | account |
| `wallet_get_account_collection` | Get account collection for a specific network from wallet  # Safety  -... | account_collection |
| `wallet_get_account_count` | Get number of accounts  # Safety  - `wallet` must be a valid pointer to an... | account |
| `wallet_get_account_xpriv` | Get extended private key for account  # Safety  - `wallet` must be a valid... | keys |
| `wallet_get_account_xpub` | Get extended public key for account  # Safety  - `wallet` must be a valid... | keys |
| `wallet_get_id` | Get wallet ID (32-byte hash)  # Safety  - `wallet` must be a valid pointer... | wallet |
| `wallet_get_top_up_account_with_registration_index` | Get an IdentityTopUp account handle with a specific registration index This... | account |
| `wallet_get_utxos` | Get all UTXOs (deprecated - use managed_wallet_get_utxos instead)  # Safety ... | utxo |
| `wallet_get_xpub` | Get extended public key for account  # Safety  - `wallet` must be a valid... | wallet |
| `wallet_has_mnemonic` | Check if wallet has mnemonic  # Safety  - `wallet` must be a valid pointer... | wallet |
| `wallet_is_watch_only` | Check if wallet is watch-only  # Safety  - `wallet` must be a valid pointer... | wallet |
| `wallet_sign_transaction` | Sign a transaction  # Safety  - `wallet` must be a valid pointer to an... | transaction |

### Account Management

Functions: 109

| Function | Description | Module |
|----------|-------------|--------|
| `account_collection_count` | Get the total number of accounts in the collection  # Safety  - `collection`... | account_collection |
| `account_collection_free` | Free an account collection handle  # Safety  - `collection` must be a valid... | account_collection |
| `account_collection_get_bip32_account` | Get a BIP32 account by index from the collection  # Safety  - `collection`... | account_collection |
| `account_collection_get_bip32_indices` | Get all BIP32 account indices  # Safety  - `collection` must be a valid... | account_collection |
| `account_collection_get_bip44_account` | Get a BIP44 account by index from the collection  # Safety  - `collection`... | account_collection |
| `account_collection_get_bip44_indices` | Get all BIP44 account indices  # Safety  - `collection` must be a valid... | account_collection |
| `account_collection_get_coinjoin_account` | Get a CoinJoin account by index from the collection  # Safety  -... | account_collection |
| `account_collection_get_coinjoin_indices` | Get all CoinJoin account indices  # Safety  - `collection` must be a valid... | account_collection |
| `account_collection_get_identity_invitation` | Get the identity invitation account if it exists  # Safety  - `collection`... | account_collection |
| `account_collection_get_identity_registration` | Get the identity registration account if it exists  # Safety  - `collection`... | account_collection |
| `account_collection_get_identity_topup` | Get an identity topup account by registration index  # Safety  -... | account_collection |
| `account_collection_get_identity_topup_indices` | Get all identity topup registration indices  # Safety  - `collection` must... | account_collection |
| `account_collection_get_identity_topup_not_bound` | Get the identity topup not bound account if it exists  # Safety  -... | account_collection |
| `account_collection_get_provider_operator_keys` | Get the provider operator keys account if it exists Note: Returns null if... | account_collection |
| `account_collection_get_provider_owner_keys` | Get the provider owner keys account if it exists  # Safety  - `collection`... | account_collection |
| `account_collection_get_provider_platform_keys` | Get the provider platform keys account if it exists Note: Returns null if... | account_collection |
| `account_collection_get_provider_voting_keys` | Get the provider voting keys account if it exists  # Safety  - `collection`... | account_collection |
| `account_collection_has_identity_invitation` | Check if identity invitation account exists  # Safety  - `collection` must... | account_collection |
| `account_collection_has_identity_registration` | Check if identity registration account exists  # Safety  - `collection` must... | account_collection |
| `account_collection_has_identity_topup_not_bound` | Check if identity topup not bound account exists  # Safety  - `collection`... | account_collection |
| `account_collection_has_provider_operator_keys` | Check if provider operator keys account exists  # Safety  - `collection`... | account_collection |
| `account_collection_has_provider_owner_keys` | Check if provider owner keys account exists  # Safety  - `collection` must... | account_collection |
| `account_collection_has_provider_platform_keys` | Check if provider platform keys account exists  # Safety  - `collection`... | account_collection |
| `account_collection_has_provider_voting_keys` | Check if provider voting keys account exists  # Safety  - `collection` must... | account_collection |
| `account_collection_summary` | Get a human-readable summary of all accounts in the collection  Returns a... | account_collection |
| `account_collection_summary_data` | Get structured account collection summary data  Returns a struct containing... | account_collection |
| `account_collection_summary_free` | Free an account collection summary and all its allocated memory  # Safety  -... | account_collection |
| `account_derive_extended_private_key_at` | Derive an extended private key from an account at a given index, using the... | account_derivation |
| `account_derive_extended_private_key_from_mnemonic` | Derive an extended private key from a mnemonic + optional passphrase at the... | account_derivation |
| `account_derive_extended_private_key_from_seed` | Derive an extended private key from a raw seed buffer at the given index | account_derivation |
| `account_derive_private_key_as_wif_at` | Derive a private key from an account at a given chain/index and return as... | account_derivation |
| `account_derive_private_key_at` | Derive a private key (secp256k1) from an account at a given chain/index,... | account_derivation |
| `account_derive_private_key_from_mnemonic` | Derive a private key from a mnemonic + optional passphrase at the given index | account_derivation |
| `account_derive_private_key_from_seed` | Derive a private key from a raw seed buffer at the given index | account_derivation |
| `account_free` | Free an account handle  # Safety  - `account` must be a valid pointer to an... | account |
| `account_get_account_type` | Get the account type of an account  # Safety  - `account` must be a valid... | account |
| `account_get_extended_public_key_as_string` | Get the extended public key of an account as a string  # Safety  - `account`... | account |
| `account_get_is_watch_only` | Check if an account is watch-only  # Safety  - `account` must be a valid... | account |
| `account_get_network` | Get the network of an account  # Safety  - `account` must be a valid pointer... | account |
| `bls_account_derive_private_key_from_mnemonic` | No description | account_derivation |
| `bls_account_derive_private_key_from_seed` | No description | account_derivation |
| `bls_account_free` | No description | account |
| `bls_account_get_account_type` | No description | account |
| `bls_account_get_extended_public_key_as_string` | No description | account |
| `bls_account_get_is_watch_only` | No description | account |
| `bls_account_get_network` | No description | account |
| `derivation_bip44_account_path` | Derive a BIP44 account path (m/44'/5'/account') | derivation |
| `eddsa_account_derive_private_key_from_mnemonic` | No description | account_derivation |
| `eddsa_account_derive_private_key_from_seed` | No description | account_derivation |
| `eddsa_account_free` | No description | account |
| `eddsa_account_get_account_type` | No description | account |
| `eddsa_account_get_extended_public_key_as_string` | No description | account |
| `eddsa_account_get_is_watch_only` | No description | account |
| `eddsa_account_get_network` | No description | account |
| `managed_account_collection_count` | Get the total number of accounts in the managed collection  # Safety  -... | managed_account_collection |
| `managed_account_collection_free` | Free a managed account collection handle  # Safety  - `collection` must be a... | managed_account_collection |
| `managed_account_collection_free_platform_payment_keys` | Free platform payment keys array returned by managed_account_collection_get_p... | managed_account_collection |
| `managed_account_collection_get_bip32_account` | Get a BIP32 account by index from the managed collection  # Safety  -... | managed_account_collection |
| `managed_account_collection_get_bip32_indices` | Get all BIP32 account indices from managed collection  # Safety  -... | managed_account_collection |
| `managed_account_collection_get_bip44_account` | Get a BIP44 account by index from the managed collection  # Safety  -... | managed_account_collection |
| `managed_account_collection_get_bip44_indices` | Get all BIP44 account indices from managed collection  # Safety  -... | managed_account_collection |
| `managed_account_collection_get_coinjoin_account` | Get a CoinJoin account by index from the managed collection  # Safety  -... | managed_account_collection |
| `managed_account_collection_get_coinjoin_indices` | Get all CoinJoin account indices from managed collection  # Safety  -... | managed_account_collection |
| `managed_account_collection_get_identity_invitation` | Get the identity invitation account if it exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_get_identity_registration` | Get the identity registration account if it exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_get_identity_topup` | Get an identity topup account by registration index from managed collection ... | managed_account_collection |
| `managed_account_collection_get_identity_topup_indices` | Get all identity topup registration indices from managed collection  #... | managed_account_collection |
| `managed_account_collection_get_identity_topup_not_bound` | Get the identity topup not bound account if it exists in managed collection ... | managed_account_collection |
| `managed_account_collection_get_platform_payment_account` | Get a Platform Payment account by account index and key class from the... | managed_account_collection |
| `managed_account_collection_get_platform_payment_keys` | Get all Platform Payment account keys from managed collection  Returns an... | managed_account_collection |
| `managed_account_collection_get_provider_operator_keys` | Get the provider operator keys account if it exists in managed collection... | managed_account_collection |
| `managed_account_collection_get_provider_owner_keys` | Get the provider owner keys account if it exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_get_provider_platform_keys` | Get the provider platform keys account if it exists in managed collection... | managed_account_collection |
| `managed_account_collection_get_provider_voting_keys` | Get the provider voting keys account if it exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_has_identity_invitation` | Check if identity invitation account exists in managed collection  # Safety ... | managed_account_collection |
| `managed_account_collection_has_identity_registration` | Check if identity registration account exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_has_identity_topup_not_bound` | Check if identity topup not bound account exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_has_platform_payment_accounts` | Check if there are any Platform Payment accounts in the managed collection ... | managed_account_collection |
| `managed_account_collection_has_provider_operator_keys` | Check if provider operator keys account exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_has_provider_owner_keys` | Check if provider owner keys account exists in managed collection  # Safety ... | managed_account_collection |
| `managed_account_collection_has_provider_platform_keys` | Check if provider platform keys account exists in managed collection  #... | managed_account_collection |
| `managed_account_collection_has_provider_voting_keys` | Check if provider voting keys account exists in managed collection  # Safety... | managed_account_collection |
| `managed_account_collection_platform_payment_count` | Get the number of Platform Payment accounts in the managed collection  #... | managed_account_collection |
| `managed_account_collection_summary` | Get a human-readable summary of all accounts in the managed collection ... | managed_account_collection |
| `managed_account_collection_summary_data` | Get structured account collection summary data for managed collection ... | managed_account_collection |
| `managed_account_collection_summary_free` | Free a managed account collection summary and all its allocated memory  #... | managed_account_collection |
| `managed_account_free` | Free a managed account handle  # Safety  - `account` must be a valid pointer... | managed_account |
| `managed_account_free_transactions` | Free transactions array returned by managed_account_get_transactions  #... | managed_account |
| `managed_account_get_account_type` | Get the account type of a managed account  # Safety  - `account` must be a... | managed_account |
| `managed_account_get_address_pool` | Get an address pool from a managed account by type  This function returns... | managed_account |
| `managed_account_get_balance` | Get the balance of a managed account  # Safety  - `account` must be a valid... | managed_account |
| `managed_account_get_external_address_pool` | Get the external address pool from a managed account  This function returns... | managed_account |
| `managed_account_get_index` | Get the account index from a managed account  Returns the primary account... | managed_account |
| `managed_account_get_internal_address_pool` | Get the internal address pool from a managed account  This function returns... | managed_account |
| `managed_account_get_is_watch_only` | Check if a managed account is watch-only  # Safety  - `account` must be a... | managed_account |
| `managed_account_get_network` | Get the network of a managed account  # Safety  - `account` must be a valid... | managed_account |
| `managed_account_get_transaction_count` | Get the number of transactions in a managed account  # Safety  - `account`... | managed_account |
| `managed_account_get_transactions` | Get all transactions from a managed account  Returns an array of... | managed_account |
| `managed_account_get_utxo_count` | Get the number of UTXOs in a managed account  # Safety  - `account` must be... | managed_account |
| `managed_platform_account_free` | Free a managed platform account handle  # Safety  - `account` must be a... | managed_account |
| `managed_platform_account_get_account_index` | Get the account index of a managed platform account  # Safety  - `account`... | managed_account |
| `managed_platform_account_get_address_pool` | Get the address pool from a managed platform account  Platform accounts only... | managed_account |
| `managed_platform_account_get_credit_balance` | Get the total credit balance of a managed platform account  Returns the... | managed_account |
| `managed_platform_account_get_duff_balance` | Get the total balance in duffs of a managed platform account  Returns the... | managed_account |
| `managed_platform_account_get_funded_address_count` | Get the number of funded addresses in a managed platform account  # Safety ... | managed_account |
| `managed_platform_account_get_is_watch_only` | Check if a managed platform account is watch-only  # Safety  - `account`... | managed_account |
| `managed_platform_account_get_key_class` | Get the key class of a managed platform account  # Safety  - `account` must... | managed_account |
| `managed_platform_account_get_network` | Get the network of a managed platform account  # Safety  - `account` must be... | managed_account |
| `managed_platform_account_get_total_address_count` | Get the total number of addresses in a managed platform account  # Safety  -... | managed_account |

### Address Management

Functions: 10

| Function | Description | Module |
|----------|-------------|--------|
| `address_array_free` | Free address array  # Safety  - `addresses` must be a valid pointer to an... | address |
| `address_free` | Free address string  # Safety  - `address` must be a valid pointer created... | address |
| `address_get_type` | Get address type  Returns: - 0: P2PKH address - 1: P2SH address - 2: Other... | address |
| `address_info_array_free` | Free an array of FFIAddressInfo structures  # Safety  - `infos` must be a... | address_pool |
| `address_info_free` | Free a single FFIAddressInfo structure  # Safety  - `info` must be a valid... | address_pool |
| `address_pool_free` | Free an address pool handle  # Safety  - `pool` must be a valid pointer to... | address_pool |
| `address_pool_get_address_at_index` | Get a single address info at a specific index from the pool  Returns... | address_pool |
| `address_pool_get_addresses_in_range` | Get a range of addresses from the pool  Returns an array of FFIAddressInfo... | address_pool |
| `address_to_pubkey_hash` | Extract public key hash from P2PKH address  # Safety - `address` must be a... | transaction |
| `address_validate` | Validate an address  # Safety  - `address` must be a valid null-terminated C... | address |

### Transaction Management

Functions: 14

| Function | Description | Module |
|----------|-------------|--------|
| `transaction_add_input` | Add an input to a transaction  # Safety - `tx` must be a valid pointer to an... | transaction |
| `transaction_add_output` | Add an output to a transaction  # Safety - `tx` must be a valid pointer to... | transaction |
| `transaction_bytes_free` | Free transaction bytes  # Safety  - `tx_bytes` must be a valid pointer... | transaction |
| `transaction_check_result_free` | Free a transaction check result  # Safety  - `result` must be a valid... | transaction_checking |
| `transaction_classify` | Get the transaction classification for routing  Returns a string describing... | transaction_checking |
| `transaction_create` | Create a new empty transaction  # Returns - Pointer to FFITransaction on... | transaction |
| `transaction_deserialize` | Deserialize a transaction  # Safety - `data` must be a valid pointer to... | transaction |
| `transaction_destroy` | Destroy a transaction  # Safety - `tx` must be a valid pointer to an... | transaction |
| `transaction_get_txid` | Get the transaction ID  # Safety - `tx` must be a valid pointer to an... | transaction |
| `transaction_get_txid_from_bytes` | Get transaction ID from raw transaction bytes  # Safety - `tx_bytes` must be... | transaction |
| `transaction_serialize` | Serialize a transaction  # Safety - `tx` must be a valid pointer to an... | transaction |
| `transaction_sighash` | Calculate signature hash for an input  # Safety - `tx` must be a valid... | transaction |
| `transaction_sign_input` | Sign a transaction input  # Safety - `tx` must be a valid pointer to an... | transaction |
| `utxo_array_free` | Free UTXO array  # Safety  - `utxos` must be a valid pointer to an array of... | utxo |

### Key Management

Functions: 14

| Function | Description | Module |
|----------|-------------|--------|
| `bip38_decrypt_private_key` | Decrypt a BIP38 encrypted private key  # Safety  This function is unsafe... | bip38 |
| `bip38_encrypt_private_key` | Encrypt a private key with BIP38  # Safety  This function is unsafe because... | bip38 |
| `derivation_derive_private_key_from_seed` | Derive private key for a specific path from seed  # Safety  - `seed` must be... | derivation |
| `derivation_new_master_key` | Create a new master extended private key from seed  # Safety  - `seed` must... | derivation |
| `extended_private_key_free` | Free an extended private key  # Safety  - `key` must be a valid pointer... | keys |
| `extended_private_key_get_private_key` | Get the private key from an extended private key  Extracts the non-extended... | keys |
| `extended_private_key_to_string` | Get extended private key as string (xprv format)  Returns the extended... | keys |
| `extended_public_key_free` | Free an extended public key  # Safety  - `key` must be a valid pointer... | keys |
| `extended_public_key_get_public_key` | Get the public key from an extended public key  Extracts the non-extended... | keys |
| `extended_public_key_to_string` | Get extended public key as string (xpub format)  Returns the extended public... | keys |
| `private_key_free` | Free a private key  # Safety  - `key` must be a valid pointer created by... | keys |
| `private_key_to_wif` | Get private key as WIF string from FFIPrivateKey  # Safety  - `key` must be... | keys |
| `public_key_free` | Free a public key  # Safety  - `key` must be a valid pointer created by... | keys |
| `public_key_to_hex` | Get public key as hex string from FFIPublicKey  # Safety  - `key` must be a... | keys |

### Mnemonic Operations

Functions: 6

| Function | Description | Module |
|----------|-------------|--------|
| `mnemonic_free` | Free a mnemonic string  # Safety  - `mnemonic` must be a valid pointer... | mnemonic |
| `mnemonic_generate` | Generate a new mnemonic with specified word count (12, 15, 18, 21, or 24) | mnemonic |
| `mnemonic_generate_with_language` | Generate a new mnemonic with specified language and word count | mnemonic |
| `mnemonic_to_seed` | Convert mnemonic to seed with optional passphrase  # Safety  - `mnemonic`... | mnemonic |
| `mnemonic_validate` | Validate a mnemonic phrase  # Safety  - `mnemonic` must be a valid... | mnemonic |
| `mnemonic_word_count` | Get word count from mnemonic  # Safety  - `mnemonic` must be a valid... | mnemonic |

### Utility Functions

Functions: 18

| Function | Description | Module |
|----------|-------------|--------|
| `derivation_bip44_payment_path` | Derive a BIP44 payment path (m/44'/5'/account'/change/index) | derivation |
| `derivation_coinjoin_path` | Derive CoinJoin path (m/9'/5'/4'/account') | derivation |
| `derivation_identity_authentication_path` | Derive identity authentication path (m/9'/5'/5'/0'/identity_index'/key_index') | derivation |
| `derivation_identity_registration_path` | Derive identity registration path (m/9'/5'/5'/1'/index') | derivation |
| `derivation_identity_topup_path` | Derive identity top-up path (m/9'/5'/5'/2'/identity_index'/top_up_index') | derivation |
| `derivation_path_free` | Free derivation path arrays Note: This function expects the count to... | keys |
| `derivation_path_parse` | Convert derivation path string to indices  # Safety  - `path` must be a... | keys |
| `derivation_string_free` | Free derivation path string  # Safety  - `s` must be a valid pointer to a C... | derivation |
| `derivation_xpriv_free` | Free extended private key  # Safety  - `xpriv` must be a valid pointer to an... | derivation |
| `derivation_xpriv_to_string` | Get extended private key as string  # Safety  - `xpriv` must be a valid... | derivation |
| `derivation_xpriv_to_xpub` | Derive public key from extended private key  # Safety  - `xpriv` must be a... | derivation |
| `derivation_xpub_fingerprint` | Get fingerprint from extended public key (4 bytes)  # Safety  - `xpub` must... | derivation |
| `derivation_xpub_free` | Free extended public key  # Safety  - `xpub` must be a valid pointer to an... | derivation |
| `derivation_xpub_to_string` | Get extended public key as string  # Safety  - `xpub` must be a valid... | derivation |
| `ffi_network_get_name` | No description | types |
| `free_u32_array` | Free a u32 array allocated by this library  # Safety  - `array` must be a... | account_collection |
| `script_p2pkh` | Create a P2PKH script pubkey  # Safety - `pubkey_hash` must be a valid... | transaction |
| `string_free` | Free a string  # Safety  - `s` must be a valid pointer created by C string... | utils |

## Detailed Function Documentation

### Initialization - Detailed

#### `key_wallet_ffi_initialize`

```c
key_wallet_ffi_initialize() -> bool
```

**Description:**
Initialize the library

**Module:** `lib`

---

#### `key_wallet_ffi_version`

```c
key_wallet_ffi_version() -> *const c_char
```

**Description:**
Get library version  Returns a static string that should NOT be freed by the caller

**Module:** `lib`

---

### Error Handling - Detailed

#### `account_result_free_error`

```c
account_result_free_error(result: *mut FFIAccountResult) -> ()
```

**Description:**
Free an account result's error message (if any) Note: This does NOT free the account handle itself - use account_free for that  # Safety  - `result` must be a valid pointer to an FFIAccountResult - The error_message field must be either null or a valid CString allocated by this library - The caller must ensure the result pointer remains valid for the duration of this call

**Safety:**
- `result` must be a valid pointer to an FFIAccountResult - The error_message field must be either null or a valid CString allocated by this library - The caller must ensure the result pointer remains valid for the duration of this call

**Module:** `account`

---

#### `error_message_free`

```c
error_message_free(message: *mut c_char) -> ()
```

**Description:**
Free an error message  # Safety  - `message` must be a valid pointer to a C string that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `message` must be a valid pointer to a C string that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `error`

---

#### `managed_account_result_free_error`

```c
managed_account_result_free_error(result: *mut FFIManagedAccountResult) -> ()
```

**Description:**
Free a managed account result's error message (if any) Note: This does NOT free the account handle itself - use managed_account_free for that  # Safety  - `result` must be a valid pointer to an FFIManagedAccountResult - The error_message field must be either null or a valid CString allocated by this library - The caller must ensure the result pointer remains valid for the duration of this call

**Safety:**
- `result` must be a valid pointer to an FFIManagedAccountResult - The error_message field must be either null or a valid CString allocated by this library - The caller must ensure the result pointer remains valid for the duration of this call

**Module:** `managed_account`

---

#### `managed_platform_account_result_free_error`

```c
managed_platform_account_result_free_error(result: *mut FFIManagedPlatformAccountResult,) -> ()
```

**Description:**
Free a managed platform account result's error message (if any) Note: This does NOT free the account handle itself - use managed_platform_account_free for that  # Safety  - `result` must be a valid pointer to an FFIManagedPlatformAccountResult - The error_message field must be either null or a valid CString allocated by this library - The caller must ensure the result pointer remains valid for the duration of this call

**Safety:**
- `result` must be a valid pointer to an FFIManagedPlatformAccountResult - The error_message field must be either null or a valid CString allocated by this library - The caller must ensure the result pointer remains valid for the duration of this call

**Module:** `managed_account`

---

### Wallet Manager - Detailed

#### `wallet_manager_add_wallet_from_mnemonic`

```c
wallet_manager_add_wallet_from_mnemonic(manager: *mut FFIWalletManager, mnemonic: *const c_char, passphrase: *const c_char, error: *mut FFIError,) -> bool
```

**Description:**
Add a wallet from mnemonic to the manager (backward compatibility)  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

#### `wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes`

```c
wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(manager: *mut FFIWalletManager, mnemonic: *const c_char, passphrase: *const c_char, birth_height: c_uint, account_options: *const crate::types::FFIWalletAccountCreationOptions, downgrade_to_pubkey_wallet: bool, allow_external_signing: bool, wallet_bytes_out: *mut *mut u8, wallet_bytes_len_out: *mut usize, wallet_id_out: *mut u8, error: *mut FFIError,) -> bool
```

**Module:** `wallet_manager`

---

#### `wallet_manager_add_wallet_from_mnemonic_with_options`

```c
wallet_manager_add_wallet_from_mnemonic_with_options(manager: *mut FFIWalletManager, mnemonic: *const c_char, passphrase: *const c_char, account_options: *const crate::types::FFIWalletAccountCreationOptions, error: *mut FFIError,) -> bool
```

**Description:**
Add a wallet from mnemonic to the manager with options  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

#### `wallet_manager_create`

```c
wallet_manager_create(network: FFINetwork, error: *mut FFIError,) -> *mut FFIWalletManager
```

**Description:**
Create a new wallet manager

**Module:** `wallet_manager`

---

#### `wallet_manager_current_height`

```c
wallet_manager_current_height(manager: *const FFIWalletManager, error: *mut FFIError,) -> c_uint
```

**Description:**
Get current height for a network  # Safety  - `manager` must be a valid pointer to an FFIWalletManager - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

#### `wallet_manager_describe`

```c
wallet_manager_describe(manager: *const FFIWalletManager, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Describe the wallet manager for a given network and return a newly allocated C string.  # Safety - `manager` must be a valid pointer to an `FFIWalletManager` - Callers must free the returned string with `wallet_manager_free_string`

**Safety:**
- `manager` must be a valid pointer to an `FFIWalletManager` - Callers must free the returned string with `wallet_manager_free_string`

**Module:** `wallet_manager`

---

#### `wallet_manager_free`

```c
wallet_manager_free(manager: *mut FFIWalletManager) -> ()
```

**Description:**
Free wallet manager  # Safety  - `manager` must be a valid pointer to an FFIWalletManager that was created by this library - The pointer must not be used after calling this function - This function must only be called once per manager

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager that was created by this library - The pointer must not be used after calling this function - This function must only be called once per manager

**Module:** `wallet_manager`

---

#### `wallet_manager_free_addresses`

```c
wallet_manager_free_addresses(addresses: *mut *mut c_char, count: usize) -> ()
```

**Description:**
Free address array  # Safety  - `addresses` must be a valid pointer to an array of C string pointers allocated by this library - `count` must match the original allocation size - Each address pointer in the array must be either null or a valid C string allocated by this library - The pointers must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `addresses` must be a valid pointer to an array of C string pointers allocated by this library - `count` must match the original allocation size - Each address pointer in the array must be either null or a valid C string allocated by this library - The pointers must not be used after calling this function - This function must only be called once per allocation

**Module:** `wallet_manager`

---

#### `wallet_manager_free_string`

```c
wallet_manager_free_string(value: *mut c_char) -> ()
```

**Description:**
Free a string previously returned by wallet manager APIs.  # Safety - `value` must be either null or a pointer obtained from `wallet_manager_describe` (or other wallet manager FFI helpers that specify this free function). - The pointer must not be used after this call returns.

**Safety:**
- `value` must be either null or a pointer obtained from `wallet_manager_describe` (or other wallet manager FFI helpers that specify this free function). - The pointer must not be used after this call returns.

**Module:** `wallet_manager`

---

#### `wallet_manager_free_wallet_bytes`

```c
wallet_manager_free_wallet_bytes(wallet_bytes: *mut u8, bytes_len: usize) -> ()
```

**Module:** `wallet_manager`

---

#### `wallet_manager_free_wallet_ids`

```c
wallet_manager_free_wallet_ids(wallet_ids: *mut u8, count: usize) -> ()
```

**Description:**
Free wallet IDs buffer  # Safety  - `wallet_ids` must be a valid pointer to a buffer allocated by this library - `count` must match the number of wallet IDs in the buffer - The pointer must not be used after calling this function - This function must only be called once per buffer

**Safety:**
- `wallet_ids` must be a valid pointer to a buffer allocated by this library - `count` must match the number of wallet IDs in the buffer - The pointer must not be used after calling this function - This function must only be called once per buffer

**Module:** `wallet_manager`

---

#### `wallet_manager_get_managed_wallet_info`

```c
wallet_manager_get_managed_wallet_info(manager: *const FFIWalletManager, wallet_id: *const u8, error: *mut FFIError,) -> *mut crate::managed_wallet::FFIManagedWalletInfo
```

**Description:**
Get managed wallet info from the manager  Returns a reference to the managed wallet info if found  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned managed wallet info must be freed with managed_wallet_info_free()

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned managed wallet info must be freed with managed_wallet_info_free()

**Module:** `wallet_manager`

---

#### `wallet_manager_get_wallet`

```c
wallet_manager_get_wallet(manager: *const FFIWalletManager, wallet_id: *const u8, error: *mut FFIError,) -> *const crate::types::FFIWallet
```

**Description:**
Get a wallet from the manager  Returns a reference to the wallet if found  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned wallet must be freed with wallet_free_const()

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned wallet must be freed with wallet_free_const()

**Module:** `wallet_manager`

---

#### `wallet_manager_get_wallet_balance`

```c
wallet_manager_get_wallet_balance(manager: *const FFIWalletManager, wallet_id: *const u8, confirmed_out: *mut u64, unconfirmed_out: *mut u64, error: *mut FFIError,) -> bool
```

**Description:**
Get wallet balance  Returns the confirmed and unconfirmed balance for a specific wallet  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `confirmed_out` must be a valid pointer to a u64 (maps to C uint64_t) - `unconfirmed_out` must be a valid pointer to a u64 (maps to C uint64_t) - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `confirmed_out` must be a valid pointer to a u64 (maps to C uint64_t) - `unconfirmed_out` must be a valid pointer to a u64 (maps to C uint64_t) - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

#### `wallet_manager_get_wallet_ids`

```c
wallet_manager_get_wallet_ids(manager: *const FFIWalletManager, wallet_ids_out: *mut *mut u8, count_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Get wallet IDs  # Safety  - `manager` must be a valid pointer to an FFIWalletManager - `wallet_ids_out` must be a valid pointer to a pointer that will receive the wallet IDs - `count_out` must be a valid pointer to receive the count - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager - `wallet_ids_out` must be a valid pointer to a pointer that will receive the wallet IDs - `count_out` must be a valid pointer to receive the count - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

#### `wallet_manager_import_wallet_from_bytes`

```c
wallet_manager_import_wallet_from_bytes(manager: *mut FFIWalletManager, wallet_bytes: *const u8, wallet_bytes_len: usize, wallet_id_out: *mut u8, error: *mut FFIError,) -> bool
```

**Module:** `wallet_manager`

---

#### `wallet_manager_network`

```c
wallet_manager_network(manager: *const FFIWalletManager, error: *mut FFIError,) -> FFINetwork
```

**Description:**
Get the network for this wallet manager  # Safety  - `manager` must be a valid pointer to an FFIWalletManager - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

#### `wallet_manager_process_transaction`

```c
wallet_manager_process_transaction(manager: *mut FFIWalletManager, tx_bytes: *const u8, tx_len: usize, context: *const crate::types::FFITransactionContextDetails, update_state_if_found: bool, error: *mut FFIError,) -> bool
```

**Description:**
Process a transaction through all wallets  Checks a transaction against all wallets and updates their states if relevant. Returns true if the transaction was relevant to at least one wallet.  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `tx_bytes` must be a valid pointer to transaction bytes - `tx_len` must be the length of the transaction bytes - `context` must be a valid pointer to FFITransactionContextDetails - `update_state_if_found` indicates whether to update wallet state when transaction is relevant - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `tx_bytes` must be a valid pointer to transaction bytes - `tx_len` must be the length of the transaction bytes - `context` must be a valid pointer to FFITransactionContextDetails - `update_state_if_found` indicates whether to update wallet state when transaction is relevant - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

#### `wallet_manager_wallet_count`

```c
wallet_manager_wallet_count(manager: *const FFIWalletManager, error: *mut FFIError,) -> usize
```

**Description:**
Get wallet count  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet_manager`

---

### Wallet Operations - Detailed

#### `account_get_parent_wallet_id`

```c
account_get_parent_wallet_id(account: *const FFIAccount) -> *const u8
```

**Description:**
Get the parent wallet ID of an account  # Safety  - `account` must be a valid pointer to an FFIAccount instance - Returns a pointer to the 32-byte wallet ID, or NULL if not set or account is null - The returned pointer is valid only as long as the account exists - The caller should copy the data if needed for longer use

**Safety:**
- `account` must be a valid pointer to an FFIAccount instance - Returns a pointer to the 32-byte wallet ID, or NULL if not set or account is null - The returned pointer is valid only as long as the account exists - The caller should copy the data if needed for longer use

**Module:** `account`

---

#### `bls_account_get_parent_wallet_id`

```c
bls_account_get_parent_wallet_id(account: *const FFIBLSAccount,) -> *const u8
```

**Module:** `account`

---

#### `eddsa_account_get_parent_wallet_id`

```c
eddsa_account_get_parent_wallet_id(account: *const FFIEdDSAAccount,) -> *const u8
```

**Module:** `account`

---

#### `ffi_managed_wallet_free`

```c
ffi_managed_wallet_free(managed_wallet: *mut FFIManagedWalletInfo) -> ()
```

**Description:**
Free a managed wallet (FFIManagedWalletInfo type)  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - This function must only be called once per managed wallet

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - This function must only be called once per managed wallet

**Module:** `transaction_checking`

---

#### `key_wallet_derive_address_from_key`

```c
key_wallet_derive_address_from_key(private_key: *const u8, network: FFINetwork,) -> *mut c_char
```

**Description:**
Derive an address from a private key  # Safety - `private_key` must be a valid pointer to 32 bytes - `network` is the network for the address  # Returns - Pointer to C string with address (caller must free) - NULL on error

**Safety:**
- `private_key` must be a valid pointer to 32 bytes - `network` is the network for the address

**Module:** `derivation`

---

#### `key_wallet_derive_address_from_seed`

```c
key_wallet_derive_address_from_seed(seed: *const u8, network: FFINetwork, path: *const c_char,) -> *mut c_char
```

**Description:**
Derive an address from a seed at a specific derivation path  # Safety - `seed` must be a valid pointer to 64 bytes - `network` is the network for the address - `path` must be a valid null-terminated C string (e.g., "m/44'/5'/0'/0/0")  # Returns - Pointer to C string with address (caller must free) - NULL on error

**Safety:**
- `seed` must be a valid pointer to 64 bytes - `network` is the network for the address - `path` must be a valid null-terminated C string (e.g., "m/44'/5'/0'/0/0")

**Module:** `derivation`

---

#### `key_wallet_derive_private_key_from_seed`

```c
key_wallet_derive_private_key_from_seed(seed: *const u8, path: *const c_char, key_out: *mut u8,) -> i32
```

**Description:**
Derive a private key from a seed at a specific derivation path  # Safety - `seed` must be a valid pointer to 64 bytes - `path` must be a valid null-terminated C string (e.g., "m/44'/5'/0'/0/0") - `key_out` must be a valid pointer to a buffer of at least 32 bytes  # Returns - 0 on success - -1 on error

**Safety:**
- `seed` must be a valid pointer to 64 bytes - `path` must be a valid null-terminated C string (e.g., "m/44'/5'/0'/0/0") - `key_out` must be a valid pointer to a buffer of at least 32 bytes

**Module:** `derivation`

---

#### `managed_account_get_parent_wallet_id`

```c
managed_account_get_parent_wallet_id(wallet_id: *const u8) -> *const u8
```

**Description:**
Get the parent wallet ID of a managed account  Note: ManagedAccount doesn't store the parent wallet ID directly. The wallet ID is typically known from the context (e.g., when getting the account from a managed wallet).  # Safety  - `wallet_id` must be a valid pointer to a 32-byte wallet ID buffer that was provided by the caller - The returned pointer is the same as the input pointer for convenience - The caller must not free the returned pointer as it's the same as the input

**Safety:**
- `wallet_id` must be a valid pointer to a 32-byte wallet ID buffer that was provided by the caller - The returned pointer is the same as the input pointer for convenience - The caller must not free the returned pointer as it's the same as the input

**Module:** `managed_account`

---

#### `managed_wallet_check_transaction`

```c
managed_wallet_check_transaction(managed_wallet: *mut FFIManagedWalletInfo, wallet: *mut FFIWallet, tx_bytes: *const u8, tx_len: usize, context_type: FFITransactionContext, block_height: c_uint, block_hash: *const u8, // 32 bytes if not null timestamp: u64, update_state: bool, result_out: *mut FFITransactionCheckResult, error: *mut FFIError,) -> bool
```

**Description:**
Check if a transaction belongs to the wallet  This function checks a transaction against all relevant account types in the wallet and returns detailed information about which accounts are affected.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet (needed for address generation and DashPay queries) - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `result_out` must be a valid pointer to store the result - `error` must be a valid pointer to an FFIError - The affected_accounts array in the result must be freed with `transaction_check_result_free`

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet (needed for address generation and DashPay queries) - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `result_out` must be a valid pointer to store the result - `error` must be a valid pointer to an FFIError - The affected_accounts array in the result must be freed with `transaction_check_result_free`

**Module:** `transaction_checking`

---

#### `managed_wallet_free`

```c
managed_wallet_free(managed_wallet: *mut FFIManagedWalletInfo) -> ()
```

**Description:**
Free managed wallet info  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo or null - After calling this function, the pointer becomes invalid and must not be used

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo or null - After calling this function, the pointer becomes invalid and must not be used

**Module:** `managed_wallet`

---

#### `managed_wallet_generate_addresses_to_index`

```c
managed_wallet_generate_addresses_to_index(managed_wallet: *mut FFIManagedWalletInfo, wallet: *const FFIWallet, account_type: FFIAccountType, account_index: c_uint, pool_type: FFIAddressPoolType, target_index: c_uint, error: *mut FFIError,) -> bool
```

**Description:**
Generate addresses up to a specific index in a pool  This ensures that addresses up to and including the specified index exist in the pool. This is useful for wallet recovery or when specific indices are needed.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet (for key derivation) - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet (for key derivation) - `error` must be a valid pointer to an FFIError or null

**Module:** `address_pool`

---

#### `managed_wallet_get_account`

```c
managed_wallet_get_account(manager: *const FFIWalletManager, wallet_id: *const u8, account_index: c_uint, account_type: FFIAccountType,) -> FFIManagedAccountResult
```

**Description:**
Get a managed account from a managed wallet  This function gets a ManagedAccount from the wallet manager's managed wallet info, returning a managed account handle that wraps the ManagedAccount.  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The caller must ensure all pointers remain valid for the duration of this call - The returned account must be freed with `managed_account_free` when no longer needed

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The caller must ensure all pointers remain valid for the duration of this call - The returned account must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account`

---

#### `managed_wallet_get_account_collection`

```c
managed_wallet_get_account_collection(manager: *const FFIWalletManager, wallet_id: *const u8, error: *mut FFIError,) -> *mut FFIManagedAccountCollection
```

**Description:**
Get managed account collection for a specific network from wallet manager  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The returned pointer must be freed with `managed_account_collection_free` when no longer needed

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The returned pointer must be freed with `managed_account_collection_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_wallet_get_account_count`

```c
managed_wallet_get_account_count(manager: *const FFIWalletManager, wallet_id: *const u8, error: *mut FFIError,) -> c_uint
```

**Description:**
Get number of accounts in a managed wallet  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `managed_account`

---

#### `managed_wallet_get_address_pool_info`

```c
managed_wallet_get_address_pool_info(managed_wallet: *const FFIManagedWalletInfo, account_type: FFIAccountType, account_index: c_uint, pool_type: FFIAddressPoolType, info_out: *mut FFIAddressPoolInfo, error: *mut FFIError,) -> bool
```

**Description:**
Get address pool information for an account  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `info_out` must be a valid pointer to store the pool info - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `info_out` must be a valid pointer to store the pool info - `error` must be a valid pointer to an FFIError or null

**Module:** `address_pool`

---

#### `managed_wallet_get_balance`

```c
managed_wallet_get_balance(managed_wallet: *const FFIManagedWalletInfo, confirmed_out: *mut u64, unconfirmed_out: *mut u64, immature_out: *mut u64, locked_out: *mut u64, total_out: *mut u64, error: *mut FFIError,) -> bool
```

**Description:**
Get wallet balance from managed wallet info  Returns the balance breakdown including confirmed, unconfirmed, immature, locked, and total amounts.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `confirmed_out` must be a valid pointer to store the confirmed balance - `unconfirmed_out` must be a valid pointer to store the unconfirmed balance - `immature_out` must be a valid pointer to store the immature balance - `locked_out` must be a valid pointer to store the locked balance - `total_out` must be a valid pointer to store the total balance - `error` must be a valid pointer to an FFIError

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `confirmed_out` must be a valid pointer to store the confirmed balance - `unconfirmed_out` must be a valid pointer to store the unconfirmed balance - `immature_out` must be a valid pointer to store the immature balance - `locked_out` must be a valid pointer to store the locked balance - `total_out` must be a valid pointer to store the total balance - `error` must be a valid pointer to an FFIError

**Module:** `managed_wallet`

---

#### `managed_wallet_get_bip_44_external_address_range`

```c
managed_wallet_get_bip_44_external_address_range(managed_wallet: *mut FFIManagedWalletInfo, wallet: *const FFIWallet, account_index: std::os::raw::c_uint, start_index: std::os::raw::c_uint, end_index: std::os::raw::c_uint, addresses_out: *mut *mut *mut c_char, count_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Get BIP44 external (receive) addresses in the specified range  Returns external addresses from start_index (inclusive) to end_index (exclusive). If addresses in the range haven't been generated yet, they will be generated.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `addresses_out` must be a valid pointer to store the address array pointer - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError - Free the result with address_array_free(addresses_out, count_out)

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `addresses_out` must be a valid pointer to store the address array pointer - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError - Free the result with address_array_free(addresses_out, count_out)

**Module:** `managed_wallet`

---

#### `managed_wallet_get_bip_44_internal_address_range`

```c
managed_wallet_get_bip_44_internal_address_range(managed_wallet: *mut FFIManagedWalletInfo, wallet: *const FFIWallet, account_index: std::os::raw::c_uint, start_index: std::os::raw::c_uint, end_index: std::os::raw::c_uint, addresses_out: *mut *mut *mut c_char, count_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Get BIP44 internal (change) addresses in the specified range  Returns internal addresses from start_index (inclusive) to end_index (exclusive). If addresses in the range haven't been generated yet, they will be generated.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `addresses_out` must be a valid pointer to store the address array pointer - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError - Free the result with address_array_free(addresses_out, count_out)

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `addresses_out` must be a valid pointer to store the address array pointer - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError - Free the result with address_array_free(addresses_out, count_out)

**Module:** `managed_wallet`

---

#### `managed_wallet_get_dashpay_external_account`

```c
managed_wallet_get_dashpay_external_account(manager: *const FFIWalletManager, wallet_id: *const u8, account_index: c_uint, user_identity_id: *const u8, friend_identity_id: *const u8,) -> FFIManagedAccountResult
```

**Description:**
Get a managed DashPay external account by composite key  # Safety - Pointers must be valid

**Safety:**
- Pointers must be valid

**Module:** `managed_account`

---

#### `managed_wallet_get_dashpay_receiving_account`

```c
managed_wallet_get_dashpay_receiving_account(manager: *const FFIWalletManager, wallet_id: *const u8, account_index: c_uint, user_identity_id: *const u8, friend_identity_id: *const u8,) -> FFIManagedAccountResult
```

**Description:**
Get a managed DashPay receiving funds account by composite key  # Safety - `manager`, `wallet_id` must be valid - `user_identity_id` and `friend_identity_id` must each point to 32 bytes

**Safety:**
- `manager`, `wallet_id` must be valid - `user_identity_id` and `friend_identity_id` must each point to 32 bytes

**Module:** `managed_account`

---

#### `managed_wallet_get_next_bip44_change_address`

```c
managed_wallet_get_next_bip44_change_address(managed_wallet: *mut FFIManagedWalletInfo, wallet: *const FFIWallet, account_index: std::os::raw::c_uint, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get the next unused change address  Generates the next unused change address for the specified account. This properly manages address gaps and updates the managed wallet state.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed by the caller

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed by the caller

**Module:** `managed_wallet`

---

#### `managed_wallet_get_next_bip44_receive_address`

```c
managed_wallet_get_next_bip44_receive_address(managed_wallet: *mut FFIManagedWalletInfo, wallet: *const FFIWallet, account_index: std::os::raw::c_uint, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get the next unused receive address  Generates the next unused receive address for the specified account. This properly manages address gaps and updates the managed wallet state.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed by the caller

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed by the caller

**Module:** `managed_wallet`

---

#### `managed_wallet_get_platform_payment_account`

```c
managed_wallet_get_platform_payment_account(manager: *const FFIWalletManager, wallet_id: *const u8, account_index: c_uint, key_class: c_uint,) -> FFIManagedPlatformAccountResult
```

**Description:**
Get a managed platform payment account from a managed wallet  Platform Payment accounts (DIP-17) are identified by account index and key_class. Returns a platform account handle that wraps the ManagedPlatformAccount.  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The caller must ensure all pointers remain valid for the duration of this call - The returned account must be freed with `managed_platform_account_free` when no longer needed

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The caller must ensure all pointers remain valid for the duration of this call - The returned account must be freed with `managed_platform_account_free` when no longer needed

**Module:** `managed_account`

---

#### `managed_wallet_get_top_up_account_with_registration_index`

```c
managed_wallet_get_top_up_account_with_registration_index(manager: *const FFIWalletManager, wallet_id: *const u8, registration_index: c_uint,) -> FFIManagedAccountResult
```

**Description:**
Get a managed IdentityTopUp account with a specific registration index  This is used for top-up accounts that are bound to a specific identity. Returns a managed account handle that wraps the ManagedAccount.  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The caller must ensure all pointers remain valid for the duration of this call - The returned account must be freed with `managed_account_free` when no longer needed

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The caller must ensure all pointers remain valid for the duration of this call - The returned account must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account`

---

#### `managed_wallet_get_utxos`

```c
managed_wallet_get_utxos(managed_info: *const FFIManagedWalletInfo, utxos_out: *mut *mut FFIUTXO, count_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Get all UTXOs from managed wallet info  # Safety  - `managed_info` must be a valid pointer to an FFIManagedWalletInfo instance - `utxos_out` must be a valid pointer to store the UTXO array pointer - `count_out` must be a valid pointer to store the UTXO count - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned UTXO array must be freed with `utxo_array_free` when no longer needed

**Safety:**
- `managed_info` must be a valid pointer to an FFIManagedWalletInfo instance - `utxos_out` must be a valid pointer to store the UTXO array pointer - `count_out` must be a valid pointer to store the UTXO count - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned UTXO array must be freed with `utxo_array_free` when no longer needed

**Module:** `utxo`

---

#### `managed_wallet_info_free`

```c
managed_wallet_info_free(wallet_info: *mut FFIManagedWalletInfo) -> ()
```

**Description:**
Free managed wallet info returned by wallet_manager_get_managed_wallet_info  # Safety  - `wallet_info` must be a valid pointer returned by wallet_manager_get_managed_wallet_info or null - After calling this function, the pointer becomes invalid and must not be used

**Safety:**
- `wallet_info` must be a valid pointer returned by wallet_manager_get_managed_wallet_info or null - After calling this function, the pointer becomes invalid and must not be used

**Module:** `managed_wallet`

---

#### `managed_wallet_mark_address_used`

```c
managed_wallet_mark_address_used(managed_wallet: *mut FFIManagedWalletInfo, address: *const c_char, error: *mut FFIError,) -> bool
```

**Description:**
Mark an address as used in the pool  This updates the pool's tracking of which addresses have been used, which is important for gap limit management and wallet recovery.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `address` must be a valid C string - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `address` must be a valid C string - `error` must be a valid pointer to an FFIError or null

**Module:** `address_pool`

---

#### `managed_wallet_set_gap_limit`

```c
managed_wallet_set_gap_limit(managed_wallet: *mut FFIManagedWalletInfo, account_type: FFIAccountType, account_index: c_uint, pool_type: FFIAddressPoolType, gap_limit: c_uint, error: *mut FFIError,) -> bool
```

**Description:**
Set the gap limit for an address pool  The gap limit determines how many unused addresses to maintain at the end of the pool. This is important for wallet recovery and address discovery.  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `error` must be a valid pointer to an FFIError or null

**Module:** `address_pool`

---

#### `managed_wallet_synced_height`

```c
managed_wallet_synced_height(managed_wallet: *const FFIManagedWalletInfo, error: *mut FFIError,) -> c_uint
```

**Description:**
Get current synced height from wallet info  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `managed_wallet`

---

#### `wallet_add_account`

```c
wallet_add_account(wallet: *mut FFIWallet, account_type: crate::types::FFIAccountType, account_index: c_uint,) -> crate::types::FFIAccountResult
```

**Description:**
Add an account to the wallet without xpub  # Safety  This function dereferences a raw pointer to FFIWallet. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The FFIWallet remains valid for the duration of this call  # Note  This function does NOT support the following account types: - `PlatformPayment`: Use `wallet_add_platform_payment_account()` instead - `DashpayReceivingFunds`: Use `wallet_add_dashpay_receiving_account()` instead - `DashpayExternalAccount`: Use `wallet_add_dashpay_external_account_with_xpub_bytes()` instead

**Safety:**
This function dereferences a raw pointer to FFIWallet. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The FFIWallet remains valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_add_account_with_string_xpub`

```c
wallet_add_account_with_string_xpub(wallet: *mut FFIWallet, account_type: crate::types::FFIAccountType, account_index: c_uint, xpub_string: *const c_char,) -> crate::types::FFIAccountResult
```

**Description:**
Add an account to the wallet with xpub as string  # Safety  This function dereferences raw pointers. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The xpub_string pointer is either null or points to a valid null-terminated C string - The FFIWallet remains valid for the duration of this call  # Note  This function does NOT support the following account types: - `PlatformPayment`: Use `wallet_add_platform_payment_account()` instead - `DashpayReceivingFunds`: Use `wallet_add_dashpay_receiving_account()` instead - `DashpayExternalAccount`: Use `wallet_add_dashpay_external_account_with_xpub_bytes()` instead

**Safety:**
This function dereferences raw pointers. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The xpub_string pointer is either null or points to a valid null-terminated C string - The FFIWallet remains valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_add_account_with_xpub_bytes`

```c
wallet_add_account_with_xpub_bytes(wallet: *mut FFIWallet, account_type: crate::types::FFIAccountType, account_index: c_uint, xpub_bytes: *const u8, xpub_len: usize,) -> crate::types::FFIAccountResult
```

**Description:**
Add an account to the wallet with xpub as byte array  # Safety  This function dereferences raw pointers. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The xpub_bytes pointer is either null or points to at least xpub_len bytes - The FFIWallet remains valid for the duration of this call  # Note  This function does NOT support the following account types: - `PlatformPayment`: Use `wallet_add_platform_payment_account()` instead - `DashpayReceivingFunds`: Use `wallet_add_dashpay_receiving_account()` instead - `DashpayExternalAccount`: Use `wallet_add_dashpay_external_account_with_xpub_bytes()` instead

**Safety:**
This function dereferences raw pointers. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The xpub_bytes pointer is either null or points to at least xpub_len bytes - The FFIWallet remains valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_add_dashpay_external_account_with_xpub_bytes`

```c
wallet_add_dashpay_external_account_with_xpub_bytes(wallet: *mut FFIWallet, account_index: c_uint, user_identity_id: *const u8, friend_identity_id: *const u8, xpub_bytes: *const u8, xpub_len: usize,) -> FFIAccountResult
```

**Description:**
Add a DashPay external (watch-only) account with xpub bytes  # Safety - `wallet` must be valid, `xpub_bytes` must point to `xpub_len` bytes - `user_identity_id` and `friend_identity_id` must each point to 32 bytes

**Safety:**
- `wallet` must be valid, `xpub_bytes` must point to `xpub_len` bytes - `user_identity_id` and `friend_identity_id` must each point to 32 bytes

**Module:** `wallet`

---

#### `wallet_add_dashpay_receiving_account`

```c
wallet_add_dashpay_receiving_account(wallet: *mut FFIWallet, account_index: c_uint, user_identity_id: *const u8, friend_identity_id: *const u8,) -> FFIAccountResult
```

**Description:**
Add a DashPay receiving funds account  # Safety - `wallet` must be a valid pointer - `user_identity_id` and `friend_identity_id` must each point to 32 bytes

**Safety:**
- `wallet` must be a valid pointer - `user_identity_id` and `friend_identity_id` must each point to 32 bytes

**Module:** `wallet`

---

#### `wallet_add_platform_payment_account`

```c
wallet_add_platform_payment_account(wallet: *mut FFIWallet, account_index: c_uint, key_class: c_uint,) -> crate::types::FFIAccountResult
```

**Description:**
Add a Platform Payment account (DIP-17) to the wallet  Platform Payment accounts use the derivation path: `m/9'/coin_type'/17'/account'/key_class'/index`  # Arguments * `wallet` - Pointer to the wallet * `account_index` - The account index (hardened) in the derivation path * `key_class` - The key class (hardened) - typically 0' for main addresses  # Safety  This function dereferences a raw pointer to FFIWallet. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The FFIWallet remains valid for the duration of this call

**Safety:**
This function dereferences a raw pointer to FFIWallet. The caller must ensure that: - The wallet pointer is either null or points to a valid FFIWallet - The FFIWallet remains valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_build_and_sign_transaction`

```c
wallet_build_and_sign_transaction(managed_wallet: *mut FFIManagedWalletInfo, wallet: *const FFIWallet, account_index: c_uint, outputs: *const FFITxOutput, outputs_count: usize, fee_per_kb: u64, current_height: u32, tx_bytes_out: *mut *mut u8, tx_len_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Build and sign a transaction using the wallet's managed info  This is the recommended way to build transactions. It handles: - UTXO selection using coin selection algorithms - Fee calculation - Change address generation - Transaction signing  # Safety  - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `outputs` must be a valid pointer to an array of FFITxOutput with at least `outputs_count` elements - `tx_bytes_out` must be a valid pointer to store the transaction bytes pointer - `tx_len_out` must be a valid pointer to store the transaction length - `error` must be a valid pointer to an FFIError - The returned transaction bytes must be freed with `transaction_bytes_free`

**Safety:**
- `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo - `wallet` must be a valid pointer to an FFIWallet - `outputs` must be a valid pointer to an array of FFITxOutput with at least `outputs_count` elements - `tx_bytes_out` must be a valid pointer to store the transaction bytes pointer - `tx_len_out` must be a valid pointer to store the transaction length - `error` must be a valid pointer to an FFIError - The returned transaction bytes must be freed with `transaction_bytes_free`

**Module:** `transaction`

---

#### `wallet_build_transaction`

```c
wallet_build_transaction(wallet: *mut FFIWallet, account_index: c_uint, outputs: *const FFITxOutput, outputs_count: usize, fee_per_kb: u64, tx_bytes_out: *mut *mut u8, tx_len_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Build a transaction (unsigned)  This creates an unsigned transaction. Use wallet_sign_transaction to sign it afterward. For a combined build+sign operation, use wallet_build_and_sign_transaction.  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `outputs` must be a valid pointer to an array of FFITxOutput with at least `outputs_count` elements - `tx_bytes_out` must be a valid pointer to store the transaction bytes pointer - `tx_len_out` must be a valid pointer to store the transaction length - `error` must be a valid pointer to an FFIError - The returned transaction bytes must be freed with `transaction_bytes_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `outputs` must be a valid pointer to an array of FFITxOutput with at least `outputs_count` elements - `tx_bytes_out` must be a valid pointer to store the transaction bytes pointer - `tx_len_out` must be a valid pointer to store the transaction length - `error` must be a valid pointer to an FFIError - The returned transaction bytes must be freed with `transaction_bytes_free`

**Module:** `transaction`

---

#### `wallet_check_transaction`

```c
wallet_check_transaction(wallet: *mut FFIWallet, tx_bytes: *const u8, tx_len: usize, context_type: FFITransactionContext, block_height: u32, block_hash: *const u8, // 32 bytes if not null timestamp: u64, update_state: bool, result_out: *mut FFITransactionCheckResult, error: *mut FFIError,) -> bool
```

**Description:**
Check if a transaction belongs to the wallet using ManagedWalletInfo  # Safety  - `wallet` must be a valid mutable pointer to an FFIWallet - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `inputs_spent_out` must be a valid pointer to store the spent inputs count - `addresses_used_out` must be a valid pointer to store the used addresses count - `new_balance_out` must be a valid pointer to store the new balance - `new_address_out` must be a valid pointer to store the address array pointer - `new_address_count_out` must be a valid pointer to store the address count - `error` must be a valid pointer to an FFIError

**Safety:**
- `wallet` must be a valid mutable pointer to an FFIWallet - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `inputs_spent_out` must be a valid pointer to store the spent inputs count - `addresses_used_out` must be a valid pointer to store the used addresses count - `new_balance_out` must be a valid pointer to store the new balance - `new_address_out` must be a valid pointer to store the address array pointer - `new_address_count_out` must be a valid pointer to store the address count - `error` must be a valid pointer to an FFIError

**Module:** `transaction`

---

#### `wallet_create_from_mnemonic`

```c
wallet_create_from_mnemonic(mnemonic: *const c_char, passphrase: *const c_char, network: FFINetwork, error: *mut FFIError,) -> *mut FFIWallet
```

**Description:**
Create a new wallet from mnemonic (backward compatibility - single network)  # Safety  - `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned pointer must be freed with `wallet_free` when no longer needed

**Safety:**
- `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned pointer must be freed with `wallet_free` when no longer needed

**Module:** `wallet`

---

#### `wallet_create_from_mnemonic_with_options`

```c
wallet_create_from_mnemonic_with_options(mnemonic: *const c_char, passphrase: *const c_char, network: FFINetwork, account_options: *const FFIWalletAccountCreationOptions, error: *mut FFIError,) -> *mut FFIWallet
```

**Description:**
Create a new wallet from mnemonic with options  # Safety  - `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned pointer must be freed with `wallet_free` when no longer needed

**Safety:**
- `mnemonic` must be a valid pointer to a null-terminated C string - `passphrase` must be a valid pointer to a null-terminated C string or null - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned pointer must be freed with `wallet_free` when no longer needed

**Module:** `wallet`

---

#### `wallet_create_from_seed`

```c
wallet_create_from_seed(seed: *const u8, seed_len: usize, network: FFINetwork, error: *mut FFIError,) -> *mut FFIWallet
```

**Description:**
Create a new wallet from seed (backward compatibility)  # Safety  - `seed` must be a valid pointer to a byte array of `seed_len` length - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `seed` must be a valid pointer to a byte array of `seed_len` length - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_create_from_seed_with_options`

```c
wallet_create_from_seed_with_options(seed: *const u8, seed_len: usize, network: FFINetwork, account_options: *const FFIWalletAccountCreationOptions, error: *mut FFIError,) -> *mut FFIWallet
```

**Description:**
Create a new wallet from seed with options  # Safety  - `seed` must be a valid pointer to a byte array of `seed_len` length - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `seed` must be a valid pointer to a byte array of `seed_len` length - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_create_managed_wallet`

```c
wallet_create_managed_wallet(wallet: *const FFIWallet, error: *mut FFIError,) -> *mut FFIManagedWalletInfo
```

**Description:**
Create a managed wallet from a regular wallet  This creates a ManagedWalletInfo instance from a Wallet, which includes address pools and transaction checking capabilities.  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError or null - The returned pointer must be freed with `managed_wallet_info_free` (or `ffi_managed_wallet_free` for compatibility)

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError or null - The returned pointer must be freed with `managed_wallet_info_free` (or `ffi_managed_wallet_free` for compatibility)

**Module:** `transaction_checking`

---

#### `wallet_create_random`

```c
wallet_create_random(network: FFINetwork, error: *mut FFIError,) -> *mut FFIWallet
```

**Description:**
Create a new random wallet (backward compatibility)  # Safety  - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure the pointer remains valid for the duration of this call

**Safety:**
- `error` must be a valid pointer to an FFIError structure or null - The caller must ensure the pointer remains valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_create_random_with_options`

```c
wallet_create_random_with_options(network: FFINetwork, account_options: *const FFIWalletAccountCreationOptions, error: *mut FFIError,) -> *mut FFIWallet
```

**Description:**
Create a new random wallet with options  # Safety  - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_derive_extended_private_key`

```c
wallet_derive_extended_private_key(wallet: *const FFIWallet, derivation_path: *const c_char, error: *mut FFIError,) -> *mut FFIExtendedPrivateKey
```

**Description:**
Derive extended private key at a specific path Returns an opaque FFIExtendedPrivateKey pointer that must be freed with extended_private_key_free  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `extended_private_key_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `extended_private_key_free`

**Module:** `keys`

---

#### `wallet_derive_extended_public_key`

```c
wallet_derive_extended_public_key(wallet: *const FFIWallet, derivation_path: *const c_char, error: *mut FFIError,) -> *mut FFIExtendedPublicKey
```

**Description:**
Derive extended public key at a specific path Returns an opaque FFIExtendedPublicKey pointer that must be freed with extended_public_key_free  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `extended_public_key_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `extended_public_key_free`

**Module:** `keys`

---

#### `wallet_derive_private_key`

```c
wallet_derive_private_key(wallet: *const FFIWallet, derivation_path: *const c_char, error: *mut FFIError,) -> *mut FFIPrivateKey
```

**Description:**
Derive private key at a specific path Returns an opaque FFIPrivateKey pointer that must be freed with private_key_free  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `private_key_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `private_key_free`

**Module:** `keys`

---

#### `wallet_derive_private_key_as_wif`

```c
wallet_derive_private_key_as_wif(wallet: *const FFIWallet, derivation_path: *const c_char, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Derive private key at a specific path and return as WIF string  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

#### `wallet_derive_public_key`

```c
wallet_derive_public_key(wallet: *const FFIWallet, derivation_path: *const c_char, error: *mut FFIError,) -> *mut FFIPublicKey
```

**Description:**
Derive public key at a specific path Returns an opaque FFIPublicKey pointer that must be freed with public_key_free  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `public_key_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `public_key_free`

**Module:** `keys`

---

#### `wallet_derive_public_key_as_hex`

```c
wallet_derive_public_key_as_hex(wallet: *const FFIWallet, derivation_path: *const c_char, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Derive public key at a specific path and return as hex string  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `derivation_path` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

#### `wallet_free`

```c
wallet_free(wallet: *mut FFIWallet) -> ()
```

**Description:**
Free a wallet  # Safety  - `wallet` must be a valid pointer to an FFIWallet that was created by this library - The pointer must not be used after calling this function - This function must only be called once per wallet

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet that was created by this library - The pointer must not be used after calling this function - This function must only be called once per wallet

**Module:** `wallet`

---

#### `wallet_free_const`

```c
wallet_free_const(wallet: *const FFIWallet) -> ()
```

**Description:**
Free a const wallet handle  This is a const-safe wrapper for wallet_free() that accepts a const pointer. Use this function when you have a *const FFIWallet that needs to be freed, such as wallets returned from wallet_manager_get_wallet().  # Safety  - `wallet` must be a valid pointer created by wallet creation functions or null - After calling this function, the pointer becomes invalid - This function must only be called once per wallet - The wallet must have been allocated by this library (not stack or static memory)

**Safety:**
- `wallet` must be a valid pointer created by wallet creation functions or null - After calling this function, the pointer becomes invalid - This function must only be called once per wallet - The wallet must have been allocated by this library (not stack or static memory)

**Module:** `wallet`

---

#### `wallet_get_account`

```c
wallet_get_account(wallet: *const FFIWallet, account_index: c_uint, account_type: FFIAccountType,) -> FFIAccountResult
```

**Description:**
Get an account handle for a specific account type Returns a result containing either the account handle or an error  # Safety  - `wallet` must be a valid pointer to an FFIWallet instance - The caller must ensure the wallet pointer remains valid for the duration of this call

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet instance - The caller must ensure the wallet pointer remains valid for the duration of this call

**Module:** `account`

---

#### `wallet_get_account_collection`

```c
wallet_get_account_collection(wallet: *const FFIWallet, error: *mut FFIError,) -> *mut FFIAccountCollection
```

**Description:**
Get account collection for a specific network from wallet  # Safety  - `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The returned pointer must be freed with `account_collection_free` when no longer needed

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The returned pointer must be freed with `account_collection_free` when no longer needed

**Module:** `account_collection`

---

#### `wallet_get_account_count`

```c
wallet_get_account_count(wallet: *const FFIWallet, error: *mut FFIError,) -> c_uint
```

**Description:**
Get number of accounts  # Safety  - `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure both pointers remain valid for the duration of this call

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure both pointers remain valid for the duration of this call

**Module:** `account`

---

#### `wallet_get_account_xpriv`

```c
wallet_get_account_xpriv(wallet: *const FFIWallet, account_index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get extended private key for account  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

#### `wallet_get_account_xpub`

```c
wallet_get_account_xpub(wallet: *const FFIWallet, account_index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get extended public key for account  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

#### `wallet_get_id`

```c
wallet_get_id(wallet: *const FFIWallet, id_out: *mut u8, error: *mut FFIError,) -> bool
```

**Description:**
Get wallet ID (32-byte hash)  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `id_out` must be a valid pointer to a 32-byte buffer - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `id_out` must be a valid pointer to a 32-byte buffer - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_get_top_up_account_with_registration_index`

```c
wallet_get_top_up_account_with_registration_index(wallet: *const FFIWallet, registration_index: c_uint,) -> FFIAccountResult
```

**Description:**
Get an IdentityTopUp account handle with a specific registration index This is used for top-up accounts that are bound to a specific identity Returns a result containing either the account handle or an error  # Safety  - `wallet` must be a valid pointer to an FFIWallet instance - The caller must ensure the wallet pointer remains valid for the duration of this call

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet instance - The caller must ensure the wallet pointer remains valid for the duration of this call

**Module:** `account`

---

#### `wallet_get_utxos`

```c
wallet_get_utxos(_wallet: *const crate::types::FFIWallet, utxos_out: *mut *mut FFIUTXO, count_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Get all UTXOs (deprecated - use managed_wallet_get_utxos instead)  # Safety  This function is deprecated and returns an empty list. Use `managed_wallet_get_utxos` with a ManagedWalletInfo instead.

**Safety:**
This function is deprecated and returns an empty list. Use `managed_wallet_get_utxos` with a ManagedWalletInfo instead.

**Module:** `utxo`

---

#### `wallet_get_xpub`

```c
wallet_get_xpub(wallet: *const FFIWallet, account_index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get extended public key for account  # Safety  - `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned C string must be freed by the caller when no longer needed

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call - The returned C string must be freed by the caller when no longer needed

**Module:** `wallet`

---

#### `wallet_has_mnemonic`

```c
wallet_has_mnemonic(wallet: *const FFIWallet, error: *mut FFIError,) -> bool
```

**Description:**
Check if wallet has mnemonic  # Safety  - `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_is_watch_only`

```c
wallet_is_watch_only(wallet: *const FFIWallet, error: *mut FFIError,) -> bool
```

**Description:**
Check if wallet is watch-only  # Safety  - `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet instance - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `wallet`

---

#### `wallet_sign_transaction`

```c
wallet_sign_transaction(wallet: *const FFIWallet, tx_bytes: *const u8, tx_len: usize, signed_tx_out: *mut *mut u8, signed_len_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Sign a transaction  # Safety  - `wallet` must be a valid pointer to an FFIWallet - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `signed_tx_out` must be a valid pointer to store the signed transaction bytes pointer - `signed_len_out` must be a valid pointer to store the signed transaction length - `error` must be a valid pointer to an FFIError - The returned signed transaction bytes must be freed with `transaction_bytes_free`

**Safety:**
- `wallet` must be a valid pointer to an FFIWallet - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `signed_tx_out` must be a valid pointer to store the signed transaction bytes pointer - `signed_len_out` must be a valid pointer to store the signed transaction length - `error` must be a valid pointer to an FFIError - The returned signed transaction bytes must be freed with `transaction_bytes_free`

**Module:** `transaction`

---

### Account Management - Detailed

#### `account_collection_count`

```c
account_collection_count(collection: *const FFIAccountCollection,) -> c_uint
```

**Description:**
Get the total number of accounts in the collection  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_free`

```c
account_collection_free(collection: *mut FFIAccountCollection) -> ()
```

**Description:**
Free an account collection handle  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection created by this library - `collection` must not be used after calling this function

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection created by this library - `collection` must not be used after calling this function

**Module:** `account_collection`

---

#### `account_collection_get_bip32_account`

```c
account_collection_get_bip32_account(collection: *const FFIAccountCollection, index: c_uint,) -> *mut FFIAccount
```

**Description:**
Get a BIP32 account by index from the collection  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_bip32_indices`

```c
account_collection_get_bip32_indices(collection: *const FFIAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all BIP32 account indices  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_bip44_account`

```c
account_collection_get_bip44_account(collection: *const FFIAccountCollection, index: c_uint,) -> *mut FFIAccount
```

**Description:**
Get a BIP44 account by index from the collection  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_bip44_indices`

```c
account_collection_get_bip44_indices(collection: *const FFIAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all BIP44 account indices  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_coinjoin_account`

```c
account_collection_get_coinjoin_account(collection: *const FFIAccountCollection, index: c_uint,) -> *mut FFIAccount
```

**Description:**
Get a CoinJoin account by index from the collection  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_coinjoin_indices`

```c
account_collection_get_coinjoin_indices(collection: *const FFIAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all CoinJoin account indices  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_identity_invitation`

```c
account_collection_get_identity_invitation(collection: *const FFIAccountCollection,) -> *mut FFIAccount
```

**Description:**
Get the identity invitation account if it exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_identity_registration`

```c
account_collection_get_identity_registration(collection: *const FFIAccountCollection,) -> *mut FFIAccount
```

**Description:**
Get the identity registration account if it exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_identity_topup`

```c
account_collection_get_identity_topup(collection: *const FFIAccountCollection, registration_index: c_uint,) -> *mut FFIAccount
```

**Description:**
Get an identity topup account by registration index  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_identity_topup_indices`

```c
account_collection_get_identity_topup_indices(collection: *const FFIAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all identity topup registration indices  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_identity_topup_not_bound`

```c
account_collection_get_identity_topup_not_bound(collection: *const FFIAccountCollection,) -> *mut FFIAccount
```

**Description:**
Get the identity topup not bound account if it exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_provider_operator_keys`

```c
account_collection_get_provider_operator_keys(collection: *const FFIAccountCollection,) -> *mut std::os::raw::c_void
```

**Description:**
Get the provider operator keys account if it exists Note: Returns null if the `bls` feature is not enabled  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `bls_account_free` when no longer needed (when BLS is enabled)

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `bls_account_free` when no longer needed (when BLS is enabled)

**Module:** `account_collection`

---

#### `account_collection_get_provider_owner_keys`

```c
account_collection_get_provider_owner_keys(collection: *const FFIAccountCollection,) -> *mut FFIAccount
```

**Description:**
Get the provider owner keys account if it exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_get_provider_platform_keys`

```c
account_collection_get_provider_platform_keys(collection: *const FFIAccountCollection,) -> *mut std::os::raw::c_void
```

**Description:**
Get the provider platform keys account if it exists Note: Returns null if the `eddsa` feature is not enabled  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `eddsa_account_free` when no longer needed (when EdDSA is enabled)

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `eddsa_account_free` when no longer needed (when EdDSA is enabled)

**Module:** `account_collection`

---

#### `account_collection_get_provider_voting_keys`

```c
account_collection_get_provider_voting_keys(collection: *const FFIAccountCollection,) -> *mut FFIAccount
```

**Description:**
Get the provider voting keys account if it exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_free` when no longer needed

**Module:** `account_collection`

---

#### `account_collection_has_identity_invitation`

```c
account_collection_has_identity_invitation(collection: *const FFIAccountCollection,) -> bool
```

**Description:**
Check if identity invitation account exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_has_identity_registration`

```c
account_collection_has_identity_registration(collection: *const FFIAccountCollection,) -> bool
```

**Description:**
Check if identity registration account exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_has_identity_topup_not_bound`

```c
account_collection_has_identity_topup_not_bound(collection: *const FFIAccountCollection,) -> bool
```

**Description:**
Check if identity topup not bound account exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_has_provider_operator_keys`

```c
account_collection_has_provider_operator_keys(collection: *const FFIAccountCollection,) -> bool
```

**Description:**
Check if provider operator keys account exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_has_provider_owner_keys`

```c
account_collection_has_provider_owner_keys(collection: *const FFIAccountCollection,) -> bool
```

**Description:**
Check if provider owner keys account exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_has_provider_platform_keys`

```c
account_collection_has_provider_platform_keys(collection: *const FFIAccountCollection,) -> bool
```

**Description:**
Check if provider platform keys account exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_has_provider_voting_keys`

```c
account_collection_has_provider_voting_keys(collection: *const FFIAccountCollection,) -> bool
```

**Description:**
Check if provider voting keys account exists  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection

**Module:** `account_collection`

---

#### `account_collection_summary`

```c
account_collection_summary(collection: *const FFIAccountCollection,) -> *mut c_char
```

**Description:**
Get a human-readable summary of all accounts in the collection  Returns a formatted string showing all account types and their indices. The format is designed to be clear and readable for end users.  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned string must be freed with `string_free` when no longer needed - Returns null if the collection pointer is null

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned string must be freed with `string_free` when no longer needed - Returns null if the collection pointer is null

**Module:** `account_collection`

---

#### `account_collection_summary_data`

```c
account_collection_summary_data(collection: *const FFIAccountCollection,) -> *mut FFIAccountCollectionSummary
```

**Description:**
Get structured account collection summary data  Returns a struct containing arrays of indices for each account type and boolean flags for special accounts. This provides Swift with programmatic access to account information.  # Safety  - `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_collection_summary_free` when no longer needed - Returns null if the collection pointer is null

**Safety:**
- `collection` must be a valid pointer to an FFIAccountCollection - The returned pointer must be freed with `account_collection_summary_free` when no longer needed - Returns null if the collection pointer is null

**Module:** `account_collection`

---

#### `account_collection_summary_free`

```c
account_collection_summary_free(summary: *mut FFIAccountCollectionSummary,) -> ()
```

**Description:**
Free an account collection summary and all its allocated memory  # Safety  - `summary` must be a valid pointer to an FFIAccountCollectionSummary created by `account_collection_summary_data` - `summary` must not be used after calling this function

**Safety:**
- `summary` must be a valid pointer to an FFIAccountCollectionSummary created by `account_collection_summary_data` - `summary` must not be used after calling this function

**Module:** `account_collection`

---

#### `account_derive_extended_private_key_at`

```c
account_derive_extended_private_key_at(account: *const FFIAccount, master_xpriv: *const FFIExtendedPrivateKey, index: c_uint, error: *mut FFIError,) -> *mut FFIExtendedPrivateKey
```

**Description:**
Derive an extended private key from an account at a given index, using the provided master xpriv.  Returns an opaque FFIExtendedPrivateKey pointer that must be freed with `extended_private_key_free`.  Notes: - This is chain-agnostic. For accounts with internal/external chains, this returns an error. - For hardened-only account types (e.g., EdDSA), a hardened index is used.  # Safety - `account` and `master_xpriv` must be valid, non-null pointers allocated by this library. - `error` must be a valid pointer to an FFIError or null. - The caller must free the returned pointer with `extended_private_key_free`.

**Safety:**
- `account` and `master_xpriv` must be valid, non-null pointers allocated by this library. - `error` must be a valid pointer to an FFIError or null. - The caller must free the returned pointer with `extended_private_key_free`.

**Module:** `account_derivation`

---

#### `account_derive_extended_private_key_from_mnemonic`

```c
account_derive_extended_private_key_from_mnemonic(account: *const FFIAccount, mnemonic: *const c_char, passphrase: *const c_char, index: c_uint, error: *mut FFIError,) -> *mut FFIExtendedPrivateKey
```

**Description:**
Derive an extended private key from a mnemonic + optional passphrase at the given index. Returns an opaque FFIExtendedPrivateKey pointer that must be freed with `extended_private_key_free`.  # Safety - `account` must be a valid pointer to an FFIAccount - `mnemonic` must be a valid, null-terminated C string - `passphrase` may be null; if not null, must be a valid C string - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `account` must be a valid pointer to an FFIAccount - `mnemonic` must be a valid, null-terminated C string - `passphrase` may be null; if not null, must be a valid C string - `error` must be a valid pointer to an FFIError or null

**Module:** `account_derivation`

---

#### `account_derive_extended_private_key_from_seed`

```c
account_derive_extended_private_key_from_seed(account: *const FFIAccount, seed: *const u8, seed_len: usize, index: c_uint, error: *mut FFIError,) -> *mut FFIExtendedPrivateKey
```

**Description:**
Derive an extended private key from a raw seed buffer at the given index. Returns an opaque FFIExtendedPrivateKey pointer that must be freed with `extended_private_key_free`.  # Safety - `account` must be a valid pointer to an FFIAccount - `seed` must point to a valid buffer of length `seed_len` - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `account` must be a valid pointer to an FFIAccount - `seed` must point to a valid buffer of length `seed_len` - `error` must be a valid pointer to an FFIError or null

**Module:** `account_derivation`

---

#### `account_derive_private_key_as_wif_at`

```c
account_derive_private_key_as_wif_at(account: *const FFIAccount, master_xpriv: *const FFIExtendedPrivateKey, index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Derive a private key from an account at a given chain/index and return as WIF string. Caller must free the returned string with `string_free`.  # Safety - `account` and `master_xpriv` must be valid pointers allocated by this library - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `account` and `master_xpriv` must be valid pointers allocated by this library - `error` must be a valid pointer to an FFIError or null

**Module:** `account_derivation`

---

#### `account_derive_private_key_at`

```c
account_derive_private_key_at(account: *const FFIAccount, master_xpriv: *const FFIExtendedPrivateKey, index: c_uint, error: *mut FFIError,) -> *mut FFIPrivateKey
```

**Description:**
Derive a private key (secp256k1) from an account at a given chain/index, using the provided master xpriv. Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.  # Safety - `account` and `master_xpriv` must be valid pointers allocated by this library - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `account` and `master_xpriv` must be valid pointers allocated by this library - `error` must be a valid pointer to an FFIError or null

**Module:** `account_derivation`

---

#### `account_derive_private_key_from_mnemonic`

```c
account_derive_private_key_from_mnemonic(account: *const FFIAccount, mnemonic: *const c_char, passphrase: *const c_char, index: c_uint, error: *mut FFIError,) -> *mut FFIPrivateKey
```

**Description:**
Derive a private key from a mnemonic + optional passphrase at the given index. Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.  # Safety - `account` must be a valid pointer to an FFIAccount - `mnemonic` must be a valid, null-terminated C string - `passphrase` may be null; if not null, must be a valid C string - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `account` must be a valid pointer to an FFIAccount - `mnemonic` must be a valid, null-terminated C string - `passphrase` may be null; if not null, must be a valid C string - `error` must be a valid pointer to an FFIError or null

**Module:** `account_derivation`

---

#### `account_derive_private_key_from_seed`

```c
account_derive_private_key_from_seed(account: *const FFIAccount, seed: *const u8, seed_len: usize, index: c_uint, error: *mut FFIError,) -> *mut FFIPrivateKey
```

**Description:**
Derive a private key from a raw seed buffer at the given index. Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.  # Safety - `account` must be a valid pointer to an FFIAccount - `seed` must point to a valid buffer of length `seed_len` - `error` must be a valid pointer to an FFIError or null

**Safety:**
- `account` must be a valid pointer to an FFIAccount - `seed` must point to a valid buffer of length `seed_len` - `error` must be a valid pointer to an FFIError or null

**Module:** `account_derivation`

---

#### `account_free`

```c
account_free(account: *mut FFIAccount) -> ()
```

**Description:**
Free an account handle  # Safety  - `account` must be a valid pointer to an FFIAccount that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `account` must be a valid pointer to an FFIAccount that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `account`

---

#### `account_get_account_type`

```c
account_get_account_type(account: *const FFIAccount, out_index: *mut c_uint,) -> FFIAccountType
```

**Description:**
Get the account type of an account  # Safety  - `account` must be a valid pointer to an FFIAccount instance - `out_index` must be a valid pointer to a c_uint where the index will be stored - Returns FFIAccountType::StandardBIP44 with index 0 if the account is null

**Safety:**
- `account` must be a valid pointer to an FFIAccount instance - `out_index` must be a valid pointer to a c_uint where the index will be stored - Returns FFIAccountType::StandardBIP44 with index 0 if the account is null

**Module:** `account`

---

#### `account_get_extended_public_key_as_string`

```c
account_get_extended_public_key_as_string(account: *const FFIAccount,) -> *mut std::os::raw::c_char
```

**Description:**
Get the extended public key of an account as a string  # Safety  - `account` must be a valid pointer to an FFIAccount instance - The returned string must be freed by the caller using `string_free` - Returns NULL if the account is null

**Safety:**
- `account` must be a valid pointer to an FFIAccount instance - The returned string must be freed by the caller using `string_free` - Returns NULL if the account is null

**Module:** `account`

---

#### `account_get_is_watch_only`

```c
account_get_is_watch_only(account: *const FFIAccount) -> bool
```

**Description:**
Check if an account is watch-only  # Safety  - `account` must be a valid pointer to an FFIAccount instance - Returns false if the account is null

**Safety:**
- `account` must be a valid pointer to an FFIAccount instance - Returns false if the account is null

**Module:** `account`

---

#### `account_get_network`

```c
account_get_network(account: *const FFIAccount) -> FFINetwork
```

**Description:**
Get the network of an account  # Safety  - `account` must be a valid pointer to an FFIAccount instance - Returns `FFINetwork::Dash` if the account is null

**Safety:**
- `account` must be a valid pointer to an FFIAccount instance - Returns `FFINetwork::Dash` if the account is null

**Module:** `account`

---

#### `bls_account_derive_private_key_from_mnemonic`

```c
bls_account_derive_private_key_from_mnemonic(account: *const FFIBLSAccount, mnemonic: *const c_char, passphrase: *const c_char, index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Module:** `account_derivation`

---

#### `bls_account_derive_private_key_from_seed`

```c
bls_account_derive_private_key_from_seed(account: *const FFIBLSAccount, seed: *const u8, seed_len: usize, index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Module:** `account_derivation`

---

#### `bls_account_free`

```c
bls_account_free(account: *mut FFIBLSAccount) -> ()
```

**Module:** `account`

---

#### `bls_account_get_account_type`

```c
bls_account_get_account_type(account: *const FFIBLSAccount, out_index: *mut c_uint,) -> FFIAccountType
```

**Module:** `account`

---

#### `bls_account_get_extended_public_key_as_string`

```c
bls_account_get_extended_public_key_as_string(account: *const FFIBLSAccount,) -> *mut std::os::raw::c_char
```

**Module:** `account`

---

#### `bls_account_get_is_watch_only`

```c
bls_account_get_is_watch_only(account: *const FFIBLSAccount) -> bool
```

**Module:** `account`

---

#### `bls_account_get_network`

```c
bls_account_get_network(account: *const FFIBLSAccount) -> FFINetwork
```

**Module:** `account`

---

#### `derivation_bip44_account_path`

```c
derivation_bip44_account_path(network: FFINetwork, account_index: c_uint, path_out: *mut c_char, path_max_len: usize, error: *mut FFIError,) -> bool
```

**Description:**
Derive a BIP44 account path (m/44'/5'/account')

**Module:** `derivation`

---

#### `eddsa_account_derive_private_key_from_mnemonic`

```c
eddsa_account_derive_private_key_from_mnemonic(account: *const FFIEdDSAAccount, mnemonic: *const c_char, passphrase: *const c_char, index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Module:** `account_derivation`

---

#### `eddsa_account_derive_private_key_from_seed`

```c
eddsa_account_derive_private_key_from_seed(account: *const FFIEdDSAAccount, seed: *const u8, seed_len: usize, index: c_uint, error: *mut FFIError,) -> *mut c_char
```

**Module:** `account_derivation`

---

#### `eddsa_account_free`

```c
eddsa_account_free(account: *mut FFIEdDSAAccount) -> ()
```

**Module:** `account`

---

#### `eddsa_account_get_account_type`

```c
eddsa_account_get_account_type(account: *const FFIEdDSAAccount, out_index: *mut c_uint,) -> FFIAccountType
```

**Module:** `account`

---

#### `eddsa_account_get_extended_public_key_as_string`

```c
eddsa_account_get_extended_public_key_as_string(account: *const FFIEdDSAAccount,) -> *mut std::os::raw::c_char
```

**Module:** `account`

---

#### `eddsa_account_get_is_watch_only`

```c
eddsa_account_get_is_watch_only(account: *const FFIEdDSAAccount) -> bool
```

**Module:** `account`

---

#### `eddsa_account_get_network`

```c
eddsa_account_get_network(account: *const FFIEdDSAAccount) -> FFINetwork
```

**Module:** `account`

---

#### `managed_account_collection_count`

```c
managed_account_collection_count(collection: *const FFIManagedAccountCollection,) -> c_uint
```

**Description:**
Get the total number of accounts in the managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_free`

```c
managed_account_collection_free(collection: *mut FFIManagedAccountCollection,) -> ()
```

**Description:**
Free a managed account collection handle  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection created by this library - `collection` must not be used after calling this function

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection created by this library - `collection` must not be used after calling this function

**Module:** `managed_account_collection`

---

#### `managed_account_collection_free_platform_payment_keys`

```c
managed_account_collection_free_platform_payment_keys(keys: *mut crate::managed_account::FFIPlatformPaymentAccountKey, count: usize,) -> ()
```

**Description:**
Free platform payment keys array returned by managed_account_collection_get_platform_payment_keys  # Safety  - `keys` must be a pointer returned by `managed_account_collection_get_platform_payment_keys` - `count` must be the count returned by `managed_account_collection_get_platform_payment_keys` - This function must only be called once per allocation

**Safety:**
- `keys` must be a pointer returned by `managed_account_collection_get_platform_payment_keys` - `count` must be the count returned by `managed_account_collection_get_platform_payment_keys` - This function must only be called once per allocation

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_bip32_account`

```c
managed_account_collection_get_bip32_account(collection: *const FFIManagedAccountCollection, index: c_uint,) -> *mut FFIManagedAccount
```

**Description:**
Get a BIP32 account by index from the managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_bip32_indices`

```c
managed_account_collection_get_bip32_indices(collection: *const FFIManagedAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all BIP32 account indices from managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_bip44_account`

```c
managed_account_collection_get_bip44_account(collection: *const FFIManagedAccountCollection, index: c_uint,) -> *mut FFIManagedAccount
```

**Description:**
Get a BIP44 account by index from the managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_bip44_indices`

```c
managed_account_collection_get_bip44_indices(collection: *const FFIManagedAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all BIP44 account indices from managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_coinjoin_account`

```c
managed_account_collection_get_coinjoin_account(collection: *const FFIManagedAccountCollection, index: c_uint,) -> *mut FFIManagedAccount
```

**Description:**
Get a CoinJoin account by index from the managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_coinjoin_indices`

```c
managed_account_collection_get_coinjoin_indices(collection: *const FFIManagedAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all CoinJoin account indices from managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_identity_invitation`

```c
managed_account_collection_get_identity_invitation(collection: *const FFIManagedAccountCollection,) -> *mut FFIManagedAccount
```

**Description:**
Get the identity invitation account if it exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_identity_registration`

```c
managed_account_collection_get_identity_registration(collection: *const FFIManagedAccountCollection,) -> *mut FFIManagedAccount
```

**Description:**
Get the identity registration account if it exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_identity_topup`

```c
managed_account_collection_get_identity_topup(collection: *const FFIManagedAccountCollection, registration_index: c_uint,) -> *mut FFIManagedAccount
```

**Description:**
Get an identity topup account by registration index from managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_identity_topup_indices`

```c
managed_account_collection_get_identity_topup_indices(collection: *const FFIManagedAccountCollection, out_indices: *mut *mut c_uint, out_count: *mut usize,) -> bool
```

**Description:**
Get all identity topup registration indices from managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_indices` must be a valid pointer to store the indices array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `free_u32_array` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_identity_topup_not_bound`

```c
managed_account_collection_get_identity_topup_not_bound(collection: *const FFIManagedAccountCollection,) -> *mut FFIManagedAccount
```

**Description:**
Get the identity topup not bound account if it exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - `manager` must be a valid pointer to an FFIWalletManager - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - `manager` must be a valid pointer to an FFIWalletManager - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_platform_payment_account`

```c
managed_account_collection_get_platform_payment_account(collection: *const FFIManagedAccountCollection, account_index: c_uint, key_class: c_uint,) -> *mut crate::managed_account::FFIManagedPlatformAccount
```

**Description:**
Get a Platform Payment account by account index and key class from the managed collection  Platform Payment accounts (DIP-17) are identified by two indices: - account_index: The account' level in the derivation path - key_class: The key_class' level in the derivation path (typically 0)  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_platform_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_platform_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_platform_payment_keys`

```c
managed_account_collection_get_platform_payment_keys(collection: *const FFIManagedAccountCollection, out_keys: *mut *mut crate::managed_account::FFIPlatformPaymentAccountKey, out_count: *mut usize,) -> bool
```

**Description:**
Get all Platform Payment account keys from managed collection  Returns an array of FFIPlatformPaymentAccountKey structures.  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_keys` must be a valid pointer to store the keys array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `managed_account_collection_free_platform_payment_keys` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - `out_keys` must be a valid pointer to store the keys array - `out_count` must be a valid pointer to store the count - The returned array must be freed with `managed_account_collection_free_platform_payment_keys` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_provider_operator_keys`

```c
managed_account_collection_get_provider_operator_keys(collection: *const FFIManagedAccountCollection,) -> *mut std::os::raw::c_void
```

**Description:**
Get the provider operator keys account if it exists in managed collection Note: Returns null if the `bls` feature is not enabled  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed (when BLS is enabled)

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed (when BLS is enabled)

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_provider_owner_keys`

```c
managed_account_collection_get_provider_owner_keys(collection: *const FFIManagedAccountCollection,) -> *mut FFIManagedAccount
```

**Description:**
Get the provider owner keys account if it exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_provider_platform_keys`

```c
managed_account_collection_get_provider_platform_keys(collection: *const FFIManagedAccountCollection,) -> *mut std::os::raw::c_void
```

**Description:**
Get the provider platform keys account if it exists in managed collection Note: Returns null if the `eddsa` feature is not enabled  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed (when EdDSA is enabled)

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed (when EdDSA is enabled)

**Module:** `managed_account_collection`

---

#### `managed_account_collection_get_provider_voting_keys`

```c
managed_account_collection_get_provider_voting_keys(collection: *const FFIManagedAccountCollection,) -> *mut FFIManagedAccount
```

**Description:**
Get the provider voting keys account if it exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_free` when no longer needed

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_identity_invitation`

```c
managed_account_collection_has_identity_invitation(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if identity invitation account exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_identity_registration`

```c
managed_account_collection_has_identity_registration(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if identity registration account exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_identity_topup_not_bound`

```c
managed_account_collection_has_identity_topup_not_bound(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if identity topup not bound account exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_platform_payment_accounts`

```c
managed_account_collection_has_platform_payment_accounts(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if there are any Platform Payment accounts in the managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_provider_operator_keys`

```c
managed_account_collection_has_provider_operator_keys(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if provider operator keys account exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_provider_owner_keys`

```c
managed_account_collection_has_provider_owner_keys(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if provider owner keys account exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_provider_platform_keys`

```c
managed_account_collection_has_provider_platform_keys(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if provider platform keys account exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_has_provider_voting_keys`

```c
managed_account_collection_has_provider_voting_keys(collection: *const FFIManagedAccountCollection,) -> bool
```

**Description:**
Check if provider voting keys account exists in managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_platform_payment_count`

```c
managed_account_collection_platform_payment_count(collection: *const FFIManagedAccountCollection,) -> c_uint
```

**Description:**
Get the number of Platform Payment accounts in the managed collection  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection

**Module:** `managed_account_collection`

---

#### `managed_account_collection_summary`

```c
managed_account_collection_summary(collection: *const FFIManagedAccountCollection,) -> *mut c_char
```

**Description:**
Get a human-readable summary of all accounts in the managed collection  Returns a formatted string showing all account types and their indices. The format is designed to be clear and readable for end users.  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned string must be freed with `string_free` when no longer needed - Returns null if the collection pointer is null

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned string must be freed with `string_free` when no longer needed - Returns null if the collection pointer is null

**Module:** `managed_account_collection`

---

#### `managed_account_collection_summary_data`

```c
managed_account_collection_summary_data(collection: *const FFIManagedAccountCollection,) -> *mut FFIManagedAccountCollectionSummary
```

**Description:**
Get structured account collection summary data for managed collection  Returns a struct containing arrays of indices for each account type and boolean flags for special accounts. This provides Swift with programmatic access to account information.  # Safety  - `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_collection_summary_free` when no longer needed - Returns null if the collection pointer is null

**Safety:**
- `collection` must be a valid pointer to an FFIManagedAccountCollection - The returned pointer must be freed with `managed_account_collection_summary_free` when no longer needed - Returns null if the collection pointer is null

**Module:** `managed_account_collection`

---

#### `managed_account_collection_summary_free`

```c
managed_account_collection_summary_free(summary: *mut FFIManagedAccountCollectionSummary,) -> ()
```

**Description:**
Free a managed account collection summary and all its allocated memory  # Safety  - `summary` must be a valid pointer to an FFIManagedAccountCollectionSummary created by `managed_account_collection_summary_data` - `summary` must not be used after calling this function

**Safety:**
- `summary` must be a valid pointer to an FFIManagedAccountCollectionSummary created by `managed_account_collection_summary_data` - `summary` must not be used after calling this function

**Module:** `managed_account_collection`

---

#### `managed_account_free`

```c
managed_account_free(account: *mut FFIManagedAccount) -> ()
```

**Description:**
Free a managed account handle  # Safety  - `account` must be a valid pointer to an FFIManagedAccount that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `managed_account`

---

#### `managed_account_free_transactions`

```c
managed_account_free_transactions(transactions: *mut FFITransactionRecord, count: usize,) -> ()
```

**Description:**
Free transactions array returned by managed_account_get_transactions  # Safety  - `transactions` must be a pointer returned by `managed_account_get_transactions` - `count` must be the count returned by `managed_account_get_transactions` - This function must only be called once per allocation

**Safety:**
- `transactions` must be a pointer returned by `managed_account_get_transactions` - `count` must be the count returned by `managed_account_get_transactions` - This function must only be called once per allocation

**Module:** `managed_account`

---

#### `managed_account_get_account_type`

```c
managed_account_get_account_type(account: *const FFIManagedAccount, index_out: *mut c_uint,) -> FFIAccountType
```

**Description:**
Get the account type of a managed account  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance - `index_out` must be a valid pointer to receive the account index (or null)

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance - `index_out` must be a valid pointer to receive the account index (or null)

**Module:** `managed_account`

---

#### `managed_account_get_address_pool`

```c
managed_account_get_address_pool(account: *const FFIManagedAccount, pool_type: FFIAddressPoolType,) -> *mut FFIAddressPool
```

**Description:**
Get an address pool from a managed account by type  This function returns the appropriate address pool based on the pool type parameter. For Standard accounts with External/Internal pool types, returns the corresponding pool. For non-standard accounts with Single pool type, returns their single address pool.  # Safety  - `manager` must be a valid pointer to an FFIWalletManager instance - `account` must be a valid pointer to an FFIManagedAccount instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The returned pool must be freed with `address_pool_free` when no longer needed

**Safety:**
- `manager` must be a valid pointer to an FFIWalletManager instance - `account` must be a valid pointer to an FFIManagedAccount instance - `wallet_id` must be a valid pointer to a 32-byte wallet ID - The returned pool must be freed with `address_pool_free` when no longer needed

**Module:** `managed_account`

---

#### `managed_account_get_balance`

```c
managed_account_get_balance(account: *const FFIManagedAccount, balance_out: *mut crate::types::FFIBalance,) -> bool
```

**Description:**
Get the balance of a managed account  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance - `balance_out` must be a valid pointer to an FFIBalance structure

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance - `balance_out` must be a valid pointer to an FFIBalance structure

**Module:** `managed_account`

---

#### `managed_account_get_external_address_pool`

```c
managed_account_get_external_address_pool(account: *const FFIManagedAccount,) -> *mut FFIAddressPool
```

**Description:**
Get the external address pool from a managed account  This function returns the external (receive) address pool for Standard accounts. Returns NULL for account types that don't have separate external/internal pools.  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance - The returned pool must be freed with `address_pool_free` when no longer needed

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance - The returned pool must be freed with `address_pool_free` when no longer needed

**Module:** `managed_account`

---

#### `managed_account_get_index`

```c
managed_account_get_index(account: *const FFIManagedAccount) -> c_uint
```

**Description:**
Get the account index from a managed account  Returns the primary account index for Standard and CoinJoin accounts. Returns 0 for account types that don't have an index (like Identity or Provider accounts).  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance

**Module:** `managed_account`

---

#### `managed_account_get_internal_address_pool`

```c
managed_account_get_internal_address_pool(account: *const FFIManagedAccount,) -> *mut FFIAddressPool
```

**Description:**
Get the internal address pool from a managed account  This function returns the internal (change) address pool for Standard accounts. Returns NULL for account types that don't have separate external/internal pools.  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance - The returned pool must be freed with `address_pool_free` when no longer needed

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance - The returned pool must be freed with `address_pool_free` when no longer needed

**Module:** `managed_account`

---

#### `managed_account_get_is_watch_only`

```c
managed_account_get_is_watch_only(account: *const FFIManagedAccount,) -> bool
```

**Description:**
Check if a managed account is watch-only  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance

**Module:** `managed_account`

---

#### `managed_account_get_network`

```c
managed_account_get_network(account: *const FFIManagedAccount,) -> FFINetwork
```

**Description:**
Get the network of a managed account  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance - Returns `FFINetwork::Dash` if the account is null

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance - Returns `FFINetwork::Dash` if the account is null

**Module:** `managed_account`

---

#### `managed_account_get_transaction_count`

```c
managed_account_get_transaction_count(account: *const FFIManagedAccount,) -> c_uint
```

**Description:**
Get the number of transactions in a managed account  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance

**Module:** `managed_account`

---

#### `managed_account_get_transactions`

```c
managed_account_get_transactions(account: *const FFIManagedAccount, transactions_out: *mut *mut FFITransactionRecord, count_out: *mut usize,) -> bool
```

**Description:**
Get all transactions from a managed account  Returns an array of FFITransactionRecord structures.  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance - `transactions_out` must be a valid pointer to receive the transactions array pointer - `count_out` must be a valid pointer to receive the count - The caller must free the returned array using `managed_account_free_transactions`

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance - `transactions_out` must be a valid pointer to receive the transactions array pointer - `count_out` must be a valid pointer to receive the count - The caller must free the returned array using `managed_account_free_transactions`

**Module:** `managed_account`

---

#### `managed_account_get_utxo_count`

```c
managed_account_get_utxo_count(account: *const FFIManagedAccount,) -> c_uint
```

**Description:**
Get the number of UTXOs in a managed account  # Safety  - `account` must be a valid pointer to an FFIManagedAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedAccount instance

**Module:** `managed_account`

---

#### `managed_platform_account_free`

```c
managed_platform_account_free(account: *mut FFIManagedPlatformAccount) -> ()
```

**Description:**
Free a managed platform account handle  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `managed_account`

---

#### `managed_platform_account_get_account_index`

```c
managed_platform_account_get_account_index(account: *const FFIManagedPlatformAccount,) -> c_uint
```

**Description:**
Get the account index of a managed platform account  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Module:** `managed_account`

---

#### `managed_platform_account_get_address_pool`

```c
managed_platform_account_get_address_pool(account: *const FFIManagedPlatformAccount,) -> *mut FFIAddressPool
```

**Description:**
Get the address pool from a managed platform account  Platform accounts only have a single address pool.  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance - The returned pool must be freed with `address_pool_free` when no longer needed

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance - The returned pool must be freed with `address_pool_free` when no longer needed

**Module:** `managed_account`

---

#### `managed_platform_account_get_credit_balance`

```c
managed_platform_account_get_credit_balance(account: *const FFIManagedPlatformAccount,) -> u64
```

**Description:**
Get the total credit balance of a managed platform account  Returns the balance in credits (1000 credits = 1 duff)  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Module:** `managed_account`

---

#### `managed_platform_account_get_duff_balance`

```c
managed_platform_account_get_duff_balance(account: *const FFIManagedPlatformAccount,) -> u64
```

**Description:**
Get the total balance in duffs of a managed platform account  Returns the balance in duffs (credit_balance / 1000)  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Module:** `managed_account`

---

#### `managed_platform_account_get_funded_address_count`

```c
managed_platform_account_get_funded_address_count(account: *const FFIManagedPlatformAccount,) -> c_uint
```

**Description:**
Get the number of funded addresses in a managed platform account  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Module:** `managed_account`

---

#### `managed_platform_account_get_is_watch_only`

```c
managed_platform_account_get_is_watch_only(account: *const FFIManagedPlatformAccount,) -> bool
```

**Description:**
Check if a managed platform account is watch-only  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Module:** `managed_account`

---

#### `managed_platform_account_get_key_class`

```c
managed_platform_account_get_key_class(account: *const FFIManagedPlatformAccount,) -> c_uint
```

**Description:**
Get the key class of a managed platform account  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Module:** `managed_account`

---

#### `managed_platform_account_get_network`

```c
managed_platform_account_get_network(account: *const FFIManagedPlatformAccount,) -> FFINetwork
```

**Description:**
Get the network of a managed platform account  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance - Returns `FFINetwork::Dash` if the account is null

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance - Returns `FFINetwork::Dash` if the account is null

**Module:** `managed_account`

---

#### `managed_platform_account_get_total_address_count`

```c
managed_platform_account_get_total_address_count(account: *const FFIManagedPlatformAccount,) -> c_uint
```

**Description:**
Get the total number of addresses in a managed platform account  # Safety  - `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Safety:**
- `account` must be a valid pointer to an FFIManagedPlatformAccount instance

**Module:** `managed_account`

---

### Address Management - Detailed

#### `address_array_free`

```c
address_array_free(addresses: *mut *mut c_char, count: usize) -> ()
```

**Description:**
Free address array  # Safety  - `addresses` must be a valid pointer to an array of address strings or null - Each address in the array must be a valid C string pointer - `count` must be the correct number of addresses in the array - After calling this function, all pointers become invalid

**Safety:**
- `addresses` must be a valid pointer to an array of address strings or null - Each address in the array must be a valid C string pointer - `count` must be the correct number of addresses in the array - After calling this function, all pointers become invalid

**Module:** `address`

---

#### `address_free`

```c
address_free(address: *mut c_char) -> ()
```

**Description:**
Free address string  # Safety  - `address` must be a valid pointer created by address functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `address` must be a valid pointer created by address functions or null - After calling this function, the pointer becomes invalid

**Module:** `address`

---

#### `address_get_type`

```c
address_get_type(address: *const c_char, network: FFINetwork, error: *mut FFIError,) -> c_uchar
```

**Description:**
Get address type  Returns: - 0: P2PKH address - 1: P2SH address - 2: Other address type - u8::MAX (255): Error occurred  # Safety  - `address` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError

**Safety:**
- `address` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError

**Module:** `address`

---

#### `address_info_array_free`

```c
address_info_array_free(infos: *mut *mut FFIAddressInfo, count: usize) -> ()
```

**Description:**
Free an array of FFIAddressInfo structures  # Safety  - `infos` must be a valid pointer to an array of FFIAddressInfo pointers allocated by this library or null - `count` must be the exact number of elements in the array - The pointers must not be used after calling this function

**Safety:**
- `infos` must be a valid pointer to an array of FFIAddressInfo pointers allocated by this library or null - `count` must be the exact number of elements in the array - The pointers must not be used after calling this function

**Module:** `address_pool`

---

#### `address_info_free`

```c
address_info_free(info: *mut FFIAddressInfo) -> ()
```

**Description:**
Free a single FFIAddressInfo structure  # Safety  - `info` must be a valid pointer to an FFIAddressInfo allocated by this library or null - The pointer must not be used after calling this function

**Safety:**
- `info` must be a valid pointer to an FFIAddressInfo allocated by this library or null - The pointer must not be used after calling this function

**Module:** `address_pool`

---

#### `address_pool_free`

```c
address_pool_free(pool: *mut FFIAddressPool) -> ()
```

**Description:**
Free an address pool handle  # Safety  - `pool` must be a valid pointer to an FFIAddressPool that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `pool` must be a valid pointer to an FFIAddressPool that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `address_pool`

---

#### `address_pool_get_address_at_index`

```c
address_pool_get_address_at_index(pool: *const FFIAddressPool, index: u32, error: *mut FFIError,) -> *mut FFIAddressInfo
```

**Description:**
Get a single address info at a specific index from the pool  Returns detailed information about the address at the given index, or NULL if the index is out of bounds or not generated yet.  # Safety  - `pool` must be a valid pointer to an FFIAddressPool - `error` must be a valid pointer to an FFIError or null - The returned FFIAddressInfo must be freed using `address_info_free`

**Safety:**
- `pool` must be a valid pointer to an FFIAddressPool - `error` must be a valid pointer to an FFIError or null - The returned FFIAddressInfo must be freed using `address_info_free`

**Module:** `address_pool`

---

#### `address_pool_get_addresses_in_range`

```c
address_pool_get_addresses_in_range(pool: *const FFIAddressPool, start_index: u32, end_index: u32, count_out: *mut usize, error: *mut FFIError,) -> *mut *mut FFIAddressInfo
```

**Description:**
Get a range of addresses from the pool  Returns an array of FFIAddressInfo structures for addresses in the range [start_index, end_index). The count_out parameter will be set to the actual number of addresses returned.  Note: This function only reads existing addresses from the pool. It does not generate new addresses. Use managed_wallet_generate_addresses_to_index if you need to generate addresses first.  # Safety  - `pool` must be a valid pointer to an FFIAddressPool - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError or null - The returned array must be freed using `address_info_array_free`

**Safety:**
- `pool` must be a valid pointer to an FFIAddressPool - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError or null - The returned array must be freed using `address_info_array_free`

**Module:** `address_pool`

---

#### `address_to_pubkey_hash`

```c
address_to_pubkey_hash(address: *const c_char, network: FFINetwork, hash_out: *mut u8,) -> i32
```

**Description:**
Extract public key hash from P2PKH address  # Safety - `address` must be a valid pointer to a null-terminated C string - `hash_out` must be a valid pointer to a buffer of at least 20 bytes  # Returns - 0 on success - -1 on error

**Safety:**
- `address` must be a valid pointer to a null-terminated C string - `hash_out` must be a valid pointer to a buffer of at least 20 bytes

**Module:** `transaction`

---

#### `address_validate`

```c
address_validate(address: *const c_char, network: FFINetwork, error: *mut FFIError,) -> bool
```

**Description:**
Validate an address  # Safety  - `address` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError

**Safety:**
- `address` must be a valid null-terminated C string - `error` must be a valid pointer to an FFIError

**Module:** `address`

---

### Transaction Management - Detailed

#### `transaction_add_input`

```c
transaction_add_input(tx: *mut FFITransaction, input: *const FFITxIn,) -> i32
```

**Description:**
Add an input to a transaction  # Safety - `tx` must be a valid pointer to an FFITransaction - `input` must be a valid pointer to an FFITxIn  # Returns - 0 on success - -1 on error

**Safety:**
- `tx` must be a valid pointer to an FFITransaction - `input` must be a valid pointer to an FFITxIn

**Module:** `transaction`

---

#### `transaction_add_output`

```c
transaction_add_output(tx: *mut FFITransaction, output: *const FFITxOut,) -> i32
```

**Description:**
Add an output to a transaction  # Safety - `tx` must be a valid pointer to an FFITransaction - `output` must be a valid pointer to an FFITxOut  # Returns - 0 on success - -1 on error

**Safety:**
- `tx` must be a valid pointer to an FFITransaction - `output` must be a valid pointer to an FFITxOut

**Module:** `transaction`

---

#### `transaction_bytes_free`

```c
transaction_bytes_free(tx_bytes: *mut u8) -> ()
```

**Description:**
Free transaction bytes  # Safety  - `tx_bytes` must be a valid pointer created by transaction functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `tx_bytes` must be a valid pointer created by transaction functions or null - After calling this function, the pointer becomes invalid

**Module:** `transaction`

---

#### `transaction_check_result_free`

```c
transaction_check_result_free(result: *mut FFITransactionCheckResult) -> ()
```

**Description:**
Free a transaction check result  # Safety  - `result` must be a valid pointer to an FFITransactionCheckResult - This function must only be called once per result

**Safety:**
- `result` must be a valid pointer to an FFITransactionCheckResult - This function must only be called once per result

**Module:** `transaction_checking`

---

#### `transaction_classify`

```c
transaction_classify(tx_bytes: *const u8, tx_len: usize, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get the transaction classification for routing  Returns a string describing the transaction type (e.g., "Standard", "CoinJoin", "AssetLock", "AssetUnlock", "ProviderRegistration", etc.)  # Safety  - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `error` must be a valid pointer to an FFIError or null - The returned string must be freed by the caller

**Safety:**
- `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes - `error` must be a valid pointer to an FFIError or null - The returned string must be freed by the caller

**Module:** `transaction_checking`

---

#### `transaction_create`

```c
transaction_create() -> *mut FFITransaction
```

**Description:**
Create a new empty transaction  # Returns - Pointer to FFITransaction on success - NULL on error

**Module:** `transaction`

---

#### `transaction_deserialize`

```c
transaction_deserialize(data: *const u8, len: u32) -> *mut FFITransaction
```

**Description:**
Deserialize a transaction  # Safety - `data` must be a valid pointer to serialized transaction data - `len` must be the correct length of the data  # Returns - Pointer to FFITransaction on success - NULL on error

**Safety:**
- `data` must be a valid pointer to serialized transaction data - `len` must be the correct length of the data

**Module:** `transaction`

---

#### `transaction_destroy`

```c
transaction_destroy(tx: *mut FFITransaction) -> ()
```

**Description:**
Destroy a transaction  # Safety - `tx` must be a valid pointer to an FFITransaction created by transaction functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `tx` must be a valid pointer to an FFITransaction created by transaction functions or null - After calling this function, the pointer becomes invalid

**Module:** `transaction`

---

#### `transaction_get_txid`

```c
transaction_get_txid(tx: *const FFITransaction, txid_out: *mut u8) -> i32
```

**Description:**
Get the transaction ID  # Safety - `tx` must be a valid pointer to an FFITransaction - `txid_out` must be a valid pointer to a buffer of at least 32 bytes  # Returns - 0 on success - -1 on error

**Safety:**
- `tx` must be a valid pointer to an FFITransaction - `txid_out` must be a valid pointer to a buffer of at least 32 bytes

**Module:** `transaction`

---

#### `transaction_get_txid_from_bytes`

```c
transaction_get_txid_from_bytes(tx_bytes: *const u8, tx_len: usize, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get transaction ID from raw transaction bytes  # Safety - `tx_bytes` must be a valid pointer to transaction bytes - `tx_len` must be the correct length of the transaction - `error` must be a valid pointer to an FFIError  # Returns - Pointer to null-terminated hex string of TXID (must be freed with string_free) - NULL on error

**Safety:**
- `tx_bytes` must be a valid pointer to transaction bytes - `tx_len` must be the correct length of the transaction - `error` must be a valid pointer to an FFIError

**Module:** `transaction`

---

#### `transaction_serialize`

```c
transaction_serialize(tx: *const FFITransaction, out_buf: *mut u8, out_len: *mut u32,) -> i32
```

**Description:**
Serialize a transaction  # Safety - `tx` must be a valid pointer to an FFITransaction - `out_buf` can be NULL to get size only - `out_len` must be a valid pointer to store the size  # Returns - 0 on success - -1 on error

**Safety:**
- `tx` must be a valid pointer to an FFITransaction - `out_buf` can be NULL to get size only - `out_len` must be a valid pointer to store the size

**Module:** `transaction`

---

#### `transaction_sighash`

```c
transaction_sighash(tx: *const FFITransaction, input_index: u32, script_pubkey: *const u8, script_pubkey_len: u32, sighash_type: u32, hash_out: *mut u8,) -> i32
```

**Description:**
Calculate signature hash for an input  # Safety - `tx` must be a valid pointer to an FFITransaction - `script_pubkey` must be a valid pointer to the script pubkey - `hash_out` must be a valid pointer to a buffer of at least 32 bytes  # Returns - 0 on success - -1 on error

**Safety:**
- `tx` must be a valid pointer to an FFITransaction - `script_pubkey` must be a valid pointer to the script pubkey - `hash_out` must be a valid pointer to a buffer of at least 32 bytes

**Module:** `transaction`

---

#### `transaction_sign_input`

```c
transaction_sign_input(tx: *mut FFITransaction, input_index: u32, private_key: *const u8, script_pubkey: *const u8, script_pubkey_len: u32, sighash_type: u32,) -> i32
```

**Description:**
Sign a transaction input  # Safety - `tx` must be a valid pointer to an FFITransaction - `private_key` must be a valid pointer to a 32-byte private key - `script_pubkey` must be a valid pointer to the script pubkey  # Returns - 0 on success - -1 on error

**Safety:**
- `tx` must be a valid pointer to an FFITransaction - `private_key` must be a valid pointer to a 32-byte private key - `script_pubkey` must be a valid pointer to the script pubkey

**Module:** `transaction`

---

#### `utxo_array_free`

```c
utxo_array_free(utxos: *mut FFIUTXO, count: usize) -> ()
```

**Description:**
Free UTXO array  # Safety  - `utxos` must be a valid pointer to an array of FFIUTXO structs allocated by this library - `count` must match the number of UTXOs in the array - The pointer must not be used after calling this function - This function must only be called once per array

**Safety:**
- `utxos` must be a valid pointer to an array of FFIUTXO structs allocated by this library - `count` must match the number of UTXOs in the array - The pointer must not be used after calling this function - This function must only be called once per array

**Module:** `utxo`

---

### Key Management - Detailed

#### `bip38_decrypt_private_key`

```c
bip38_decrypt_private_key(encrypted_key: *const c_char, passphrase: *const c_char, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Decrypt a BIP38 encrypted private key  # Safety  This function is unsafe because it dereferences raw pointers: - `encrypted_key` must be a valid, null-terminated C string - `passphrase` must be a valid, null-terminated C string - `error` must be a valid pointer to an FFIError or null

**Safety:**
This function is unsafe because it dereferences raw pointers: - `encrypted_key` must be a valid, null-terminated C string - `passphrase` must be a valid, null-terminated C string - `error` must be a valid pointer to an FFIError or null

**Module:** `bip38`

---

#### `bip38_encrypt_private_key`

```c
bip38_encrypt_private_key(private_key: *const c_char, passphrase: *const c_char, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Encrypt a private key with BIP38  # Safety  This function is unsafe because it dereferences raw pointers: - `private_key` must be a valid, null-terminated C string - `passphrase` must be a valid, null-terminated C string - `error` must be a valid pointer to an FFIError or null

**Safety:**
This function is unsafe because it dereferences raw pointers: - `private_key` must be a valid, null-terminated C string - `passphrase` must be a valid, null-terminated C string - `error` must be a valid pointer to an FFIError or null

**Module:** `bip38`

---

#### `derivation_derive_private_key_from_seed`

```c
derivation_derive_private_key_from_seed(seed: *const u8, seed_len: usize, path: *const c_char, network: FFINetwork, error: *mut FFIError,) -> *mut FFIExtendedPrivKey
```

**Description:**
Derive private key for a specific path from seed  # Safety  - `seed` must be a valid pointer to a byte array of `seed_len` length - `path` must be a valid pointer to a null-terminated C string - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Safety:**
- `seed` must be a valid pointer to a byte array of `seed_len` length - `path` must be a valid pointer to a null-terminated C string - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure all pointers remain valid for the duration of this call

**Module:** `derivation`

---

#### `derivation_new_master_key`

```c
derivation_new_master_key(seed: *const u8, seed_len: usize, network: FFINetwork, error: *mut FFIError,) -> *mut FFIExtendedPrivKey
```

**Description:**
Create a new master extended private key from seed  # Safety  - `seed` must be a valid pointer to a byte array of `seed_len` length - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure the seed pointer remains valid for the duration of this call

**Safety:**
- `seed` must be a valid pointer to a byte array of `seed_len` length - `error` must be a valid pointer to an FFIError structure or null - The caller must ensure the seed pointer remains valid for the duration of this call

**Module:** `derivation`

---

#### `extended_private_key_free`

```c
extended_private_key_free(key: *mut FFIExtendedPrivateKey) -> ()
```

**Description:**
Free an extended private key  # Safety  - `key` must be a valid pointer created by extended private key functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `key` must be a valid pointer created by extended private key functions or null - After calling this function, the pointer becomes invalid

**Module:** `keys`

---

#### `extended_private_key_get_private_key`

```c
extended_private_key_get_private_key(extended_key: *const FFIExtendedPrivateKey, error: *mut FFIError,) -> *mut FFIPrivateKey
```

**Description:**
Get the private key from an extended private key  Extracts the non-extended private key from an extended private key.  # Safety  - `extended_key` must be a valid pointer to an FFIExtendedPrivateKey - `error` must be a valid pointer to an FFIError - The returned FFIPrivateKey must be freed with `private_key_free`

**Safety:**
- `extended_key` must be a valid pointer to an FFIExtendedPrivateKey - `error` must be a valid pointer to an FFIError - The returned FFIPrivateKey must be freed with `private_key_free`

**Module:** `keys`

---

#### `extended_private_key_to_string`

```c
extended_private_key_to_string(key: *const FFIExtendedPrivateKey, network: FFINetwork, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get extended private key as string (xprv format)  Returns the extended private key in base58 format (xprv... for mainnet, tprv... for testnet)  # Safety  - `key` must be a valid pointer to an FFIExtendedPrivateKey - `network` is ignored; the network is encoded in the extended key - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `key` must be a valid pointer to an FFIExtendedPrivateKey - `network` is ignored; the network is encoded in the extended key - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

#### `extended_public_key_free`

```c
extended_public_key_free(key: *mut FFIExtendedPublicKey) -> ()
```

**Description:**
Free an extended public key  # Safety  - `key` must be a valid pointer created by extended public key functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `key` must be a valid pointer created by extended public key functions or null - After calling this function, the pointer becomes invalid

**Module:** `keys`

---

#### `extended_public_key_get_public_key`

```c
extended_public_key_get_public_key(extended_key: *const FFIExtendedPublicKey, error: *mut FFIError,) -> *mut FFIPublicKey
```

**Description:**
Get the public key from an extended public key  Extracts the non-extended public key from an extended public key.  # Safety  - `extended_key` must be a valid pointer to an FFIExtendedPublicKey - `error` must be a valid pointer to an FFIError - The returned FFIPublicKey must be freed with `public_key_free`

**Safety:**
- `extended_key` must be a valid pointer to an FFIExtendedPublicKey - `error` must be a valid pointer to an FFIError - The returned FFIPublicKey must be freed with `public_key_free`

**Module:** `keys`

---

#### `extended_public_key_to_string`

```c
extended_public_key_to_string(key: *const FFIExtendedPublicKey, network: FFINetwork, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get extended public key as string (xpub format)  Returns the extended public key in base58 format (xpub... for mainnet, tpub... for testnet)  # Safety  - `key` must be a valid pointer to an FFIExtendedPublicKey - `network` is ignored; the network is encoded in the extended key - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `key` must be a valid pointer to an FFIExtendedPublicKey - `network` is ignored; the network is encoded in the extended key - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

#### `private_key_free`

```c
private_key_free(key: *mut FFIPrivateKey) -> ()
```

**Description:**
Free a private key  # Safety  - `key` must be a valid pointer created by private key functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `key` must be a valid pointer created by private key functions or null - After calling this function, the pointer becomes invalid

**Module:** `keys`

---

#### `private_key_to_wif`

```c
private_key_to_wif(key: *const FFIPrivateKey, network: FFINetwork, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get private key as WIF string from FFIPrivateKey  # Safety  - `key` must be a valid pointer to an FFIPrivateKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `key` must be a valid pointer to an FFIPrivateKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

#### `public_key_free`

```c
public_key_free(key: *mut FFIPublicKey) -> ()
```

**Description:**
Free a public key  # Safety  - `key` must be a valid pointer created by public key functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `key` must be a valid pointer created by public key functions or null - After calling this function, the pointer becomes invalid

**Module:** `keys`

---

#### `public_key_to_hex`

```c
public_key_to_hex(key: *const FFIPublicKey, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get public key as hex string from FFIPublicKey  # Safety  - `key` must be a valid pointer to an FFIPublicKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `key` must be a valid pointer to an FFIPublicKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `keys`

---

### Mnemonic Operations - Detailed

#### `mnemonic_free`

```c
mnemonic_free(mnemonic: *mut c_char) -> ()
```

**Description:**
Free a mnemonic string  # Safety  - `mnemonic` must be a valid pointer created by mnemonic generation functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `mnemonic` must be a valid pointer created by mnemonic generation functions or null - After calling this function, the pointer becomes invalid

**Module:** `mnemonic`

---

#### `mnemonic_generate`

```c
mnemonic_generate(word_count: c_uint, error: *mut FFIError) -> *mut c_char
```

**Description:**
Generate a new mnemonic with specified word count (12, 15, 18, 21, or 24)

**Module:** `mnemonic`

---

#### `mnemonic_generate_with_language`

```c
mnemonic_generate_with_language(word_count: c_uint, language: FFILanguage, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Generate a new mnemonic with specified language and word count

**Module:** `mnemonic`

---

#### `mnemonic_to_seed`

```c
mnemonic_to_seed(mnemonic: *const c_char, passphrase: *const c_char, seed_out: *mut u8, seed_len: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Convert mnemonic to seed with optional passphrase  # Safety  - `mnemonic` must be a valid null-terminated C string - `passphrase` must be a valid null-terminated C string or null - `seed_out` must be a valid pointer to a buffer of at least 64 bytes - `seed_len` must be a valid pointer to store the seed length - `error` must be a valid pointer to an FFIError

**Safety:**
- `mnemonic` must be a valid null-terminated C string - `passphrase` must be a valid null-terminated C string or null - `seed_out` must be a valid pointer to a buffer of at least 64 bytes - `seed_len` must be a valid pointer to store the seed length - `error` must be a valid pointer to an FFIError

**Module:** `mnemonic`

---

#### `mnemonic_validate`

```c
mnemonic_validate(mnemonic: *const c_char, error: *mut FFIError) -> bool
```

**Description:**
Validate a mnemonic phrase  # Safety  - `mnemonic` must be a valid null-terminated C string or null - `error` must be a valid pointer to an FFIError

**Safety:**
- `mnemonic` must be a valid null-terminated C string or null - `error` must be a valid pointer to an FFIError

**Module:** `mnemonic`

---

#### `mnemonic_word_count`

```c
mnemonic_word_count(mnemonic: *const c_char, error: *mut FFIError,) -> c_uint
```

**Description:**
Get word count from mnemonic  # Safety  - `mnemonic` must be a valid null-terminated C string or null - `error` must be a valid pointer to an FFIError

**Safety:**
- `mnemonic` must be a valid null-terminated C string or null - `error` must be a valid pointer to an FFIError

**Module:** `mnemonic`

---

### Utility Functions - Detailed

#### `derivation_bip44_payment_path`

```c
derivation_bip44_payment_path(network: FFINetwork, account_index: c_uint, is_change: bool, address_index: c_uint, path_out: *mut c_char, path_max_len: usize, error: *mut FFIError,) -> bool
```

**Description:**
Derive a BIP44 payment path (m/44'/5'/account'/change/index)

**Module:** `derivation`

---

#### `derivation_coinjoin_path`

```c
derivation_coinjoin_path(network: FFINetwork, account_index: c_uint, path_out: *mut c_char, path_max_len: usize, error: *mut FFIError,) -> bool
```

**Description:**
Derive CoinJoin path (m/9'/5'/4'/account')

**Module:** `derivation`

---

#### `derivation_identity_authentication_path`

```c
derivation_identity_authentication_path(network: FFINetwork, identity_index: c_uint, key_index: c_uint, path_out: *mut c_char, path_max_len: usize, error: *mut FFIError,) -> bool
```

**Description:**
Derive identity authentication path (m/9'/5'/5'/0'/identity_index'/key_index')

**Module:** `derivation`

---

#### `derivation_identity_registration_path`

```c
derivation_identity_registration_path(network: FFINetwork, identity_index: c_uint, path_out: *mut c_char, path_max_len: usize, error: *mut FFIError,) -> bool
```

**Description:**
Derive identity registration path (m/9'/5'/5'/1'/index')

**Module:** `derivation`

---

#### `derivation_identity_topup_path`

```c
derivation_identity_topup_path(network: FFINetwork, identity_index: c_uint, topup_index: c_uint, path_out: *mut c_char, path_max_len: usize, error: *mut FFIError,) -> bool
```

**Description:**
Derive identity top-up path (m/9'/5'/5'/2'/identity_index'/top_up_index')

**Module:** `derivation`

---

#### `derivation_path_free`

```c
derivation_path_free(indices: *mut u32, hardened: *mut bool, count: usize,) -> ()
```

**Description:**
Free derivation path arrays Note: This function expects the count to properly free the slices  # Safety  - `indices` must be a valid pointer created by `derivation_path_parse` or null - `hardened` must be a valid pointer created by `derivation_path_parse` or null - `count` must match the count from `derivation_path_parse` - After calling this function, the pointers become invalid

**Safety:**
- `indices` must be a valid pointer created by `derivation_path_parse` or null - `hardened` must be a valid pointer created by `derivation_path_parse` or null - `count` must match the count from `derivation_path_parse` - After calling this function, the pointers become invalid

**Module:** `keys`

---

#### `derivation_path_parse`

```c
derivation_path_parse(path: *const c_char, indices_out: *mut *mut u32, hardened_out: *mut *mut bool, count_out: *mut usize, error: *mut FFIError,) -> bool
```

**Description:**
Convert derivation path string to indices  # Safety  - `path` must be a valid null-terminated C string or null - `indices_out` must be a valid pointer to store the indices array pointer - `hardened_out` must be a valid pointer to store the hardened flags array pointer - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError - The returned arrays must be freed with `derivation_path_free`

**Safety:**
- `path` must be a valid null-terminated C string or null - `indices_out` must be a valid pointer to store the indices array pointer - `hardened_out` must be a valid pointer to store the hardened flags array pointer - `count_out` must be a valid pointer to store the count - `error` must be a valid pointer to an FFIError - The returned arrays must be freed with `derivation_path_free`

**Module:** `keys`

---

#### `derivation_string_free`

```c
derivation_string_free(s: *mut c_char) -> ()
```

**Description:**
Free derivation path string  # Safety  - `s` must be a valid pointer to a C string that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `s` must be a valid pointer to a C string that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `derivation`

---

#### `derivation_xpriv_free`

```c
derivation_xpriv_free(xpriv: *mut FFIExtendedPrivKey) -> ()
```

**Description:**
Free extended private key  # Safety  - `xpriv` must be a valid pointer to an FFIExtendedPrivKey that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `xpriv` must be a valid pointer to an FFIExtendedPrivKey that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `derivation`

---

#### `derivation_xpriv_to_string`

```c
derivation_xpriv_to_string(xpriv: *const FFIExtendedPrivKey, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get extended private key as string  # Safety  - `xpriv` must be a valid pointer to an FFIExtendedPrivKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `xpriv` must be a valid pointer to an FFIExtendedPrivKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `derivation`

---

#### `derivation_xpriv_to_xpub`

```c
derivation_xpriv_to_xpub(xpriv: *const FFIExtendedPrivKey, error: *mut FFIError,) -> *mut FFIExtendedPubKey
```

**Description:**
Derive public key from extended private key  # Safety  - `xpriv` must be a valid pointer to an FFIExtendedPrivKey - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `extended_public_key_free`

**Safety:**
- `xpriv` must be a valid pointer to an FFIExtendedPrivKey - `error` must be a valid pointer to an FFIError - The returned pointer must be freed with `extended_public_key_free`

**Module:** `derivation`

---

#### `derivation_xpub_fingerprint`

```c
derivation_xpub_fingerprint(xpub: *const FFIExtendedPubKey, fingerprint_out: *mut u8, error: *mut FFIError,) -> bool
```

**Description:**
Get fingerprint from extended public key (4 bytes)  # Safety  - `xpub` must be a valid pointer to an FFIExtendedPubKey - `fingerprint_out` must be a valid pointer to a buffer of at least 4 bytes - `error` must be a valid pointer to an FFIError

**Safety:**
- `xpub` must be a valid pointer to an FFIExtendedPubKey - `fingerprint_out` must be a valid pointer to a buffer of at least 4 bytes - `error` must be a valid pointer to an FFIError

**Module:** `derivation`

---

#### `derivation_xpub_free`

```c
derivation_xpub_free(xpub: *mut FFIExtendedPubKey) -> ()
```

**Description:**
Free extended public key  # Safety  - `xpub` must be a valid pointer to an FFIExtendedPubKey that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Safety:**
- `xpub` must be a valid pointer to an FFIExtendedPubKey that was allocated by this library - The pointer must not be used after calling this function - This function must only be called once per allocation

**Module:** `derivation`

---

#### `derivation_xpub_to_string`

```c
derivation_xpub_to_string(xpub: *const FFIExtendedPubKey, error: *mut FFIError,) -> *mut c_char
```

**Description:**
Get extended public key as string  # Safety  - `xpub` must be a valid pointer to an FFIExtendedPubKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Safety:**
- `xpub` must be a valid pointer to an FFIExtendedPubKey - `error` must be a valid pointer to an FFIError - The returned string must be freed with `string_free`

**Module:** `derivation`

---

#### `ffi_network_get_name`

```c
ffi_network_get_name(network: FFINetwork) -> *const c_char
```

**Module:** `types`

---

#### `free_u32_array`

```c
free_u32_array(array: *mut c_uint, count: usize) -> ()
```

**Description:**
Free a u32 array allocated by this library  # Safety  - `array` must be a valid pointer to an array allocated by this library - `array` must not be used after calling this function

**Safety:**
- `array` must be a valid pointer to an array allocated by this library - `array` must not be used after calling this function

**Module:** `account_collection`

---

#### `script_p2pkh`

```c
script_p2pkh(pubkey_hash: *const u8, out_buf: *mut u8, out_len: *mut u32,) -> i32
```

**Description:**
Create a P2PKH script pubkey  # Safety - `pubkey_hash` must be a valid pointer to a 20-byte public key hash - `out_buf` can be NULL to get size only - `out_len` must be a valid pointer to store the size  # Returns - 0 on success - -1 on error

**Safety:**
- `pubkey_hash` must be a valid pointer to a 20-byte public key hash - `out_buf` can be NULL to get size only - `out_len` must be a valid pointer to store the size

**Module:** `transaction`

---

#### `string_free`

```c
string_free(s: *mut c_char) -> ()
```

**Description:**
Free a string  # Safety  - `s` must be a valid pointer created by C string creation functions or null - After calling this function, the pointer becomes invalid

**Safety:**
- `s` must be a valid pointer created by C string creation functions or null - After calling this function, the pointer becomes invalid

**Module:** `utils`

---

## Type Definitions

### Core Types

- `FFIError` - Error handling structure
- `FFIWallet` - Wallet handle
- `FFIWalletManager` - Wallet manager handle
- `FFIBalance` - Balance information
- `FFIUTXO` - Unspent transaction output
- `FFINetwork` - Network enumeration

## Memory Management

### Important Rules

1. **Ownership Transfer**: Functions returning pointers transfer ownership to the caller
2. **Cleanup Required**: All returned pointers must be freed using the appropriate `_free` or `_destroy` function
3. **Thread Safety**: Most functions are thread-safe, but check individual function documentation
4. **Error Handling**: Always check the `FFIError` parameter after function calls

## Usage Examples

### Basic Wallet Manager Usage

```c
// Create wallet manager
FFIError error = {0};
FFIWalletManager* manager = wallet_manager_create(&error);
if (error.code != 0) {
    // Handle error
}

// Get wallet count
size_t count = wallet_manager_wallet_count(manager, &error);

// Clean up
wallet_manager_free(manager);
```
