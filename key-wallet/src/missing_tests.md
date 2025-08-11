# Missing Tests in key-wallet (Low-Level Components)

## 1. Wallet Module Tests (`wallet.rs`)

### Core Wallet Operations
- ✓ `test_wallet_creation_from_mnemonic` - Create wallet from mnemonic
- ✓ `test_wallet_creation_empty` - Create empty wallet
- ✓ `test_wallet_recovery_from_seed` - Full wallet recovery process
- `test_wallet_import_export` - Import/export wallet data
- `test_wallet_encryption` - Encrypt/decrypt wallet data
- `test_wallet_backup_restore` - Complete backup/restore cycle
- `test_wallet_migration` - Migrate wallet versions

### Single Wallet Account Management
- ✓ `test_account_creation` - Create individual accounts
- ✓ `test_account_retrieval` - Get accounts by index
- ✓ `test_account_metadata` - Account metadata management

## 2. Account Module Tests (`account.rs`)

### Gap Limit Scenarios
- `test_gap_limit_with_sparse_usage` - Addresses used with gaps
- `test_gap_limit_recovery` - Recovery with various gap patterns
- `test_gap_limit_edge_cases` - Boundary conditions
- `test_dynamic_gap_limit_adjustment` - Adjust gap limit on the fly

### Address Management
- `test_address_labeling` - Add/update address labels
- `test_address_metadata` - Custom metadata management
- `test_address_sorting_bip69` - BIP69 deterministic sorting
- `test_address_reuse_detection` - Detect address reuse
- `test_change_address_optimization` - Optimize change address selection

### CoinJoin/PrivateSend
- `test_coinjoin_rounds` - Track CoinJoin rounds
- `test_coinjoin_denomination` - Denomination management
- `test_coinjoin_balance_tracking` - Separate CoinJoin balance
- `test_coinjoin_address_isolation` - Address pool isolation

## 3. Address Pool Module Tests (`address_pool.rs`)

### Performance Tests
- `test_large_pool_generation` - Generate 10000+ addresses
- `test_pool_pruning` - Prune unused addresses
- `test_concurrent_address_generation` - Thread-safe generation
- `test_address_caching` - Cache performance

### Edge Cases
- `test_pool_reset` - Reset pool state
- `test_pool_migration` - Migrate pool format
- `test_corrupted_pool_recovery` - Recover from corruption

## 4. BIP32/BIP39 Tests (`bip32.rs`, `mnemonic.rs`)

### Language Support
- ✓ `test_mnemonic_japanese` - Japanese wordlist
- ✓ `test_mnemonic_french` - French wordlist
- ✓ `test_mnemonic_spanish` - Spanish wordlist
- ✓ `test_mnemonic_italian` - Italian wordlist
- ✓ `test_mnemonic_korean` - Korean wordlist
- ✓ `test_mnemonic_czech` - Czech wordlist
- ✓ `test_mnemonic_portuguese` - Portuguese wordlist
- ✓ `test_mnemonic_chinese_simplified` - Chinese simplified
- ✓ `test_mnemonic_chinese_traditional` - Chinese traditional

### Mnemonic Recovery
- `test_mnemonic_missing_word_recovery` - Find missing word
- `test_mnemonic_typo_correction` - Correct typos
- `test_mnemonic_similar_words` - Handle similar words
- `test_partial_mnemonic_recovery` - Recover from partial phrase

### Special Derivation Paths
- ✓ `test_identity_authentication_derivation` - Identity auth keys
- ✓ `test_identity_registration_derivation` - Identity registration
- ✓ `test_identity_topup_derivation` - Identity top-up
- ✓ `test_provider_voting_derivation` - Provider voting keys
- ✓ `test_provider_operator_derivation` - Provider operator keys
- ✓ `test_dashpay_derivation` - DashPay contact keys

## 5. Key Management Tests (`derivation.rs`)

### BIP38 Support
- `test_bip38_encryption` - Encrypt private keys
- `test_bip38_decryption` - Decrypt with password
- `test_bip38_wrong_password` - Handle wrong password
- `test_bip38_scrypt_parameters` - Different scrypt params

### Key Operations
- ✓ `test_key_signing_deterministic` - Deterministic signatures
- `test_key_signing_compact` - Compact signatures
- ✓ `test_key_verification` - Signature verification
- ✓ `test_key_recovery_from_signature` - Recover pubkey from sig

## 6. Low-Level Cryptographic Tests

### Key Operations (stays in key-wallet)
- ✓ `test_key_signing_deterministic` - Deterministic signatures (already implemented above)
- `test_key_signing_compact` - Compact signatures  
- ✓ `test_key_verification` - Signature verification (already implemented above)
- ✓ `test_key_recovery_from_signature` - Recover pubkey from sig (already implemented above)

### Address Generation
- `test_address_generation_accuracy` - Verify address generation
- `test_address_network_validation` - Network-specific addresses

## Files to Add Tests To (key-wallet only):

1. **wallet.rs** - Add 8-10 core wallet operation tests
2. **account.rs** - Add 10-12 account management tests  
3. **address_pool.rs** - Add 5-7 pool optimization tests
4. **gap_limit.rs** - Add 3-4 edge case tests
5. **mnemonic.rs** - Add 9 language tests + 4 recovery tests
6. **derivation.rs** - Add 8-10 key operation tests

## Test Data Requirements

- Test vectors from BIP32/BIP39/BIP44 specifications
- DashSync test vectors for compatibility
- Language-specific mnemonic test cases
- Key derivation test vectors

## Priority Order

1. **High Priority**: Mnemonic handling, key derivation, address generation
2. **Medium Priority**: Multi-language mnemonics, BIP38, gap limit edge cases
3. **Low Priority**: Performance tests, CoinJoin, migration tests

## Note

High-level tests involving:
- Transaction building and signing
- UTXO management and coin selection  
- Fee calculation and management
- Multi-wallet operations
- Balance tracking

Have been moved to `key-wallet-manager/missing_tests.md`