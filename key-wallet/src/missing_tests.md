# Missing Tests in key-wallet (from DashSync-iOS)

## 1. Wallet Module Tests (`wallet.rs`)

### Transaction Management
- `test_transaction_creation` - Create transactions with specific amounts
- `test_transaction_with_fee_calculation` - Fee calculation for different transaction sizes
- `test_transaction_signing` - Sign transactions with wallet keys
- `test_transaction_registration` - Register and track transactions
- `test_balance_after_transactions` - Balance updates after tx registration
- `test_pending_transactions` - Handle unconfirmed transactions
- `test_transaction_removal` - Remove transactions and update balance
- `test_chain_synchronization_fingerprint` - Generate sync fingerprints
- `test_wallet_recovery_from_seed` - Full wallet recovery process
- `test_wallet_import_export` - Import/export wallet data

### Multi-Account Management
- `test_multiple_account_balances` - Track balances across accounts
- `test_account_discovery` - Discover accounts during recovery
- `test_account_switching` - Switch active account
- `test_account_metadata_persistence` - Persist account metadata

### Advanced Features
- `test_watch_only_wallet_operations` - Complete watch-only workflow
- `test_wallet_encryption` - Encrypt/decrypt wallet data
- `test_wallet_backup_restore` - Complete backup/restore cycle
- `test_wallet_migration` - Migrate wallet versions

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
- `test_mnemonic_japanese` - Japanese wordlist
- `test_mnemonic_french` - French wordlist
- `test_mnemonic_spanish` - Spanish wordlist
- `test_mnemonic_italian` - Italian wordlist
- `test_mnemonic_korean` - Korean wordlist
- `test_mnemonic_czech` - Czech wordlist
- `test_mnemonic_portuguese` - Portuguese wordlist
- `test_mnemonic_chinese_simplified` - Chinese simplified
- `test_mnemonic_chinese_traditional` - Chinese traditional

### Mnemonic Recovery
- `test_mnemonic_missing_word_recovery` - Find missing word
- `test_mnemonic_typo_correction` - Correct typos
- `test_mnemonic_similar_words` - Handle similar words
- `test_partial_mnemonic_recovery` - Recover from partial phrase

### Special Derivation Paths
- `test_identity_authentication_derivation` - Identity auth keys
- `test_identity_registration_derivation` - Identity registration
- `test_identity_topup_derivation` - Identity top-up
- `test_provider_voting_derivation` - Provider voting keys
- `test_provider_operator_derivation` - Provider operator keys
- `test_dashpay_derivation` - DashPay contact keys

## 5. Key Management Tests (`derivation.rs`)

### BIP38 Support
- `test_bip38_encryption` - Encrypt private keys
- `test_bip38_decryption` - Decrypt with password
- `test_bip38_wrong_password` - Handle wrong password
- `test_bip38_scrypt_parameters` - Different scrypt params

### Key Operations
- `test_key_signing_deterministic` - Deterministic signatures
- `test_key_signing_compact` - Compact signatures
- `test_key_verification` - Signature verification
- `test_key_recovery_from_signature` - Recover pubkey from sig

## 6. UTXO Management Tests (new `utxo.rs`)

### UTXO Tracking
- `test_utxo_selection_smallest` - Select smallest UTXOs
- `test_utxo_selection_largest` - Select largest UTXOs
- `test_utxo_selection_optimize_size` - Optimize tx size
- `test_utxo_selection_privacy` - Privacy-focused selection
- `test_utxo_coin_control` - Manual UTXO selection
- `test_utxo_locking` - Lock/unlock UTXOs
- `test_utxo_spent_detection` - Detect spent UTXOs
- `test_utxo_maturity` - Handle coinbase maturity

### UTXO Sets
- `test_utxo_set_update` - Update UTXO set
- `test_utxo_set_rollback` - Rollback on reorg
- `test_utxo_set_persistence` - Persist UTXO set

## 7. Transaction Tests (integrate with wallet)

### Transaction Types
- `test_standard_transaction` - Standard P2PKH
- `test_multisig_transaction` - Multisig creation
- `test_timelocked_transaction` - Timelock handling
- `test_asset_lock_transaction` - Platform asset locks
- `test_asset_unlock_transaction` - Platform unlocks

### Fee Management
- `test_fee_estimation` - Estimate fees accurately
- `test_fee_bumping` - RBF fee bumping
- `test_dust_threshold` - Handle dust outputs
- `test_change_output_creation` - Change output logic

## 8. Integration Tests

### Full Wallet Lifecycle
- `test_wallet_full_lifecycle` - Create, use, backup, restore
- `test_wallet_concurrent_operations` - Thread safety
- `test_wallet_performance_benchmark` - Performance metrics
- `test_wallet_memory_usage` - Memory profiling

### Network Simulation
- `test_chain_reorg_handling` - Handle reorgs
- `test_double_spend_detection` - Detect double spends
- `test_mempool_transaction_handling` - Mempool txs

## Files to Add Tests To:

1. **wallet.rs** - Add 15-20 comprehensive wallet tests
2. **account.rs** - Add 10-12 account management tests
3. **address_pool.rs** - Add 5-7 pool optimization tests
4. **gap_limit.rs** - Add 3-4 edge case tests
5. **mnemonic.rs** - Add 9 language tests + 4 recovery tests
6. **derivation.rs** - Add 8-10 key operation tests
7. **NEW: utxo.rs** - Create with 12-15 UTXO tests
8. **NEW: transaction.rs** - Create with 10-12 tx tests
9. **NEW: integration_tests.rs** - Create with 8-10 integration tests

## Test Data Requirements

- Test vectors from BIP32/BIP39/BIP44 specifications
- DashSync test vectors for compatibility
- Language-specific mnemonic test cases
- Transaction test vectors
- Chain synchronization test data

## Priority Order

1. **High Priority**: UTXO management, transaction creation, fee calculation
2. **Medium Priority**: Multi-language mnemonics, BIP38, CoinJoin
3. **Low Priority**: Performance tests, edge cases, migration tests