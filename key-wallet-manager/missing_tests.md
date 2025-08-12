# Missing Tests in key-wallet-manager

## 1. WalletManager Multi-Wallet Tests (`wallet_manager.rs`)

### Multi-Wallet Management
- `test_create_multiple_wallets` - Create and manage multiple wallets
- `test_wallet_isolation` - Ensure wallets are isolated from each other
- `test_wallet_removal` - Remove wallets and cleanup resources
- `test_wallet_metadata_management` - Update wallet names, descriptions
- `test_duplicate_wallet_id_prevention` - Prevent duplicate wallet IDs
- `test_wallet_enumeration` - List and iterate over wallets

### Multi-Account Operations
- `test_cross_wallet_account_operations` - Account operations across wallets
- `test_wallet_account_balances` - Balance tracking per wallet/account
- `test_account_creation_per_wallet` - Create accounts in specific wallets
- `test_account_discovery_per_wallet` - Discover accounts during wallet recovery

### Transaction Management (High-Level)
- `test_multi_wallet_transaction_history` - Transaction history per wallet
- `test_cross_wallet_balance_tracking` - Total vs per-wallet balances
- `test_transaction_wallet_assignment` - Assign transactions to correct wallet
- `test_concurrent_wallet_transactions` - Thread-safe wallet operations

## 2. Transaction Builder Tests (`transaction_builder.rs`)

### Transaction Construction
- `test_transaction_creation` - Create transactions with specific amounts
- `test_transaction_with_fee_calculation` - Fee calculation for different transaction sizes
- `test_transaction_signing` - Sign transactions with wallet keys
- `test_multiple_recipients` - Send to multiple recipients
- `test_change_output_creation` - Change output logic
- `test_dust_threshold` - Handle dust outputs

### Fee Management
- `test_fee_estimation` - Estimate fees accurately
- `test_fee_levels` - Test different fee levels (Low, Normal, High)
- `test_custom_fee_rates` - Custom fee rate setting
- `test_fee_bumping` - RBF fee bumping
- `test_insufficient_funds_handling` - Handle insufficient balance

### Transaction Types
- `test_standard_transaction` - Standard P2PKH
- `test_multisig_transaction` - Multisig creation
- `test_timelocked_transaction` - Timelock handling
- `test_asset_lock_transaction` - Platform asset locks
- `test_asset_unlock_transaction` - Platform unlocks

## 3. UTXO Management Tests (`utxo.rs`)

### UTXO Set Operations
- `test_utxo_set_update` - Update UTXO set
- `test_utxo_set_rollback` - Rollback on reorg
- `test_utxo_set_persistence` - Persist UTXO set
- `test_utxo_balance_tracking` - Track confirmed/unconfirmed balances
- `test_utxo_locking` - Lock/unlock UTXOs
- `test_utxo_spent_detection` - Detect spent UTXOs
- `test_utxo_maturity` - Handle coinbase maturity

### Per-Wallet UTXO Management
- `test_wallet_utxo_isolation` - UTXOs isolated per wallet
- `test_wallet_utxo_addition` - Add UTXOs to specific wallets
- `test_global_vs_wallet_utxos` - Global vs per-wallet UTXO sets
- `test_utxo_wallet_assignment` - Assign UTXOs to correct wallets

## 4. Coin Selection Tests (`coin_selection.rs`)

### Selection Strategies
- `test_utxo_selection_smallest` - Select smallest UTXOs
- `test_utxo_selection_largest` - Select largest UTXOs
- `test_utxo_selection_optimize_size` - Optimize tx size
- `test_utxo_selection_privacy` - Privacy-focused selection
- `test_utxo_selection_branch_and_bound` - Branch and bound algorithm
- `test_utxo_coin_control` - Manual UTXO selection

### Selection Edge Cases
- `test_exact_amount_selection` - Exact change scenarios
- `test_insufficient_utxos` - Not enough UTXOs available
- `test_dust_avoidance` - Avoid creating dust change
- `test_locked_utxo_exclusion` - Exclude locked UTXOs

## 5. Fee Calculation Tests (`fee.rs`)

### Fee Estimation
- `test_fee_rate_calculation` - Calculate fee rates
- `test_transaction_size_estimation` - Estimate transaction sizes
- `test_fee_level_mapping` - Map fee levels to rates
- `test_dynamic_fee_adjustment` - Adjust fees based on network

### Fee Edge Cases
- `test_minimum_fee_enforcement` - Enforce minimum fees
- `test_maximum_fee_protection` - Prevent excessive fees
- `test_fee_overpayment_detection` - Detect fee overpayment

## 6. Watch-Only Wallet Tests

### Watch-Only Operations
- `test_watch_only_wallet_creation` - Create watch-only wallets
- `test_watch_only_balance_tracking` - Track balances without private keys
- `test_watch_only_transaction_monitoring` - Monitor transactions
- `test_watch_only_utxo_management` - UTXO tracking for watch-only

## 7. Integration Tests (`integration_tests.rs`)

### Full Wallet Manager Lifecycle
- `test_wallet_manager_full_lifecycle` - Create, use, backup, restore wallets
- `test_wallet_manager_concurrent_operations` - Thread safety across wallets
- `test_wallet_manager_performance_benchmark` - Performance with multiple wallets
- `test_wallet_manager_memory_usage` - Memory profiling with multiple wallets

### Cross-Wallet Scenarios
- `test_cross_wallet_transactions` - Transactions between wallets
- `test_wallet_balance_aggregation` - Aggregate balances across wallets
- `test_wallet_synchronization` - Keep wallets synchronized

### Error Handling
- `test_wallet_not_found_errors` - Handle missing wallet IDs
- `test_account_not_found_errors` - Handle missing accounts
- `test_transaction_build_failures` - Handle transaction build errors
- `test_utxo_management_errors` - Handle UTXO operation errors

## 8. Persistence Tests

### Wallet State Persistence
- `test_wallet_metadata_persistence` - Persist wallet metadata
- `test_utxo_set_persistence` - Persist UTXO sets per wallet
- `test_transaction_history_persistence` - Persist transaction history
- `test_wallet_state_recovery` - Recover wallet state after restart

## Files to Add Tests To:

1. **wallet_manager.rs** - Add 15-20 multi-wallet management tests
2. **transaction_builder.rs** - Add 12-15 transaction building tests
3. **utxo.rs** - Add 10-12 UTXO management tests
4. **coin_selection.rs** - Add 8-10 coin selection tests
5. **fee.rs** - Add 5-7 fee calculation tests
6. **NEW: integration_tests.rs** - Create with 10-12 integration tests

## Test Data Requirements

- Multi-wallet test scenarios
- Cross-wallet transaction test vectors
- UTXO set test data
- Fee calculation test cases
- Coin selection algorithm test vectors

## Priority Order

1. **High Priority**: Multi-wallet management, transaction building, UTXO management
2. **Medium Priority**: Coin selection, fee calculation, watch-only wallets
3. **Low Priority**: Performance tests, edge cases, persistence tests