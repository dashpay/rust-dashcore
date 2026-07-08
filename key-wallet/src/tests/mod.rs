//! Comprehensive test suite for the key-wallet library
//!
//! This module contains exhaustive tests for all functionality.

mod account_tests;

mod balance_tests;

mod address_pool_tests;

mod advanced_transaction_tests;

mod backup_restore_tests;

mod edge_case_tests;

mod integration_tests;

mod keep_finalized_transactions_tests;

mod managed_account_collection_tests;

mod late_account_finality_boundary_test;

mod performance_tests;

mod special_transaction_matching_tests;

mod special_transaction_tests;

mod transaction_tests;

mod observed_spent_outpoints_tests;

mod async_chainlock_prune_race_test;

mod net_amount_source_of_truth_test;

mod spent_outpoints_tests;

mod unit_variant_wallet_tests;

mod wallet_tests;
