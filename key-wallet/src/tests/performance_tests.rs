//! Performance and stress tests for wallet operations
//!
//! Tests wallet performance under various load conditions.

use crate::account::{AccountType, StandardAccountType};
use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use crate::mnemonic::{Language, Mnemonic};
use crate::wallet::{Wallet, WalletConfig};
use crate::Network;
use secp256k1::Secp256k1;
use std::time::{Duration, Instant};

/// Performance metrics structure
struct PerformanceMetrics {
    _operation: String,
    _iterations: usize,
    total_time: Duration,
    avg_time: Duration,
    min_time: Duration,
    max_time: Duration,
    ops_per_second: f64,
}

impl PerformanceMetrics {
    pub fn from_times(operation: &str, times: Vec<Duration>) -> Self {
        let iterations = times.len();
        let total_time: Duration = times.iter().sum();
        let avg_time = total_time / iterations as u32;
        let min_time = *times.iter().min().unwrap();
        let max_time = *times.iter().max().unwrap();
        let ops_per_second = iterations as f64 / total_time.as_secs_f64();

        Self {
            _operation: operation.to_string(),
            _iterations: iterations,
            total_time,
            avg_time,
            min_time,
            max_time,
            ops_per_second,
        }
    }

    pub fn _print_summary(&self) {
        println!("Performance: {}", self._operation);
        println!("  Iterations: {}", self._iterations);
        println!("  Total time: {:?}", self.total_time);
        println!("  Avg time: {:?}", self.avg_time);
        println!("  Min time: {:?}", self.min_time);
        println!("  Max time: {:?}", self.max_time);
        println!("  Ops/sec: {:.2}", self.ops_per_second);
    }
}

#[test]
fn test_key_derivation_performance() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let secp = Secp256k1::new();

    let iterations = 1000;
    let mut times = Vec::new();

    for i in 0..iterations {
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(5).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(i).unwrap(),
        ]);

        let start = Instant::now();
        let _key = master.derive_priv(&secp, &path).unwrap();
        times.push(start.elapsed());
    }

    let metrics = PerformanceMetrics::from_times("Key Derivation", times);

    // Assert performance requirements (relaxed for test environment)
    assert!(metrics.avg_time < Duration::from_millis(10), "Key derivation too slow");
    assert!(metrics.ops_per_second > 100.0, "Should derive >100 keys/sec");
}

#[test]
fn test_account_creation_performance() {
    let config = WalletConfig::default();
    let mut wallet = Wallet::new_random(
        config,
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    let iterations = 100;
    let mut times = Vec::new();

    for i in 0..iterations {
        let start = Instant::now();
        // Try to add account, OK if already exists (e.g., account 0)
        wallet
            .add_account(
                AccountType::Standard {
                    index: i as u32,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Network::Testnet,
                None,
            )
            .ok();
        times.push(start.elapsed());
    }

    let metrics = PerformanceMetrics::from_times("Account Creation", times);

    // Assert performance requirements
    assert!(metrics.avg_time < Duration::from_millis(10), "Account creation too slow");
    assert!(metrics.ops_per_second > 100.0, "Should create >100 accounts/sec");
}

#[test]
fn test_wallet_recovery_performance() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();

    let config = WalletConfig::default();
    let iterations = 10;
    let mut times = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();
        let _wallet = Wallet::from_mnemonic(
            mnemonic.clone(),
            config.clone(),
            Network::Testnet,
            crate::wallet::initialization::WalletAccountCreationOptions::None,
        )
        .unwrap();
        times.push(start.elapsed());
    }

    let metrics = PerformanceMetrics::from_times("Wallet Recovery", times);

    // Print detailed performance metrics before assertion
    println!("\n=== Wallet Recovery Performance ===");
    println!("Average time: {:?}", metrics.avg_time);
    println!("Total time for {} iterations: {:?}", iterations, metrics.total_time);
    println!("Operations per second: {:.2}", metrics.ops_per_second);
    println!("Min/Max times: {:?} / {:?}", metrics.min_time, metrics.max_time);
    println!("Expected: < 50ms per recovery");
    println!("===================================\n");

    // Assert performance requirements
    assert!(
        metrics.avg_time < Duration::from_millis(50),
        "Wallet recovery too slow: avg {:?}, expected < 50ms",
        metrics.avg_time
    );
}

#[test]
fn test_address_generation_batch_performance() {
    use crate::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

    let secp = Secp256k1::new();
    let account_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44).unwrap(),
        ChildNumber::from_hardened_idx(5).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_key = master.derive_priv(&secp, &account_path).unwrap();
    let key_source = KeySource::Private(account_key);

    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let mut pool =
        AddressPool::new(base_path, AddressPoolType::External, 20, Network::Testnet, &key_source)
            .unwrap();

    // Batch generation test
    let batch_sizes = vec![10, 50, 100, 500];

    for batch_size in batch_sizes {
        let start = Instant::now();
        let _addresses = pool.generate_addresses(batch_size, &key_source).unwrap();
        let elapsed = start.elapsed();

        let ops_per_second = batch_size as f64 / elapsed.as_secs_f64();

        // Assert batch performance
        assert!(ops_per_second > 100.0, "Should generate >100 addresses/sec");
    }
}

#[test]
fn test_large_wallet_memory_usage() {
    let config = WalletConfig::default();
    let mut wallet = Wallet::new_random(
        config,
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add many accounts
    let num_accounts = 100;

    for i in 0..num_accounts {
        wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Network::Testnet,
                None,
            )
            .ok(); // OK if already exists
    }

    // Memory usage would be measured with external tools
    // For now, just verify the wallet can handle many accounts
    assert_eq!(
        wallet.accounts.get(&Network::Testnet).unwrap().standard_bip44_accounts.len(),
        num_accounts as usize
    );
}

#[test]
fn test_concurrent_derivation_performance() {
    use std::sync::Arc;
    use std::thread;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();
    let seed = mnemonic.to_seed("");
    let master = Arc::new(ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap());

    let num_threads = 4;
    let iterations_per_thread = 250;
    let mut handles = Vec::new();

    let start = Instant::now();

    for thread_id in 0..num_threads {
        let master_clone = Arc::clone(&master);

        let handle = thread::spawn(move || {
            let secp = Secp256k1::new();
            let mut times = Vec::new();

            for i in 0..iterations_per_thread {
                let index = thread_id * iterations_per_thread + i;
                let path = DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(44).unwrap(),
                    ChildNumber::from_hardened_idx(5).unwrap(),
                    ChildNumber::from_hardened_idx(index).unwrap(),
                ]);

                let thread_start = Instant::now();
                let _key = master_clone.derive_priv(&secp, &path).unwrap();
                times.push(thread_start.elapsed());
            }

            times
        });

        handles.push(handle);
    }

    // Collect all times
    let mut all_times = Vec::new();
    for handle in handles {
        all_times.extend(handle.join().unwrap());
    }

    let total_elapsed = start.elapsed();
    let total_operations = num_threads * iterations_per_thread;
    let ops_per_second = total_operations as f64 / total_elapsed.as_secs_f64();

    // Assert concurrent performance
    assert!(ops_per_second > 500.0, "Concurrent derivation too slow");
}

#[test]
fn test_wallet_serialization_performance() {
    // Serialization test would require bincode feature
    // For now, just test wallet creation/destruction cycle
    let config = WalletConfig::default();
    let iterations = 100;
    let mut creation_times = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();
        let _wallet = Wallet::new_random(
            config.clone(),
            Network::Testnet,
            crate::wallet::initialization::WalletAccountCreationOptions::None,
        )
        .unwrap();
        creation_times.push(start.elapsed());
    }

    let metrics = PerformanceMetrics::from_times("Wallet Creation", creation_times);

    // Assert creation performance (relaxed for test environment)
    assert!(metrics.avg_time < Duration::from_millis(50));
}

#[test]
fn test_transaction_checking_performance() {
    use dashcore::hashes::Hash;
    use dashcore::{OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

    // Create many transactions to check
    let num_transactions = 1000;
    let mut transactions = Vec::new();

    for i in 0..num_transactions {
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([(i % 256) as u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::default(),
            }],
            output: vec![TxOut {
                value: 100000,
                script_pubkey: ScriptBuf::new(),
            }],
            special_transaction_payload: None,
        };
        transactions.push(tx);
    }

    let start = Instant::now();

    // Simulate checking transactions
    for tx in &transactions {
        let _txid = tx.txid();
        let _is_coinbase = tx.is_coin_base();
        // In real implementation would check against wallet addresses
    }

    let elapsed = start.elapsed();
    let ops_per_second = num_transactions as f64 / elapsed.as_secs_f64();

    // Print detailed performance metrics before assertion
    println!("\n=== Transaction Checking Performance ===");
    println!("Checked {} transactions in {:?}", num_transactions, elapsed);
    println!("Transactions per second: {:.2}", ops_per_second);
    println!("Average time per transaction: {:?}", elapsed / num_transactions as u32);
    println!("Expected: > 10,000 transactions/sec");
    println!("=========================================\n");

    // Assert transaction checking performance
    assert!(
        ops_per_second > 10000.0,
        "Should check >10000 transactions/sec, but got {:.2} tx/sec",
        ops_per_second
    );
}

#[test]
fn test_gap_limit_scan_performance() {
    use crate::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

    let secp = Secp256k1::new();
    let account_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44).unwrap(),
        ChildNumber::from_hardened_idx(5).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_key = master.derive_priv(&secp, &account_path).unwrap();
    let key_source = KeySource::Private(account_key);

    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let mut pool =
        AddressPool::new(base_path, AddressPoolType::External, 20, Network::Testnet, &key_source)
            .unwrap();

    // Generate addresses with gaps
    pool.generate_addresses(100, &key_source).unwrap();

    // Mark some as used (with gaps)
    let used_indices = vec![0, 1, 5, 10, 25, 50, 75];
    for &index in &used_indices {
        pool.mark_index_used(index);
    }

    // Scan for gap limit
    let start = Instant::now();
    pool.maintain_gap_limit(&key_source).unwrap();
    let elapsed = start.elapsed();

    // Assert gap limit maintenance performance
    assert!(elapsed < Duration::from_millis(10), "Gap limit scan too slow");
}

#[test]
fn test_worst_case_derivation_path() {
    // Test performance with maximum depth derivation path
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let secp = Secp256k1::new();

    // Build a very deep path
    let mut path = DerivationPath::master();
    for i in 0..10 {
        path = path.child(ChildNumber::from_hardened_idx(i).unwrap());
    }

    let iterations = 100;
    let mut times = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();
        let _key = master.derive_priv(&secp, &path).unwrap();
        times.push(start.elapsed());
    }

    let metrics = PerformanceMetrics::from_times("Deep Path Derivation", times);

    // Even deep paths should be reasonably fast (relaxed threshold for test environment)
    assert!(metrics.avg_time < Duration::from_millis(20), "Deep path derivation too slow");
}
