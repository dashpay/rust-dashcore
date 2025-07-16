//! Comprehensive unit tests for transaction processor
//!
//! This module tests the critical functionality of transaction processing,
//! including transaction relevance detection, UTXO tracking, and output matching.

#[cfg(test)]
mod tests {
    use super::super::transaction_processor::*;
    use crate::storage::MemoryStorageManager;
    use crate::wallet::{Utxo, Wallet};
    use dashcore::{
        block::{Header as BlockHeader, Version},
        pow::CompactTarget,
        Address, Block, Network, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn, TxOut, Txid,
        Witness,
    };
    use dashcore_hashes::Hash;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Helper functions for test setup

    async fn create_test_wallet() -> Wallet {
        let storage = Arc::new(RwLock::new(
            MemoryStorageManager::new()
                .await
                .expect("Failed to create memory storage manager for test"),
        ));
        Wallet::new(storage)
    }

    fn create_test_address(seed: u8) -> Address {
        let pubkey_hash = PubkeyHash::from_slice(&[seed; 20])
            .expect("Valid 20-byte slice for pubkey hash");
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);
        Address::from_script(&script, Network::Testnet)
            .expect("Valid P2PKH script should produce valid address")
    }

    fn create_test_block_with_transactions(transactions: Vec<Transaction>) -> Block {
        let header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: dashcore::BlockHash::all_zeros(),
            merkle_root: dashcore_hashes::sha256d::Hash::all_zeros().into(),
            time: 1234567890,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };

        Block {
            header,
            txdata: transactions,
        }
    }

    fn create_coinbase_transaction(output_value: u64, output_script: ScriptBuf) -> Transaction {
        Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script,
            }],
            special_transaction_payload: None,
        }
    }

    fn create_regular_transaction(
        inputs: Vec<OutPoint>,
        outputs: Vec<(u64, ScriptBuf)>,
    ) -> Transaction {
        let tx_inputs = inputs
            .into_iter()
            .map(|outpoint| TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
                witness: Witness::new(),
            })
            .collect();

        let tx_outputs = outputs
            .into_iter()
            .map(|(value, script)| TxOut {
                value,
                script_pubkey: script,
            })
            .collect();

        Transaction {
            version: 1,
            lock_time: 0,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: None,
        }
    }

    fn create_test_outpoint(tx_num: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_slice(&[tx_num; 32]).expect("Valid test txid"),
            vout,
        }
    }

    // Transaction relevance detection tests

    #[tokio::test]
    async fn test_detect_relevant_transaction_by_output() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        wallet
            .add_watched_address(address.clone())
            .await
            .expect("Should add watched address successfully");

        // Create transaction with output to watched address
        let tx = create_regular_transaction(
            vec![create_test_outpoint(1, 0)],
            vec![(100000, address.script_pubkey())],
        );

        // Process transaction
        let result = processor
            .process_transaction(&tx, 100, false, &[address.clone()], &wallet, &mut storage)
            .await
            .expect("Should process transaction successfully");

        assert!(result.is_relevant);
        assert_eq!(result.utxos_added.len(), 1);
        assert_eq!(result.utxos_spent.len(), 0);
    }

    #[tokio::test]
    async fn test_detect_relevant_transaction_by_input() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        wallet
            .add_watched_address(address.clone())
            .await
            .expect("Should add watched address successfully");

        // First add a UTXO to the wallet
        let utxo_outpoint = create_test_outpoint(1, 0);
        let utxo = Utxo::new(
            utxo_outpoint,
            TxOut {
                value: 100000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );
        wallet.add_utxo(utxo).await.expect("Should add UTXO successfully");

        // Create transaction that spends our UTXO
        let tx = create_regular_transaction(
            vec![utxo_outpoint],
            vec![(90000, ScriptBuf::new())], // Send to different address
        );

        // Process transaction
        let result = processor
            .process_transaction(&tx, 101, false, &[address], &wallet, &mut storage)
            .await
            .expect("Should process transaction successfully");

        assert!(result.is_relevant);
        assert_eq!(result.utxos_added.len(), 0);
        assert_eq!(result.utxos_spent.len(), 1);
        assert_eq!(result.utxos_spent[0], utxo_outpoint);
    }

    #[tokio::test]
    async fn test_detect_irrelevant_transaction() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        let other_address = create_test_address(2);
        wallet
            .add_watched_address(address.clone())
            .await
            .expect("Should add watched address successfully");

        // Create transaction with no relevance to watched addresses
        let tx = create_regular_transaction(
            vec![create_test_outpoint(1, 0)],
            vec![(100000, other_address.script_pubkey())],
        );

        // Process transaction
        let result = processor
            .process_transaction(&tx, 100, false, &[address], &wallet, &mut storage)
            .await
            .expect("Should process transaction successfully");

        assert!(!result.is_relevant);
        assert_eq!(result.utxos_added.len(), 0);
        assert_eq!(result.utxos_spent.len(), 0);
    }

    // Output matching tests

    #[tokio::test]
    async fn test_match_multiple_outputs_to_different_addresses() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address1 = create_test_address(1);
        let address2 = create_test_address(2);
        let address3 = create_test_address(3);

        wallet
            .add_watched_address(address1.clone())
            .await
            .expect("Should add watched address1 successfully");
        wallet
            .add_watched_address(address2.clone())
            .await
            .expect("Should add watched address2 successfully");

        // Create transaction with outputs to multiple watched addresses
        let tx = create_regular_transaction(
            vec![create_test_outpoint(1, 0)],
            vec![
                (100000, address1.script_pubkey()),
                (200000, address2.script_pubkey()),
                (300000, address3.script_pubkey()), // Not watched
            ],
        );

        let watched_addresses = vec![address1.clone(), address2.clone()];
        let result = processor
            .process_transaction(&tx, 100, false, &watched_addresses, &wallet, &mut storage)
            .await
            .expect("Should process transaction successfully");

        assert!(result.is_relevant);
        assert_eq!(result.utxos_added.len(), 2);
        assert_eq!(result.utxos_spent.len(), 0);

        // Verify correct outputs were matched
        let utxo1 = result
            .utxos_added
            .iter()
            .find(|u| u.outpoint.vout == 0)
            .expect("Should find UTXO for vout 0");
        assert_eq!(utxo1.address, address1);
        assert_eq!(utxo1.txout.value, 100000);

        let utxo2 = result
            .utxos_added
            .iter()
            .find(|u| u.outpoint.vout == 1)
            .expect("Should find UTXO for vout 1");
        assert_eq!(utxo2.address, address2);
        assert_eq!(utxo2.txout.value, 200000);
    }

    #[tokio::test]
    async fn test_match_change_output() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        wallet
            .add_watched_address(address.clone())
            .await
            .expect("Should add watched address successfully");

        // Add a UTXO to spend
        let utxo_outpoint = create_test_outpoint(1, 0);
        let utxo = Utxo::new(
            utxo_outpoint,
            TxOut {
                value: 100000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );
        wallet.add_utxo(utxo).await.expect("Should add UTXO successfully");

        // Create transaction that spends our UTXO and sends change back
        let tx = create_regular_transaction(
            vec![utxo_outpoint],
            vec![
                (60000, ScriptBuf::new()),        // Payment to other
                (39000, address.script_pubkey()), // Change back to us
            ],
        );

        let result = processor
            .process_transaction(&tx, 101, false, &[address.clone()], &wallet, &mut storage)
            .await
            .expect("Should process transaction successfully");

        assert!(result.is_relevant);
        assert_eq!(result.utxos_spent.len(), 1);
        assert_eq!(result.utxos_added.len(), 1);

        // Verify change output
        let change_utxo = &result.utxos_added[0];
        assert_eq!(change_utxo.outpoint.vout, 1);
        assert_eq!(change_utxo.txout.value, 39000);
        assert_eq!(change_utxo.address, address);
    }

    // Block processing tests

    #[tokio::test]
    async fn test_process_block_with_mixed_transactions() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address1 = create_test_address(1);
        let address2 = create_test_address(2);

        wallet
            .add_watched_address(address1.clone())
            .await
            .expect("Should add watched address1 successfully");

        // Create block with multiple transactions
        let coinbase_tx = create_coinbase_transaction(5000000000, address1.script_pubkey());
        let relevant_tx = create_regular_transaction(
            vec![create_test_outpoint(1, 0)],
            vec![(100000, address1.script_pubkey())],
        );
        let irrelevant_tx = create_regular_transaction(
            vec![create_test_outpoint(2, 0)],
            vec![(200000, address2.script_pubkey())],
        );

        let block =
            create_test_block_with_transactions(vec![coinbase_tx, relevant_tx, irrelevant_tx]);

        let result = processor
            .process_block(&block, 100, &wallet, &mut storage)
            .await
            .expect("Should process block successfully");

        assert_eq!(result.height, 100);
        assert_eq!(result.transactions.len(), 3);
        assert_eq!(result.relevant_transaction_count, 2); // Coinbase + relevant_tx
        assert_eq!(result.total_utxos_added, 2);
        assert_eq!(result.total_utxos_spent, 0);

        // Verify transaction results
        assert!(result.transactions[0].is_relevant); // Coinbase
        assert!(result.transactions[1].is_relevant); // Relevant tx
        assert!(!result.transactions[2].is_relevant); // Irrelevant tx
    }

    #[tokio::test]
    async fn test_process_empty_block_with_watched_addresses() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        wallet
            .add_watched_address(address)
            .await
            .expect("Should add watched address successfully");

        let block = create_test_block_with_transactions(vec![]);
        let result = processor
            .process_block(&block, 100, &wallet, &mut storage)
            .await
            .expect("Should process empty block successfully");

        assert_eq!(result.transactions.len(), 0);
        assert_eq!(result.relevant_transaction_count, 0);
        assert_eq!(result.total_utxos_added, 0);
        assert_eq!(result.total_utxos_spent, 0);
    }

    // Coinbase handling tests

    #[tokio::test]
    async fn test_coinbase_transaction_handling() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        wallet
            .add_watched_address(address.clone())
            .await
            .expect("Should add watched address successfully");

        let coinbase_tx = create_coinbase_transaction(5000000000, address.script_pubkey());
        let block = create_test_block_with_transactions(vec![coinbase_tx]);

        let result = processor
            .process_block(&block, 100, &wallet, &mut storage)
            .await
            .expect("Should process block successfully");

        assert_eq!(result.transactions.len(), 1);
        let tx_result = &result.transactions[0];
        assert!(tx_result.is_relevant);
        assert_eq!(tx_result.utxos_added.len(), 1);
        assert_eq!(tx_result.utxos_spent.len(), 0);

        // Verify coinbase UTXO properties
        let coinbase_utxo = &tx_result.utxos_added[0];
        assert!(coinbase_utxo.is_coinbase);
        assert_eq!(coinbase_utxo.height, 100);
        assert_eq!(coinbase_utxo.txout.value, 5000000000);
    }

    #[tokio::test]
    async fn test_coinbase_inputs_not_checked_for_spending() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        wallet
            .add_watched_address(address.clone())
            .await
            .expect("Should add watched address successfully");

        // Add a UTXO with null outpoint (should never happen in practice)
        let null_utxo = Utxo::new(
            OutPoint::null(),
            TxOut {
                value: 100000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );
        wallet
            .add_utxo(null_utxo)
            .await
            .expect("Should add UTXO successfully");

        let coinbase_tx = create_coinbase_transaction(5000000000, address.script_pubkey());
        let result = processor
            .process_transaction(&coinbase_tx, 101, true, &[address], &wallet, &mut storage)
            .await
            .expect("Should process coinbase transaction successfully");

        // Coinbase should not spend the null UTXO
        assert_eq!(result.utxos_spent.len(), 0);
        assert_eq!(result.utxos_added.len(), 1);
    }

    // Address statistics tests

    #[tokio::test]
    async fn test_get_address_stats_empty() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let address = create_test_address(1);

        let stats = processor
            .get_address_stats(&address, &wallet)
            .await
            .expect("Should get address stats successfully");

        assert_eq!(stats.address, address);
        assert_eq!(stats.utxo_count, 0);
        assert_eq!(stats.total_value, dashcore::Amount::ZERO);
        assert_eq!(stats.confirmed_value, dashcore::Amount::ZERO);
        assert_eq!(stats.pending_value, dashcore::Amount::ZERO);
        assert_eq!(stats.spendable_count, 0);
        assert_eq!(stats.coinbase_count, 0);
    }

    #[tokio::test]
    async fn test_get_address_stats_with_mixed_utxos() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let address = create_test_address(1);

        // Add regular UTXO
        let regular_utxo = Utxo::new(
            create_test_outpoint(1, 0),
            TxOut {
                value: 100000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            999000, // Old enough to be confirmed
            false,
        );

        // Add coinbase UTXO
        let coinbase_utxo = Utxo::new(
            create_test_outpoint(2, 0),
            TxOut {
                value: 5000000000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            999900, // Recent coinbase
            true,
        );

        // Add pending UTXO
        let pending_utxo = Utxo::new(
            create_test_outpoint(3, 0),
            TxOut {
                value: 50000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            999998, // Very recent
            false,
        );

        wallet
            .add_utxo(regular_utxo)
            .await
            .expect("Should add regular UTXO successfully");
        wallet
            .add_utxo(coinbase_utxo)
            .await
            .expect("Should add coinbase UTXO successfully");
        wallet
            .add_utxo(pending_utxo)
            .await
            .expect("Should add pending UTXO successfully");

        let stats = processor
            .get_address_stats(&address, &wallet)
            .await
            .expect("Should get address stats successfully");

        assert_eq!(stats.utxo_count, 3);
        assert_eq!(stats.total_value, dashcore::Amount::from_sat(5000150000));
        assert_eq!(stats.coinbase_count, 1);
        assert_eq!(stats.spendable_count, 3); // All spendable with high assumed height
        
        // With assumed height of 1000000, all should be confirmed
        assert_eq!(stats.confirmed_value, dashcore::Amount::from_sat(5000150000));
        assert_eq!(stats.pending_value, dashcore::Amount::ZERO);
    }

    // Error handling tests

    #[tokio::test]
    async fn test_process_block_with_no_watched_addresses() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        // Don't add any watched addresses
        let tx = create_regular_transaction(
            vec![create_test_outpoint(1, 0)],
            vec![(100000, ScriptBuf::new())],
        );
        let block = create_test_block_with_transactions(vec![tx]);

        let result = processor
            .process_block(&block, 100, &wallet, &mut storage)
            .await
            .expect("Should process block successfully");

        // Should skip processing when no addresses are watched
        assert_eq!(result.transactions.len(), 0);
        assert_eq!(result.relevant_transaction_count, 0);
    }

    // Complex transaction scenarios

    #[tokio::test]
    async fn test_transaction_with_multiple_inputs_and_outputs() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address1 = create_test_address(1);
        let address2 = create_test_address(2);
        let address3 = create_test_address(3);

        wallet
            .add_watched_address(address1.clone())
            .await
            .expect("Should add watched address1 successfully");
        wallet
            .add_watched_address(address2.clone())
            .await
            .expect("Should add watched address2 successfully");

        // Add UTXOs to spend
        let utxo1 = Utxo::new(
            create_test_outpoint(1, 0),
            TxOut {
                value: 100000,
                script_pubkey: address1.script_pubkey(),
            },
            address1.clone(),
            100,
            false,
        );
        let utxo2 = Utxo::new(
            create_test_outpoint(2, 1),
            TxOut {
                value: 200000,
                script_pubkey: address2.script_pubkey(),
            },
            address2.clone(),
            100,
            false,
        );

        wallet
            .add_utxo(utxo1)
            .await
            .expect("Should add UTXO1 successfully");
        wallet
            .add_utxo(utxo2)
            .await
            .expect("Should add UTXO2 successfully");

        // Create complex transaction
        let tx = create_regular_transaction(
            vec![
                create_test_outpoint(1, 0), // Our UTXO
                create_test_outpoint(2, 1), // Our UTXO
                create_test_outpoint(3, 0), // Someone else's UTXO
            ],
            vec![
                (50000, address1.script_pubkey()),  // Output to us
                (75000, address3.script_pubkey()),  // Output to other
                (100000, address2.script_pubkey()), // Output to us
            ],
        );

        let watched = vec![address1, address2];
        let result = processor
            .process_transaction(&tx, 101, false, &watched, &wallet, &mut storage)
            .await
            .expect("Should process transaction successfully");

        assert!(result.is_relevant);
        assert_eq!(result.utxos_spent.len(), 2); // Both our UTXOs spent
        assert_eq!(result.utxos_added.len(), 2); // Two new outputs to us
        
        // Verify correct outputs
        assert!(result.utxos_added.iter().any(|u| u.outpoint.vout == 0 && u.txout.value == 50000));
        assert!(result.utxos_added.iter().any(|u| u.outpoint.vout == 2 && u.txout.value == 100000));
    }

    #[tokio::test]
    async fn test_self_transfer_transaction() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage manager for test");

        let address = create_test_address(1);
        wallet
            .add_watched_address(address.clone())
            .await
            .expect("Should add watched address successfully");

        // Add UTXO to spend
        let utxo = Utxo::new(
            create_test_outpoint(1, 0),
            TxOut {
                value: 100000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );
        wallet.add_utxo(utxo).await.expect("Should add UTXO successfully");

        // Create self-transfer (consolidation) transaction
        let tx = create_regular_transaction(
            vec![create_test_outpoint(1, 0)],
            vec![(99000, address.script_pubkey())], // Minus fee
        );

        let result = processor
            .process_transaction(&tx, 101, false, &[address], &wallet, &mut storage)
            .await
            .expect("Should process transaction successfully");

        assert!(result.is_relevant);
        assert_eq!(result.utxos_spent.len(), 1);
        assert_eq!(result.utxos_added.len(), 1);
        assert_eq!(result.utxos_added[0].txout.value, 99000);
    }
}