//! Transaction processing for wallet UTXO management.
//!
//! This module handles processing blocks and transactions to extract relevant
//! UTXOs and update the wallet state.

use dashcore::{Address, Block, OutPoint, Transaction};
use tracing;

use crate::error::Result;
use crate::storage::StorageManager;
use crate::wallet::{Utxo, Wallet};

/// Result of processing a transaction.
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// UTXOs that were added (new outputs to watched addresses).
    pub utxos_added: Vec<Utxo>,
    
    /// UTXOs that were spent (inputs that spent our UTXOs).
    pub utxos_spent: Vec<OutPoint>,
    
    /// The transaction that was processed.
    pub transaction: Transaction,
    
    /// Whether this transaction is relevant to the wallet.
    pub is_relevant: bool,
}

/// Result of processing a block.
#[derive(Debug, Clone)]
pub struct BlockResult {
    /// All transaction results from this block.
    pub transactions: Vec<TransactionResult>,
    
    /// Block height.
    pub height: u32,
    
    /// Block hash.
    pub block_hash: dashcore::BlockHash,
    
    /// Total number of relevant transactions.
    pub relevant_transaction_count: usize,
    
    /// Total UTXOs added from this block.
    pub total_utxos_added: usize,
    
    /// Total UTXOs spent from this block.
    pub total_utxos_spent: usize,
}

/// Processes transactions and blocks to extract wallet-relevant data.
pub struct TransactionProcessor;

impl TransactionProcessor {
    /// Create a new transaction processor.
    pub fn new() -> Self {
        Self
    }
    
    /// Process a block and extract relevant transactions and UTXOs.
    ///
    /// This is the main entry point for processing downloaded blocks.
    /// It will:
    /// 1. Check each transaction for relevance to watched addresses
    /// 2. Extract new UTXOs for watched addresses
    /// 3. Mark spent UTXOs as spent
    /// 4. Update the wallet's UTXO set
    pub async fn process_block(
        &self,
        block: &Block,
        height: u32,
        wallet: &Wallet,
        storage: &mut dyn StorageManager,
    ) -> Result<BlockResult> {
        let block_hash = block.block_hash();
        
        tracing::info!(
            "🔍 Processing block {} at height {} ({} transactions)",
            block_hash,
            height,
            block.txdata.len()
        );
        
        // Get the current watched addresses
        let watched_addresses = wallet.get_watched_addresses().await;
        if watched_addresses.is_empty() {
            tracing::debug!("No watched addresses, skipping block processing");
            return Ok(BlockResult {
                transactions: vec![],
                height,
                block_hash,
                relevant_transaction_count: 0,
                total_utxos_added: 0,
                total_utxos_spent: 0,
            });
        }
        
        tracing::debug!("Processing block with {} watched addresses", watched_addresses.len());
        
        let mut transaction_results = Vec::new();
        let mut total_utxos_added = 0;
        let mut total_utxos_spent = 0;
        let mut relevant_transaction_count = 0;
        
        // Process each transaction in the block
        for (tx_index, transaction) in block.txdata.iter().enumerate() {
            let is_coinbase = tx_index == 0;
            
            let tx_result = self.process_transaction(
                transaction,
                height,
                is_coinbase,
                &watched_addresses,
                wallet,
                storage,
            ).await?;
            
            if tx_result.is_relevant {
                relevant_transaction_count += 1;
                total_utxos_added += tx_result.utxos_added.len();
                total_utxos_spent += tx_result.utxos_spent.len();
                
                tracing::debug!(
                    "📝 Transaction {} is relevant: +{} UTXOs, -{} UTXOs",
                    transaction.txid(),
                    tx_result.utxos_added.len(),
                    tx_result.utxos_spent.len()
                );
            }
            
            transaction_results.push(tx_result);
        }
        
        if relevant_transaction_count > 0 {
            tracing::info!(
                "✅ Block {} processed: {} relevant transactions, +{} UTXOs, -{} UTXOs",
                block_hash,
                relevant_transaction_count,
                total_utxos_added,
                total_utxos_spent
            );
        } else {
            tracing::debug!("Block {} has no relevant transactions", block_hash);
        }
        
        Ok(BlockResult {
            transactions: transaction_results,
            height,
            block_hash,
            relevant_transaction_count,
            total_utxos_added,
            total_utxos_spent,
        })
    }
    
    /// Process a single transaction to extract relevant UTXOs.
    async fn process_transaction(
        &self,
        transaction: &Transaction,
        height: u32,
        is_coinbase: bool,
        watched_addresses: &[Address],
        wallet: &Wallet,
        _storage: &mut dyn StorageManager,
    ) -> Result<TransactionResult> {
        let txid = transaction.txid();
        let mut utxos_added = Vec::new();
        let mut utxos_spent = Vec::new();
        let mut is_relevant = false;
        
        // Check inputs for spent UTXOs (skip for coinbase transactions)
        if !is_coinbase {
            for input in &transaction.input {
                let outpoint = input.previous_output;
                
                // Check if this input spends one of our UTXOs
                if let Some(spent_utxo) = wallet.remove_utxo(&outpoint).await? {
                    utxos_spent.push(outpoint);
                    is_relevant = true;
                    
                    tracing::debug!(
                        "💸 UTXO spent: {} (value: {})",
                        outpoint,
                        spent_utxo.value()
                    );
                }
            }
        }
        
        // Check outputs for new UTXOs to watched addresses
        for (vout, output) in transaction.output.iter().enumerate() {
            // Check if the output script matches any watched address script
            if let Some(watched_address) = watched_addresses.iter().find(|addr| addr.script_pubkey() == output.script_pubkey) {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                
                let utxo = Utxo::new(
                    outpoint,
                    output.clone(),
                    watched_address.clone(),
                    height,
                    is_coinbase,
                );
                
                // Add the UTXO to the wallet
                wallet.add_utxo(utxo.clone()).await?;
                utxos_added.push(utxo);
                is_relevant = true;
                
                tracing::debug!(
                    "💰 New UTXO: {} to {} (value: {})",
                    outpoint,
                    watched_address,
                    dashcore::Amount::from_sat(output.value)
                );
            }
        }
        
        Ok(TransactionResult {
            utxos_added,
            utxos_spent,
            transaction: transaction.clone(),
            is_relevant,
        })
    }
    
    /// Extract an address from a script pubkey.
    ///
    /// This handles common script types like P2PKH, P2SH, etc.
    /// Returns None if the script type is not supported or doesn't contain an address.
    #[allow(dead_code)]
    fn extract_address_from_script(&self, script: &dashcore::ScriptBuf) -> Option<Address> {
        // Try to get address from script - this handles P2PKH, P2SH, P2WPKH, P2WSH
        Address::from_script(script, dashcore::Network::Dash).ok()
            .or_else(|| Address::from_script(script, dashcore::Network::Testnet).ok())
            .or_else(|| Address::from_script(script, dashcore::Network::Regtest).ok())
    }
    
    /// Get statistics about UTXOs for a specific address.
    pub async fn get_address_stats(
        &self,
        address: &Address,
        wallet: &Wallet,
    ) -> Result<AddressStats> {
        let utxos = wallet.get_utxos_for_address(address).await;
        
        let mut total_value = 0u64;
        let mut confirmed_value = 0u64;
        let mut pending_value = 0u64;
        let mut spendable_count = 0;
        let mut coinbase_count = 0;
        
        // For this basic implementation, we'll use a simple heuristic for confirmations
        // TODO: In future phases, integrate with actual chain tip and confirmation logic
        let assumed_current_height = 1000000; // Placeholder
        
        for utxo in &utxos {
            total_value += utxo.txout.value;
            
            if utxo.is_coinbase {
                coinbase_count += 1;
            }
            
            if utxo.is_spendable(assumed_current_height) {
                spendable_count += 1;
            }
            
            // Simple confirmation logic (6+ blocks = confirmed)
            if assumed_current_height >= utxo.height + 6 {
                confirmed_value += utxo.txout.value;
            } else {
                pending_value += utxo.txout.value;
            }
        }
        
        Ok(AddressStats {
            address: address.clone(),
            utxo_count: utxos.len(),
            total_value: dashcore::Amount::from_sat(total_value),
            confirmed_value: dashcore::Amount::from_sat(confirmed_value),
            pending_value: dashcore::Amount::from_sat(pending_value),
            spendable_count,
            coinbase_count,
        })
    }
}

/// Statistics about UTXOs for a specific address.
#[derive(Debug, Clone)]
pub struct AddressStats {
    /// The address these stats are for.
    pub address: Address,
    
    /// Total number of UTXOs.
    pub utxo_count: usize,
    
    /// Total value of all UTXOs.
    pub total_value: dashcore::Amount,
    
    /// Value of confirmed UTXOs (6+ confirmations).
    pub confirmed_value: dashcore::Amount,
    
    /// Value of pending UTXOs (< 6 confirmations).
    pub pending_value: dashcore::Amount,
    
    /// Number of spendable UTXOs (excluding immature coinbase).
    pub spendable_count: usize,
    
    /// Number of coinbase UTXOs.
    pub coinbase_count: usize,
}

impl Default for TransactionProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorageManager;
    use crate::wallet::Wallet;
    use dashcore::{
        block::{Header as BlockHeader, Version},
        pow::CompactTarget,
        Address, Network, ScriptBuf, PubkeyHash,
        Transaction, TxIn, TxOut, OutPoint, Txid,
        Witness,
    };
    use dashcore_hashes::Hash;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    async fn create_test_wallet() -> Wallet {
        let storage = Arc::new(RwLock::new(MemoryStorageManager::new().await.unwrap()));
        Wallet::new(storage)
    }
    
    fn create_test_address() -> Address {
        let pubkey_hash = PubkeyHash::from_slice(&[1u8; 20]).unwrap();
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);
        Address::from_script(&script, Network::Testnet).unwrap()
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
        let tx_inputs = inputs.into_iter().map(|outpoint| TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::new(),
        }).collect();
        
        let tx_outputs = outputs.into_iter().map(|(value, script)| TxOut {
            value,
            script_pubkey: script,
        }).collect();
        
        Transaction {
            version: 1,
            lock_time: 0,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: None,
        }
    }
    
    #[tokio::test]
    async fn test_transaction_processor_creation() {
        let processor = TransactionProcessor::new();
        
        // Test that we can create a processor
        assert_eq!(std::mem::size_of_val(&processor), 0); // Zero-sized struct
    }
    
    #[tokio::test]
    async fn test_extract_address_from_script() {
        let processor = TransactionProcessor::new();
        let address = create_test_address();
        let script = address.script_pubkey();
        
        let extracted = processor.extract_address_from_script(&script);
        assert!(extracted.is_some());
        // The extracted address should have the same script, even if it's on a different network
        assert_eq!(extracted.unwrap().script_pubkey(), script);
    }
    
    #[tokio::test]
    async fn test_process_empty_block() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        let block = create_test_block_with_transactions(vec![]);
        let result = processor.process_block(&block, 100, &wallet, &mut storage).await.unwrap();
        
        assert_eq!(result.height, 100);
        assert_eq!(result.transactions.len(), 0);
        assert_eq!(result.relevant_transaction_count, 0);
        assert_eq!(result.total_utxos_added, 0);
        assert_eq!(result.total_utxos_spent, 0);
    }
    
    #[tokio::test]
    async fn test_process_block_with_coinbase_to_watched_address() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        let address = create_test_address();
        wallet.add_watched_address(address.clone()).await.unwrap();
        
        let coinbase_tx = create_coinbase_transaction(5000000000, address.script_pubkey());
        let block = create_test_block_with_transactions(vec![coinbase_tx.clone()]);
        
        let result = processor.process_block(&block, 100, &wallet, &mut storage).await.unwrap();
        
        assert_eq!(result.relevant_transaction_count, 1);
        assert_eq!(result.total_utxos_added, 1);
        assert_eq!(result.total_utxos_spent, 0);
        
        let tx_result = &result.transactions[0];
        assert!(tx_result.is_relevant);
        assert_eq!(tx_result.utxos_added.len(), 1);
        assert_eq!(tx_result.utxos_spent.len(), 0);
        
        let utxo = &tx_result.utxos_added[0];
        assert_eq!(utxo.outpoint.txid, coinbase_tx.txid());
        assert_eq!(utxo.outpoint.vout, 0);
        assert_eq!(utxo.txout.value, 5000000000);
        assert_eq!(utxo.address, address);
        assert_eq!(utxo.height, 100);
        assert!(utxo.is_coinbase);
        
        // Verify the UTXO was added to the wallet
        let wallet_utxos = wallet.get_utxos_for_address(&address).await;
        assert_eq!(wallet_utxos.len(), 1);
        assert_eq!(wallet_utxos[0], utxo.clone());
    }
    
    #[tokio::test]
    async fn test_process_block_with_regular_transaction_to_watched_address() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        let address = create_test_address();
        wallet.add_watched_address(address.clone()).await.unwrap();
        
        // Create a regular transaction that sends to our watched address
        let input_outpoint = OutPoint {
            txid: Txid::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap(),
            vout: 0,
        };
        
        let regular_tx = create_regular_transaction(
            vec![input_outpoint],
            vec![(1000000, address.script_pubkey())],
        );
        
        // Create a coinbase transaction for index 0
        let coinbase_tx = create_coinbase_transaction(5000000000, ScriptBuf::new());
        
        let block = create_test_block_with_transactions(vec![coinbase_tx, regular_tx.clone()]);
        
        let result = processor.process_block(&block, 200, &wallet, &mut storage).await.unwrap();
        
        assert_eq!(result.relevant_transaction_count, 1);
        assert_eq!(result.total_utxos_added, 1);
        assert_eq!(result.total_utxos_spent, 0);
        
        let tx_result = &result.transactions[1]; // Index 1 is the regular transaction
        assert!(tx_result.is_relevant);
        assert_eq!(tx_result.utxos_added.len(), 1);
        assert_eq!(tx_result.utxos_spent.len(), 0);
        
        let utxo = &tx_result.utxos_added[0];
        assert_eq!(utxo.outpoint.txid, regular_tx.txid());
        assert_eq!(utxo.outpoint.vout, 0);
        assert_eq!(utxo.txout.value, 1000000);
        assert_eq!(utxo.address, address);
        assert_eq!(utxo.height, 200);
        assert!(!utxo.is_coinbase);
    }
    
    #[tokio::test]
    async fn test_process_block_with_spending_transaction() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        let address = create_test_address();
        wallet.add_watched_address(address.clone()).await.unwrap();
        
        // First, add a UTXO to the wallet
        let utxo_outpoint = OutPoint {
            txid: Txid::from_str("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890").unwrap(),
            vout: 1,
        };
        
        let utxo = Utxo::new(
            utxo_outpoint,
            TxOut {
                value: 500000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );
        
        wallet.add_utxo(utxo).await.unwrap();
        
        // Now create a transaction that spends this UTXO
        let spending_tx = create_regular_transaction(
            vec![utxo_outpoint],
            vec![(450000, ScriptBuf::new())], // Send to different address (not watched)
        );
        
        // Create a coinbase transaction for index 0
        let coinbase_tx = create_coinbase_transaction(5000000000, ScriptBuf::new());
        
        let block = create_test_block_with_transactions(vec![coinbase_tx, spending_tx.clone()]);
        
        let result = processor.process_block(&block, 300, &wallet, &mut storage).await.unwrap();
        
        assert_eq!(result.relevant_transaction_count, 1);
        assert_eq!(result.total_utxos_added, 0);
        assert_eq!(result.total_utxos_spent, 1);
        
        let tx_result = &result.transactions[1]; // Index 1 is the spending transaction
        assert!(tx_result.is_relevant);
        assert_eq!(tx_result.utxos_added.len(), 0);
        assert_eq!(tx_result.utxos_spent.len(), 1);
        assert_eq!(tx_result.utxos_spent[0], utxo_outpoint);
        
        // Verify the UTXO was removed from the wallet
        let wallet_utxos = wallet.get_utxos_for_address(&address).await;
        assert_eq!(wallet_utxos.len(), 0);
    }
    
    #[tokio::test]
    async fn test_process_block_with_irrelevant_transactions() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        // Don't add any watched addresses
        
        let irrelevant_tx = create_regular_transaction(
            vec![OutPoint {
                txid: Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
                vout: 0,
            }],
            vec![(1000000, ScriptBuf::new())],
        );
        
        let block = create_test_block_with_transactions(vec![irrelevant_tx]);
        
        let result = processor.process_block(&block, 400, &wallet, &mut storage).await.unwrap();
        
        assert_eq!(result.relevant_transaction_count, 0);
        assert_eq!(result.total_utxos_added, 0);
        assert_eq!(result.total_utxos_spent, 0);
        
        // With no watched addresses, no transactions are processed
        assert_eq!(result.transactions.len(), 0);
    }
    
    #[tokio::test]
    async fn test_get_address_stats() {
        let processor = TransactionProcessor::new();
        let wallet = create_test_wallet().await;
        
        let address = create_test_address();
        wallet.add_watched_address(address.clone()).await.unwrap();
        
        // Add some UTXOs
        let utxo1 = Utxo::new(
            OutPoint {
                txid: Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
                vout: 0,
            },
            TxOut {
                value: 1000000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );
        
        let utxo2 = Utxo::new(
            OutPoint {
                txid: Txid::from_str("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
                vout: 0,
            },
            TxOut {
                value: 5000000000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            200,
            true, // coinbase
        );
        
        wallet.add_utxo(utxo1).await.unwrap();
        wallet.add_utxo(utxo2).await.unwrap();
        
        let stats = processor.get_address_stats(&address, &wallet).await.unwrap();
        
        assert_eq!(stats.address, address);
        assert_eq!(stats.utxo_count, 2);
        assert_eq!(stats.total_value, dashcore::Amount::from_sat(5001000000));
        assert_eq!(stats.coinbase_count, 1);
        assert_eq!(stats.spendable_count, 2); // Both should be spendable with our high assumed height
    }
}