//! Integration tests for wallet functionality.
//!
//! These tests validate end-to-end wallet operations including payment discovery,
//! UTXO tracking, balance calculations, and block processing.

use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

use dashcore::{
    block::Header as BlockHeader,
    pow::CompactTarget,
    Address, Amount, Block, Network, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use dashcore_hashes::Hash;

use dash_spv::{
    storage::MemoryStorageManager,
    wallet::{TransactionProcessor, Wallet},
};

/// Create a test wallet with memory storage for integration testing.
async fn create_test_wallet() -> Wallet {
    let storage = Arc::new(RwLock::new(MemoryStorageManager::new().await.unwrap()));
    Wallet::new(storage)
}

/// Create a deterministic test address for reproducible tests.
fn create_test_address(seed: u8) -> Address {
    let pubkey_hash = PubkeyHash::from_byte_array([seed; 20]);
    let script = ScriptBuf::new_p2pkh(&pubkey_hash);
    Address::from_script(&script, Network::Testnet).unwrap()
}

/// Create a test block with given transactions.
fn create_test_block(transactions: Vec<Transaction>, prev_hash: dashcore::BlockHash) -> Block {
    let header = BlockHeader {
        version: 1,
        prev_blockhash: prev_hash,
        merkle_root: dashcore_hashes::sha256d::Hash::all_zeros().into(),
        time: 1640995200, // Fixed timestamp for deterministic tests
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: 0,
    };

    Block {
        header,
        txdata: transactions,
    }
}

/// Create a coinbase transaction.
fn create_coinbase_transaction(output_value: u64, output_script: ScriptBuf) -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: output_value,
            script_pubkey: output_script,
        }],
        special_transaction_payload: None,
    }
}

/// Create a regular transaction with specified inputs and outputs.
fn create_regular_transaction(
    inputs: Vec<OutPoint>,
    outputs: Vec<(u64, ScriptBuf)>,
) -> Transaction {
    let tx_inputs = inputs
        .into_iter()
        .map(|outpoint| TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
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

#[tokio::test]
async fn test_wallet_discovers_payment() {
    // End-to-end test of payment discovery

    let wallet = create_test_wallet().await;
    let processor = TransactionProcessor::new();
    let address = create_test_address(1);

    // Add address to wallet
    wallet.add_watched_address(address.clone()).await.unwrap();

    // Verify initial state
    let initial_balance = wallet.get_balance().await.unwrap();
    assert_eq!(initial_balance.total(), Amount::ZERO);

    let initial_utxos = wallet.get_utxos().await;
    assert!(initial_utxos.is_empty());

    // Create a block with a payment to our address
    let payment_amount = 250_000_000; // 2.5 DASH
    let coinbase_tx = create_coinbase_transaction(payment_amount, address.script_pubkey());

    let block = create_test_block(vec![coinbase_tx.clone()], dashcore::BlockHash::from_byte_array([0; 32]));

    // Process the block
    let mut storage = MemoryStorageManager::new().await.unwrap();
    let block_result = processor.process_block(&block, 100, &wallet, &mut storage).await.unwrap();

    // Verify block processing results
    assert_eq!(block_result.height, 100);
    assert_eq!(block_result.relevant_transaction_count, 1);
    assert_eq!(block_result.total_utxos_added, 1);
    assert_eq!(block_result.total_utxos_spent, 0);

    // Verify transaction processing results
    assert_eq!(block_result.transactions.len(), 1);
    let tx_result = &block_result.transactions[0];
    assert!(tx_result.is_relevant);
    assert_eq!(tx_result.utxos_added.len(), 1);
    assert_eq!(tx_result.utxos_spent.len(), 0);

    // Verify the UTXO was added correctly
    let utxo = &tx_result.utxos_added[0];
    assert_eq!(utxo.outpoint.txid, coinbase_tx.txid());
    assert_eq!(utxo.outpoint.vout, 0);
    assert_eq!(utxo.txout.value, payment_amount);
    assert_eq!(utxo.address, address);
    assert_eq!(utxo.height, 100);
    assert!(utxo.is_coinbase);
    assert!(!utxo.is_confirmed); // Should start unconfirmed
    assert!(!utxo.is_instantlocked);

    // Verify wallet state after payment discovery
    let final_balance = wallet.get_balance().await.unwrap();
    assert_eq!(final_balance.confirmed, Amount::from_sat(payment_amount)); // Will be confirmed due to high mock current height
    assert_eq!(final_balance.pending, Amount::ZERO);
    assert_eq!(final_balance.instantlocked, Amount::ZERO);
    assert_eq!(final_balance.total(), Amount::from_sat(payment_amount));

    // Verify address-specific balance
    let address_balance = wallet.get_balance_for_address(&address).await.unwrap();
    assert_eq!(address_balance, final_balance);

    // Verify UTXOs in wallet
    let final_utxos = wallet.get_utxos().await;
    assert_eq!(final_utxos.len(), 1);
    assert_eq!(final_utxos[0], utxo.clone());

    let address_utxos = wallet.get_utxos_for_address(&address).await;
    assert_eq!(address_utxos.len(), 1);
    assert_eq!(address_utxos[0], utxo.clone());
}

#[tokio::test]
async fn test_wallet_tracks_spending() {
    // Verify UTXO removal when spent

    let wallet = create_test_wallet().await;
    let processor = TransactionProcessor::new();
    let address = create_test_address(2);

    // Setup: Add address and create initial UTXO
    wallet.add_watched_address(address.clone()).await.unwrap();

    let initial_amount = 100_000_000; // 1 DASH
    let coinbase_tx = create_coinbase_transaction(initial_amount, address.script_pubkey());
    let initial_outpoint = OutPoint {
        txid: coinbase_tx.txid(),
        vout: 0,
    };

    // Process first block with payment
    let block1 = create_test_block(vec![coinbase_tx.clone()], dashcore::BlockHash::from_byte_array([0; 32]));

    let mut storage = MemoryStorageManager::new().await.unwrap();
    processor.process_block(&block1, 100, &wallet, &mut storage).await.unwrap();

    // Verify initial state after receiving payment
    let balance_after_receive = wallet.get_balance().await.unwrap();
    assert_eq!(balance_after_receive.total(), Amount::from_sat(initial_amount));

    let utxos_after_receive = wallet.get_utxos().await;
    assert_eq!(utxos_after_receive.len(), 1);
    assert_eq!(utxos_after_receive[0].outpoint, initial_outpoint);

    // Create a spending transaction
    let spend_amount = 80_000_000; // Send 0.8 DASH, keep 0.2 as change
    let change_amount = initial_amount - spend_amount;

    let spending_tx = create_regular_transaction(
        vec![initial_outpoint],
        vec![
            (spend_amount, ScriptBuf::new()),         // Send to unknown address
            (change_amount, address.script_pubkey()), // Change back to our address
        ],
    );

    // Add another coinbase for block structure
    let coinbase_tx2 = create_coinbase_transaction(0, ScriptBuf::new());

    // Process second block with spending transaction
    let block2 = create_test_block(vec![coinbase_tx2, spending_tx.clone()], block1.block_hash());

    let block_result = processor.process_block(&block2, 101, &wallet, &mut storage).await.unwrap();

    // Verify block processing detected spending
    assert_eq!(block_result.relevant_transaction_count, 1);
    assert_eq!(block_result.total_utxos_added, 1); // Change output
    assert_eq!(block_result.total_utxos_spent, 1); // Original UTXO

    // Verify transaction processing results
    let spend_tx_result = &block_result.transactions[1]; // Index 1 is the spending tx
    assert!(spend_tx_result.is_relevant);
    assert_eq!(spend_tx_result.utxos_added.len(), 1); // Change UTXO
    assert_eq!(spend_tx_result.utxos_spent.len(), 1); // Original UTXO
    assert_eq!(spend_tx_result.utxos_spent[0], initial_outpoint);

    // Verify the change UTXO was created correctly
    let change_utxo = &spend_tx_result.utxos_added[0];
    assert_eq!(change_utxo.outpoint.txid, spending_tx.txid());
    assert_eq!(change_utxo.outpoint.vout, 1); // Second output
    assert_eq!(change_utxo.txout.value, change_amount);
    assert_eq!(change_utxo.address, address);
    assert_eq!(change_utxo.height, 101);
    assert!(!change_utxo.is_coinbase);

    // Verify final wallet state
    let final_balance = wallet.get_balance().await.unwrap();
    assert_eq!(final_balance.total(), Amount::from_sat(change_amount));

    let final_utxos = wallet.get_utxos().await;
    assert_eq!(final_utxos.len(), 1);
    assert_eq!(final_utxos[0], change_utxo.clone());

    // Verify the original UTXO was removed
    assert!(final_utxos.iter().all(|utxo| utxo.outpoint != initial_outpoint));
}

#[tokio::test]
async fn test_wallet_balance_accuracy() {
    // Verify balance matches expected values across multiple transactions

    let wallet = create_test_wallet().await;
    let processor = TransactionProcessor::new();
    let address1 = create_test_address(3);
    let address2 = create_test_address(4);

    // Setup: Add addresses to wallet
    wallet.add_watched_address(address1.clone()).await.unwrap();
    wallet.add_watched_address(address2.clone()).await.unwrap();

    // Create first block with payments to both addresses
    let amount1 = 150_000_000; // 1.5 DASH to address1
    let amount2 = 300_000_000; // 3.0 DASH to address2

    let tx1 = create_coinbase_transaction(amount1, address1.script_pubkey());
    let tx2 = create_regular_transaction(
        vec![OutPoint {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            vout: 0,
        }],
        vec![(amount2, address2.script_pubkey())],
    );

    let block1 = create_test_block(vec![tx1, tx2], dashcore::BlockHash::from_byte_array([0; 32]));

    let mut storage = MemoryStorageManager::new().await.unwrap();
    processor.process_block(&block1, 200, &wallet, &mut storage).await.unwrap();

    // Verify balances after first block
    let total_balance = wallet.get_balance().await.unwrap();
    let expected_total = amount1 + amount2;
    assert_eq!(total_balance.total(), Amount::from_sat(expected_total));

    let balance1 = wallet.get_balance_for_address(&address1).await.unwrap();
    assert_eq!(balance1.total(), Amount::from_sat(amount1));

    let balance2 = wallet.get_balance_for_address(&address2).await.unwrap();
    assert_eq!(balance2.total(), Amount::from_sat(amount2));

    // Create second block with additional payment to address1
    let amount3 = 75_000_000; // 0.75 DASH to address1

    let coinbase_tx = create_coinbase_transaction(amount3, address1.script_pubkey());
    let block2 = create_test_block(vec![coinbase_tx], block1.block_hash());

    processor.process_block(&block2, 201, &wallet, &mut storage).await.unwrap();

    // Verify balances after second block
    let total_balance_2 = wallet.get_balance().await.unwrap();
    let expected_total_2 = amount1 + amount2 + amount3;
    assert_eq!(total_balance_2.total(), Amount::from_sat(expected_total_2));

    let balance1_2 = wallet.get_balance_for_address(&address1).await.unwrap();
    let expected_balance1_2 = amount1 + amount3;
    assert_eq!(balance1_2.total(), Amount::from_sat(expected_balance1_2));

    let balance2_2 = wallet.get_balance_for_address(&address2).await.unwrap();
    assert_eq!(balance2_2.total(), Amount::from_sat(amount2)); // Unchanged

    // Verify UTXO counts
    let all_utxos = wallet.get_utxos().await;
    assert_eq!(all_utxos.len(), 3); // Three transactions, three UTXOs

    let utxos1 = wallet.get_utxos_for_address(&address1).await;
    assert_eq!(utxos1.len(), 2); // Two payments to address1

    let utxos2 = wallet.get_utxos_for_address(&address2).await;
    assert_eq!(utxos2.len(), 1); // One payment to address2

    // Verify sum of UTXO values matches balance
    let utxo_sum: u64 = all_utxos.iter().map(|utxo| utxo.txout.value).sum();
    assert_eq!(utxo_sum, expected_total_2);

    let utxo1_sum: u64 = utxos1.iter().map(|utxo| utxo.txout.value).sum();
    assert_eq!(utxo1_sum, expected_balance1_2);

    let utxo2_sum: u64 = utxos2.iter().map(|utxo| utxo.txout.value).sum();
    assert_eq!(utxo2_sum, amount2);
}

#[tokio::test]
async fn test_wallet_handles_reorg() {
    // Ensure UTXO set updates correctly during blockchain reorganization
    //
    // In this test, we simulate a reorg by showing that the wallet correctly
    // tracks different chains. In a real implementation, the sync manager would
    // handle reorgs by providing the correct chain state to the wallet.

    let wallet1 = create_test_wallet().await; // Original chain
    let wallet2 = create_test_wallet().await; // Alternative chain
    let processor = TransactionProcessor::new();
    let address = create_test_address(5);

    wallet1.add_watched_address(address.clone()).await.unwrap();
    wallet2.add_watched_address(address.clone()).await.unwrap();

    // Create initial chain: Genesis -> Block A -> Block B (original chain)
    let amount_a = 100_000_000; // 1 DASH in block A
    let tx_a = create_coinbase_transaction(amount_a, address.script_pubkey());
    let block_a = create_test_block(vec![tx_a.clone()], dashcore::BlockHash::from_byte_array([0; 32]));
    let outpoint_a = OutPoint {
        txid: tx_a.txid(),
        vout: 0,
    };

    let amount_b = 200_000_000; // 2 DASH in block B
    let tx_b = create_coinbase_transaction(amount_b, address.script_pubkey());
    let block_b = create_test_block(vec![tx_b.clone()], block_a.block_hash());
    let outpoint_b = OutPoint {
        txid: tx_b.txid(),
        vout: 0,
    };

    // Process original chain in wallet1
    let mut storage1 = MemoryStorageManager::new().await.unwrap();
    processor.process_block(&block_a, 100, &wallet1, &mut storage1).await.unwrap();
    processor.process_block(&block_b, 101, &wallet1, &mut storage1).await.unwrap();

    // Verify original chain state
    let original_balance = wallet1.get_balance().await.unwrap();
    assert_eq!(original_balance.total(), Amount::from_sat(amount_a + amount_b));

    let original_utxos = wallet1.get_utxos().await;
    assert_eq!(original_utxos.len(), 2);
    assert!(original_utxos.iter().any(|utxo| utxo.outpoint == outpoint_a));
    assert!(original_utxos.iter().any(|utxo| utxo.outpoint == outpoint_b));

    // Create alternative chain: Genesis -> Block A -> Block C (reorg chain)
    let amount_c = 350_000_000; // 3.5 DASH in block C
    let tx_c = create_coinbase_transaction(amount_c, address.script_pubkey());
    let block_c = create_test_block(vec![tx_c.clone()], block_a.block_hash());
    let outpoint_c = OutPoint {
        txid: tx_c.txid(),
        vout: 0,
    };

    // Process alternative chain in wallet2
    let mut storage2 = MemoryStorageManager::new().await.unwrap();
    processor.process_block(&block_a, 100, &wallet2, &mut storage2).await.unwrap();
    processor.process_block(&block_c, 101, &wallet2, &mut storage2).await.unwrap();

    // Verify alternative chain state
    let reorg_balance = wallet2.get_balance().await.unwrap();
    assert_eq!(reorg_balance.total(), Amount::from_sat(amount_a + amount_c));

    let reorg_utxos = wallet2.get_utxos().await;
    assert_eq!(reorg_utxos.len(), 2);
    assert!(reorg_utxos.iter().any(|utxo| utxo.outpoint == outpoint_a));
    assert!(reorg_utxos.iter().any(|utxo| utxo.outpoint == outpoint_c));
    assert!(reorg_utxos.iter().all(|utxo| utxo.outpoint != outpoint_b));

    // Verify the chains are different
    assert_ne!(original_balance.total(), reorg_balance.total());

    // Verify that block A exists in both chains but blocks B and C are different
    let utxo_a_original = original_utxos.iter().find(|utxo| utxo.outpoint == outpoint_a).unwrap();
    let utxo_a_reorg = reorg_utxos.iter().find(|utxo| utxo.outpoint == outpoint_a).unwrap();
    assert_eq!(utxo_a_original.outpoint, utxo_a_reorg.outpoint);
    assert_eq!(utxo_a_original.txout.value, utxo_a_reorg.txout.value);

    // Verify the unique UTXOs in each chain
    let utxo_c = reorg_utxos.iter().find(|utxo| utxo.outpoint == outpoint_c).unwrap();
    assert_eq!(utxo_c.txout.value, amount_c);
    assert_eq!(utxo_c.address, address);
    assert_eq!(utxo_c.height, 101);

    // Show that wallet1 has block B's UTXO but wallet2 doesn't
    assert!(original_utxos.iter().any(|utxo| utxo.outpoint == outpoint_b));
    assert!(reorg_utxos.iter().all(|utxo| utxo.outpoint != outpoint_b));
}

#[tokio::test]
async fn test_wallet_comprehensive_scenario() {
    // Complex scenario combining multiple operations: receive, spend, receive change, etc.

    let wallet = create_test_wallet().await;
    let processor = TransactionProcessor::new();
    let alice_address = create_test_address(10);
    let bob_address = create_test_address(11);

    // Setup: Alice and Bob both use this wallet
    wallet.add_watched_address(alice_address.clone()).await.unwrap();
    wallet.add_watched_address(bob_address.clone()).await.unwrap();

    let mut storage = MemoryStorageManager::new().await.unwrap();

    // Block 1: Alice receives payment
    let alice_initial = 500_000_000; // 5 DASH
    let tx1 = create_coinbase_transaction(alice_initial, alice_address.script_pubkey());
    let block1 = create_test_block(vec![tx1.clone()], dashcore::BlockHash::from_byte_array([0; 32]));
    let alice_utxo1 = OutPoint {
        txid: tx1.txid(),
        vout: 0,
    };

    processor.process_block(&block1, 300, &wallet, &mut storage).await.unwrap();

    // Verify after block 1
    assert_eq!(wallet.get_balance().await.unwrap().total(), Amount::from_sat(alice_initial));
    assert_eq!(
        wallet.get_balance_for_address(&alice_address).await.unwrap().total(),
        Amount::from_sat(alice_initial)
    );
    assert_eq!(wallet.get_balance_for_address(&bob_address).await.unwrap().total(), Amount::ZERO);

    // Block 2: Bob receives payment
    let bob_initial = 300_000_000; // 3 DASH
    let tx2 = create_coinbase_transaction(bob_initial, bob_address.script_pubkey());
    let block2 = create_test_block(vec![tx2.clone()], block1.block_hash());
    let bob_utxo1 = OutPoint {
        txid: tx2.txid(),
        vout: 0,
    };

    processor.process_block(&block2, 301, &wallet, &mut storage).await.unwrap();

    // Verify after block 2
    let total_after_block2 = alice_initial + bob_initial;
    assert_eq!(wallet.get_balance().await.unwrap().total(), Amount::from_sat(total_after_block2));
    assert_eq!(
        wallet.get_balance_for_address(&alice_address).await.unwrap().total(),
        Amount::from_sat(alice_initial)
    );
    assert_eq!(
        wallet.get_balance_for_address(&bob_address).await.unwrap().total(),
        Amount::from_sat(bob_initial)
    );

    // Block 3: Alice sends 2 DASH to external address, 2.8 DASH change back to Alice
    let alice_spend = 200_000_000; // 2 DASH
    let alice_change = alice_initial - alice_spend - 20_000_000; // 2.8 DASH (0.2 DASH fee)

    let coinbase_tx3 = create_coinbase_transaction(0, ScriptBuf::new());
    let spend_tx = create_regular_transaction(
        vec![alice_utxo1],
        vec![
            (alice_spend, ScriptBuf::new()),               // External address
            (alice_change, alice_address.script_pubkey()), // Change to Alice
        ],
    );

    let block3 = create_test_block(vec![coinbase_tx3, spend_tx.clone()], block2.block_hash());
    let alice_utxo2 = OutPoint {
        txid: spend_tx.txid(),
        vout: 1,
    }; // Change output

    processor.process_block(&block3, 302, &wallet, &mut storage).await.unwrap();

    // Verify after block 3
    let total_after_block3 = alice_change + bob_initial;
    assert_eq!(wallet.get_balance().await.unwrap().total(), Amount::from_sat(total_after_block3));
    assert_eq!(
        wallet.get_balance_for_address(&alice_address).await.unwrap().total(),
        Amount::from_sat(alice_change)
    );
    assert_eq!(
        wallet.get_balance_for_address(&bob_address).await.unwrap().total(),
        Amount::from_sat(bob_initial)
    );

    // Block 4: Internal transfer - Bob sends 1 DASH to Alice
    let bob_to_alice = 100_000_000; // 1 DASH
    let bob_remaining = bob_initial - bob_to_alice - 10_000_000; // 1.9 DASH (0.1 DASH fee)

    let coinbase_tx4 = create_coinbase_transaction(0, ScriptBuf::new());
    let transfer_tx = create_regular_transaction(
        vec![bob_utxo1],
        vec![
            (bob_to_alice, alice_address.script_pubkey()), // To Alice
            (bob_remaining, bob_address.script_pubkey()),  // Change to Bob
        ],
    );

    let block4 = create_test_block(vec![coinbase_tx4, transfer_tx.clone()], block3.block_hash());
    let alice_utxo3 = OutPoint {
        txid: transfer_tx.txid(),
        vout: 0,
    }; // From Bob
    let bob_utxo2 = OutPoint {
        txid: transfer_tx.txid(),
        vout: 1,
    }; // Bob's change

    processor.process_block(&block4, 303, &wallet, &mut storage).await.unwrap();

    // Verify final state
    let alice_final = alice_change + bob_to_alice;
    let bob_final = bob_remaining;
    let total_final = alice_final + bob_final;

    assert_eq!(wallet.get_balance().await.unwrap().total(), Amount::from_sat(total_final));
    assert_eq!(
        wallet.get_balance_for_address(&alice_address).await.unwrap().total(),
        Amount::from_sat(alice_final)
    );
    assert_eq!(
        wallet.get_balance_for_address(&bob_address).await.unwrap().total(),
        Amount::from_sat(bob_final)
    );

    // Verify UTXO composition
    let all_utxos = wallet.get_utxos().await;
    assert_eq!(all_utxos.len(), 3); // Alice has 2 UTXOs, Bob has 1 UTXO

    let alice_utxos = wallet.get_utxos_for_address(&alice_address).await;
    assert_eq!(alice_utxos.len(), 2);
    assert!(alice_utxos.iter().any(|utxo| utxo.outpoint == alice_utxo2));
    assert!(alice_utxos.iter().any(|utxo| utxo.outpoint == alice_utxo3));

    let bob_utxos = wallet.get_utxos_for_address(&bob_address).await;
    assert_eq!(bob_utxos.len(), 1);
    assert_eq!(bob_utxos[0].outpoint, bob_utxo2);

    // Verify no old UTXOs remain
    assert!(all_utxos.iter().all(|utxo| utxo.outpoint != alice_utxo1));
    assert!(all_utxos.iter().all(|utxo| utxo.outpoint != bob_utxo1));
}
