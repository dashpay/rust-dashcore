#![cfg(feature = "skip_mock_implementation_incomplete")]

// This test is currently disabled because the WalletManager<ManagedWalletInfo> API has changed
// and these methods don't exist anymore. The test needs to be rewritten to use
// the new wallet interface.

// dash-spv/tests/instantsend_integration_test.rs
//
// TODO: These tests need to be updated to work with the new WalletManager<ManagedWalletInfo> API
// The following methods don't exist in WalletManager<ManagedWalletInfo>:
// - add_utxo
// - add_watched_address
// - get_utxos
// - get_balance (should be get_total_balance)
// - process_verified_instantlock
//
// These tests are currently ignored until they can be properly updated.

// use std::sync::Arc;
// use tokio::sync::RwLock;

use blsful::{Bls12381G2Impl, SecretKey};
// keep module path available for validator usage
use dashcore::{
    Address, InstantLock, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness,
};
use dashcore_hashes::Hash;
// use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
// use key_wallet_manager::wallet_manager::WalletManager;
use rand::thread_rng;

// /// Helper to create a test wallet manager.
// Removed unused helper create_test_wallet (test scaffolding simplified)
/// Create a deterministic test address.
fn create_test_address() -> Address {
    let pubkey_hash = dashcore::PubkeyHash::from_byte_array([1; 20]);
    let script = ScriptBuf::new_p2pkh(&pubkey_hash);
    Address::from_script(&script, Network::Testnet).unwrap()
}

/// Create a regular transaction.
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

/// Create a signed InstantLock for a transaction.
fn create_signed_instantlock(tx: &Transaction, _sk: &SecretKey<Bls12381G2Impl>) -> InstantLock {
    let inputs = tx.input.iter().map(|input| input.previous_output).collect();

    // Create a non-zero dummy signature that will pass basic validation
    let mut sig_bytes = [0u8; 96];
    sig_bytes[0] = 0x01; // Set first byte to make it non-zero
    sig_bytes[95] = 0x01; // Set last byte too for good measure

    // TODO: Implement proper signing when InstantLockValidator methods are available
    InstantLock {
        version: 1,
        inputs,
        txid: tx.txid(),
        signature: dashcore::bls_sig_utils::BLSSignature::from(sig_bytes),
        cyclehash: dashcore::BlockHash::from_byte_array([0; 32]),
    }
}

#[tokio::test]
#[ignore = "instantsend tests not yet updated"]
async fn test_instantsend_end_to_end() {
    // 1. Create a dummy spending transaction (skipped wallet operations due to API changes)
    let spend_tx = create_regular_transaction(vec![], vec![(80_000_000, ScriptBuf::new())]);

    // At this point, the transaction is in the mempool (conceptually).
    // The wallet balance would show the initial_amount as confirmed.

    // 3. Create a valid InstantLock for the spending transaction.
    let sk = SecretKey::<Bls12381G2Impl>::random(&mut thread_rng());
    let instant_lock = create_signed_instantlock(&spend_tx, &sk);

    // 4. Simulate the client receiving and processing the InstantLock.
    // We need to mock the quorum lookup.
    // For this test, we will directly call the validation and wallet update.

    // First, validate the instantlock.
    let validator = dash_spv::validation::InstantLockValidator::new();
    assert!(validator.validate(&instant_lock).is_ok());

    // Now, process it with the wallet.
    // Note: This won't update anything because spend_tx is spending FROM our wallet,
    // not creating new UTXOs for us. We'll test InstantLock processing in the next section.

    // 5. Assert the wallet state has been updated correctly.
    // TODO: get_utxos() method no longer exists on WalletManager<ManagedWalletInfo>
    // Need to access UTXOs through WalletInterface or base WalletManager
    // let utxos = wallet.read().await.get_utxos().await;
    // let spent_utxo = utxos.iter().find(|u| u.outpoint == initial_outpoint);

    // The original UTXO should now be marked as instant-locked.
    // Note: In a real scenario, the UTXO would be *removed* and a new *change* UTXO added.
    // For this test, we simplify by just marking the spent UTXO.
    // A more realistic test would involve the TransactionProcessor.
    // Let's adjust the test to reflect spending and receiving change.

    // Let's refine the test to be more realistic.
    // We will process the transaction first, which will remove the old UTXO and add a change UTXO.
    // Then we will process the InstantLock.

    // This test setup is getting complicated without the full block processor.
    // Let's simplify and focus on the direct impact of the InstantLock on a UTXO.

    // Let's create a new UTXO that represents a payment *to* us, and then InstantLock it.
    let address = create_test_address();
    // TODO: add_watched_address() method no longer exists
    // wallet.write().await.add_watched_address(address.clone()).await.unwrap();

    let incoming_amount = 50_000_000;
    // Create a transaction with a dummy input (from external source)
    let dummy_input = OutPoint {
        txid: Txid::from_byte_array([99; 32]),
        vout: 0,
    };
    let incoming_tx = create_regular_transaction(
        vec![dummy_input],
        vec![(incoming_amount, address.script_pubkey())],
    );
    // Create an outpoint for the received UTXO (skipped due to API changes)
    // TODO: add_utxo() method no longer exists
    // wallet.write().await.add_utxo(incoming_utxo).await.unwrap();

    // Balance should be pending.
    // TODO: get_balance() method no longer exists - need to use get_total_balance() or similar
    // let balance1 = wallet.read().await.get_balance().await.unwrap();
    // assert_eq!(balance1.pending, Amount::from_sat(incoming_amount));
    // assert_eq!(balance1.instantlocked, Amount::ZERO);

    // Create and process the InstantLock.
    let sk = SecretKey::<Bls12381G2Impl>::random(&mut thread_rng());
    let instant_lock = create_signed_instantlock(&incoming_tx, &sk);

    let validator = dash_spv::validation::InstantLockValidator::new();
    assert!(validator.validate(&instant_lock).is_ok());

    // TODO: process_verified_instantlock() method no longer exists
    // let updated =
    //     wallet.write().await.process_verified_instantlock(incoming_tx.txid()).await.unwrap();
    // assert!(updated);

    // Verify the UTXO is now marked as instant-locked.
    // TODO: get_utxos() method no longer exists
    // let utxos = wallet.read().await.get_utxos().await;
    // let locked_utxo = utxos.iter().find(|u| u.outpoint == incoming_outpoint).unwrap();
    // assert!(locked_utxo.is_instantlocked);

    // Verify the balance has moved from pending to instantlocked.
    // TODO: get_balance() method no longer exists
    // let balance2 = wallet.read().await.get_balance().await.unwrap();
    // assert_eq!(balance2.pending, Amount::ZERO);
    // assert_eq!(balance2.instantlocked, Amount::from_sat(incoming_amount));
}
