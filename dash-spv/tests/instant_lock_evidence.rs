#![cfg(feature = "test-utils")]

use dash_spv::test_utils::{InstantLockFixture, MockNetworkManager};
use dash_spv::{ClientConfig, DashSpvClient, InstantLockVerificationError, VerifiedInstantLock};
use dashcore::{InstantLock, Network};
use dashcore::{OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use key_wallet_manager::test_utils::MockWallet;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

#[tokio::test]
async fn should_verify_instant_lock_after_cycle_arrives_without_wallet_arithmetic() {
    let directory = TempDir::new().unwrap();
    let config = ClientConfig::mainnet().without_filters().with_storage_path(directory.path());
    let wallet = Arc::new(RwLock::new(MockWallet::new()));
    let client = DashSpvClient::new(config, MockNetworkManager::new(), wallet.clone(), vec![])
        .await
        .unwrap();
    let transaction = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: u64::MAX,
                script_pubkey: ScriptBuf::new()
            };
            2
        ],
        special_transaction_payload: None,
    };
    let fixture = InstantLockFixture::new(&transaction).unwrap();
    let lock = fixture.instant_lock();
    assert!(client.verify_instant_lock(lock).await.unwrap().is_none());
    fixture.install(&client).await.unwrap();
    let proof: VerifiedInstantLock = client.verify_instant_lock(lock).await.unwrap().unwrap();
    assert!(proof.matches_transaction(&transaction));
    assert_eq!(proof.instant_lock(), lock);
    assert_eq!(proof.txid(), transaction.txid());
    assert!(wallet.read().await.processed_instant_locks.lock().await.is_empty());

    let mut changed_body = transaction.clone();
    changed_body.output[0].value -= 1;
    assert!(!proof.matches_transaction(&changed_body));
    let mut wrong_txid = lock.clone();
    wrong_txid.txid = changed_body.txid();
    let mut wrong_input = lock.clone();
    wrong_input.inputs[0].vout += 1;
    let mut wrong_signature = lock.clone();
    wrong_signature.signature = dashcore::bls_sig_utils::BLSSignature::from([1; 96]);
    for invalid in [wrong_txid, wrong_input, wrong_signature] {
        assert!(matches!(
            client.verify_instant_lock(&invalid).await,
            Err(InstantLockVerificationError::InvalidSignature(_))
        ));
    }
}

#[tokio::test]
async fn should_defer_instant_lock_when_masternodes_are_disabled() {
    let directory = TempDir::new().unwrap();
    let config = ClientConfig::mainnet()
        .without_filters()
        .without_masternodes()
        .with_storage_path(directory.path());
    let client = DashSpvClient::new(
        config,
        MockNetworkManager::new(),
        Arc::new(RwLock::new(MockWallet::new())),
        vec![],
    )
    .await
    .unwrap();
    assert!(client.verify_instant_lock(&InstantLock::dummy(0..1)).await.unwrap().is_none());
    assert!(matches!(
        client.verify_instant_lock(&InstantLock::default()).await,
        Err(InstantLockVerificationError::Malformed(_))
    ));
}

#[tokio::test]
async fn should_defer_instant_lock_until_selected_quorum_arrives() {
    let directory = TempDir::new().unwrap();
    let config = ClientConfig::mainnet().without_filters().with_storage_path(directory.path());
    let client = DashSpvClient::new(
        config,
        MockNetworkManager::new(),
        Arc::new(RwLock::new(MockWallet::new())),
        vec![],
    )
    .await
    .unwrap();
    let transaction = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
            ..Default::default()
        }],
        output: vec![],
        special_transaction_payload: None,
    };
    let fixture = InstantLockFixture::new(&transaction).unwrap();
    let lock = fixture.instant_lock();
    let mut missing = 0;
    // The test quorum type has two active slots; exactly one signs this lock.
    for index in 0..2 {
        fixture.clone().without_quorum(index).install(&client).await.unwrap();
        match client.verify_instant_lock(lock).await {
            Ok(None) => missing += 1,
            Ok(Some(proof)) => assert!(proof.matches_transaction(&transaction)),
            Err(error) => panic!("incomplete quorum data is unavailable, not invalid: {error}"),
        }
    }
    assert_eq!(missing, 1);
    fixture.clone().without_quorum(0).without_quorum(1).install(&client).await.unwrap();
    assert!(client.verify_instant_lock(lock).await.unwrap().is_none());
    fixture.install(&client).await.unwrap();
    assert!(client
        .verify_instant_lock(lock)
        .await
        .unwrap()
        .unwrap()
        .matches_transaction(&transaction));
}

#[tokio::test]
async fn should_bind_instant_lock_evidence_to_the_verifying_network() {
    let transaction = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
            ..Default::default()
        }],
        output: vec![],
        special_transaction_payload: None,
    };
    let fixture = InstantLockFixture::new(&transaction).unwrap();
    for network in [Network::Mainnet, Network::Testnet] {
        let directory = TempDir::new().unwrap();
        let config =
            ClientConfig::new(network).without_filters().with_storage_path(directory.path());
        let client = DashSpvClient::new(
            config,
            MockNetworkManager::new(),
            Arc::new(RwLock::new(MockWallet::new())),
            vec![],
        )
        .await
        .unwrap();
        fixture.install(&client).await.unwrap();
        let proof = client.verify_instant_lock(fixture.instant_lock()).await.unwrap().unwrap();
        assert!(proof.matches_transaction(&transaction));
        assert_eq!(proof.network(), network);
        let other_network = if network == Network::Mainnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };
        assert_ne!(proof.network(), other_network);
    }
}
