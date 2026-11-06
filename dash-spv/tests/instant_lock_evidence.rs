#![cfg(feature = "test-utils")]

use dash_spv::test_utils::{InstantLockFixture, MockNetworkManager};
use dash_spv::{ClientConfig, DashSpvClient, InstantLockVerificationError, VerifiedInstantLock};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::{InstantLock, Network, OutPoint, Transaction, TxIn, Txid};
use key_wallet_manager::test_utils::MockWallet;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

type TestClient = DashSpvClient<MockWallet, MockNetworkManager>;

/// A client built from `config`, storing into a directory that lives as long as it.
async fn client(config: ClientConfig) -> (TestClient, Arc<RwLock<MockWallet>>, TempDir) {
    let directory = TempDir::new().unwrap();
    let wallet = Arc::new(RwLock::new(MockWallet::new()));
    let config = config.without_filters().with_storage_path(directory.path());
    let client = DashSpvClient::new(config, MockNetworkManager::new(), wallet.clone(), vec![])
        .await
        .unwrap();
    (client, wallet, directory)
}

fn spend() -> Transaction {
    let mut transaction = Transaction::dummy_empty();
    transaction.input.push(TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
        ..Default::default()
    });
    transaction
}

fn with_wrong_signature(lock: &InstantLock) -> InstantLock {
    InstantLock {
        signature: BLSSignature::from([1; 96]),
        ..lock.clone()
    }
}

#[tokio::test]
async fn should_verify_instant_lock_after_cycle_arrives_without_wallet_arithmetic() {
    let (client, wallet, _directory) = client(ClientConfig::mainnet()).await;
    let transaction = spend();
    let fixture = InstantLockFixture::new(Network::Mainnet, &transaction).unwrap();
    let lock = fixture.instant_lock();
    assert!(client.verify_instant_lock(lock).await.unwrap().is_none());
    fixture.install(&client).await.unwrap();
    let proof: VerifiedInstantLock = client.verify_instant_lock(lock).await.unwrap().unwrap();
    assert!(proof.matches_transaction(Network::Mainnet, &transaction));
    assert_eq!(proof.instant_lock(), lock);
    assert!(wallet.read().await.processed_instant_locks.lock().await.is_empty());
    assert!(matches!(
        client.verify_instant_lock(&with_wrong_signature(lock)).await,
        Err(InstantLockVerificationError::InvalidSignature(_))
    ));
}

#[tokio::test]
async fn should_defer_instant_lock_when_masternodes_are_disabled() {
    let (client, _wallet, _directory) = client(ClientConfig::mainnet().without_masternodes()).await;
    assert!(client.verify_instant_lock(&InstantLock::dummy(0..1)).await.unwrap().is_none());
    assert!(matches!(
        client.verify_instant_lock(&InstantLock::default()).await,
        Err(InstantLockVerificationError::Malformed(_))
    ));
}

#[tokio::test]
async fn should_defer_instant_lock_until_selected_quorum_arrives() {
    // Regtest's InstantSend quorum type has two active slots; exactly one signs this lock.
    let (client, _wallet, _directory) = client(ClientConfig::regtest()).await;
    let transaction = spend();
    let fixture = InstantLockFixture::new(Network::Regtest, &transaction).unwrap();
    let lock = fixture.instant_lock();
    let mut missing = 0;
    for index in 0..2 {
        fixture.clone().without_quorum(index).install(&client).await.unwrap();
        match client.verify_instant_lock(lock).await {
            Ok(None) => missing += 1,
            Ok(Some(proof)) => assert!(proof.matches_transaction(Network::Regtest, &transaction)),
            Err(error) => panic!("incomplete quorum data is unavailable, not invalid: {error}"),
        }
        assert!(
            client.verify_instant_lock(&with_wrong_signature(lock)).await.unwrap().is_none(),
            "a partial cycle cannot refute a lock"
        );
    }
    assert_eq!(missing, 1);
    fixture.clone().without_quorum(0).without_quorum(1).install(&client).await.unwrap();
    assert!(client.verify_instant_lock(lock).await.unwrap().is_none());
    fixture.install(&client).await.unwrap();
    assert!(client.verify_instant_lock(lock).await.unwrap().is_some());
}

#[tokio::test]
async fn should_bind_instant_lock_evidence_to_the_verifying_network() {
    let transaction = spend();
    for network in [Network::Mainnet, Network::Testnet] {
        let (client, _wallet, _directory) = client(ClientConfig::new(network)).await;
        let fixture = InstantLockFixture::new(network, &transaction).unwrap();
        fixture.install(&client).await.unwrap();
        let proof = client.verify_instant_lock(fixture.instant_lock()).await.unwrap().unwrap();
        assert_eq!(proof.network(), network);
        assert!(proof.matches_transaction(network, &transaction));
        for other in [Network::Mainnet, Network::Testnet].into_iter().filter(|n| *n != network) {
            assert!(!proof.matches_transaction(other, &transaction));
        }
    }
}

#[tokio::test]
async fn should_not_verify_lock_of_another_instant_send_quorum_type() {
    let (client, _wallet, _directory) = client(ClientConfig::mainnet()).await;
    let fixture = InstantLockFixture::new(Network::Regtest, &spend()).unwrap();
    fixture.install(&client).await.unwrap();
    assert!(client.verify_instant_lock(fixture.instant_lock()).await.unwrap().is_none());
}
