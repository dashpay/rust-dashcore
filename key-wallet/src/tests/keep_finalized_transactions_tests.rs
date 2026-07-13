//! Tests for the `keep-finalized-transactions` Cargo feature.
//!
//! These tests assert the dual semantics of the feature:
//!
//! - With the feature ON, every processed transaction stays in the
//!   in-memory `transactions` map for the wallet's lifetime, including
//!   chainlocked ones.
//! - With the feature OFF (the default), records of chainlocked
//!   transactions are dropped from the map and only their txids are kept
//!   for dedup. IS-locked-but-not-yet-chainlocked records still live in
//!   the map so we don't lose the block-confirmation event when it
//!   arrives.
//!
//! "Finalized" in this crate means *chainlocked* — see
//! [`crate::transaction_checking::TransactionContext::is_chain_locked`].
//! IS-lock alone is **not** finality.

use crate::{
    account::{AccountType, StandardAccountType},
    managed_account::managed_account_trait::ManagedAccountTrait,
    test_utils::TestWalletContext,
    transaction_checking::{BlockInfo, TransactionContext},
    wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface,
};
#[cfg(not(feature = "keep-finalized-transactions"))]
use crate::{
    managed_account::{
        address_pool::KeySource, managed_account_type::ManagedAccountType, ManagedCoreKeysAccount,
    },
    transaction_checking::account_checker::{AccountMatch, CoreAccountTypeMatch},
    transaction_checking::transaction_router::TransactionType as RoutedTransactionType,
    Network,
};
use dashcore::ephemerealdata::chain_lock::ChainLock;
#[cfg(not(feature = "keep-finalized-transactions"))]
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, Transaction};

fn bip44_account_type() -> AccountType {
    AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    }
}

/// Walks a single transaction through Mempool → InBlock → InChainLockedBlock
/// and asserts that the record survives the chainlock when the feature is ON.
#[cfg(feature = "keep-finalized-transactions")]
#[tokio::test]
async fn test_chainlocked_record_kept_when_feature_on() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();

    // Mempool → record exists
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transactions().contains_key(&txid));

    // InBlock → record still there, finalization stays false
    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(!ctx.bip44_account().transaction_is_finalized(&txid));

    // InChainLockedBlock → record MUST still live in the map.
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));
    assert!(
        ctx.bip44_account().transactions().contains_key(&txid),
        "with the feature ON the record must stay in the map after chainlock"
    );
}

/// With the feature OFF (default) a chainlocked transaction's record is
/// dropped from the map; only the txid is retained for dedup. The
/// `has_transaction` / `transaction_is_finalized` queries must keep
/// working off the txid set.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn test_chainlocked_record_dropped_when_feature_off() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();

    // Mempool → record exists in the map.
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(ctx.bip44_account().transactions().contains_key(&txid));

    // InChainLockedBlock → record dropped, but `has_transaction` and
    // `transaction_is_finalized` still report the tx via the txid set.
    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(
        !ctx.bip44_account().transactions().contains_key(&txid),
        "with the feature OFF the chainlocked record must be dropped"
    );
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));
}

/// IS-lock is **not** finalization. The record must NOT be dropped when
/// the feature is OFF because we still need the in-memory record to
/// absorb the eventual block-confirmation event (height / block hash).
/// This guards against the pre-review bug where dropping on IS-lock
/// lost block-confirmation tracking.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn test_islocked_record_kept_when_feature_off() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();

    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    let _ =
        ctx.check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default())).await;

    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(
        !ctx.bip44_account().transaction_is_finalized(&txid),
        "IS-lock alone is not finalization — only a chainlock counts"
    );
    assert!(
        ctx.bip44_account().transactions().contains_key(&txid),
        "IS-locked records must survive so a later InBlock event can populate \
         block-confirmation info"
    );
}

/// `apply_chain_lock` at a height covering an `InBlock` record
/// promotes its context. With the feature OFF the record is dropped
/// from the map. With the feature ON it stays with the new context.
#[tokio::test]
async fn test_apply_chain_lock_promotes_in_block_records() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();
    let block_hash = BlockHash::from_slice(&[9u8; 32]).expect("hash");

    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InBlock(BlockInfo::new(50, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(ctx.bip44_account().transactions().contains_key(&txid));

    ctx.managed_wallet.update_last_processed_height(50);
    let outcome = ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(50));
    assert!(
        outcome.metadata_advanced,
        "first chainlock must advance metadata from None to Some(50)"
    );
    let promoted = outcome
        .locked_transactions
        .get(&bip44_account_type())
        .expect("BIP44 account should have a promotion entry");
    assert_eq!(promoted, &vec![txid]);
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));

    #[cfg(feature = "keep-finalized-transactions")]
    {
        let record = ctx.bip44_account().transactions().get(&txid).expect("record kept");
        assert!(matches!(record.context, TransactionContext::InChainLockedBlock(_)));
    }
    #[cfg(not(feature = "keep-finalized-transactions"))]
    {
        assert!(
            !ctx.bip44_account().transactions().contains_key(&txid),
            "with the feature OFF the record must be dropped after promotion"
        );
    }
}

/// `apply_chain_lock` only promotes records at or below `cl_height` and
/// never touches `Mempool` / `InstantSend` records (those have not been
/// mined yet, and chainlock-finality requires a block).
#[tokio::test]
async fn test_apply_chain_lock_skips_unmined_and_above_height() {
    let mut ctx = TestWalletContext::new_random();
    let mempool_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[120_000]);
    let block_tx = Transaction::dummy(&ctx.receive_address, 1..2, &[150_000]);
    let mempool_txid = mempool_tx.txid();
    let block_txid = block_tx.txid();
    let block_hash = BlockHash::from_slice(&[1u8; 32]).expect("hash");

    let _ = ctx.check_transaction(&mempool_tx, TransactionContext::Mempool).await;
    let _ = ctx
        .check_transaction(
            &block_tx,
            TransactionContext::InBlock(BlockInfo::new(200, block_hash, 1_700_000_000)),
        )
        .await;

    // Chainlock at 100 sits below the InBlock-at-200 record and above
    // the mempool record's (absent) height, so neither promotes.
    ctx.managed_wallet.update_last_processed_height(200);
    let outcome = ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(100));
    assert!(outcome.locked_transactions.is_empty());
    assert!(
        outcome.metadata_advanced,
        "metadata must still advance to the new finality boundary even when no record promotes"
    );
    assert!(!ctx.bip44_account().transaction_is_finalized(&mempool_txid));
    assert!(!ctx.bip44_account().transaction_is_finalized(&block_txid));
}

/// Build a masternode-registration transaction whose DIP-3 payload carries a
/// service endpoint, plus the [`AccountMatch`] a provider owner-keys account
/// would report for it.
#[cfg(not(feature = "keep-finalized-transactions"))]
fn proreg_tx_and_owner_match() -> (Transaction, AccountMatch) {
    use dashcore::blockdata::transaction::special_transaction::provider_registration::{
        ProviderMasternodeType, ProviderRegistrationPayload,
    };
    use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
    use dashcore::bls_sig_utils::BLSPublicKey;
    use dashcore::hash_types::InputsHash;
    use dashcore::{OutPoint, PubkeyHash, ScriptBuf, Txid};
    use std::net::SocketAddr;
    use std::str::FromStr;

    let key_hash = PubkeyHash::from_slice(&[0x70; 20]).expect("hash160");
    let payload = ProviderRegistrationPayload {
        version: 1,
        masternode_type: ProviderMasternodeType::Regular,
        masternode_mode: 0,
        collateral_outpoint: OutPoint {
            txid: Txid::from_slice(&[0x19; 32]).expect("txid"),
            vout: 1,
        },
        service_address: SocketAddr::from_str("54.148.58.128:9999").expect("socket addr"),
        owner_key_hash: key_hash,
        operator_public_key: BLSPublicKey::from([0x11; 48]),
        voting_key_hash: key_hash,
        operator_reward: 0,
        script_payout: ScriptBuf::new(),
        inputs_hash: InputsHash::from_slice(&[0x22; 32]).expect("inputs hash"),
        signature: vec![0x33; 65],
        platform_node_id: None,
        platform_p2p_port: None,
        platform_http_port: None,
    };
    let tx = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![],
        output: vec![],
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            payload,
        )),
    };
    let account_match = AccountMatch {
        account_type_match: CoreAccountTypeMatch::ProviderOwnerKeys {
            involved_addresses: vec![],
        },
        received: 0,
        sent: 0,
        received_for_credit_conversion: 0,
    };
    (tx, account_match)
}

/// Build a keys account of the given type without key material (the
/// retention decision only looks at the account type and the payload).
#[cfg(not(feature = "keep-finalized-transactions"))]
fn keys_account(account_type: AccountType) -> ManagedCoreKeysAccount {
    let managed_type = ManagedAccountType::from_account_type(
        account_type,
        Network::Testnet,
        &KeySource::NoKeySource,
    )
    .expect("managed account type");
    ManagedCoreKeysAccount::new(managed_type, Network::Testnet)
}

/// A `ProRegTx` first seen already chainlocked (the historical-rescan case
/// from masternode-key discovery) must keep its full record on a provider
/// owner-keys account even with the feature OFF: the payload's service
/// IP / proTxHash data is what the account exists to surface.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[test]
fn test_provider_payload_record_retained_on_provider_account() {
    let mut account = keys_account(AccountType::ProviderOwnerKeys);
    let (tx, account_match) = proreg_tx_and_owner_match();
    let txid = tx.txid();

    let block_hash = BlockHash::from_slice(&[5u8; 32]).expect("hash");
    let _ = account.record_transaction(
        &tx,
        &account_match,
        TransactionContext::InChainLockedBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        RoutedTransactionType::ProviderRegistration,
    );

    assert!(account.transaction_is_finalized(&txid));
    assert!(account.has_transaction(&txid));
    let record = account
        .transactions()
        .get(&txid)
        .expect("provider payload record must be retained past finalization");
    assert!(record.transaction.special_transaction_payload.is_some());
}

/// The retention exception is payload-driven: a payload-less transaction
/// on the same provider account still drops at finalization.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[test]
fn test_plain_record_still_dropped_on_provider_account() {
    let mut account = keys_account(AccountType::ProviderOwnerKeys);
    let (_, account_match) = proreg_tx_and_owner_match();
    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
        special_transaction_payload: None,
    };
    let txid = tx.txid();

    let block_hash = BlockHash::from_slice(&[6u8; 32]).expect("hash");
    let _ = account.record_transaction(
        &tx,
        &account_match,
        TransactionContext::InChainLockedBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        RoutedTransactionType::Standard,
    );

    assert!(account.transaction_is_finalized(&txid));
    assert!(account.has_transaction(&txid));
    assert!(
        !account.transactions().contains_key(&txid),
        "payload-less records must still be dropped at finalization"
    );
}

/// The retention exception is also account-driven: the same `ProRegTx`
/// record drops at finalization on a non-provider keys account.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[test]
fn test_provider_payload_record_dropped_on_non_provider_account() {
    let mut account = keys_account(AccountType::IdentityRegistration);
    let (tx, _) = proreg_tx_and_owner_match();
    let account_match = AccountMatch {
        account_type_match: CoreAccountTypeMatch::IdentityRegistration {
            involved_addresses: vec![],
        },
        received: 0,
        sent: 0,
        received_for_credit_conversion: 0,
    };
    let txid = tx.txid();

    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let _ = account.record_transaction(
        &tx,
        &account_match,
        TransactionContext::InChainLockedBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        RoutedTransactionType::ProviderRegistration,
    );

    assert!(account.transaction_is_finalized(&txid));
    assert!(!account.transactions().contains_key(&txid));
}

/// A retained provider record must also survive the deferred-chainlock
/// path (`apply_chain_lock` promoting an `InBlock` record) with its
/// context updated, and repeated chainlocks must be idempotent.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[test]
fn test_provider_payload_record_retained_through_apply_chain_lock() {
    let mut account = keys_account(AccountType::ProviderOwnerKeys);
    let (tx, account_match) = proreg_tx_and_owner_match();
    let txid = tx.txid();

    let block_hash = BlockHash::from_slice(&[8u8; 32]).expect("hash");
    let _ = account.record_transaction(
        &tx,
        &account_match,
        TransactionContext::InBlock(BlockInfo::new(50, block_hash, 1_700_000_000)),
        RoutedTransactionType::ProviderRegistration,
    );

    let promoted = account.apply_chain_lock(60);
    assert_eq!(promoted, vec![txid]);
    assert!(account.transaction_is_finalized(&txid));
    let record = account.transactions().get(&txid).expect("record retained");
    assert!(matches!(record.context, TransactionContext::InChainLockedBlock(_)));

    // A later chainlock must not re-promote (or drop) the retained record.
    let promoted_again = account.apply_chain_lock(70);
    assert!(promoted_again.is_empty());
    assert!(account.transactions().contains_key(&txid));
}

/// IS-lock first, then a chainlocked block: the record must drop only at
/// the chainlock step. We also assert that the chainlock event still
/// "lands" — `transaction_is_finalized` must report `true` when asked
/// via the txid set.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn test_islocked_then_chainlocked_drops_at_chainlock() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let txid = tx.txid();

    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    let _ =
        ctx.check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default())).await;
    assert!(ctx.bip44_account().transactions().contains_key(&txid), "still present after IS-lock");

    let block_hash = BlockHash::from_slice(&[3u8; 32]).expect("hash");
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(42, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(!ctx.bip44_account().transactions().contains_key(&txid), "dropped at chainlock");
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));
}
