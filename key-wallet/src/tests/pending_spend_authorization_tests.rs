//! A pending spend seen before its funding holds the coin back only when the coin's owner
//! signed it, or when the network has already accepted it or something built on it.

use dashcore::blockdata::script::{Builder, PushBytes, ScriptBuf};
use dashcore::hashes::Hash;
use dashcore::opcodes::all::OP_CAT;
use dashcore::{Address, BlockHash, InstantLock, OutPoint, Transaction, TxIn, TxOut};
use test_case::test_case;

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::transaction_builder::TransactionSigner;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::Utxo;

const FUNDED: u64 = 1_000_000;
const CHANGE: u64 = 600_000;

fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_650_000_000 + height,
    ))
}

fn elsewhere() -> ScriptBuf {
    Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
        dashcore::Network::Testnet,
    )
    .script_pubkey()
}

/// The wallet, a funding transaction it has not seen paying its receive address, and an
/// unsigned spend of that coin paying change back to it.
fn spend_first() -> (TestWalletContext, Transaction, Transaction) {
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[FUNDED]);
    let change = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("BIP44 account")
        .next_receive_address(Some(&ctx.xpub), true)
        .expect("change address");
    let spend = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.txid(), 0),
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: FUNDED - CHANGE - 1_000,
                script_pubkey: elsewhere(),
            },
            TxOut {
                value: CHANGE,
                script_pubkey: change.script_pubkey(),
            },
        ],
        special_transaction_payload: None,
    };
    (ctx, funding, spend)
}

/// `spend` with its only input signed as the owner of `parent`'s output it spends.
async fn signed(ctx: &TestWalletContext, parent: &Transaction, spend: Transaction) -> Transaction {
    let prevout = parent.output[spend.input[0].previous_output.vout as usize].clone();
    let address =
        Address::from_script(&prevout.script_pubkey, ctx.wallet.network).expect("address");
    let coin = Utxo::new(spend.input[0].previous_output, prevout, address.clone(), 0, false);
    let path = ctx.bip44_account().address_derivation_path(&address).expect("path");
    ctx.wallet.sign_tx(spend, vec![coin], move |_| Some(path.clone())).await.expect("signed")
}

/// A spend of `parent`'s change output, paying change back to the wallet.
fn child_of(ctx: &TestWalletContext, parent: &Transaction) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(parent.txid(), 1),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: CHANGE - 1_000,
            script_pubkey: ctx.receive_address.script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

fn holds_coin(ctx: &TestWalletContext, funding: &Transaction) -> bool {
    ctx.bip44_account().utxos.contains_key(&OutPoint::new(funding.txid(), 0))
}

#[tokio::test]
async fn an_authorized_spend_seen_before_its_coin_keeps_the_coin_spent() {
    let (mut ctx, funding, spend) = spend_first();
    let spend = signed(&ctx, &funding, spend).await;
    assert!(ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert!(result.is_relevant);
    assert!(result.swept_transactions.is_empty());
    assert!(!holds_coin(&ctx, &funding), "the spent coin is not credited");
    assert!(ctx.bip44_account().transactions().contains_key(&spend.txid()));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[test_case(false ; "unsigned")]
#[test_case(true ; "push-only with a bad signature")]
#[tokio::test]
async fn an_unauthorized_claim_does_not_hide_the_coin(bad_signature: bool) {
    let (mut ctx, funding, mut spend) = spend_first();
    if bad_signature {
        spend = signed(&ctx, &funding, spend).await;
        let script = &mut spend.input[0].script_sig;
        let last_der_byte = usize::from(script.as_bytes()[0]) - 1;
        script.as_mut_bytes()[last_der_byte] ^= 1;
    }
    assert!(ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert!(result.is_relevant);
    assert_eq!(result.swept_transactions, vec![spend.txid()]);
    assert_eq!(result.released_outpoints, vec![OutPoint::new(funding.txid(), 0)]);
    assert!(holds_coin(&ctx, &funding), "the coin is credited");
    assert!(!ctx.bip44_account().transactions().contains_key(&spend.txid()));
    assert!(ctx.bip44_account().utxos.keys().all(|outpoint| outpoint.txid != spend.txid()));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

#[tokio::test]
async fn a_claim_signed_for_a_different_coin_does_not_hide_the_coin() {
    let (mut ctx, funding, mut spend) = spend_first();
    let other = Transaction::dummy(&ctx.receive_address, 1..2, &[FUNDED]);
    spend.input[0].previous_output = OutPoint::new(other.txid(), 0);
    let mut spend = signed(&ctx, &other, spend).await;
    spend.input[0].previous_output = OutPoint::new(funding.txid(), 0);
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert_eq!(result.swept_transactions, vec![spend.txid()]);
    assert!(holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

#[tokio::test]
async fn a_claim_that_may_build_its_signature_at_run_time_keeps_the_coin_spent() {
    let (mut ctx, funding, spend) = spend_first();
    let mut spend = signed(&ctx, &funding, spend).await;
    let pushes: Vec<_> =
        spend.input[0].script_sig.instructions().map(|i| i.expect("instruction")).collect();
    let signature = pushes[0].push_bytes().expect("signature push").as_bytes().to_vec();
    let owner = pushes[1].push_bytes().expect("key push").as_bytes().to_vec();
    let (head, tail) = signature.split_at(10);
    spend.input[0].script_sig = Builder::new()
        .push_slice(<&PushBytes>::try_from(head).expect("push"))
        .push_slice(<&PushBytes>::try_from(tail).expect("push"))
        .push_opcode(OP_CAT)
        .push_slice(<&PushBytes>::try_from(owner.as_slice()).expect("push"))
        .into_script();
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert!(result.swept_transactions.is_empty());
    assert!(!holds_coin(&ctx, &funding));
    assert!(ctx.bip44_account().transactions().contains_key(&spend.txid()));
}

#[test_case(in_block(90); "mined")]
#[test_case(TransactionContext::InstantSend(InstantLock::default()); "instant send locked")]
#[tokio::test]
async fn a_settled_spend_needs_no_signature_check(context: TransactionContext) {
    let (mut ctx, funding, spend) = spend_first();
    assert!(ctx.check_transaction(&spend, context).await.is_relevant);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert!(result.swept_transactions.is_empty());
    assert!(!holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[test_case(in_block(95); "mined")]
#[test_case(TransactionContext::InstantSend(InstantLock::default()); "instant send locked")]
#[tokio::test]
async fn an_unsigned_claim_with_a_settled_descendant_keeps_the_coin_spent(
    context: TransactionContext,
) {
    let (mut ctx, funding, spend) = spend_first();
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;
    let child = child_of(&ctx, &spend);
    assert!(ctx.check_transaction(&child, context).await.is_relevant);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert!(result.swept_transactions.is_empty());
    assert!(!holds_coin(&ctx, &funding));
    assert!(ctx.bip44_account().transactions().contains_key(&spend.txid()));
    assert!(ctx.bip44_account().transactions().contains_key(&child.txid()));
}

#[tokio::test]
async fn an_unsigned_claim_with_a_pending_descendant_is_dropped_with_it() {
    let (mut ctx, funding, spend) = spend_first();
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;
    let child = signed(&ctx, &spend, child_of(&ctx, &spend)).await;
    assert!(ctx.check_transaction(&child, TransactionContext::Mempool).await.is_relevant);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    let mut dropped = vec![spend.txid(), child.txid()];
    dropped.sort_unstable();
    assert_eq!(result.swept_transactions, dropped);
    assert!(holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}
