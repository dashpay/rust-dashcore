//! A pending spend holds a coin back only when its owner signed it, before or after the coin's
//! funding is seen, or when the network has accepted it or something built on it.

use dashcore::blockdata::script::{Builder, PushBytes, ScriptBuf};
use dashcore::ecdsa::Signature;
use dashcore::opcodes::all::{OP_CAT, OP_NOP};
use dashcore::sighash::SighashCache;
use dashcore::{
    Address, BlockHash, InstantLock, Network, OutPoint, PublicKey, Transaction, TxIn, TxOut,
};
use test_case::test_case;

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::transaction_builder::TransactionSigner;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::DismissalChange;

const FUNDED: u64 = 1_000_000;
const CHANGE: u64 = 600_000;
const ALL_ANYONE_CAN_PAY: u32 = 0x81;

fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_650_000_000 + height,
    ))
}

fn elsewhere() -> ScriptBuf {
    Address::p2pkh(&PublicKey::from_slice(&[0x02; 33]).expect("pubkey"), Network::Testnet)
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
        .next_receive_address(Some(&ctx.xpub))
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

/// An input script with opcodes other than pushes, which relay policy rejects.
#[derive(Clone, Copy, Debug)]
enum NotPushOnly {
    SignatureBuiltWithOpCat,
    Nop,
    SignatureThenNop,
    SignatureAndKeyThenNop,
}

/// `spend`, signed for `funding`, with its input script rewritten as `script`.
async fn rewritten(
    ctx: &TestWalletContext,
    funding: &Transaction,
    spend: Transaction,
    script: NotPushOnly,
) -> Transaction {
    let mut spend = ctx.signed(spend, &[funding]).await;
    let pushes: Vec<Vec<u8>> = spend.input[0]
        .script_sig
        .instructions()
        .map(|i| i.expect("instruction").push_bytes().expect("push").as_bytes().to_vec())
        .collect();
    let push = |bytes: &[u8]| <&PushBytes>::try_from(bytes).expect("push").to_owned();
    let (head, tail) = pushes[0].split_at(10);
    spend.input[0].script_sig = match script {
        NotPushOnly::SignatureBuiltWithOpCat => Builder::new()
            .push_slice(push(head))
            .push_slice(push(tail))
            .push_opcode(OP_CAT)
            .push_slice(push(&pushes[1])),
        NotPushOnly::Nop => Builder::new().push_opcode(OP_NOP),
        NotPushOnly::SignatureThenNop => {
            Builder::new().push_slice(push(&pushes[0])).push_opcode(OP_NOP)
        }
        NotPushOnly::SignatureAndKeyThenNop => Builder::new()
            .push_slice(push(&pushes[0]))
            .push_slice(push(&pushes[1]))
            .push_opcode(OP_NOP),
    }
    .into_script();
    spend
}

#[tokio::test]
async fn an_authorized_spend_seen_before_its_coin_keeps_the_coin_spent() {
    let (mut ctx, funding, spend) = spend_first();
    let spend = ctx.signed(spend, &[&funding]).await;
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
        spend = ctx.signed(spend, &[&funding]).await;
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
    let mut spend = ctx.signed(spend, &[&other]).await;
    spend.input[0].previous_output = OutPoint::new(funding.txid(), 0);
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert_eq!(result.swept_transactions, vec![spend.txid()]);
    assert!(holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

#[test_case(NotPushOnly::SignatureBuiltWithOpCat; "signature built with OP_CAT")]
#[test_case(NotPushOnly::Nop; "no pushes")]
#[test_case(NotPushOnly::SignatureThenNop; "signature then OP_NOP")]
#[test_case(NotPushOnly::SignatureAndKeyThenNop; "valid signature and key then OP_NOP")]
#[tokio::test]
async fn a_pending_claim_that_is_not_push_only_does_not_hide_the_coin(script: NotPushOnly) {
    let (mut ctx, funding, spend) = spend_first();
    let spend = rewritten(&ctx, &funding, spend, script).await;
    assert!(ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert_eq!(result.swept_transactions, vec![spend.txid()]);
    assert!(holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

#[tokio::test]
async fn a_dropped_claim_does_not_release_a_coin_another_claim_holds() {
    let (mut ctx, funding, unsigned) = spend_first();
    let mut signed = unsigned.clone();
    signed.output[0].value -= 1;
    let signed = ctx.signed(signed, &[&funding]).await;
    ctx.check_transaction(&unsigned, TransactionContext::Mempool).await;
    ctx.check_transaction(&signed, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert_eq!(result.swept_transactions, vec![unsigned.txid()]);
    assert!(result.released_outpoints.is_empty());
    assert!(!holds_coin(&ctx, &funding), "the signed claim keeps the coin spent");
    assert!(ctx.bip44_account().transactions().contains_key(&signed.txid()));
}

#[tokio::test]
async fn an_unsigned_claim_whose_output_a_block_spends_keeps_the_coin_spent() {
    let (mut ctx, funding, spend) = spend_first();
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;
    let mut onward = child_of(&ctx, &spend);
    onward.input[0].previous_output.vout = 0;
    ctx.managed_wallet.record_observed_spends(&onward, 95);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert!(result.swept_transactions.is_empty());
    assert!(!holds_coin(&ctx, &funding));
    assert!(ctx.bip44_account().transactions().contains_key(&spend.txid()));
}

#[tokio::test]
async fn a_dropped_claim_does_not_release_a_coin_a_block_spent() {
    let (mut ctx, funding, mut spend) = spend_first();
    let other = OutPoint::new(Transaction::dummy(&ctx.receive_address, 5..6, &[1]).txid(), 0);
    spend.input.push(TxIn {
        previous_output: other,
        ..Default::default()
    });
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;
    let mut rival = child_of(&ctx, &spend);
    rival.input[0].previous_output = other;
    ctx.managed_wallet.record_observed_spends(&rival, 95);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    assert_eq!(result.swept_transactions, vec![spend.txid()]);
    assert_eq!(result.released_outpoints, vec![OutPoint::new(funding.txid(), 0)]);
}

#[tokio::test]
async fn a_dropped_claim_does_not_release_a_coin_its_funding_spends() {
    let (mut ctx, funding, mut spend) = spend_first();
    spend.input.push(TxIn {
        previous_output: funding.input[0].previous_output,
        ..Default::default()
    });
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert_eq!(result.swept_transactions, vec![spend.txid()]);
    assert_eq!(result.released_outpoints, vec![OutPoint::new(funding.txid(), 0)]);
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
    let child = ctx.signed(child_of(&ctx, &spend), &[&spend]).await;
    assert!(ctx.check_transaction(&child, TransactionContext::Mempool).await.is_relevant);

    let result = ctx.check_transaction(&funding, in_block(100)).await;
    let mut dropped = vec![spend.txid(), child.txid()];
    dropped.sort_unstable();
    assert_eq!(result.swept_transactions, dropped);
    assert!(holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

/// A claim the funding shows unsigned is dismissed as a sweep is, not as the user's abandon,
/// so a peer's forgeries can't push the user's abandons out.
#[tokio::test]
async fn a_dropped_claim_is_dismissed_not_abandoned() {
    let (mut ctx, funding, spend) = spend_first();
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;
    let child = ctx.signed(child_of(&ctx, &spend), &[&spend]).await;
    ctx.check_transaction(&child, TransactionContext::Mempool).await;
    ctx.managed_wallet.take_dismissal_changes();

    ctx.check_transaction(&funding, in_block(100)).await;

    let changes = ctx.managed_wallet.take_dismissal_changes();
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert!(changes.contains(&DismissalChange::Dismissed(spend.txid())));
    assert!(changes.contains(&DismissalChange::Dismissed(child.txid())));
}

/// The wallet holding a mined coin, and an unsigned spend of it paying change back to the
/// wallet.
async fn coin_held() -> (TestWalletContext, Transaction, Transaction) {
    let (mut ctx, funding, spend) = spend_first();
    assert!(ctx.check_transaction(&funding, in_block(100)).await.is_relevant);
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
    (ctx, funding, spend)
}

#[tokio::test]
async fn an_authorized_spend_from_another_device_spends_a_held_coin() {
    let (mut ctx, funding, spend) = coin_held().await;
    let spend = ctx.signed(spend, &[&funding]).await;

    let result = ctx.check_transaction(&spend, TransactionContext::Mempool).await;
    assert!(result.is_relevant);
    assert!(!holds_coin(&ctx, &funding), "the coin is spent");
    assert!(ctx.bip44_account().transactions().contains_key(&spend.txid()));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[tokio::test]
async fn an_unauthorized_claim_on_a_held_coin_is_ignored() {
    let (mut ctx, funding, spend) = coin_held().await;

    let result = ctx.check_transaction(&spend, TransactionContext::Mempool).await;
    assert!(!result.is_relevant);
    assert!(result.new_records.is_empty());
    assert!(holds_coin(&ctx, &funding), "the coin stays counted");
    assert!(!ctx.bip44_account().transactions().contains_key(&spend.txid()));
    assert!(ctx.bip44_account().utxos.keys().all(|outpoint| outpoint.txid != spend.txid()));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

#[tokio::test]
async fn a_claim_on_a_held_coin_signed_for_another_coin_is_ignored() {
    let (mut ctx, funding, mut spend) = coin_held().await;
    let other = Transaction::dummy(&ctx.receive_address, 1..2, &[FUNDED]);
    spend.input[0].previous_output = OutPoint::new(other.txid(), 0);
    let mut spend = ctx.signed(spend, &[&other]).await;
    spend.input[0].previous_output = OutPoint::new(funding.txid(), 0);

    assert!(!ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert!(holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

#[test_case(NotPushOnly::SignatureBuiltWithOpCat; "signature built with OP_CAT")]
#[test_case(NotPushOnly::Nop; "no pushes")]
#[test_case(NotPushOnly::SignatureThenNop; "signature then OP_NOP")]
#[test_case(NotPushOnly::SignatureAndKeyThenNop; "valid signature and key then OP_NOP")]
#[tokio::test]
async fn a_pending_claim_on_a_held_coin_that_is_not_push_only_is_ignored(script: NotPushOnly) {
    let (mut ctx, funding, spend) = coin_held().await;
    let spend = rewritten(&ctx, &funding, spend, script).await;

    assert!(!ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert!(holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), FUNDED);
}

#[tokio::test]
async fn an_unsigned_claim_on_a_coin_a_pending_spend_holds_is_ignored() {
    let (mut ctx, funding, spend) = coin_held().await;
    let mut rival = spend.clone();
    rival.output[0].value -= 1;
    let spend = ctx.signed(spend, &[&funding]).await;
    assert!(ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);

    assert!(!ctx.check_transaction(&rival, TransactionContext::Mempool).await.is_relevant);
    assert!(!ctx.bip44_account().transactions().contains_key(&rival.txid()));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[tokio::test]
async fn an_unsigned_claim_on_a_coin_a_signed_claim_holds_is_ignored() {
    let (mut ctx, funding, unsigned) = spend_first();
    let mut signed = unsigned.clone();
    signed.output[0].value -= 1;
    let signed = ctx.signed(signed, &[&funding]).await;
    ctx.check_transaction(&signed, TransactionContext::Mempool).await;
    ctx.check_transaction(&funding, in_block(100)).await;

    assert!(!ctx.check_transaction(&unsigned, TransactionContext::Mempool).await.is_relevant);
    assert!(!ctx.bip44_account().transactions().contains_key(&unsigned.txid()));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[tokio::test]
async fn a_spend_of_a_held_coin_signed_anyone_can_pay_is_taken() {
    let (mut ctx, funding, mut spend) = coin_held().await;
    let prevout = &funding.output[0].script_pubkey;
    let sighash = SighashCache::new(&spend)
        .legacy_signature_hash(0, prevout, ALL_ANYONE_CAN_PAY)
        .expect("sighash");
    let path = ctx.bip44_account().address_derivation_path(&ctx.receive_address).expect("path");
    let (signature, key) = ctx.wallet.sig_and_pubkey(sighash, path).await.expect("signs");
    let mut signature = Signature::sighash_all(signature.into()).serialize().to_vec();
    *signature.last_mut().expect("hash type byte") = ALL_ANYONE_CAN_PAY as u8;
    spend.input[0].script_sig = Builder::new()
        .push_slice(<&PushBytes>::try_from(signature.as_slice()).expect("push"))
        .push_key(&PublicKey::new(key))
        .into_script();

    assert!(ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert!(!holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[tokio::test]
async fn a_mined_spend_of_a_held_coin_built_with_op_cat_is_taken() {
    let (mut ctx, funding, spend) = coin_held().await;
    let spend = rewritten(&ctx, &funding, spend, NotPushOnly::SignatureBuiltWithOpCat).await;

    assert!(ctx.check_transaction(&spend, in_block(101)).await.is_relevant);
    assert!(!holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[tokio::test]
async fn a_claim_on_two_held_coins_with_one_unsigned_is_ignored() {
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[FUNDED, FUNDED]);
    assert!(ctx.check_transaction(&funding, in_block(100)).await.is_relevant);
    let spend = Transaction {
        version: 2,
        lock_time: 0,
        input: (0..2)
            .map(|vout| TxIn {
                previous_output: OutPoint::new(funding.txid(), vout),
                ..Default::default()
            })
            .collect(),
        output: vec![TxOut {
            value: 2 * FUNDED - 1_000,
            script_pubkey: elsewhere(),
        }],
        special_transaction_payload: None,
    };
    let mut spend = ctx.signed(spend, &[&funding]).await;
    spend.input[1].script_sig = ScriptBuf::new();

    assert!(!ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert_eq!(ctx.bip44_account().utxos.len(), 2);
    assert_eq!(ctx.managed_wallet.balance().total(), 2 * FUNDED);
}

#[test_case(in_block(101); "mined")]
#[test_case(TransactionContext::InstantSend(InstantLock::default()); "instant send locked")]
#[tokio::test]
async fn an_ignored_claim_is_taken_once_settled(context: TransactionContext) {
    let (mut ctx, funding, spend) = coin_held().await;
    assert!(!ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);

    assert!(ctx.check_transaction(&spend, context).await.is_relevant);
    assert!(!holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[tokio::test]
async fn a_claim_whose_lock_arrived_first_is_taken() {
    let (mut ctx, funding, spend) = coin_held().await;
    ctx.managed_wallet.mark_instant_send_utxos(&spend.txid(), &InstantLock::default());

    assert!(ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert!(!holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}

#[test_case(in_block(101); "mined")]
#[test_case(TransactionContext::InstantSend(InstantLock::default()); "instant send locked")]
#[tokio::test]
async fn a_settled_spend_of_a_held_coin_needs_no_signature_check(context: TransactionContext) {
    let (mut ctx, funding, spend) = coin_held().await;

    assert!(ctx.check_transaction(&spend, context).await.is_relevant);
    assert!(!holds_coin(&ctx, &funding));
    assert_eq!(ctx.managed_wallet.balance().total(), CHANGE);
}
