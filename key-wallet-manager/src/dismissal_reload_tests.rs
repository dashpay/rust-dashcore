//! A pending claim on a held coin that its funding exposes, checked where no event reports the
//! sweep, keeps its stored row while its dismissal goes unreported. Each load judges it again by
//! the rule that dropped it: one that provably lacks authorization is dropped again and the coin
//! offered, and one that may be authorized holds the coin.

use super::test_helpers::*;
use super::*;
use dashcore::block::{Block, Header, Version};
use dashcore::blockdata::script::{Builder, PushBytes};
use dashcore::opcodes::all::{OP_CAT, OP_NOP};
use dashcore::{BlockHash, CompactTarget, ScriptBuf, TxMerkleNode};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::wallet::managed_wallet_info::DismissalChange;
use test_case::test_case;

const FUNDING_HEIGHT: CoreBlockHeight = 100;
const CLAIM_PAYS: u64 = TX_AMOUNT - 1_000;

/// The input script of a claim on the wallet's coin.
#[derive(Clone, Copy, Debug)]
enum Claim {
    Unsigned,
    BadSignature,
    Unparseable,
    SignatureAndKeyThenNop,
    KeyBuiltWithOpCat,
}

/// The order a load replays the stored rows in.
#[derive(Clone, Copy, Debug)]
enum Replay {
    AsStored,
    MinedFirst,
}

/// What a persister mirroring the wallet holds: each row as last reported, in the order first
/// stored, the dismissal sets, and every txid a sweep event removed.
#[derive(Default)]
struct Store {
    rows: Vec<TransactionRecord>,
    abandoned: Vec<Txid>,
    swept: Vec<Txid>,
    removed: Vec<Txid>,
}

impl Store {
    fn upsert(&mut self, record: &TransactionRecord) {
        match self.rows.iter_mut().find(|row| row.txid == record.txid) {
            Some(row) => *row = record.clone(),
            None => self.rows.push(record.clone()),
        }
    }

    fn mirror(&mut self, rx: &mut mpsc::UnboundedReceiver<WalletEvent>) {
        while let Ok(event) = rx.try_recv() {
            match event {
                WalletEvent::TransactionDetected {
                    record,
                    ..
                } => self.upsert(&record),
                WalletEvent::BlockProcessed {
                    inserted,
                    updated,
                    ..
                } => inserted.iter().chain(&updated).for_each(|record| self.upsert(record)),
                WalletEvent::TransactionsSwept {
                    txids,
                    ..
                } => {
                    self.rows.retain(|row| !txids.contains(&row.txid));
                    self.removed.extend(txids);
                }
                WalletEvent::DismissalsChanged {
                    changes,
                    ..
                } => {
                    for change in changes {
                        match change {
                            DismissalChange::Dismissed(txid) => self.swept.push(txid),
                            DismissalChange::Abandoned(txid) => self.abandoned.push(txid),
                            DismissalChange::Forgotten(txid) => {
                                self.swept.retain(|t| *t != txid);
                                self.abandoned.retain(|t| *t != txid);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn holds(&self, txid: &Txid) -> bool {
        self.rows.iter().any(|row| row.txid == *txid)
    }
}

fn block_of(tx: &Transaction) -> Block {
    Block {
        header: Header {
            version: Version::default(),
            prev_blockhash: BlockHash::from_byte_array([FUNDING_HEIGHT as u8; 32]),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_650_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata: vec![tx.clone()],
    }
}

/// A spend of `funding`'s coin paying the wallet, with `kind`'s input script.
async fn claim_on(
    manager: &WalletManager<ManagedWalletInfo>,
    wallet_id: &WalletId,
    addr: &Address,
    funding: &Transaction,
    kind: Claim,
) -> Transaction {
    let mut claim = create_tx_paying_to(addr, 0xc2);
    claim.input[0].previous_output = OutPoint::new(funding.txid(), 0);
    claim.output[0].value = CLAIM_PAYS;
    if let Claim::Unsigned = kind {
        return claim;
    }
    let mut claim = signed_spend(manager, wallet_id, claim, &[funding]).await;
    let pushes: Vec<Vec<u8>> = claim.input[0]
        .script_sig
        .instructions()
        .map(|i| i.expect("instruction").push_bytes().expect("push").as_bytes().to_vec())
        .collect();
    let push = |bytes: &[u8]| <&PushBytes>::try_from(bytes).expect("push").to_owned();
    claim.input[0].script_sig = match kind {
        Claim::Unsigned => unreachable!(),
        Claim::BadSignature => {
            let mut signature = pushes[0].clone();
            let last_der_byte = signature.len() - 2;
            signature[last_der_byte] ^= 1;
            Builder::new().push_slice(push(&signature)).push_slice(push(&pushes[1])).into_script()
        }
        Claim::Unparseable => {
            let mut script = claim.input[0].script_sig.to_bytes();
            script.push(1);
            ScriptBuf::from_bytes(script)
        }
        Claim::SignatureAndKeyThenNop => Builder::new()
            .push_slice(push(&pushes[0]))
            .push_slice(push(&pushes[1]))
            .push_opcode(OP_NOP)
            .into_script(),
        Claim::KeyBuiltWithOpCat => {
            let (key_head, key_tail) = pushes[1].split_at(1);
            Builder::new()
                .push_slice(push(&pushes[0]))
                .push_slice(push(key_head))
                .push_slice(push(key_tail))
                .push_opcode(OP_CAT)
                .into_script()
        }
    };
    claim
}

struct Session {
    manager: WalletManager<ManagedWalletInfo>,
    wallet_id: WalletId,
    coin: OutPoint,
}

impl Session {
    fn info(&mut self) -> &mut ManagedWalletInfo {
        self.manager.wallet_infos.get_mut(&self.wallet_id).expect("wallet")
    }

    fn offers_coin(&self) -> bool {
        let account = self.manager.wallet_infos[&self.wallet_id].first_bip44_managed_account();
        account.expect("BIP44 account").utxos.contains_key(&self.coin)
    }

    fn holds_record(&self, txid: &Txid) -> bool {
        let account = self.manager.wallet_infos[&self.wallet_id].first_bip44_managed_account();
        account.expect("BIP44 account").transactions().contains_key(txid)
    }
}

/// The claim seen pending, then its funding checked in a block where no event reports what the
/// check sweeps. The store keeps the records the check hands back, but learns of no removal.
async fn first_session(kind: Claim) -> (Session, Store, Transaction, Vec<Txid>) {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.take_persistence_receiver().expect("persistence receiver");
    let mut store = Store::default();
    let funding = create_tx_paying_to(&addr, 0xc1);
    let claim = claim_on(&manager, &wallet_id, &addr, &funding, kind).await;
    manager.process_mempool_transaction(&claim, None).await;
    store.mirror(&mut rx);
    assert!(store.holds(&claim.txid()), "the pending claim is stored");

    let block = block_of(&funding);
    let context = TransactionContext::InBlock(BlockInfo::new(
        FUNDING_HEIGHT,
        block.block_hash(),
        block.header.time,
    ));
    let result = manager.check_transaction_in_all_wallets(&funding, context, true, true).await;
    for record in
        result.per_wallet_new_records.values().chain(result.per_wallet_updated_records.values())
    {
        record.iter().for_each(|record| store.upsert(record));
    }
    store.mirror(&mut rx);
    assert!(store.holds(&funding.txid()), "the funding is stored");
    let swept = result.per_wallet_swept.get(&wallet_id).cloned().unwrap_or_default();
    let mut session = Session {
        manager,
        wallet_id,
        coin: OutPoint::new(funding.txid(), 0),
    };
    assert!(session.info().take_dismissal_changes().is_empty(), "no dismissal is reported");
    assert!(store.swept.is_empty() && store.abandoned.is_empty());
    (session, store, claim, swept)
}

/// Loads the wallet again from `store`: restores the dismissals, then replays the rows in
/// `order`, mirroring what the replay reports.
async fn reload(store: &mut Store, order: Replay, coin: OutPoint) -> Session {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    let mut rx = manager.take_persistence_receiver().expect("persistence receiver");
    let info = manager.wallet_infos.get_mut(&wallet_id).expect("wallet");
    info.restore_dismissed(store.abandoned.clone(), store.swept.clone());
    let mut rows = store.rows.clone();
    if let Replay::MinedFirst = order {
        rows.sort_by_key(|row| row.context.block_info().is_none());
    }
    let wallets = BTreeSet::from([wallet_id]);
    for row in rows {
        match row.context.block_info() {
            Some(info) => {
                let block = block_of(&row.transaction);
                assert_eq!(block.block_hash(), info.block_hash());
                manager
                    .process_block_for_wallets(&block, block.block_hash(), info.height(), &wallets)
                    .await;
            }
            None => {
                manager.process_mempool_transaction(&row.transaction, None).await;
            }
        }
        store.mirror(&mut rx);
    }
    Session {
        manager,
        wallet_id,
        coin,
    }
}

/// A claim the rule drops is dismissed as a sweep, but no event reports it, so its row stays
/// stored. Each load drops it again by the same rule, from either replay order, and offers the
/// coin; a peer relaying it again changes nothing.
#[test_case(Claim::Unsigned, Replay::AsStored; "unsigned, replayed as stored")]
#[test_case(Claim::Unsigned, Replay::MinedFirst; "unsigned, mined first")]
#[test_case(Claim::BadSignature, Replay::AsStored; "bad signature, replayed as stored")]
#[test_case(Claim::BadSignature, Replay::MinedFirst; "bad signature, mined first")]
#[test_case(Claim::Unparseable, Replay::AsStored; "unparseable, replayed as stored")]
#[test_case(Claim::Unparseable, Replay::MinedFirst; "unparseable, mined first")]
#[tokio::test]
async fn an_unreported_dropped_claim_is_dropped_again_on_each_load(kind: Claim, order: Replay) {
    let (mut session, mut store, claim, swept) = first_session(kind).await;
    let (txid, coin) = (claim.txid(), session.coin);
    assert_eq!(swept, vec![txid], "the claim is dropped");
    assert!(session.info().is_dismissed(&txid), "the claim is dismissed as a sweep");
    assert!(session.offers_coin());
    assert!(store.holds(&txid), "the dropped claim's row stays stored");

    for load in 1..=2 {
        let mut session = reload(&mut store, order, coin).await;
        assert!(session.offers_coin(), "load {load}: the coin is offered");
        assert!(!session.holds_record(&txid), "load {load}: the claim is not taken");
        assert_eq!(session.info().balance().total(), TX_AMOUNT, "load {load}");
        match order {
            Replay::AsStored => {
                assert!(!store.holds(&txid), "load {load}: the sweep event removes the row");
                assert_eq!(store.swept, vec![txid], "load {load}: the store keeps it dismissed");
            }
            Replay::MinedFirst => {
                assert!(store.removed.is_empty() && store.swept.is_empty(), "load {load}");
                assert!(store.holds(&txid), "load {load}: the row waits for the next load");
            }
        }

        session.manager.process_mempool_transaction(&claim, None).await;
        assert!(session.offers_coin(), "load {load}: a relayed claim changes nothing");
        assert!(!session.holds_record(&txid), "load {load}");
    }
}

/// A claim the rule can't prove unauthorized holds the coin as pending: it is never dropped or
/// dismissed, in the first session or on any load, from either replay order.
#[test_case(Claim::SignatureAndKeyThenNop, Replay::AsStored; "signature and key then OP_NOP, replayed as stored")]
#[test_case(Claim::SignatureAndKeyThenNop, Replay::MinedFirst; "signature and key then OP_NOP, mined first")]
#[test_case(Claim::KeyBuiltWithOpCat, Replay::AsStored; "key built with OP_CAT, replayed as stored")]
#[test_case(Claim::KeyBuiltWithOpCat, Replay::MinedFirst; "key built with OP_CAT, mined first")]
#[tokio::test]
async fn a_claim_that_is_not_push_only_holds_its_coin_on_each_load(kind: Claim, order: Replay) {
    let (mut session, mut store, claim, swept) = first_session(kind).await;
    let (txid, coin) = (claim.txid(), session.coin);
    assert!(swept.is_empty(), "the claim is kept");
    assert!(!session.info().is_dismissed(&txid));
    assert!(!session.offers_coin());
    assert!(session.holds_record(&txid));

    for load in 1..=2 {
        let mut session = reload(&mut store, order, coin).await;
        assert!(!session.offers_coin(), "load {load}: the claim holds the coin");
        assert!(session.holds_record(&txid), "load {load}: the claim is taken");
        assert!(!session.info().is_dismissed(&txid), "load {load}");
        assert!(session.info().take_dismissal_changes().is_empty(), "load {load}");
        assert_eq!(session.info().balance().total(), CLAIM_PAYS, "load {load}");
        assert!(store.removed.is_empty() && store.swept.is_empty(), "load {load}");
        let row = store.rows.iter().find(|row| row.txid == txid);
        assert!(
            row.is_some_and(|row| row.context == TransactionContext::Mempool),
            "load {load}: the claim stays stored as pending"
        );
    }
}
