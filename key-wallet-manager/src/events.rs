//! Wallet events for notifying consumers of wallet state changes.
//!
//! Each variant is self-contained: it carries the transaction record(s) that
//! triggered it and the wallet's new balance after the change. Consumers can
//! persist the transaction(s) and balance atomically off a single event.

use std::collections::BTreeMap;

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::Txid;
use key_wallet::account::AccountType;
use key_wallet::managed_account::address_pool::{AddressPoolType, PublicKeyType};
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::transaction_checking::DerivedAddressInfo;
use key_wallet::WalletCoreBalance;

use crate::WalletId;

/// One address derived as a side effect of gap-limit maintenance during
/// transaction processing.
///
/// Emitted on [`WalletEvent::TransactionDetected`] /
/// [`WalletEvent::BlockProcessed`] so persisters can mirror the on-disk
/// address pool transactionally with the tx/block records that triggered
/// the derivation. Keeping the derivation here (rather than as a
/// stand-alone event) is what lets consumers store
/// `Wallet → Account → CoreAddress → Txo` without breaking the
/// `CoreAddress` link for UTXOs landing on freshly derived addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAddress {
    /// The account that derived this address.
    pub account_type: AccountType,
    /// Which pool of the account the address belongs to (External /
    /// Internal / Absent / AbsentHardened).
    pub pool_type: AddressPoolType,
    /// Derivation index within the pool. Combined with `account_type`
    /// (which carries any account-level indices like the Dashpay
    /// `user_identity_id` / `friend_identity_id`) and `pool_type`, this
    /// fully determines the derivation path — consumers that need a
    /// rendered path can recompute it deterministically rather than
    /// shipping a redundant string on every event.
    pub derivation_index: u32,
    /// The derived address.
    pub address: dashcore::Address,
    /// Compressed ECDSA public key (33 bytes). Non-ECDSA pools
    /// (BLS / EdDSA) are skipped during projection.
    pub public_key: [u8; 33],
}

impl DerivedAddress {
    /// Project a [`DerivedAddressInfo`] from key-wallet into a
    /// `DerivedAddress` event payload. Returns `None` for non-ECDSA pools
    /// (BLS / EdDSA) since the event field carries a 33-byte compressed
    /// key — those pools don't trigger gap-limit extension on Core
    /// transactions in practice, but skip rather than panic if they do.
    pub fn from_info(derived: DerivedAddressInfo) -> Option<Self> {
        let public_key = match derived.info.public_key.as_ref()? {
            PublicKeyType::ECDSA(bytes) => {
                if bytes.len() != 33 {
                    return None;
                }
                let mut arr = [0u8; 33];
                arr.copy_from_slice(bytes);
                arr
            }
            PublicKeyType::BLS(_) | PublicKeyType::EdDSA(_) => return None,
        };
        Some(Self {
            account_type: derived.account_type,
            pool_type: derived.pool_type,
            derivation_index: derived.info.index,
            address: derived.info.address,
            public_key,
        })
    }
}

/// Project an iterator of [`DerivedAddressInfo`] entries into a
/// deduplicated [`DerivedAddress`] vec.
///
/// Dedup keys on `(account_type, pool_type, derivation_index)` so that two
/// records in the same block both pushing the same gap-limit boundary
/// collapse to a single entry. Non-ECDSA pools are silently dropped (see
/// [`DerivedAddress::from_info`]).
pub(crate) fn project_derived_addresses<I>(infos: I) -> Vec<DerivedAddress>
where
    I: IntoIterator<Item = DerivedAddressInfo>,
{
    let mut out: Vec<DerivedAddress> = Vec::new();
    let mut seen: std::collections::HashSet<(AccountType, AddressPoolType, u32)> =
        std::collections::HashSet::new();
    for info in infos {
        let key = (info.account_type, info.pool_type, info.info.index);
        if !seen.insert(key) {
            continue;
        }
        if let Some(d) = DerivedAddress::from_info(info) {
            out.push(d);
        }
    }
    out
}

/// Diff `current` against `prior` and return only the entries whose
/// balance changed (including ones missing from `prior`). Intended for
/// pairing two snapshots taken via
/// [`WalletInfoInterface::account_balances`] before and after a
/// mutation.
pub(crate) fn diff_account_balances(
    prior: &BTreeMap<AccountType, WalletCoreBalance>,
    current: &BTreeMap<AccountType, WalletCoreBalance>,
) -> BTreeMap<AccountType, WalletCoreBalance> {
    let mut changed = BTreeMap::new();
    for (account_type, new_balance) in current {
        match prior.get(account_type) {
            Some(prior_balance) if prior_balance == new_balance => {}
            _ => {
                changed.insert(*account_type, *new_balance);
            }
        }
    }
    changed
}

/// Render the changed-account balance map as a short bracketed list
/// suitable for log lines, e.g. `[Standard{idx:0,BIP44}=>1.5 DASH]`.
fn format_account_balances(map: &BTreeMap<AccountType, WalletCoreBalance>) -> String {
    if map.is_empty() {
        return "[]".to_string();
    }
    let parts: Vec<String> = map
        .iter()
        .map(|(account_type, balance)| {
            format!("{}=>{}", account_type, dashcore::Amount::from_sat(balance.total()))
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

/// Events emitted by the wallet manager.
///
/// Each event represents a meaningful wallet state change. Events that
/// modify balance carry the wallet's balance *after* the change so
/// consumers can persist the record(s) and balance atomically.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// First time the wallet sees an off-chain wallet-relevant transaction
    /// (mempool, or directly via an InstantSend lock — in that case
    /// `record.context` is `InstantSend(..)`).
    TransactionDetected {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// The full transaction record with all details.
        record: Box<TransactionRecord>,
        /// Wallet balance after the transaction was recorded.
        balance: WalletCoreBalance,
        /// Post-event balance **snapshots** for accounts whose balance
        /// changed as a result of this event. Each value is the account's
        /// full balance after the change — not a delta. Accounts whose
        /// balance was unchanged are omitted to keep the payload small
        /// (most transactions touch only 1–2 accounts).
        account_balances: BTreeMap<AccountType, WalletCoreBalance>,
        /// Addresses derived as a side effect of gap-limit maintenance
        /// while processing this transaction. Empty in the common case.
        /// Persisters that mirror the address pool to disk should write
        /// these rows transactionally with `record` so UTXOs landing on
        /// them retain a parent address row.
        addresses_derived: Vec<DerivedAddress>,
    },
    /// An InstantSend lock was applied to a previously-seen off-chain
    /// wallet-relevant transaction.
    TransactionInstantLocked {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Transaction ID.
        txid: Txid,
        /// The InstantSend lock now applied to the transaction.
        instant_lock: InstantLock,
        /// Wallet balance after the status change.
        balance: WalletCoreBalance,
        /// Post-event balance **snapshots** for accounts whose balance
        /// changed as a result of this event. Each value is the account's
        /// full balance after the change — not a delta.
        account_balances: BTreeMap<AccountType, WalletCoreBalance>,
    },
    /// A block was processed for a wallet. Carries records bucketed by what
    /// happened to them in this block, plus the post-block balance.
    /// `inserted` is records first stored in this block, `updated` is
    /// previously-known records that just confirmed, `matured` is older
    /// coinbase records that crossed the maturity threshold as the scanned
    /// height advanced.
    BlockProcessed {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Height of the block that was processed.
        height: CoreBlockHeight,
        /// Records first stored for this wallet in this block.
        inserted: Vec<TransactionRecord>,
        /// Previously-known records confirmed by this block.
        updated: Vec<TransactionRecord>,
        /// Older coinbase records whose maturity threshold was crossed by
        /// this height advance.
        matured: Vec<TransactionRecord>,
        /// Wallet balance after the block was processed.
        balance: WalletCoreBalance,
        /// Post-event balance **snapshots** for accounts whose balance
        /// changed during processing of this block. Each value is the
        /// account's full balance after the change — not a delta. Accounts
        /// whose balance was unchanged are omitted.
        account_balances: BTreeMap<AccountType, WalletCoreBalance>,
        /// Addresses derived as a side effect of gap-limit maintenance
        /// across every record in the block, deduplicated by
        /// `(account_type, pool_type, derivation_index)`. Empty in the
        /// common case. Persisters should write these rows
        /// transactionally with the inserted/updated records so UTXOs
        /// landing on them retain a parent address row.
        addresses_derived: Vec<DerivedAddress>,
    },
    /// The wallet's scan cursor advanced because the filter pipeline
    /// committed a batch covering blocks up to `height`. No records or
    /// balance — consumers persist this as a checkpoint atomically with
    /// any records/balance from prior `BlockProcessed` events in the batch.
    SyncHeightAdvanced {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// New scanned height for the wallet.
        height: CoreBlockHeight,
    },
}

impl WalletEvent {
    /// ID of the wallet this event pertains to.
    pub fn wallet_id(&self) -> WalletId {
        match self {
            WalletEvent::TransactionDetected {
                wallet_id,
                ..
            }
            | WalletEvent::TransactionInstantLocked {
                wallet_id,
                ..
            }
            | WalletEvent::BlockProcessed {
                wallet_id,
                ..
            }
            | WalletEvent::SyncHeightAdvanced {
                wallet_id,
                ..
            } => *wallet_id,
        }
    }

    /// Short description for logging.
    pub fn description(&self) -> String {
        match self {
            WalletEvent::TransactionDetected {
                record,
                balance,
                account_balances,
                addresses_derived,
                ..
            } => {
                format!(
                    "TransactionDetected(txid={}, context={}, balance={}, account_balances={}, derived={})",
                    record.txid,
                    record.context,
                    balance,
                    format_account_balances(account_balances),
                    addresses_derived.len(),
                )
            }
            WalletEvent::TransactionInstantLocked {
                txid,
                balance,
                account_balances,
                ..
            } => {
                format!(
                    "TransactionInstantLocked(txid={}, balance={}, account_balances={})",
                    txid,
                    balance,
                    format_account_balances(account_balances),
                )
            }
            WalletEvent::BlockProcessed {
                height,
                inserted,
                updated,
                matured,
                balance,
                account_balances,
                addresses_derived,
                ..
            } => {
                format!(
                    "BlockProcessed(height={}, inserted={}, updated={}, matured={}, balance={}, account_balances={}, derived={})",
                    height,
                    inserted.len(),
                    updated.len(),
                    matured.len(),
                    balance,
                    format_account_balances(account_balances),
                    addresses_derived.len(),
                )
            }
            WalletEvent::SyncHeightAdvanced {
                height,
                ..
            } => {
                format!("SyncHeightAdvanced(height={})", height)
            }
        }
    }
}
