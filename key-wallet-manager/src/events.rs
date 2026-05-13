//! Wallet events for notifying consumers of wallet state changes.
//!
//! Each variant is self-contained: it carries the transaction record(s) that
//! triggered it and the wallet's new balance after the change. Consumers can
//! persist the transaction(s) and balance atomically off a single event.

use std::collections::BTreeMap;
use std::fmt;

use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{PublicKey, Txid};
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// ECDSA public key for the derived address. Non-ECDSA pools
    /// (BLS / EdDSA) are skipped during projection.
    pub public_key: PublicKey,
}

impl DerivedAddress {
    /// Project a [`DerivedAddressInfo`] from key-wallet into a
    /// `DerivedAddress` event payload. Returns `None` for non-ECDSA pools
    /// (BLS / EdDSA) since the event field carries an ECDSA key. Those
    /// pools don't trigger gap-limit extension on Core transactions in
    /// practice, but skip rather than panic if they do. Drops are logged
    /// so a future change that wires gap-limit extension into a BLS /
    /// EdDSA pool surfaces in traces rather than silently orphaning UTXOs
    /// at the persister.
    pub(crate) fn from_info(derived: DerivedAddressInfo) -> Option<Self> {
        let account_type = derived.account_type;
        let pool_type = derived.pool_type;
        let index = derived.info.index;
        let public_key = match derived.info.public_key.as_ref() {
            None => {
                tracing::warn!(
                    ?account_type,
                    ?pool_type,
                    index,
                    "dropping derived address with no public key from event projection"
                );
                return None;
            }
            Some(PublicKeyType::ECDSA(bytes)) => match PublicKey::from_slice(bytes) {
                Ok(pk) => pk,
                Err(err) => {
                    // Producer (`generate_address_at_index`) always stores
                    // valid compressed keys, so a parse failure is a bug,
                    // not an expected drop.
                    tracing::warn!(
                        ?account_type,
                        ?pool_type,
                        index,
                        %err,
                        "dropping derived address: ECDSA public key failed to parse"
                    );
                    return None;
                }
            },
            Some(PublicKeyType::BLS(_)) | Some(PublicKeyType::EdDSA(_)) => {
                tracing::debug!(
                    ?account_type,
                    ?pool_type,
                    index,
                    "dropping non-ECDSA derived address from event projection \
                     (event field is ECDSA only)"
                );
                return None;
            }
        };
        Some(Self {
            account_type,
            pool_type,
            derivation_index: index,
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
        /// while processing this transaction, attributed to the same
        /// account as `record` (a tx that pays into multiple accounts
        /// of the same wallet emits one event per record, each scoped
        /// to its own account's derivations). Empty in the common case.
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
        /// `Some(chain_lock)` iff the wallet's finality boundary at
        /// processing time covers `height`, meaning every record in
        /// this event has a [`key_wallet::transaction_checking::TransactionContext::InChainLockedBlock`]
        /// context and the transactions are already finalized. The
        /// chainlock carried here is the proof that established the
        /// boundary, retained so consumers can persist the signing
        /// proof alongside the block. By construction
        /// `chain_lock.block_height >= height` whenever `Some`. The
        /// per-record `context` is the source of truth and will agree.
        chain_lock: Option<ChainLock>,
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
    /// Previously-recorded `InBlock` transactions were promoted to
    /// [`key_wallet::transaction_checking::TransactionContext::InChainLockedBlock`] because a chainlock now
    /// covers their height. Emitted by the wallet manager after the
    /// coordinator applies a chainlock. Carries only net-new
    /// promotions, grouped per account.
    ///
    /// Transactions born directly in a chainlocked block (block at
    /// height `<= last_applied_chain_lock.block_height` at processing
    /// time) are surfaced via [`WalletEvent::BlockProcessed`] with
    /// `chain_lock = Some(..)` and their records already in
    /// `InChainLockedBlock` context. They do not appear here, since no
    /// promotion took place.
    TransactionsChainlocked {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// The chainlock that drove this batch of promotions. Carries
        /// the signing proof (`block_height`, `block_hash`,
        /// `signature`) so consumers can persist it alongside the
        /// promotions. The wallet's `last_applied_chain_lock` is
        /// advanced to this chainlock (clamped forward by height).
        chain_lock: ChainLock,
        /// Per-account net-new finalized txids: records that flipped
        /// from `InBlock` to `InChainLockedBlock` in this promotion.
        /// Accounts with no net-new promotions are omitted. No balance
        /// is carried because a chainlock does not change UTXO state
        /// (only the certainty of the parent transaction).
        per_account: BTreeMap<AccountType, Vec<Txid>>,
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
            }
            | WalletEvent::TransactionsChainlocked {
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
                chain_lock,
                inserted,
                updated,
                matured,
                balance,
                account_balances,
                addresses_derived,
                ..
            } => {
                format!(
                    "BlockProcessed(height={}, chainlocked={}, inserted={}, updated={}, matured={}, balance={}, account_balances={}, derived={})",
                    height,
                    chain_lock.is_some(),
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
            WalletEvent::TransactionsChainlocked {
                chain_lock,
                per_account,
                ..
            } => {
                let total_txids: usize = per_account.values().map(|v| v.len()).sum();
                format!(
                    "TransactionsChainlocked(chainlock_height={}, accounts={}, finalized_txids={})",
                    chain_lock.block_height,
                    per_account.len(),
                    total_txids,
                )
            }
        }
    }
}

impl fmt::Display for WalletEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description())
    }
}

#[cfg(test)]
mod project_derived_addresses_tests {
    use super::*;
    use key_wallet::account::StandardAccountType;
    use key_wallet::bip32::{ChildNumber, DerivationPath};
    use key_wallet::managed_account::address_pool::AddressInfo;
    use std::collections::BTreeMap;

    /// Compressed encoding of the secp256k1 generator point (G).
    const TEST_PUBKEY_G: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    /// Compressed encoding of 2G. A second well-known on-curve point,
    /// used to distinguish two `DerivedAddressInfo` entries when testing
    /// dedup behavior. The point must be on-curve so the projection's
    /// `PublicKey::from_slice` parse succeeds.
    const TEST_PUBKEY_2G: [u8; 33] = [
        0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0,
        0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c,
        0x70, 0x9e, 0xe5,
    ];

    /// Build a stub `DerivedAddressInfo` for unit-testing the projection
    /// without spinning up a wallet. `alt_key` toggles between G and 2G
    /// so "first-seen wins" can be observed across duplicates.
    fn make_derived(
        account_type: AccountType,
        pool_type: AddressPoolType,
        index: u32,
        alt_key: bool,
    ) -> DerivedAddressInfo {
        // Always derive the address from `G` regardless of `alt_key`.
        // Tests don't depend on address↔pubkey consistency, only on
        // dedup keys and pubkey round-trip.
        let pubkey =
            dashcore::PublicKey::from_slice(&TEST_PUBKEY_G).expect("generator point is valid");
        let address = dashcore::Address::p2pkh(&pubkey, key_wallet::Network::Testnet);
        let script_pubkey = address.script_pubkey();
        let path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ]);
        let pubkey_bytes = if alt_key {
            TEST_PUBKEY_2G.to_vec()
        } else {
            TEST_PUBKEY_G.to_vec()
        };
        DerivedAddressInfo {
            account_type,
            pool_type,
            info: AddressInfo {
                address,
                script_pubkey,
                public_key: Some(PublicKeyType::ECDSA(pubkey_bytes)),
                index,
                path,
                used: false,
                generated_at: 0,
                used_at: None,
                tx_count: 0,
                total_received: 0,
                total_sent: 0,
                balance: 0,
                label: None,
                metadata: BTreeMap::new(),
            },
        }
    }

    fn standard_account_0() -> AccountType {
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        }
    }

    /// Two `DerivedAddressInfo` entries with the same
    /// `(account_type, pool_type, index)` must collapse to one
    /// `DerivedAddress`. First-seen wins, so the surviving entry's
    /// `public_key` matches the first input — this guards against a
    /// regression that swaps to last-wins or drops the dedup entirely.
    #[test]
    fn project_dedups_overlapping_keys() {
        let acct = standard_account_0();
        let first = make_derived(acct, AddressPoolType::External, 5, false);
        let second = make_derived(acct, AddressPoolType::External, 5, true);

        let projected = project_derived_addresses(vec![first, second]);
        assert_eq!(projected.len(), 1, "duplicate (account, pool, index) must dedup to one entry");
        assert_eq!(projected[0].account_type, acct);
        assert_eq!(projected[0].pool_type, AddressPoolType::External);
        assert_eq!(projected[0].derivation_index, 5);
        let expected = PublicKey::from_slice(&TEST_PUBKEY_G).expect("G is valid");
        assert_eq!(projected[0].public_key, expected);
    }

    /// Different indices on the same pool must NOT dedup.
    #[test]
    fn project_keeps_distinct_indices_on_same_pool() {
        let acct = standard_account_0();
        let infos = vec![
            make_derived(acct, AddressPoolType::External, 5, false),
            make_derived(acct, AddressPoolType::External, 6, false),
            make_derived(acct, AddressPoolType::External, 7, false),
        ];
        let projected = project_derived_addresses(infos);
        assert_eq!(projected.len(), 3);
        let mut indices: Vec<u32> = projected.iter().map(|d| d.derivation_index).collect();
        indices.sort_unstable();
        assert_eq!(indices, vec![5, 6, 7]);
    }

    /// Same index, different pool types must NOT dedup — the dedup key
    /// includes `pool_type`.
    #[test]
    fn project_keeps_same_index_across_different_pools() {
        let acct = standard_account_0();
        let projected = project_derived_addresses(vec![
            make_derived(acct, AddressPoolType::External, 5, false),
            make_derived(acct, AddressPoolType::Internal, 5, false),
        ]);
        assert_eq!(projected.len(), 2);
        let pools: std::collections::BTreeSet<AddressPoolType> =
            projected.iter().map(|d| d.pool_type).collect();
        assert!(pools.contains(&AddressPoolType::External));
        assert!(pools.contains(&AddressPoolType::Internal));
    }

    /// `from_info` (and therefore `project_derived_addresses`) must drop
    /// entries that don't carry an ECDSA pubkey. A surviving result of
    /// length 0 is the contract — no panic.
    #[test]
    fn project_drops_entry_with_missing_pubkey() {
        let mut info = make_derived(standard_account_0(), AddressPoolType::External, 5, false);
        info.info.public_key = None;
        let projected = project_derived_addresses(vec![info]);
        assert!(projected.is_empty());
    }

    /// 33 bytes that don't parse as a valid compressed secp256k1 point
    /// must drop rather than panic.
    #[test]
    fn project_drops_entry_with_invalid_curve_point() {
        let mut info = make_derived(standard_account_0(), AddressPoolType::External, 5, false);
        info.info.public_key = Some(PublicKeyType::ECDSA(vec![0xff; 33]));
        let projected = project_derived_addresses(vec![info]);
        assert!(projected.is_empty());
    }
}
