//! Wallet events for notifying consumers of wallet state changes.
//!
//! Each variant is self-contained: it carries the transaction record(s) that
//! triggered it and the wallet's new balance after the change. Consumers can
//! persist the transaction(s) and balance atomically off a single event.

use std::collections::BTreeMap;
use std::fmt;

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
    /// Drops are logged so a future change that wires gap-limit extension
    /// into a BLS / EdDSA pool surfaces in traces rather than silently
    /// orphaning UTXOs at the persister.
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
            Some(PublicKeyType::ECDSA(bytes)) => {
                if bytes.len() != 33 {
                    // Producer (`generate_address_at_index`) always stores
                    // 33-byte compressed keys, so a length mismatch is a
                    // bug, not an expected drop.
                    tracing::warn!(
                        ?account_type,
                        ?pool_type,
                        index,
                        len = bytes.len(),
                        "dropping derived address: ECDSA public key is not 33 bytes"
                    );
                    return None;
                }
                let mut arr = [0u8; 33];
                arr.copy_from_slice(bytes);
                arr
            }
            Some(PublicKeyType::BLS(_)) | Some(PublicKeyType::EdDSA(_)) => {
                tracing::debug!(
                    ?account_type,
                    ?pool_type,
                    index,
                    "dropping non-ECDSA derived address from event projection \
                     (event field is 33-byte compressed ECDSA only)"
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

    /// Compressed encoding of the secp256k1 generator point — a known
    /// on-curve 33-byte value `dashcore::PublicKey::from_slice` accepts.
    /// Tests don't care which key it is; they care that projection
    /// preserves the bytes round-trip.
    const TEST_PUBKEY_G: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    /// Build a stub `DerivedAddressInfo` for unit-testing the projection
    /// without spinning up a wallet. `tag` differentiates the
    /// `public_key` so "first-seen wins" can be observed across
    /// duplicates; pass `None` to use the default valid key.
    fn make_derived(
        account_type: AccountType,
        pool_type: AddressPoolType,
        index: u32,
        tag: Option<u8>,
    ) -> DerivedAddressInfo {
        // Take a real compressed pubkey and tweak only the `public_key`
        // bytes via `tag` (which the projection passes through verbatim).
        // We don't actually re-derive the address from the tagged bytes —
        // tests don't depend on address↔pubkey consistency, only on
        // dedup keys and pubkey round-trip.
        let pubkey =
            dashcore::PublicKey::from_slice(&TEST_PUBKEY_G).expect("generator point is valid");
        let address = dashcore::Address::p2pkh(&pubkey, key_wallet::Network::Testnet);
        let script_pubkey = address.script_pubkey();
        let path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ]);
        let mut pubkey_bytes = TEST_PUBKEY_G.to_vec();
        if let Some(t) = tag {
            // Tag a non-prefix byte so `[u8; 33]` round-trip is observable
            // without affecting the leading `0x02` compressed marker.
            pubkey_bytes[32] = t;
        }
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
        let first = make_derived(acct, AddressPoolType::External, 5, Some(0xaa));
        let first_bytes = match first.info.public_key.as_ref().expect("ECDSA pubkey") {
            PublicKeyType::ECDSA(b) => b.clone(),
            _ => unreachable!(),
        };
        let second = make_derived(acct, AddressPoolType::External, 5, Some(0xbb));

        let projected = project_derived_addresses(vec![first, second]);
        assert_eq!(projected.len(), 1, "duplicate (account, pool, index) must dedup to one entry");
        assert_eq!(projected[0].account_type, acct);
        assert_eq!(projected[0].pool_type, AddressPoolType::External);
        assert_eq!(projected[0].derivation_index, 5);
        // First-seen wins: surviving pubkey matches `first`, not `second`.
        assert_eq!(&projected[0].public_key[..], first_bytes.as_slice());
        assert_eq!(projected[0].public_key[32], 0xaa);
    }

    /// Different indices on the same pool must NOT dedup.
    #[test]
    fn project_keeps_distinct_indices_on_same_pool() {
        let acct = standard_account_0();
        let infos = vec![
            make_derived(acct, AddressPoolType::External, 5, None),
            make_derived(acct, AddressPoolType::External, 6, None),
            make_derived(acct, AddressPoolType::External, 7, None),
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
            make_derived(acct, AddressPoolType::External, 5, None),
            make_derived(acct, AddressPoolType::Internal, 5, None),
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
        let mut info = make_derived(standard_account_0(), AddressPoolType::External, 5, None);
        info.info.public_key = None;
        let projected = project_derived_addresses(vec![info]);
        assert!(projected.is_empty());
    }
}
