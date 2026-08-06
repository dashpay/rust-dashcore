//! Managed wallet information
//!
//! This module contains the mutable metadata and information about a wallet
//! that is managed separately from the core wallet structure.

pub mod asset_lock_builder;
pub mod coin_selection;
pub mod fee;
pub mod helpers;
pub mod managed_account_operations;
pub mod managed_accounts;
pub mod transaction_builder;
pub mod transaction_building;
pub mod wallet_info_interface;

pub use managed_account_operations::ManagedAccountOperations;

use super::balance::WalletCoreBalance;
use super::metadata::WalletMetadata;
use crate::account::ManagedAccountCollection;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::{Network, Wallet};
use dashcore::blockdata::transaction::OutPoint;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Transaction, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Information about a managed wallet
///
/// This struct contains the mutable metadata and descriptive information
/// about a wallet, kept separate from the core wallet structure to maintain
/// immutability of the wallet itself.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedWalletInfo {
    /// Network this wallet info is associated with
    pub network: Network,
    /// Unique wallet ID (SHA256 hash of root public key) - should match the Wallet's wallet_id
    pub wallet_id: [u8; 32],
    /// Wallet name
    pub name: Option<String>,
    /// Wallet description
    pub description: Option<String>,
    /// Wallet metadata
    pub metadata: WalletMetadata,
    /// All managed accounts.
    ///
    /// Prefer the `add_managed_*` methods to add accounts to a live wallet:
    /// they rewind the sync checkpoint so the new account's coins get filter
    /// coverage. Inserting directly here without that rewind can reopen
    /// dashpay/rust-dashcore#649 for the added account.
    pub accounts: ManagedAccountCollection,
    /// Cached wallet core balance - should be updated when accounts change
    pub balance: WalletCoreBalance,
    /// Transactions that have received an InstantSend lock.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) instant_send_locks: HashSet<Txid>,
    /// Outpoints observed spent by transactions seen in a processed block,
    /// mapped to the height of the block that spent them.
    ///
    /// This is the wallet-level, classification-independent record of "this
    /// coin was consumed on-chain" used to keep out-of-order rescan delivery
    /// from resurrecting a spent UTXO (dashpay/rust-dashcore#649). A spend can
    /// be delivered before the transaction that funded the coin it spends, and
    /// it may be routed away from — or fail to match — the account that owns
    /// the coin; recording every block-observed spend here, independent of the
    /// spending transaction's classification, lets the funding-side insert be
    /// reconciled away whichever order the two blocks arrive in.
    ///
    /// Membership is bounded-permanent: an entry is retained until its spend
    /// height is provably final, then evicted by
    /// [`Self::prune_finalized_observed_spends`]. Until then it is only ever
    /// added, never removed, and reorg rollback does NOT retract it — treating a
    /// coin as spendable again after a spend was observed is the failure this
    /// set exists to prevent. Only spends seen in a block (`InBlock` /
    /// `InChainLockedBlock`) are recorded; mempool-context spends are never
    /// recorded, so an unconfirmed spend can never wrongly invalidate a coin.
    ///
    /// # Bounded permanence
    ///
    /// An entry `(outpoint, height)` is removed only when
    /// `height <= min(last_applied_chain_lock.block_height, synced_height)` —
    /// the finality boundary. At that boundary the spend is chain-locked (it can
    /// never be reorged out) and any funding transaction for the outpoint has
    /// been delivered (BIP158 filters have no false negatives below
    /// `synced_height`) and finalized (promoted into `finalized_txids`, or kept
    /// as a chainlocked record), so every redelivery path short-circuits before
    /// a coin could be re-inserted — in both `keep-finalized-transactions`
    /// configurations and across a reload. No other removal path may be added
    /// without a deliberate decision.
    ///
    /// Eviction is event-driven (chainlock application, sync-checkpoint commit),
    /// never age- or recency-based: during an out-of-order rescan `synced_height`
    /// is low, so nothing is pruned in exactly the window where #649 ordering
    /// hazards live, and the set self-repopulates on any replay since
    /// `record_observed_spends` runs unconditionally per checked tx. A naive
    /// age/LRU eviction would instead evict the cold entries whose funding tx may
    /// still arrive out of order, reopening #649 for that coin. Steady-state size
    /// is the above-boundary window only — roughly one block's inputs on a
    /// healthy chain. A defensive cap on the deserialized entry count (see the
    /// serde adapter) guards against a corrupted or hostile wallet file forcing
    /// an unbounded allocation on load.
    ///
    /// # Persistence
    ///
    /// The field is serde-serializable so it is preserved wherever a
    /// `ManagedWalletInfo` is serialized. Its real value, though, is
    /// order-independent correctness *within a single continuous processing run*
    /// — which is what the observed #649 symptom needs, since a cold rescan is a
    /// full fresh replay in one process. `#[serde(default)]` keeps snapshots
    /// written before this field existed loadable, seeding an empty set (a
    /// pre-fix wallet gets no retroactive backfill; only spends observed after
    /// the field exists are protected). That default applies only to
    /// self-describing formats (e.g. JSON) that can detect the absent field;
    /// non-self-describing serde formats (bincode-serde, `platform_value::Value`)
    /// cannot default a missing field, so consumers using those need a versioned
    /// migration to load pre-field snapshots.
    #[cfg_attr(feature = "serde", serde(default, with = "observed_spent_outpoints_serde"))]
    pub(crate) observed_spent_outpoints: BTreeMap<OutPoint, CoreBlockHeight>,
    /// Generation counter for the wallet's account set, bumped every time an
    /// account is added to a live wallet (see
    /// [`Self::rewind_sync_checkpoint_for_new_account`]).
    ///
    /// Filter-sync layers snapshot this when they scan a range for the wallet
    /// and compare at commit time: a batch scanned under an older generation
    /// must not certify coverage (`synced_height`) for the current account
    /// set, because the added account's scripts were not part of the scan
    /// (dashpay/rust-dashcore#649). A height-only contiguity check cannot
    /// detect this when the account-add rewind lands inside the batch's range
    /// — or moves nothing at all because the checkpoint already sat at the
    /// birth floor.
    ///
    /// In-memory only (`serde(skip)`): the snapshots comparing against it are
    /// in-flight scan state that does not survive a restart either, and a
    /// fresh process restarts both sides at 0.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) account_generation: u64,
}

/// Serde adapter for [`ManagedWalletInfo::observed_spent_outpoints`] that
/// encodes the map as a sequence of `(OutPoint, height)` pairs rather than as a
/// map.
///
/// This is for format-agnosticism, not a JSON limitation: `OutPoint` serializes
/// to a string in human-readable formats (so it is a fine `serde_json` object
/// key) but to a struct `{ txid, vout }` in non-human-readable / strict-key
/// encoders (bincode's serde layer, `platform_value::Value`), where a struct
/// cannot be a map key. Encoding the map as a sequence of key/value pairs
/// round-trips identically across every serde format.
///
/// Deserialization applies a defensive cap ([`MAX_OBSERVED_SPENT_OUTPOINTS`]):
/// a corrupted or hostile wallet file declaring an absurd number of entries is
/// rejected rather than driving an unbounded allocation.
#[cfg(feature = "serde")]
mod observed_spent_outpoints_serde {
    use super::{BTreeMap, CoreBlockHeight, OutPoint, MAX_OBSERVED_SPENT_OUTPOINTS};
    use core::fmt;
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S>(
        map: &BTreeMap<OutPoint, CoreBlockHeight>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(map.len()))?;
        for entry in map {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<OutPoint, CoreBlockHeight>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PairsVisitor;

        impl<'de> Visitor<'de> for PairsVisitor {
            type Value = BTreeMap<OutPoint, CoreBlockHeight>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a sequence of (OutPoint, height) pairs")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Stream elements one at a time and cap the count so an
                // oversized declared length cannot force an unbounded
                // allocation before we notice.
                let mut map = BTreeMap::new();
                while let Some((outpoint, height)) =
                    seq.next_element::<(OutPoint, CoreBlockHeight)>()?
                {
                    if map.len() >= MAX_OBSERVED_SPENT_OUTPOINTS {
                        return Err(A::Error::custom(format!(
                            "observed_spent_outpoints exceeds the maximum of {MAX_OBSERVED_SPENT_OUTPOINTS} entries"
                        )));
                    }
                    map.insert(outpoint, height);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_seq(PairsVisitor)
    }
}

/// Defensive upper bound on the number of [`ManagedWalletInfo::observed_spent_outpoints`]
/// entries accepted when deserializing a wallet.
///
/// Chosen far above any plausible legitimate size (matched-block spend activity
/// over a realistic rescan — a busy matched block contributes on the order of
/// 10⁴ inputs, and steady state holds only the above-finality-boundary window)
/// so it only ever rejects a corrupted or hostile wallet file, never a real
/// one. At ~40 bytes per entry this caps the load-time allocation for this
/// field at a few tens of MB.
#[cfg(feature = "serde")]
const MAX_OBSERVED_SPENT_OUTPOINTS: usize = 1_000_000;

impl ManagedWalletInfo {
    /// Create new managed wallet info with network and wallet ID
    pub fn new(network: Network, wallet_id: [u8; 32]) -> Self {
        Self {
            network,
            wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::new(),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
            observed_spent_outpoints: BTreeMap::new(),
            account_generation: 0,
        }
    }

    /// Create managed wallet info with network, wallet ID and name
    pub fn with_name(network: Network, wallet_id: [u8; 32], name: String) -> Self {
        Self {
            network,
            wallet_id,
            name: Some(name),
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::new(),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
            observed_spent_outpoints: BTreeMap::new(),
            account_generation: 0,
        }
    }

    /// Create managed wallet info from a Wallet
    /// Create managed wallet info from a Wallet, seeding the sync checkpoint at `birth_height`.
    ///
    /// Sets `birth_height` and seeds both `synced_height` and `last_processed_height` to
    /// `birth_height.saturating_sub(1)` so that the next block to scan is `birth_height`.
    pub fn from_wallet(wallet: &super::super::Wallet, birth_height: CoreBlockHeight) -> Self {
        let initial_height = birth_height.saturating_sub(1);
        Self {
            network: wallet.network,
            wallet_id: wallet.wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata {
                birth_height,
                synced_height: initial_height,
                last_processed_height: initial_height,
                ..WalletMetadata::default()
            },
            accounts: ManagedAccountCollection::from_account_collection(&wallet.accounts),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
            observed_spent_outpoints: BTreeMap::new(),
            account_generation: 0,
        }
    }

    /// Create managed wallet info from a Wallet with a name, seeding the sync checkpoint
    /// at `birth_height` (see `from_wallet` for details).
    pub fn from_wallet_with_name(
        wallet: &super::super::Wallet,
        name: String,
        birth_height: CoreBlockHeight,
    ) -> Self {
        let mut info = Self::from_wallet(wallet, birth_height);
        info.name = Some(name);
        info
    }

    /// Get the network for this wallet info
    pub fn network(&self) -> Network {
        self.network
    }

    /// Read-only access to the InstantSend lock txid set.
    ///
    /// Exposes `instant_send_locks` (a `pub(crate)` field marked
    /// `serde(skip)`) so external diagnostic surfaces (e.g. the iOS
    /// memory explorer) can list the txids that have received an
    /// IS-lock without bypassing the encapsulation that keeps mutation
    /// inside this crate.
    pub fn instant_send_locks(&self) -> &HashSet<Txid> {
        &self.instant_send_locks
    }

    /// Read-only access to the wallet-level observed-spent outpoint set
    /// (dashpay/rust-dashcore#649), mapping each on-chain-spent outpoint to the
    /// height of the block that spent it. See the field's doc comment for the
    /// invariants; exposed for diagnostics and tests.
    pub fn observed_spent_outpoints(&self) -> &BTreeMap<OutPoint, CoreBlockHeight> {
        &self.observed_spent_outpoints
    }

    /// Record every outpoint `tx` spends into [`Self::observed_spent_outpoints`]
    /// at `height`. Insert-only bookkeeping — it never touches account UTXO sets,
    /// so it is safe to call before `record_transaction` builds a spend's
    /// `input_details` from the still-present funding UTXO.
    ///
    /// A coinbase spends nothing real (its single input is the null prevout), so
    /// it is skipped. Call this only for block-context transactions
    /// (`InBlock` / `InChainLockedBlock`); mempool spends must never be recorded
    /// (see the field doc — an unconfirmed spend may never be mined).
    ///
    /// Returns whether the map actually changed (a new outpoint, or an existing
    /// one re-observed at a different height). The map is persisted wallet
    /// state, so callers must surface a `true` as a state modification —
    /// otherwise a consumer that persists only on reported modifications could
    /// drop the recorded spend across a restart and reopen #649 for it.
    pub(crate) fn record_observed_spends(
        &mut self,
        tx: &Transaction,
        height: CoreBlockHeight,
    ) -> bool {
        if tx.is_coin_base() {
            return false;
        }
        let mut changed = false;
        for input in &tx.input {
            changed |=
                self.observed_spent_outpoints.insert(input.previous_output, height) != Some(height);
        }
        changed
    }

    /// Evict [`Self::observed_spent_outpoints`] entries at or below the finality
    /// boundary `min(last_applied_chain_lock.block_height, synced_height)`.
    ///
    /// An entry `(outpoint, height)` with `height <= boundary` is safe to
    /// forget: the spend at that height is chain-locked (never reorged out) and
    /// any funding transaction for the outpoint has been delivered and finalized,
    /// so no redelivery path can re-insert the coin (dashpay/rust-dashcore#649).
    /// No-op until a chainlock has been applied (`last_applied_chain_lock` is
    /// `None`) — without a finality boundary nothing can be proven final.
    ///
    /// Called on chainlock application and sync-checkpoint commit; not age- or
    /// recency-based.
    pub(crate) fn prune_finalized_observed_spends(&mut self) {
        let Some(chain_lock) = self.metadata.last_applied_chain_lock.as_ref() else {
            return;
        };
        let boundary = chain_lock.block_height.min(self.metadata.synced_height);
        self.observed_spent_outpoints.retain(|_, height| *height > boundary);
    }

    /// Invalidate the wallet's sync certificate when an account is added.
    ///
    /// `synced_height` certifies "every filter at or below this height was
    /// matched against the wallet's scripts" — but only for the account set that
    /// existed while those filters were scanned. A newly added account has had no
    /// filter coverage, so the certificate no longer holds for the current
    /// account set, and [`Self::prune_finalized_observed_spends`] must not
    /// consume it (dashpay/rust-dashcore#649). Rewinding `synced_height` to just
    /// below wallet birth collapses the prune boundary and makes the sync layer
    /// detect the wallet as behind and backfill from birth (the dash-spv filter
    /// tick). A wallet still in initial sync (`synced_height` already at or below
    /// the floor) is left untouched; `birth_height == 0` saturates safely.
    ///
    /// `last_processed_height` and `last_applied_chain_lock` are intentionally
    /// left as-is: they are chain facts, not coverage facts, and keeping the
    /// chainlock is what lets the backfilled history arrive born-chainlocked.
    fn rewind_sync_checkpoint_for_new_account(&mut self) {
        let floor = self.metadata.birth_height.saturating_sub(1);
        self.metadata.synced_height = self.metadata.synced_height.min(floor);
        // Bump unconditionally — even when the checkpoint was already at or
        // below the floor and did not move. An in-flight filter scan snapshot
        // taken before this add did not include the new account's scripts, and
        // the generation mismatch is the only signal a commit-time check has
        // when the rewind is height-invisible (dashpay/rust-dashcore#649).
        self.account_generation += 1;
    }

    /// Current generation of the wallet's account set; see the
    /// [`Self::account_generation`] field doc. Bumped on every account add.
    pub fn account_generation(&self) -> u64 {
        self.account_generation
    }

    pub fn next_change_address(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Option<Address> {
        let collection = self.accounts_mut();

        let address = match account_type_pref {
            AccountTypePreference::BIP44 => {
                let managed_account = collection.standard_bip44_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip44_account(account_index)?;

                let address = managed_account
                    .next_change_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::BIP32 => {
                let managed_account = collection.standard_bip32_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip32_account(account_index)?;

                let address = managed_account
                    .next_change_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::CoinJoin => {
                debug_assert!(false, "CoinJoin accounts are spend-only in our current use cases");
                None
            }
        };

        address
    }

    pub fn next_receive_address(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Option<Address> {
        let collection = self.accounts_mut();

        let address = match account_type_pref {
            AccountTypePreference::BIP44 => {
                let managed_account = collection.standard_bip44_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip44_account(account_index)?;

                let address = managed_account
                    .next_receive_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::BIP32 => {
                let managed_account = collection.standard_bip32_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip32_account(account_index)?;

                let address = managed_account
                    .next_receive_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::CoinJoin => {
                debug_assert!(false, "CoinJoin accounts are spend-only in our current use cases");
                None
            }
        };

        address
    }
}

/// Re-export types from account module for convenience
pub use crate::account::TransactionRecord;
pub use crate::utxo::Utxo;
