//! Helper methods for ManagedWalletInfo

use super::ManagedWalletInfo;
use crate::account::account_collection::PlatformPaymentAccountKey;
use crate::account::ManagedCoreFundsAccount;
use crate::account::TransactionRecord;
use crate::managed_account::managed_account_ref::ManagedAccountRefMut;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::managed_platform_account::ManagedPlatformAccount;
use crate::managed_account::ManagedCoreKeysAccount;
use crate::transaction_checking::TransactionContext;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use dashcore::{OutPoint, Transaction, Txid};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// What [`ManagedWalletInfo::abandon_transaction`] removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonOutcome {
    /// Every transaction dropped: the root and its recorded descendants.
    pub abandoned: BTreeSet<Txid>,
    /// How many UTXOs those transactions had contributed.
    pub utxos_removed: usize,
    /// How many transaction records were actually dropped. Distinct from
    /// `abandoned.len()`, which counts what was *asked* for.
    pub records_removed: usize,
    /// Outpoints the abandon released, deduplicated and reconciled across
    /// every account: inputs the abandoned transactions claimed that nothing
    /// surviving in this wallet claims too. Outpoints belonging to the
    /// abandoned transactions themselves are excluded — those are outputs of
    /// records being deleted, not coins coming free.
    ///
    /// The same set, and for the same reason, as
    /// [`WalletConflictSweep::released_outpoints`]: a consumer mirroring
    /// wallet state has to mark these coins spendable again, and cannot
    /// derive the set from `abandoned` alone — that would require knowing
    /// which of their inputs some *other* surviving transaction also claims.
    ///
    /// These coins are also re-credited to this wallet's own UTXO set, so the
    /// event and in-core coin selection agree wherever the re-credit can be
    /// proven safe. Where it cannot, this set is still reported in full and
    /// the coin is withheld in core until a rescan — a deliberate,
    /// balance-understating divergence. See
    /// `ManagedCoreFundsAccount::recredit_released_outpoints` for the three
    /// cases: a chainlock-pruned funding record, a funding record that can
    /// never confirm, and a coin whose spent-status is no longer verifiable
    /// against the observed-spent map.
    pub released_outpoints: Vec<OutPoint>,
}

impl AbandonOutcome {
    /// Whether anything was actually removed.
    ///
    /// `abandoned` always contains the root, whether or not the wallet held
    /// anything for it, so it cannot answer this on its own — a root the
    /// wallet never recorded removes nothing.
    ///
    /// `released_outpoints` is checked too, on the same reasoning
    /// [`WalletConflictSweep::is_empty`] gives: only a record removal can free
    /// an outpoint today, so it can never be non-empty on its own, but a
    /// release that stopped riding along with one would otherwise stop marking
    /// the wallet dirty — silently, and visible only later as a coin still
    /// marked spent after a restart.
    pub fn is_empty(&self) -> bool {
        self.records_removed == 0 && self.utxos_removed == 0 && self.released_outpoints.is_empty()
    }
}

/// Drop from `released` every outpoint some surviving record in `accounts`
/// still spends.
///
/// Each account decides what it released from its own records alone
/// (`release_spent_marks` rebuilds the retained set from that account's
/// transactions), and a removed transaction is dropped from every account it
/// was recorded in. Pooled funding puts those accounts and the spender of a
/// given coin in different places: an account that removed a record but never
/// held the transaction still claiming one of its inputs sees nothing
/// retaining that coin and reports it free. Unioning the per-account answers
/// then carries that mistake out of the wallet.
///
/// Re-checking against every account's surviving records is the only view that
/// can settle it.
///
/// The surviving inputs are collected once and probed by hash, rather than
/// rescanning the records per candidate. The released set is not inherently
/// small: a peer can hand the wallet a transaction whose input vector is as
/// large as it likes and whose output pays an address the wallet owns, and a
/// later final transaction need conflict with only one of those inputs for the
/// rest to become candidates. Scanning per candidate is `O(released × retained
/// history)` against a wallet whose history the peer does not control either —
/// tens of millions of comparisons, run while the manager holds the winner
/// mutably and before the event can even reach persistence. Building the set is
/// one pass over that same history and is never the worse trade: a single
/// candidate already costs a full pass under the alternative.
fn retain_unclaimed_outpoints(
    released: &mut Vec<OutPoint>,
    accounts: &crate::managed_account::managed_account_collection::ManagedAccountCollection,
) {
    if released.is_empty() {
        return;
    }
    let claimed: HashSet<OutPoint> = accounts
        .all_accounts()
        .into_iter()
        .flat_map(|account| account.transactions().values())
        .flat_map(|record| record.transaction.input.iter())
        .map(|input| input.previous_output)
        .collect();
    released.retain(|outpoint| !claimed.contains(outpoint));
}

/// Txids in `records` that spend an output of anything in `abandoned`.
///
/// Settled records are never followed — what they spent was real. An
/// InstantSend lock settles a transaction against a double spend just as a
/// block does, and `is_confirmed()` does not cover it.
fn collect_spenders_of_records(
    records: &std::collections::BTreeMap<Txid, TransactionRecord>,
    abandoned: &BTreeSet<Txid>,
    into: &mut BTreeSet<Txid>,
) {
    for (txid, record) in records {
        if record.is_confirmed() || record.context.is_instant_send() || abandoned.contains(txid) {
            continue;
        }
        if record
            .transaction
            .input
            .iter()
            .any(|input| abandoned.contains(&input.previous_output.txid))
        {
            into.insert(*txid);
        }
    }
}

/// What [`ManagedWalletInfo::sweep_conflicts`] removed from the wallet: the
/// union, across every account swept, of the per-account `ConflictSweep`s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalletConflictSweep {
    /// Loser txids removed, deduplicated — one transaction can be recorded
    /// in several accounts, so the per-account results overlap.
    pub txids: Vec<Txid>,
    /// Outpoints released from `spent_outpoints` across every account swept,
    /// deduplicated. Wallet-scoped rather than attributed per loser: a
    /// caller mirroring wallet state holds every input of every loser it
    /// deletes, so it only needs to know which of them came free, not which
    /// loser freed which.
    pub released_outpoints: Vec<OutPoint>,
}

impl WalletConflictSweep {
    /// Whether the sweep changed nothing.
    ///
    /// Both fields are checked even though only a removal can free an
    /// outpoint today, so the second can never be non-empty on its own.
    /// Callers use this to decide whether wallet state was modified, and a
    /// release that stopped riding along with a removal would otherwise stop
    /// marking the wallet dirty — silently, and only visible later as a coin
    /// still marked spent after a restart.
    pub fn is_empty(&self) -> bool {
        self.txids.is_empty() && self.released_outpoints.is_empty()
    }

    /// Drop outpoints some surviving record elsewhere in the wallet still
    /// spends. See [`retain_unclaimed_outpoints`], which this shares with the
    /// abandon path.
    ///
    /// Note this does not need to cover the winner that triggered the sweep:
    /// `drop_conflicted_transactions` already withholds the inputs it spends,
    /// which it must, since on the checker path the sweep runs before the
    /// winner is recorded anywhere.
    fn retain_unclaimed(
        &mut self,
        accounts: &crate::managed_account::managed_account_collection::ManagedAccountCollection,
    ) {
        retain_unclaimed_outpoints(&mut self.released_outpoints, accounts);
    }
}

impl ManagedWalletInfo {
    /// Drop the outputs of every recorded transaction that `tx` provably beat
    /// to one of its inputs, across the whole wallet.
    ///
    /// Wallet-wide on purpose, and deliberately not gated on relevance. Two
    /// separate gaps make an account-local, relevance-gated sweep miss the
    /// cases that matter:
    ///
    /// * Pooled funding puts a loser's change in an account the winner never
    ///   touches, so sweeping only the winner's accounts leaves it credited —
    ///   and as *trusted* change it is counted confirmed and is spendable.
    /// * Relevance is computed from matching outputs and from inputs still
    ///   present in `utxos`, but the loser already removed the shared input.
    ///   A winner that spends our coin and pays only external addresses is
    ///   therefore classified irrelevant, and no account is visited at all.
    ///
    /// Returns the txids removed, so a caller mirroring wallet state can
    /// learn those rows are gone — nothing else in the event surface reports
    /// a removal, and a mirror that misses it replays the dead transaction.
    /// Also returns the outpoints released as a side effect, for the same
    /// reason: the winner is not guaranteed to appear anywhere the caller can
    /// see, so the set cannot be re-derived from the txids.
    ///
    /// The released coins are re-credited to this wallet's own UTXO set here
    /// too, once the per-account answers have been reconciled — the reported
    /// set and what coin selection can actually spend should not disagree.
    /// Where the re-credit cannot be proven safe it is withheld and the two
    /// do diverge, always with core holding *less* than the event reports.
    /// See `ManagedCoreFundsAccount::recredit_released_outpoints`.
    pub fn sweep_conflicts(
        &mut self,
        tx: &Transaction,
        context: &TransactionContext,
    ) -> WalletConflictSweep {
        let mut result = WalletConflictSweep::default();
        for account in self.accounts.all_accounts_mut() {
            if let ManagedAccountRefMut::Funds(funds) = account {
                let swept = funds.drop_conflicted_transactions(tx, context);
                result.txids.extend(swept.txids);
                result.released_outpoints.extend(swept.released_outpoints);
            }
        }
        if !result.txids.is_empty() {
            // One transaction can be recorded in several accounts, so the
            // per-account results overlap.
            result.txids.sort_unstable();
            result.txids.dedup();
            result.released_outpoints.sort_unstable();
            result.released_outpoints.dedup();
            result.retain_unclaimed(&self.accounts);
            // Strictly after `retain_unclaimed`: a coin a sibling account's
            // surviving record still spends must never be put back, and only
            // the reconciled set is safe to act on.
            self.recredit_released_outpoints(&result.released_outpoints);
            // Last, so the balance reflects both the removals and the
            // re-credits.
            self.update_balance();
        }
        result
    }

    /// Offer `released` to every funds-bearing account; each takes the coins
    /// it can prove are its own. Returns what was actually re-credited across
    /// the wallet.
    ///
    /// An outpoint is owned by at most one account — ownership is decided from
    /// the funding record's per-account output classification — so offering
    /// the whole set to each account re-credits each coin exactly once.
    ///
    /// Outpoints this wallet has *seen spent in a block* are withheld, even
    /// when the release said they were free. `release_spent_marks` answers
    /// from the wallet's own records, and a block spend of our coin that we
    /// could not attribute leaves no record to answer from: the spender pays
    /// only external addresses and, if the funding transaction had not been
    /// processed yet, never even matched (dashpay/rust-dashcore#649 — the same
    /// reason `update_utxos` refuses to insert such an output in the first
    /// place). Re-crediting one of those would hand coin selection a coin the
    /// chain has already spent.
    ///
    /// That membership test is necessary but not sufficient, and the map alone
    /// cannot make it sufficient: `prune_finalized_observed_spends` evicts
    /// entries at the finality boundary, so below
    /// [`ManagedWalletInfo::spend_proof_horizon`] a miss means "no longer
    /// recorded", not "never spent". The map and the horizon are therefore
    /// both handed down to the accounts, which withhold any coin whose
    /// spent-status is no longer cross-checkable and any coin whose funding
    /// record can never confirm. See
    /// [`ManagedCoreFundsAccount::recredit_released_outpoints`] for both
    /// rules.
    ///
    /// The released set is still *reported* as-is: that set's contract is a
    /// consumer-facing one with its own documented limits, and narrowing it is
    /// a separate change from making in-core state match it — this withholding
    /// only ever errs toward understating what we can spend.
    fn recredit_released_outpoints(&mut self, released: &[OutPoint]) -> Vec<OutPoint> {
        if released.is_empty() {
            return Vec::new();
        }
        let candidates: Vec<OutPoint> = released
            .iter()
            .filter(|outpoint| !self.observed_spent_outpoints.contains_key(outpoint))
            .copied()
            .collect();
        if candidates.is_empty() {
            return Vec::new();
        }
        let horizon = self.spend_proof_horizon();
        // Disjoint field borrows: the accounts are taken mutably while the
        // observed-spent map is read, so the per-account gate can consult it
        // without cloning a map that is bounded only by `MAX_OBSERVED_SPENT_OUTPOINTS`.
        let observed_spent = &self.observed_spent_outpoints;
        let mut recredited = Vec::new();
        for account in self.accounts.all_accounts_mut() {
            if let ManagedAccountRefMut::Funds(funds) = account {
                recredited.extend(funds.recredit_released_outpoints(
                    &candidates,
                    observed_spent,
                    horizon,
                ));
            }
        }
        recredited
    }

    /// Whether any account holds `txid` as settled by the network.
    ///
    /// Settled means chainlock-finalized, in a block, **or InstantSend-locked**
    /// — an IS lock is final against a double spend under DIP-10, so the coins
    /// it moved are as irreversibly gone as a block's. `is_confirmed()` covers
    /// only the first two, which is why the lock is checked explicitly.
    ///
    /// A finalized transaction may keep only its txid, so both the retained
    /// set and the live record have to be consulted. Keys-only accounts are
    /// included: they hold records too, and a settled record there is just as
    /// authoritative.
    fn transaction_is_settled(&self, txid: &Txid) -> bool {
        self.accounts.all_accounts().into_iter().any(|account| {
            account.transaction_is_finalized(txid)
                || account
                    .transactions()
                    .get(txid)
                    .is_some_and(|r| r.is_confirmed() || r.context.is_instant_send())
        })
    }

    /// Abandon `root` and every recorded transaction descending from it.
    ///
    /// A transaction the network never accepted still mutated this wallet:
    /// its outputs were credited and its inputs marked spent. Nothing reverses
    /// that on its own — the transaction is in no block, so no block
    /// processing revisits it — and further transactions can be built on its
    /// change, each inheriting the same fiction. Left alone the whole chain
    /// sits in the `unconfirmed` bucket permanently, as money the wallet
    /// displays and does not have.
    ///
    /// The walk is transitive and wallet-wide — every account that holds
    /// records, funds-bearing or keys-only. Pooled funding spreads a
    /// transaction's inputs across account families, so a descendant's change
    /// can land in an account holding none of the root; and an asset-lock
    /// funding transaction is recorded in both its funding account and the
    /// identity account it pays. Confirmed and
    /// finalized transactions are never followed — they are settled on chain,
    /// so whatever they spent was real.
    ///
    /// **This call asserts that the root is dead; it does not establish it.**
    /// The p2p network has no negative signal — modern Dash Core removed BIP61
    /// `reject` — so silence is not proof, and a transaction that merely went
    /// quiet may still be live in a miner's mempool. Abandoning such a
    /// transaction re-exposes its inputs to coin selection and invites a
    /// double-spend. Only call this where the death is known: a build that
    /// provably never reached the network, or an explicit user decision. The
    /// judgement belongs to the layer that owns broadcast policy.
    ///
    /// The coins the abandoned transactions consumed are released from the
    /// spent set and re-credited to the UTXO set, rebuilt from their funding
    /// transactions' own retained records — the abandon removes the spenders,
    /// not what funded them. They are reported in
    /// [`AbandonOutcome::released_outpoints`] so a persistence mirror can
    /// follow. See `ManagedCoreFundsAccount::recredit_released_outpoints`
    /// for the cases that cannot be rebuilt and are withheld until a rescan:
    /// a funding record already pruned to its txid by a chainlock, one a
    /// settled spend has doomed, and one whose coin's spent-status can no
    /// longer be cross-checked.
    ///
    /// Does not recompute the balance — callers batching several abandons
    /// should run `update_balance`
    /// (from [`WalletInfoInterface`])
    /// once at the end.
    pub fn abandon_transaction(&mut self, root: Txid) -> AbandonOutcome {
        self.abandon_transaction_with_spends(root, &BTreeMap::new())
    }

    /// [`abandon_transaction`](Self::abandon_transaction), with an external
    /// view of who spent what.
    ///
    /// The descendant walk normally reads recorded transactions, but a caller
    /// restoring a wallet may hold UTXOs whose creating transactions were
    /// never put back into the in-memory map — leaving the walk unable to see
    /// that one abandoned output funded the next transaction along. Callers
    /// with a persistence mirror can supply `external_spends`, mapping an
    /// outpoint to the transaction that spent it, and the walk follows both.
    ///
    /// An external spender the wallet holds as confirmed or finalized is
    /// **not** followed: the mirror carries no confirmation state of its own,
    /// so without this check a stale row could name a settled transaction and
    /// have its record and UTXOs deleted. The same guard rejects a confirmed
    /// root outright — a transaction in a block spent something real, and
    /// nothing built on it is fiction.
    pub fn abandon_transaction_with_spends(
        &mut self,
        root: Txid,
        external_spends: &BTreeMap<OutPoint, Txid>,
    ) -> AbandonOutcome {
        if self.transaction_is_settled(&root) {
            tracing::warn!(
                txid = %root,
                "refusing to abandon a transaction the wallet holds as settled"
            );
            return AbandonOutcome {
                abandoned: BTreeSet::new(),
                utxos_removed: 0,
                records_removed: 0,
                released_outpoints: Vec::new(),
            };
        }
        let mut abandoned = BTreeSet::from([root]);

        // Transitive closure over recorded spenders. Each pass can only add
        // txids, and the set is bounded by the recorded transactions, so this
        // terminates; a spend cycle is impossible anyway.
        loop {
            let mut found = BTreeSet::new();
            for account in self.accounts.all_accounts() {
                collect_spenders_of_records(account.transactions(), &abandoned, &mut found);
            }
            // Same step over the external view: anything spending an output of
            // an abandoned transaction is itself abandoned.
            for (outpoint, spender) in external_spends {
                if abandoned.contains(&outpoint.txid) && !self.transaction_is_settled(spender) {
                    found.insert(*spender);
                }
            }
            let before = abandoned.len();
            abandoned.extend(found);
            if abandoned.len() == before {
                break;
            }
        }

        let mut utxos_removed = 0;
        let mut records_removed = 0;
        let mut released_outpoints = Vec::new();
        for account in self.accounts.all_accounts_mut() {
            match account {
                ManagedAccountRefMut::Funds(funds) => {
                    let removed = funds.apply_abandon(&abandoned);
                    utxos_removed += removed.utxos;
                    records_removed += removed.records;
                    released_outpoints.extend(removed.released_outpoints);
                }
                // Keys-only accounts hold no UTXOs, but they do hold records
                // — an asset-lock funding transaction is recorded in both its
                // funding account and the identity account it pays. Leaving
                // the record here makes `is_new` false on a later re-sighting,
                // so the funds account never re-records the transaction and
                // never re-marks its input spent.
                ManagedAccountRefMut::Keys(keys) => {
                    for txid in &abandoned {
                        if keys.transactions_mut().remove(txid).is_some() {
                            records_removed += 1;
                        }
                    }
                }
            }
        }

        // One transaction is recorded in every account it touched, so the
        // per-account releases overlap.
        released_outpoints.sort_unstable();
        released_outpoints.dedup();
        // A coin another account's surviving record still spends was never
        // free; the per-account view cannot see that. Same reconciliation the
        // conflict sweep runs, and for the same reason.
        retain_unclaimed_outpoints(&mut released_outpoints, &self.accounts);
        // Strictly after the reconciliation: only the settled set is safe to
        // put back into coin selection.
        self.recredit_released_outpoints(&released_outpoints);

        AbandonOutcome {
            abandoned,
            utxos_removed,
            records_removed,
            released_outpoints,
        }
    }
    // BIP44 Account Helpers

    /// Get the first BIP44 managed account
    pub fn first_bip44_managed_account(&self) -> Option<&ManagedCoreFundsAccount> {
        self.bip44_managed_account_at_index(0)
    }

    /// Get the first BIP44 managed account (mutable)
    pub fn first_bip44_managed_account_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        self.bip44_managed_account_at_index_mut(0)
    }

    /// Get a BIP44 managed account at a specific index
    pub fn bip44_managed_account_at_index(&self, index: u32) -> Option<&ManagedCoreFundsAccount> {
        self.accounts.standard_bip44_accounts.get(&index)
    }

    /// Get a BIP44 managed account at a specific index (mutable)
    pub fn bip44_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreFundsAccount> {
        self.accounts.standard_bip44_accounts.get_mut(&index)
    }

    // BIP32 Account Helpers

    /// Get the first BIP32 managed account
    pub fn first_bip32_managed_account(&self) -> Option<&ManagedCoreFundsAccount> {
        self.bip32_managed_account_at_index(0)
    }

    /// Get the first BIP32 managed account (mutable)
    pub fn first_bip32_managed_account_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        self.bip32_managed_account_at_index_mut(0)
    }

    /// Get a BIP32 managed account at a specific index
    pub fn bip32_managed_account_at_index(&self, index: u32) -> Option<&ManagedCoreFundsAccount> {
        self.accounts.standard_bip32_accounts.get(&index)
    }

    /// Get a BIP32 managed account at a specific index (mutable)
    pub fn bip32_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreFundsAccount> {
        self.accounts.standard_bip32_accounts.get_mut(&index)
    }

    // CoinJoin Account Helpers

    /// Get the first CoinJoin managed account
    pub fn first_coinjoin_managed_account(&self) -> Option<&ManagedCoreFundsAccount> {
        self.coinjoin_managed_account_at_index(0)
    }

    /// Get the first CoinJoin managed account (mutable)
    pub fn first_coinjoin_managed_account_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        self.coinjoin_managed_account_at_index_mut(0)
    }

    /// Get a CoinJoin managed account at a specific index
    pub fn coinjoin_managed_account_at_index(
        &self,
        index: u32,
    ) -> Option<&ManagedCoreFundsAccount> {
        self.accounts.coinjoin_accounts.get(&index)
    }

    /// Get a CoinJoin managed account at a specific index (mutable)
    pub fn coinjoin_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreFundsAccount> {
        self.accounts.coinjoin_accounts.get_mut(&index)
    }

    // TopUp Account Helpers

    /// Get the first TopUp managed account
    pub fn first_topup_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_topup.values().next()
    }

    /// Get the first TopUp managed account (mutable)
    pub fn first_topup_managed_account_mut(&mut self) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_topup.values_mut().next()
    }

    /// Get a TopUp managed account at a specific registration index
    pub fn topup_managed_account_at_registration_index(
        &self,
        registration_index: u32,
    ) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_topup.get(&registration_index)
    }

    /// Get a TopUp managed account at a specific registration index (mutable)
    pub fn topup_managed_account_at_registration_index_mut(
        &mut self,
        registration_index: u32,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_topup.get_mut(&registration_index)
    }

    // Identity Registration Account Helper

    /// Get the identity registration managed account
    pub fn identity_registration_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_registration.as_ref()
    }

    /// Get the identity registration managed account (mutable)
    pub fn identity_registration_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_registration.as_mut()
    }

    // Identity TopUp Not Bound Account Helper

    /// Get the identity top-up not bound managed account
    pub fn identity_topup_not_bound_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_topup_not_bound.as_ref()
    }

    /// Get the identity top-up not bound managed account (mutable)
    pub fn identity_topup_not_bound_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_topup_not_bound.as_mut()
    }

    // Identity Invitation Account Helper

    /// Get the identity invitation managed account
    pub fn identity_invitation_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_invitation.as_ref()
    }

    /// Get the identity invitation managed account (mutable)
    pub fn identity_invitation_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_invitation.as_mut()
    }

    // Provider Voting Keys Account Helper

    /// Get the provider voting keys managed account
    pub fn provider_voting_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_voting_keys.as_ref()
    }

    /// Get the provider voting keys managed account (mutable)
    pub fn provider_voting_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.provider_voting_keys.as_mut()
    }

    // Provider Owner Keys Account Helper

    /// Get the provider owner keys managed account
    pub fn provider_owner_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_owner_keys.as_ref()
    }

    /// Get the provider owner keys managed account (mutable)
    pub fn provider_owner_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.provider_owner_keys.as_mut()
    }

    // Provider Operator Keys Account Helper

    /// Get the provider operator keys managed account
    pub fn provider_operator_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_operator_keys.as_ref()
    }

    /// Get the provider operator keys managed account (mutable)
    pub fn provider_operator_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.provider_operator_keys.as_mut()
    }

    // Provider Platform Keys Account Helper

    /// Get the provider platform keys managed account
    pub fn provider_platform_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_platform_keys.as_ref()
    }

    /// Get the provider platform keys managed account (mutable)
    pub fn provider_platform_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.provider_platform_keys.as_mut()
    }

    // Platform Payment Account Helpers (DIP-17)

    /// Get the first platform payment managed account
    ///
    /// Returns the platform payment account with the lowest account index and key_class 0.
    pub fn first_platform_payment_managed_account(&self) -> Option<&ManagedPlatformAccount> {
        self.platform_payment_managed_account(0, 0)
    }

    /// Get the first platform payment managed account (mutable)
    ///
    /// Returns the platform payment account with account index 0 and key_class 0.
    pub fn first_platform_payment_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedPlatformAccount> {
        self.platform_payment_managed_account_mut(0, 0)
    }

    /// Get a platform payment managed account by account index (with default key_class 0)
    pub fn platform_payment_managed_account_at_index(
        &self,
        account_index: u32,
    ) -> Option<&ManagedPlatformAccount> {
        self.platform_payment_managed_account(account_index, 0)
    }

    /// Get a platform payment managed account by account index (mutable, with default key_class 0)
    pub fn platform_payment_managed_account_at_index_mut(
        &mut self,
        account_index: u32,
    ) -> Option<&mut ManagedPlatformAccount> {
        self.platform_payment_managed_account_mut(account_index, 0)
    }

    /// Get a platform payment managed account by account index and key class
    pub fn platform_payment_managed_account(
        &self,
        account_index: u32,
        key_class: u32,
    ) -> Option<&ManagedPlatformAccount> {
        let key = PlatformPaymentAccountKey {
            account: account_index,
            key_class,
        };
        self.accounts.platform_payment_accounts.get(&key)
    }

    /// Get a platform payment managed account by account index and key class (mutable)
    pub fn platform_payment_managed_account_mut(
        &mut self,
        account_index: u32,
        key_class: u32,
    ) -> Option<&mut ManagedPlatformAccount> {
        let key = PlatformPaymentAccountKey {
            account: account_index,
            key_class,
        };
        self.accounts.platform_payment_accounts.get_mut(&key)
    }

    /// Get all platform payment managed accounts
    pub fn all_platform_payment_managed_accounts(&self) -> Vec<&ManagedPlatformAccount> {
        self.accounts.platform_payment_accounts.values().collect()
    }

    /// Get all platform payment managed accounts (mutable)
    pub fn all_platform_payment_managed_accounts_mut(
        &mut self,
    ) -> Vec<&mut ManagedPlatformAccount> {
        self.accounts.platform_payment_accounts.values_mut().collect()
    }

    /// Get the number of platform payment accounts
    pub fn platform_payment_account_count(&self) -> usize {
        self.accounts.platform_payment_accounts.len()
    }

    /// Check if a platform payment account exists
    pub fn has_platform_payment_account(&self, account_index: u32, key_class: u32) -> bool {
        let key = PlatformPaymentAccountKey {
            account: account_index,
            key_class,
        };
        self.accounts.platform_payment_accounts.contains_key(&key)
    }

    // General Helpers

    /// Check if the wallet has any accounts
    pub fn has_accounts(&self) -> bool {
        !self.accounts.is_empty()
    }

    /// Get the total number of accounts across all types
    pub fn account_count(&self) -> usize {
        self.accounts.all_accounts().len()
    }

    /// Get all accounts (mixed funds and keys variants).
    pub fn all_managed_accounts(&self) -> Vec<crate::managed_account::ManagedAccountRef<'_>> {
        self.accounts.all_accounts()
    }
}

#[cfg(test)]
mod retain_unclaimed_tests {
    use super::*;
    use crate::account::{AccountType, StandardAccountType};
    use crate::managed_account::managed_account_trait::ManagedAccountTrait;
    use crate::managed_account::transaction_record::{TransactionDirection, TransactionRecord};
    use crate::managed_account::ManagedCoreFundsAccount;
    use crate::transaction_checking::transaction_router::TransactionType;
    use crate::transaction_checking::TransactionContext;
    use dashcore::hashes::Hash;
    use dashcore::{OutPoint, ScriptBuf, Transaction, TxIn, Txid, Witness};

    fn outpoint(seed: u32) -> OutPoint {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&seed.to_le_bytes());
        OutPoint {
            txid: Txid::from_byte_array(raw),
            vout: 0,
        }
    }

    /// A surviving record spending `input`, identified by `seed`.
    fn record_spending(seed: u32, input: OutPoint) -> TransactionRecord {
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: input,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            }],
            output: vec![],
            special_transaction_payload: None,
        };
        let mut record = TransactionRecord::new(
            tx,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            TransactionContext::Mempool,
            TransactionType::Standard,
            TransactionDirection::Outgoing,
            Vec::new(),
            Vec::new(),
            0,
        );
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&seed.to_le_bytes());
        raw[31] = 0xff;
        record.txid = Txid::from_byte_array(raw);
        record
    }

    /// A large release set against a large surviving history.
    ///
    /// Neither side is bounded by anything the wallet controls: a peer can
    /// hand it a transaction with as many inputs as it likes that pays an
    /// address the wallet owns, and the history is simply whatever the
    /// wallet has retained. Probing the records per candidate is
    /// `O(released × history)` — at these sizes that is 16 million input
    /// comparisons, which is what this pins against; collecting the claimed
    /// inputs once makes it one pass plus hashed lookups.
    ///
    /// The assertion is ordinary correctness: half the candidates are
    /// claimed by a surviving record and must be withheld, half are not and
    /// must survive. The size is the point.
    #[test]
    fn a_large_release_set_against_a_large_history_is_partitioned_correctly() {
        const HISTORY: u32 = 4_000;
        const RELEASED: u32 = 4_000;

        let mut account = ManagedCoreFundsAccount::dummy_bip44();
        // The first HISTORY outpoints are each claimed by a surviving record.
        for seed in 0..HISTORY {
            let record = record_spending(seed, outpoint(seed));
            account.transactions_mut().insert(record.txid, record);
        }
        let mut accounts =
            crate::managed_account::managed_account_collection::ManagedAccountCollection::new();
        accounts.standard_bip44_accounts.insert(0, account);

        // Candidates: the claimed half, plus an equal number nothing spends.
        let mut sweep = WalletConflictSweep {
            txids: vec![Txid::all_zeros()],
            released_outpoints: (0..RELEASED * 2).map(outpoint).collect(),
        };
        sweep.retain_unclaimed(&accounts);

        assert_eq!(
            sweep.released_outpoints.len(),
            RELEASED as usize,
            "every claimed candidate is withheld and every unclaimed one survives"
        );
        assert!(sweep.released_outpoints.iter().all(|o| {
            u32::from_le_bytes(o.txid.as_byte_array()[..4].try_into().expect("4 bytes")) >= HISTORY
        }));
    }
}
