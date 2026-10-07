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
use std::collections::{BTreeMap, BTreeSet, HashMap};

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
}

impl AbandonOutcome {
    /// Whether anything was actually removed.
    ///
    /// `abandoned` always contains the root, whether or not the wallet held
    /// anything for it, so it cannot answer this on its own — a root the
    /// wallet never recorded removes nothing.
    pub fn is_empty(&self) -> bool {
        self.records_removed == 0 && self.utxos_removed == 0
    }
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

/// Every outpoint a live record anywhere in the wallet spends, with one of
/// its spenders: the lowest txid, so the choice does not depend on which
/// account is visited first.
///
/// A record of a transaction in `removed` is not live, wherever it is still
/// held: a sweep drops a loser from funds accounts only, so a keys-only
/// account keeps the record of a swept asset lock.
fn live_record_spenders(
    accounts: &crate::managed_account::managed_account_collection::ManagedAccountCollection,
    removed: &BTreeSet<Txid>,
) -> HashMap<OutPoint, Txid> {
    let mut spenders: HashMap<OutPoint, Txid> = HashMap::new();
    for account in accounts.all_accounts() {
        for (txid, record) in account.transactions() {
            if removed.contains(txid) {
                continue;
            }
            for input in &record.transaction.input {
                spenders
                    .entry(input.previous_output)
                    .and_modify(|spender| *spender = (*spender).min(*txid))
                    .or_insert(*txid);
            }
        }
    }
    spenders
}

/// Remove from `released` every outpoint a live record anywhere in the wallet
/// still spends, and return those with their spender. Records of the
/// transactions in `removed` do not count.
fn split_off_still_spent(
    released: &mut Vec<OutPoint>,
    accounts: &crate::managed_account::managed_account_collection::ManagedAccountCollection,
    removed: &BTreeSet<Txid>,
) -> Vec<(OutPoint, Txid)> {
    if released.is_empty() {
        return Vec::new();
    }
    let live_spenders = live_record_spenders(accounts, removed);
    let mut still_spent = Vec::new();
    released.retain(|outpoint| {
        let Some(spender) = live_spenders.get(outpoint) else {
            return true;
        };
        still_spent.push((*outpoint, *spender));
        false
    });
    still_spent
}

/// What [`ManagedWalletInfo::sweep_conflicts`] removed from the wallet: the
/// union, across every account swept, of the per-account `ConflictSweep`s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalletConflictSweep {
    /// Loser txids removed, deduplicated — one transaction can be recorded
    /// in several accounts, so the per-account results overlap.
    pub txids: Vec<Txid>,
    /// Outpoints the sweep left unguarded in every funding account,
    /// deduplicated: inputs of the removed losers that no surviving record
    /// spends, and outpoints whose restored claim named a removed loser.
    /// One that any funding account still guards — by a mark from its own
    /// records, ChainLocked ones included, or by a restored claim — is
    /// withheld.
    /// Wallet-scoped rather than attributed per loser: a
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
    /// spends.
    ///
    /// Each account decides what it released from its own records alone
    /// (`release_spent_marks` rebuilds the retained set from that account's
    /// transactions), and a loser is removed from every account it was
    /// recorded in. Pooled funding puts those accounts and the spender of a
    /// given coin in different places: an account that removed a loser but
    /// never recorded the transaction still claiming one of its inputs sees
    /// nothing retaining that coin and reports it free. Unioning the
    /// per-account answers then carries that mistake out of the wallet.
    ///
    /// Re-checking against every account's surviving records is the only
    /// view that can settle it. Note this does not need to cover the winner
    /// that triggered the sweep: `drop_conflicted_transactions` already
    /// withholds the inputs it spends, which it must, since on the checker
    /// path the sweep runs before the winner is recorded anywhere.
    ///
    /// The surviving inputs are collected once and probed by hash, rather
    /// than rescanning the records per candidate. The released set is not
    /// inherently small: a peer can hand the wallet a transaction whose
    /// input vector is as large as it likes and whose output pays an address
    /// the wallet owns, and a later final transaction need conflict with
    /// only one of those inputs for the rest to become candidates. Scanning
    /// per candidate is `O(released × retained history)` against a wallet
    /// whose history the peer does not control either — tens of millions of
    /// comparisons, run while the manager holds the winner mutably and
    /// before the event can even reach persistence. Building the set is one
    /// pass over that same history and is never the worse trade: a single
    /// candidate already costs a full pass under the alternative.
    ///
    /// Returns the withheld outpoints, each with a surviving spender. The
    /// transactions in `removed`, which this sweep dropped, are no survivors.
    fn retain_unclaimed(
        &mut self,
        accounts: &crate::managed_account::managed_account_collection::ManagedAccountCollection,
        removed: &BTreeSet<Txid>,
    ) -> Vec<(OutPoint, Txid)> {
        split_off_still_spent(&mut self.released_outpoints, accounts, removed)
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
    /// Restored claims are settled in every funding account as well. One on
    /// an input of `tx` becomes a permanent guard whoever its claimant is,
    /// record or not, since `tx` is final. One naming a removed loser goes
    /// through `release_restored_claims`. An input of a removed loser that
    /// a live record in another account still spends stays guarded in every
    /// funding account (see `inherit_spent_claims`).
    ///
    /// An outpoint is reported released only once no funding account guards
    /// it, whether by a restored claim or by a mark from its own records —
    /// including the mark a ChainLocked spend leaves in an account that
    /// never recorded the loser.
    pub fn sweep_conflicts(
        &mut self,
        tx: &Transaction,
        context: &TransactionContext,
    ) -> WalletConflictSweep {
        let mut result = WalletConflictSweep::default();
        if context.confirmed() || context.is_instant_send() {
            for account in self.accounts.all_funding_accounts_mut() {
                account.settle_restored_claims_spent_by(tx);
            }
        }
        for account in self.accounts.all_accounts_mut() {
            if let ManagedAccountRefMut::Funds(funds) = account {
                let swept = funds.drop_conflicted_transactions(tx, context);
                result.txids.extend(swept.txids);
                result.released_outpoints.extend(swept.released_outpoints);
            }
        }
        if !result.txids.is_empty() {
            self.update_balance();
            // One transaction can be recorded in several accounts, so the
            // per-account results overlap.
            result.txids.sort_unstable();
            result.txids.dedup();
            let removed = result.txids.iter().copied().collect();
            result.released_outpoints.extend(self.release_restored_claims(&removed));
            result.released_outpoints.sort_unstable();
            result.released_outpoints.dedup();
            let still_spent = result.retain_unclaimed(&self.accounts, &removed);
            self.inherit_spent_claims(&still_spent);
            // Each account answers for its own marks and claims only, so an
            // outpoint one account let go can still be guarded by another.
            let funding = self.accounts.all_funding_accounts();
            result.released_outpoints.retain(|outpoint| {
                !funding.iter().any(|account| account.is_outpoint_spent(outpoint))
            });
        }
        result
    }

    /// Settle the restored claims whose claimant is in `removed`, in every
    /// funding account — also those that never recorded the claimant, and
    /// when no account holds a record of it at all.
    ///
    /// A claimed outpoint that a live record anywhere in the wallet still
    /// spends keeps its claim, now naming that record, so removing the
    /// record in turn is settled here again. Any other loses its claim, and
    /// is returned — except an output of a removed transaction, which is
    /// not a coin coming free but one that never existed.
    ///
    /// Claims with no claimant, or with a claimant outside `removed`, are
    /// untouched, and so is every record-derived mark: an account holding
    /// its own mark on a returned outpoint goes on guarding it.
    fn release_restored_claims(&mut self, removed: &BTreeSet<Txid>) -> BTreeSet<OutPoint> {
        let mut released = BTreeSet::new();
        // Keeps the pass over every record off the common path where no claim is concerned.
        if !self
            .accounts
            .all_funding_accounts()
            .iter()
            .any(|account| account.has_restored_claim_of(removed))
        {
            return released;
        }
        let live_spenders = live_record_spenders(&self.accounts, removed);
        for account in self.accounts.all_funding_accounts_mut() {
            released.extend(account.release_restored_claims(removed, &live_spenders));
        }
        released.retain(|outpoint| !removed.contains(&outpoint.txid));
        released
    }

    /// Keep guarding outpoints an account just let go although a live record
    /// in another account still spends them.
    ///
    /// An account releases a mark from its own records alone, so removing a
    /// record there can leave the outpoint unguarded in that account while
    /// the wallet still holds a spend of it. Every funding account not
    /// guarding such an outpoint takes a claim naming that spender, which
    /// `release_restored_claims` settles once the spender is removed too.
    fn inherit_spent_claims(&mut self, still_spent: &[(OutPoint, Txid)]) {
        if still_spent.is_empty() {
            return;
        }
        for account in self.accounts.all_funding_accounts_mut() {
            account.inherit_spent_claims(still_spent);
        }
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
    /// spent set so a rescan can rediscover them, rather than being
    /// re-credited directly: the `Utxo` removed for a spent parent is
    /// discarded by `update_utxos` and `InputDetail` keeps only
    /// index/value/address, so the flags that decide a restored coin's
    /// balance bucket are not retained anywhere.
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
    ///
    /// Restored claims naming an abandoned transaction are released as
    /// well, whether or not the wallet holds a record of it (see
    /// `release_restored_claims`). An input of an abandoned transaction
    /// that a live record in another account still spends stays guarded
    /// (see `inherit_spent_claims`).
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
        let mut released = BTreeSet::new();
        for account in self.accounts.all_accounts_mut() {
            match account {
                ManagedAccountRefMut::Funds(funds) => {
                    let removed = funds.apply_abandon(&abandoned);
                    utxos_removed += removed.utxos;
                    records_removed += removed.records;
                    released.extend(removed.released);
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

        self.release_restored_claims(&abandoned);
        let mut released: Vec<OutPoint> = released.into_iter().collect();
        let still_spent = split_off_still_spent(&mut released, &self.accounts, &abandoned);
        self.inherit_spent_claims(&still_spent);

        AbandonOutcome {
            abandoned,
            utxos_removed,
            records_removed,
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
        sweep.retain_unclaimed(&accounts, &BTreeSet::new());

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
