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
use std::collections::{BTreeMap, BTreeSet};

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
    pub fn sweep_conflicts(&mut self, tx: &Transaction, context: &TransactionContext) -> Vec<Txid> {
        let mut swept = Vec::new();
        for account in self.accounts.all_accounts_mut() {
            if let ManagedAccountRefMut::Funds(funds) = account {
                swept.extend(funds.drop_conflicted_transactions(tx, context));
            }
        }
        if !swept.is_empty() {
            self.update_balance();
            // One transaction can be recorded in several accounts, so the
            // per-account results overlap.
            swept.sort_unstable();
            swept.dedup();
        }
        swept
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
        for account in self.accounts.all_accounts_mut() {
            match account {
                ManagedAccountRefMut::Funds(funds) => {
                    let removed = funds.apply_abandon(&abandoned);
                    utxos_removed += removed.utxos;
                    records_removed += removed.records;
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
