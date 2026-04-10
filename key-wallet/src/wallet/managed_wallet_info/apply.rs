//! Apply a [`WalletChangeSet`] onto a [`ManagedWalletInfo`] (and its
//! companion [`Wallet`]) during restore.
//!
//! This is the inverse of the mutation methods that emit changesets. Given a
//! persisted changeset, it replays each sub-changeset onto the in-memory
//! state so the wallet converges to the same state the original mutations
//! produced.
//!
//! # Invariants
//!
//! - **Idempotent.** Applying the same changeset N times produces the same
//!   state as applying it once. Callers may re-run apply on startup or after
//!   a partial write without additional bookkeeping.
//! - **Monotonic on state flags.** UTXO `is_confirmed` and `is_instantlocked`
//!   never regress on replay: if an in-memory UTXO is already confirmed or
//!   IS-locked and the changeset carries an earlier snapshot, the existing
//!   state wins. Prevents a stale persisted changeset from reverting live
//!   state under a race.
//! - **No re-emission.** `apply` does not return a new changeset. If it did,
//!   `apply(apply(cs))` would cascade. All mutation bookkeeping done here
//!   discards any inner changesets returned by helpers.
//! - **Best-effort routing for data entries.** UTXO / transaction changes
//!   are routed to the owning account via the helpers in
//!   `managed_wallet_info::helpers`. Entries that cannot be routed (e.g. an
//!   orphaned UTXO whose address doesn't match any pool) are silently
//!   skipped — the persister is authoritative and the runtime can't do
//!   anything else with them.
//! - **Loud on account-key failures.** If re-deriving an HD account from
//!   `account_keys.added` fails (for example, a watch-only wallet missing
//!   the required xpub), `apply_changeset` returns an error rather than
//!   silently skipping. A missing account cascades into dropping every
//!   downstream entry, so callers need to know.

use crate::account::AccountType;
use crate::changeset::WalletChangeSet;
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::wallet::Wallet;

/// Errors returned by [`ManagedWalletInfo::apply_changeset`].
///
/// Only restore failures that *cascade* (i.e. would cause downstream entries
/// to be silently dropped) are surfaced as errors. Orphan UTXOs / transaction
/// records that fail to route are logged and skipped, not reported.
#[derive(Debug, Clone)]
pub enum ApplyError {
    /// Re-deriving an HD account from the changeset failed. Usually means
    /// the target wallet lacks the key material (watch-only without the
    /// xpub) or is on the wrong network.
    AccountDerivationFailed {
        account_type: AccountType,
        reason: String,
    },
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApplyError::AccountDerivationFailed {
                account_type,
                reason,
            } => write!(
                f,
                "failed to re-derive account {:?} during restore: {}",
                account_type, reason
            ),
        }
    }
}

impl std::error::Error for ApplyError {}

/// Trait for info types that can have a [`WalletChangeSet`] applied to them.
///
/// Implemented by [`ManagedWalletInfo`] directly. Higher-level info types
/// (e.g. `PlatformWalletInfo` in the platform-wallet crate) implement this
/// by delegating to their inner [`ManagedWalletInfo`] and then applying any
/// platform-specific sub-changesets on top.
///
/// The companion `WalletManager<T>::apply_changeset` wrapper is generic over
/// this trait, so any info type with a sensible restore path gets the
/// wallet-manager integration for free.
pub trait ApplyChangeSet {
    /// See [`ManagedWalletInfo::apply_changeset`].
    fn apply_changeset(
        &mut self,
        wallet: &mut Wallet,
        cs: &WalletChangeSet,
    ) -> Result<(), ApplyError>;
}

impl ApplyChangeSet for ManagedWalletInfo {
    fn apply_changeset(
        &mut self,
        wallet: &mut Wallet,
        cs: &WalletChangeSet,
    ) -> Result<(), ApplyError> {
        ManagedWalletInfo::apply_changeset(self, wallet, cs)
    }
}

impl ManagedWalletInfo {
    /// Apply a [`WalletChangeSet`] onto this managed wallet info, using
    /// `wallet` as the source of HD key material for any account types
    /// that need to be re-derived.
    ///
    /// See the module docs for invariants. Typical caller is
    /// `WalletManager::apply_changeset`, which performs the split borrow
    /// of `(&mut Wallet, &mut ManagedWalletInfo)` under a single write
    /// lock.
    pub fn apply_changeset(
        &mut self,
        wallet: &mut Wallet,
        cs: &WalletChangeSet,
    ) -> Result<(), ApplyError> {
        // ------------------------------------------------------------------
        // 1. account_keys — re-derive HD accounts from the seed and mirror
        //    them into `self.accounts`. Must run first so every subsequent
        //    per-account bucket has an owning account to route into.
        //    Errors are fatal because a missing account cascades into
        //    dropping every downstream bucket.
        // ------------------------------------------------------------------
        if let Some(account_keys) = &cs.account_keys {
            for account_type in &account_keys.added {
                if let Err(e) = wallet.add_account(*account_type, None) {
                    return Err(ApplyError::AccountDerivationFailed {
                        account_type: *account_type,
                        reason: e.to_string(),
                    });
                }
                // Mirror into the managed collection if not already present.
                if self.accounts.get_by_account_type_mut(account_type).is_none() {
                    if let Err(e) = self.add_managed_account(wallet, *account_type) {
                        return Err(ApplyError::AccountDerivationFailed {
                            account_type: *account_type,
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // 2. per_account buckets — each sub-changeset was emitted into its
        //    owning account's bucket at mutation time, so routing is a
        //    direct `get_by_account_type_mut` lookup. No address scanning,
        //    no txid scanning, no fallbacks. Buckets that don't resolve
        //    to an account (orphaned persisted data, wrong-network replay)
        //    are silently skipped — the persister is authoritative.
        // ------------------------------------------------------------------
        for (account_type, bucket) in &cs.per_account {
            if let Some(account) = self.accounts.get_by_account_type_mut(account_type) {
                account.apply(bucket);
            }
        }

        // ------------------------------------------------------------------
        // 3. chain — set synced height. `block_hash` is informational: the
        //    authoritative block hash lives on the confirmed transactions'
        //    contexts, already restored via the per_account buckets.
        // ------------------------------------------------------------------
        if let Some(chain) = &cs.chain {
            if let Some(height) = chain.synced_height {
                if height > self.metadata.synced_height {
                    self.metadata.synced_height = height;
                }
            }
        }

        // ------------------------------------------------------------------
        // 4. balance — recompute from the now-restored UTXO set. The
        //    cached deltas in `cs.balance` are ignored because UTXO-driven
        //    recomputation is authoritative after the UTXO set is in
        //    place. Discard the returned changeset (apply does not
        //    re-emit).
        // ------------------------------------------------------------------
        let _ = self.update_balance();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_account::address_pool::AddressPoolType;
    use crate::test_utils::TestWalletContext;
    use crate::transaction_checking::{BlockInfo, TransactionContext};
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;

    /// Round-trip: mutate wallet A via check_core_transaction, capture the
    /// changeset, apply it to a sibling wallet B built from the same
    /// `Wallet` (so derivation paths match), and assert that B converges to
    /// A's state.
    #[tokio::test]
    async fn apply_funding_changeset_mirrors_state_to_sibling_wallet() {
        let mut ctx = TestWalletContext::new_random();

        // Sibling B: a fresh ManagedWalletInfo built from the same Wallet.
        // Same HD keys (so addresses match) but zero runtime state.
        let mut wallet_b = ctx.wallet.clone();
        let mut info_b = ManagedWalletInfo::from_wallet(&wallet_b);

        // Fund A so its changeset carries every sub-field.
        let funding_tx =
            dashcore::Transaction::dummy(&ctx.receive_address, 0..1, &[750_000]);
        let result = ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);

        // Apply A's changeset to B.
        info_b.apply_changeset(&mut wallet_b, &result.changeset).expect("apply");

        // Balance must match.
        assert_eq!(info_b.balance.unconfirmed(), ctx.managed_wallet.balance.unconfirmed());
        assert_eq!(info_b.balance.spendable(), ctx.managed_wallet.balance.spendable());

        // The UTXO must be present on B with the same value.
        let account_b = info_b.first_bip44_managed_account().expect("bip44 on b");
        assert_eq!(account_b.utxos.len(), 1);
        assert_eq!(
            account_b.utxos.values().next().expect("utxo").txout.value,
            750_000
        );

        // The transaction record must be present on B.
        assert!(account_b.transactions.contains_key(&funding_tx.txid()));

        // G1: pool.highest_used must match between A and B after apply.
        let highest_a = ctx
            .managed_wallet
            .first_bip44_managed_account()
            .expect("bip44 on a")
            .account_type
            .address_pools()
            .iter()
            .find(|p| p.pool_type == AddressPoolType::External)
            .and_then(|p| p.highest_used);
        let highest_b = account_b
            .account_type
            .address_pools()
            .iter()
            .find(|p| p.pool_type == AddressPoolType::External)
            .and_then(|p| p.highest_used);
        assert_eq!(highest_a, highest_b, "external pool highest_used must match");

        // The address must be marked used on B — `mark_address_used`
        // returns false on a second call.
        let account_b_mut =
            info_b.first_bip44_managed_account_mut().expect("bip44 on b");
        let (changed, _) = account_b_mut.mark_address_used(&ctx.receive_address);
        assert!(!changed, "address must already be marked used after apply");
    }

    #[tokio::test]
    async fn apply_is_idempotent_on_sibling_wallet() {
        let mut ctx = TestWalletContext::new_random();
        let mut wallet_b = ctx.wallet.clone();
        let mut info_b = ManagedWalletInfo::from_wallet(&wallet_b);

        let funding_tx =
            dashcore::Transaction::dummy(&ctx.receive_address, 0..1, &[321_000]);
        let result = ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;

        // First apply.
        info_b.apply_changeset(&mut wallet_b, &result.changeset).expect("apply");
        let snapshot_balance = info_b.balance;
        let snapshot_utxo_count =
            info_b.first_bip44_managed_account().expect("bip44").utxos.len();
        let snapshot_tx_count =
            info_b.first_bip44_managed_account().expect("bip44").transactions.len();

        // Second apply — state must be identical.
        info_b.apply_changeset(&mut wallet_b, &result.changeset).expect("re-apply");
        assert_eq!(info_b.balance, snapshot_balance);
        assert_eq!(
            info_b.first_bip44_managed_account().expect("bip44").utxos.len(),
            snapshot_utxo_count
        );
        assert_eq!(
            info_b.first_bip44_managed_account().expect("bip44").transactions.len(),
            snapshot_tx_count
        );
    }

    /// Per-account buckets keyed by an `AccountType` that the target
    /// doesn't own must be silently skipped. Apply still succeeds.
    #[tokio::test]
    async fn apply_skips_buckets_for_unknown_account_types() {
        use crate::account::StandardAccountType;
        use crate::changeset::{AccountChangeSet, WalletChangeSet};
        use crate::wallet::initialization::WalletAccountCreationOptions;

        // Target has no BIP44 accounts at all.
        let mut wallet_b = crate::wallet::Wallet::new_random(
            crate::Network::Testnet,
            WalletAccountCreationOptions::None,
        )
        .expect("wallet b");
        let mut info_b = ManagedWalletInfo::from_wallet(&wallet_b);
        let balance_before = info_b.balance;

        // Build a changeset carrying a per_account bucket for an account
        // type the target doesn't know about.
        let unknown_type = AccountType::Standard {
            index: 99,
            standard_account_type: StandardAccountType::BIP44Account,
        };
        let mut cs = WalletChangeSet::default();
        let mut bucket = AccountChangeSet::default();
        bucket
            .addresses_used
            .insert(dashcore::Address::dummy(dashcore::Network::Testnet, 7));
        cs.per_account.insert(unknown_type, bucket);

        info_b.apply_changeset(&mut wallet_b, &cs).expect("apply must not fail");
        assert_eq!(info_b.balance, balance_before);
        assert_eq!(info_b.accounts.all_accounts().len(), 0);
    }

    /// G2: applying a changeset whose `account_keys.added` carries a new
    /// account type must derive and install it on the target.
    #[tokio::test]
    async fn apply_account_keys_creates_new_managed_account() {
        use crate::account::StandardAccountType;
        use crate::wallet::initialization::WalletAccountCreationOptions;

        // Target starts with no BIP44 accounts at all.
        let mut wallet_b = crate::wallet::Wallet::new_random(
            crate::Network::Testnet,
            WalletAccountCreationOptions::None,
        )
        .expect("wallet b");
        let mut info_b = ManagedWalletInfo::from_wallet(&wallet_b);
        assert!(info_b.first_bip44_managed_account().is_none());

        // Build a changeset that adds the BIP44 account type.
        let new_account_type = AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        };
        let cs = WalletChangeSet {
            account_keys: Some(crate::changeset::AccountKeyChangeSet {
                added: [new_account_type].into(),
            }),
            ..Default::default()
        };

        info_b.apply_changeset(&mut wallet_b, &cs).expect("apply");

        // The account must now exist on the target.
        assert!(
            info_b.first_bip44_managed_account().is_some(),
            "account_keys replay must install the managed account"
        );
        // And the wallet side must have it too.
        assert!(wallet_b.accounts.contains_account_type(&new_account_type));
    }

    /// G3: applying a mempool→confirmed UTXO upgrade must flip
    /// `is_confirmed` on the stored UTXO without losing the entry.
    #[tokio::test]
    async fn apply_upgrades_mempool_utxo_to_confirmed() {
        let mut ctx = TestWalletContext::new_random();

        // Sibling wallet B built from the same Wallet as ctx (identical
        // HD keys → addresses match → apply can route).
        let mut wallet_b = ctx.wallet.clone();
        let mut info_b = ManagedWalletInfo::from_wallet(&wallet_b);

        // Step 1: fund via mempool on A, capture the changeset, replay
        // onto B. B ends up with an unconfirmed UTXO.
        let funding_tx =
            dashcore::Transaction::dummy(&ctx.receive_address, 0..1, &[600_000]);
        let mempool_cs =
            ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await.changeset;
        info_b.apply_changeset(&mut wallet_b, &mempool_cs).expect("apply mempool");
        let account_b = info_b.first_bip44_managed_account().expect("bip44");
        let utxo_b = account_b.utxos.values().next().expect("utxo");
        assert!(!utxo_b.is_confirmed, "precondition: mempool utxo is unconfirmed");

        // Step 2: re-process the same tx with a block context on A and
        // apply the resulting changeset to B.
        let block_hash = BlockHash::from_slice(&[3u8; 32]).expect("hash");
        let block_ctx =
            TransactionContext::InBlock(BlockInfo::new(800, block_hash, 1_700_000_000));
        let block_cs = ctx.check_transaction(&funding_tx, block_ctx).await.changeset;
        info_b.apply_changeset(&mut wallet_b, &block_cs).expect("apply block");

        // The UTXO must still be present and now confirmed.
        let account_b = info_b.first_bip44_managed_account().expect("bip44");
        assert_eq!(account_b.utxos.len(), 1);
        let utxo_b = account_b.utxos.values().next().expect("utxo");
        assert!(utxo_b.is_confirmed, "utxo must be upgraded to confirmed after apply");
    }

    /// F3 regression: a stale changeset carrying an unconfirmed UTXO must
    /// not downgrade a live UTXO that has already advanced to confirmed
    /// in memory. Flags are monotonic — true wins, false loses.
    #[tokio::test]
    async fn apply_does_not_downgrade_confirmed_utxo_on_stale_replay() {
        let mut ctx = TestWalletContext::new_random();
        let mut wallet_b = ctx.wallet.clone();
        let mut info_b = ManagedWalletInfo::from_wallet(&wallet_b);

        // Capture the early mempool changeset.
        let funding_tx =
            dashcore::Transaction::dummy(&ctx.receive_address, 0..1, &[400_000]);
        let mempool_cs = ctx
            .check_transaction(&funding_tx, TransactionContext::Mempool)
            .await
            .changeset;

        // B lands the mempool tx first, then confirms it live.
        info_b.apply_changeset(&mut wallet_b, &mempool_cs).expect("apply mempool");
        {
            let account = info_b.first_bip44_managed_account_mut().expect("bip44");
            for utxo in account.utxos.values_mut() {
                utxo.is_confirmed = true;
            }
        }

        // Re-applying the stale mempool changeset must NOT regress
        // is_confirmed back to false.
        info_b.apply_changeset(&mut wallet_b, &mempool_cs).expect("apply stale");
        let account_b = info_b.first_bip44_managed_account().expect("bip44");
        let utxo_b = account_b.utxos.values().next().expect("utxo");
        assert!(utxo_b.is_confirmed, "stale replay must not downgrade confirmed utxo");
    }
}
