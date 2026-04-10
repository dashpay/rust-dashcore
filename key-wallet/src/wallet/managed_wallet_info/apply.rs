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
//! - **No re-emission.** `apply` does not return a new changeset. If it did,
//!   `apply(apply(cs))` would cascade. All mutation bookkeeping done here
//!   discards any inner changesets returned by helpers.
//! - **Best-effort routing.** UTXO / transaction changes are routed to the
//!   owning account via `find_account_by_address_mut` /
//!   `find_account_with_utxo_mut`. Entries that cannot be routed (e.g. an
//!   orphaned UTXO whose address doesn't match any pool) are silently
//!   skipped — the persister is authoritative and the runtime can't do
//!   anything else with them.

use crate::changeset::WalletChangeSet;
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::wallet::Wallet;

impl ManagedWalletInfo {
    /// Apply a [`WalletChangeSet`] onto this managed wallet info, using
    /// `wallet` as the source of HD key material for any account types that
    /// need to be re-derived.
    ///
    /// See the module docs for invariants. Typical caller is
    /// `WalletManager::apply_changeset`, which performs the split borrow of
    /// `(&mut Wallet, &mut ManagedWalletInfo)` under a single write lock.
    pub fn apply_changeset(&mut self, wallet: &mut Wallet, cs: &WalletChangeSet) {
        // ------------------------------------------------------------------
        // 1. account_keys — re-derive HD accounts from the seed and mirror
        //    them into `self.accounts`. Both `Wallet::add_account(ty, None)`
        //    and `ManagedWalletInfo::add_managed_account` are idempotent
        //    wrappers that return Ok on replay.
        // ------------------------------------------------------------------
        if let Some(account_keys) = &cs.account_keys {
            for account_type in &account_keys.added {
                // Adding to the wallet derives the keys from the seed; it's
                // idempotent when xpub is None (no-op if the account type
                // already exists).
                if wallet.add_account(*account_type, None).is_err() {
                    // Non-derivable (watch-only wallet missing the xpub, or
                    // network mismatch). Skip — the persister will still
                    // carry the entry on the next save cycle.
                    continue;
                }
                // Mirror into the managed collection if not already present.
                let managed_type_matches =
                    self.accounts.all_accounts().iter().any(|a| {
                        a.account_type.to_account_type() == *account_type
                    });
                if !managed_type_matches {
                    let _ = self.add_managed_account(wallet, *account_type);
                }
            }
        }

        // ------------------------------------------------------------------
        // 2. account_states — addresses_used + last_revealed. Both are
        //    idempotent at the pool level.
        // ------------------------------------------------------------------
        if let Some(account_states) = &cs.account_states {
            for address in &account_states.addresses_used {
                if let Some(account) = self.find_account_by_address_mut(address) {
                    // Discard the returned changeset — apply must not
                    // re-emit. The account's `mark_address_used` is
                    // already idempotent on replay.
                    let _ = account.mark_address_used(address);
                }
            }
            for ((account_index, pool_type), highest_revealed) in
                &account_states.last_revealed
            {
                // Find the managed account by its index. `last_revealed` is
                // only populated for indexable account types (Standard,
                // CoinJoin, DashpayReceivingFunds, …) so matching on index
                // is sufficient here.
                let Some(account) = self
                    .accounts
                    .all_accounts_mut()
                    .into_iter()
                    .find(|a| a.index() == Some(*account_index))
                else {
                    continue;
                };
                for pool in account.account_type.address_pools_mut() {
                    if pool.pool_type == *pool_type {
                        pool.set_last_revealed(*highest_revealed);
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // 3. utxos — additions route by address; spends and instant locks
        //    route by outpoint. Additions are upserts (the changeset might
        //    carry an updated Utxo that upgrades is_confirmed /
        //    is_instantlocked on an existing entry).
        // ------------------------------------------------------------------
        if let Some(utxos) = &cs.utxos {
            for (outpoint, utxo) in &utxos.added {
                if let Some(account) = self.find_account_by_address_mut(&utxo.address) {
                    account.insert_utxo(*outpoint, utxo.clone());
                }
            }
            for outpoint in &utxos.spent {
                if let Some(account) = self.find_account_with_utxo_mut(outpoint) {
                    account.remove_utxo(outpoint);
                }
            }
            for outpoint in &utxos.instant_locked {
                if let Some(account) = self.find_account_with_utxo_mut(outpoint) {
                    if let Some(u) = account.utxos.get_mut(outpoint) {
                        u.is_instantlocked = true;
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // 4. transactions — insert / upsert records. Routed by looking at
        //    any address referenced by the record's output details.
        //    Transaction records persist per-account; if a record's output
        //    addresses don't match any account (e.g. a send-only tx whose
        //    inputs we owned but outputs go elsewhere) we can't route by
        //    address alone — fall back to scanning accounts for a txid
        //    match from the UTXO set.
        // ------------------------------------------------------------------
        if let Some(transactions) = &cs.transactions {
            for (txid, record) in &transactions.records {
                // Route by checking which account owns any UTXO from this
                // txid — that account is the one that recorded it.
                let owning = self.accounts.all_accounts_mut().into_iter().find(|a| {
                    a.transactions.contains_key(txid)
                        || a.utxos.values().any(|u| u.outpoint.txid == *txid)
                });
                if let Some(account) = owning {
                    account.transactions.insert(*txid, record.clone());
                    continue;
                }
                // Last-resort fallback: route via any address present in
                // the tx's witness outputs stored on the record.
                let fallback_addr = record
                    .output_details
                    .iter()
                    .find_map(|out| {
                        record.transaction.output.get(out.index as usize).and_then(
                            |txout| {
                                crate::Address::from_script(
                                    &txout.script_pubkey,
                                    self.network,
                                )
                                .ok()
                            },
                        )
                    });
                if let Some(addr) = fallback_addr {
                    if let Some(account) = self.find_account_by_address_mut(&addr) {
                        account.transactions.insert(*txid, record.clone());
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // 5. chain — set synced height and latest block hash. `block_hash`
        //    lives on the individual transaction records via their
        //    TransactionContext, so only `synced_height` lands on metadata.
        // ------------------------------------------------------------------
        if let Some(chain) = &cs.chain {
            if let Some(height) = chain.synced_height {
                if height > self.metadata.synced_height {
                    self.metadata.synced_height = height;
                }
            }
            // `chain.block_hash` is informational — the authoritative block
            // hash lives on the confirmed transactions' contexts, already
            // restored above.
        }

        // ------------------------------------------------------------------
        // 6. balance — recompute from the now-restored UTXO set. The
        //    cached deltas in `cs.balance` are ignored because UTXO-driven
        //    recomputation is authoritative after the UTXO set is in
        //    place. Discard the returned changeset (apply does not
        //    re-emit).
        // ------------------------------------------------------------------
        let _ = self.update_balance();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestWalletContext;
    use crate::transaction_checking::TransactionContext;

    /// Round-trip: mutate wallet A via check_core_transaction, capture the
    /// changeset, apply it to a sibling wallet B built from the same
    /// `Wallet` (so derivation paths match), and assert that B converges to
    /// A's state.
    #[tokio::test]
    async fn apply_funding_changeset_mirrors_state_to_sibling_wallet() {
        let mut ctx = TestWalletContext::new_random();

        // Sibling B: a fresh ManagedWalletInfo built from the same Wallet.
        // This gives B identical HD keys (so addresses match) but zero
        // runtime state.
        let mut wallet_b = ctx.wallet.clone();
        let mut info_b = ManagedWalletInfo::from_wallet(&wallet_b);

        // Fund A so its changeset carries every sub-field.
        let funding_tx =
            dashcore::Transaction::dummy(&ctx.receive_address, 0..1, &[750_000]);
        let result = ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);

        // Apply A's changeset to B.
        info_b.apply_changeset(&mut wallet_b, &result.changeset);

        // Balance must match.
        assert_eq!(info_b.balance.unconfirmed(), ctx.managed_wallet.balance.unconfirmed());
        assert_eq!(info_b.balance.spendable(), ctx.managed_wallet.balance.spendable());

        // The UTXO must be present on B with the same value.
        let account_b = info_b.first_bip44_managed_account().expect("bip44 on b");
        assert_eq!(account_b.utxos.len(), 1);
        assert_eq!(account_b.utxos.values().next().unwrap().txout.value, 750_000);

        // The transaction record must be present on B.
        assert!(account_b.transactions.contains_key(&funding_tx.txid()));

        // The address must be marked used on B — `mark_address_used`
        // returns false on a second call.
        let account_b_mut = info_b.first_bip44_managed_account_mut().unwrap();
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
        info_b.apply_changeset(&mut wallet_b, &result.changeset);
        let snapshot_balance = info_b.balance;
        let snapshot_utxo_count =
            info_b.first_bip44_managed_account().unwrap().utxos.len();
        let snapshot_tx_count =
            info_b.first_bip44_managed_account().unwrap().transactions.len();

        // Second apply — state must be identical.
        info_b.apply_changeset(&mut wallet_b, &result.changeset);
        assert_eq!(info_b.balance, snapshot_balance);
        assert_eq!(
            info_b.first_bip44_managed_account().unwrap().utxos.len(),
            snapshot_utxo_count
        );
        assert_eq!(
            info_b.first_bip44_managed_account().unwrap().transactions.len(),
            snapshot_tx_count
        );
    }

    #[tokio::test]
    async fn apply_ignores_entries_that_cannot_be_routed() {
        // Target wallet has no knowledge of source wallet's addresses —
        // apply must silently skip unroutable entries rather than panic.
        let mut ctx_source = TestWalletContext::new_random();
        let mut ctx_target = TestWalletContext::new_random();

        let funding_tx = dashcore::Transaction::dummy(
            &ctx_source.receive_address,
            0..1,
            &[42_000],
        );
        let result = ctx_source
            .check_transaction(&funding_tx, TransactionContext::Mempool)
            .await;

        let balance_before = ctx_target.managed_wallet.balance;
        let mut target_wallet = ctx_target.wallet.clone();
        ctx_target
            .managed_wallet
            .apply_changeset(&mut target_wallet, &result.changeset);

        // Balance and UTXO set must be unchanged — the source's address
        // isn't owned by the target, so no routing succeeds.
        assert_eq!(ctx_target.managed_wallet.balance, balance_before);
        assert_eq!(
            ctx_target.managed_wallet.first_bip44_managed_account().unwrap().utxos.len(),
            0
        );
    }
}
