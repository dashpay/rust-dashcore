//! Accessor and query methods for WalletManager.

use crate::{
    current_timestamp, WalletCoreBalance, WalletError, WalletEvent, WalletId, WalletManager,
};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::TransactionRecord;
use key_wallet::{Account, Address, Network, Utxo, Wallet};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::broadcast;

impl<T: WalletInfoInterface> WalletManager<T> {
    /// Get a wallet by ID
    pub fn get_wallet(&self, wallet_id: &WalletId) -> Option<&Wallet> {
        self.wallets.get(wallet_id)
    }

    /// Get wallet info by ID
    pub fn get_wallet_info(&self, wallet_id: &WalletId) -> Option<&T> {
        self.wallet_infos.get(wallet_id)
    }

    /// Get mutable wallet info by ID
    pub fn get_wallet_info_mut(&mut self, wallet_id: &WalletId) -> Option<&mut T> {
        self.wallet_infos.get_mut(wallet_id)
    }

    /// Get both wallet and info by ID
    pub fn get_wallet_and_info(&self, wallet_id: &WalletId) -> Option<(&Wallet, &T)> {
        match (self.wallets.get(wallet_id), self.wallet_infos.get(wallet_id)) {
            (Some(wallet), Some(info)) => Some((wallet, info)),
            _ => None,
        }
    }

    /// Get immutable wallet + mutable info by ID (split borrow on two maps).
    pub fn get_wallet_and_info_mut(&mut self, wallet_id: &WalletId) -> Option<(&Wallet, &mut T)> {
        match (self.wallets.get(wallet_id), self.wallet_infos.get_mut(wallet_id)) {
            (Some(wallet), Some(info)) => Some((wallet, info)),
            _ => None,
        }
    }

    /// Get mutable wallet + mutable info by ID (split borrow on two maps).
    ///
    /// Used by `apply_changeset` which needs `&mut Wallet` to idempotently
    /// re-derive HD accounts via `Wallet::add_account` during restore.
    pub fn get_wallet_mut_and_info_mut(
        &mut self,
        wallet_id: &WalletId,
    ) -> Option<(&mut Wallet, &mut T)> {
        match (self.wallets.get_mut(wallet_id), self.wallet_infos.get_mut(wallet_id)) {
            (Some(wallet), Some(info)) => Some((wallet, info)),
            _ => None,
        }
    }

    /// Insert a pre-built wallet and info pair.
    pub fn insert_wallet(&mut self, wallet: Wallet, info: T) -> Result<WalletId, WalletError> {
        let wallet_id = wallet.compute_wallet_id();
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }
        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, info);
        self.bump_structural_revision();
        Ok(wallet_id)
    }

    /// Remove a wallet
    pub fn remove_wallet(&mut self, wallet_id: &WalletId) -> Result<(Wallet, T), WalletError> {
        let wallet =
            self.wallets.remove(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let info =
            self.wallet_infos.remove(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        // Absorb the removed wallet's account-level revision so the total
        // stays monotonically increasing even though we lost a contributor.
        self.structural_revision += info.monitor_revision() + 1;
        Ok((wallet, info))
    }

    /// List all wallet IDs
    pub fn list_wallets(&self) -> Vec<&WalletId> {
        self.wallets.keys().collect()
    }

    /// Get all wallets
    pub fn get_all_wallets(&self) -> &BTreeMap<WalletId, Wallet> {
        &self.wallets
    }

    /// Get all wallet infos
    pub fn get_all_wallet_infos(&self) -> &BTreeMap<WalletId, T> {
        &self.wallet_infos
    }

    /// Get wallet count
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Get all accounts in a specific wallet
    pub fn get_accounts(&self, wallet_id: &WalletId) -> Result<Vec<&Account>, WalletError> {
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        Ok(wallet.all_accounts())
    }

    /// Get account by index in a specific wallet
    pub fn get_account(
        &self,
        wallet_id: &WalletId,
        index: u32,
    ) -> Result<Option<&Account>, WalletError> {
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        Ok(wallet.get_bip44_account(index))
    }

    /// Get transaction history for a specific wallet
    pub fn wallet_transaction_history(
        &self,
        wallet_id: &WalletId,
    ) -> Result<Vec<&TransactionRecord>, WalletError> {
        let managed_info =
            self.wallet_infos.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        Ok(managed_info.transaction_history())
    }

    /// Get UTXOs for all wallets across all networks
    pub fn get_all_utxos(&self) -> Vec<&Utxo> {
        let mut all_utxos = Vec::new();
        for info in self.wallet_infos.values() {
            all_utxos.extend(info.utxos().iter());
        }
        all_utxos
    }

    /// Get UTXOs for a specific wallet
    pub fn wallet_utxos(&self, wallet_id: &WalletId) -> Result<BTreeSet<&Utxo>, WalletError> {
        let wallet_info =
            self.wallet_infos.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        Ok(wallet_info.utxos())
    }

    /// Get total balance across all wallets and networks
    pub fn get_total_balance(&self) -> u64 {
        self.wallet_infos.values().map(|info| info.balance().total()).sum()
    }

    /// Get balance for a specific wallet
    pub fn get_wallet_balance(
        &self,
        wallet_id: &WalletId,
    ) -> Result<WalletCoreBalance, WalletError> {
        let wallet_info =
            self.wallet_infos.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        Ok(wallet_info.balance())
    }

    /// Update wallet metadata
    pub fn update_wallet_metadata(
        &mut self,
        wallet_id: &WalletId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<(), WalletError> {
        let managed_info =
            self.wallet_infos.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        if let Some(new_name) = name {
            managed_info.set_name(new_name);
        }

        if let Some(desc) = description {
            managed_info.set_description(Some(desc));
        }

        managed_info.update_last_synced(current_timestamp());

        Ok(())
    }

    /// Get the network this manager is configured for
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get monitored addresses for all wallets
    pub fn monitored_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        for info in self.wallet_infos.values() {
            addresses.extend(info.monitored_addresses());
        }
        addresses
    }

    /// Subscribe to wallet events.
    ///
    /// Returns a receiver that will receive all wallet events emitted by this manager.
    pub fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    /// Get a reference to the event sender for emitting events.
    pub fn event_sender(&self) -> &broadcast::Sender<WalletEvent> {
        &self.event_sender
    }

    /// Return the total monitor revision (structural + per-wallet account revisions).
    pub fn monitor_revision(&self) -> u64 {
        self.structural_revision
            + self.wallet_infos.values().map(|w| w.monitor_revision()).sum::<u64>()
    }

    /// Snapshot the current balance of every managed wallet.
    pub(crate) fn snapshot_balances(&self) -> Vec<(WalletId, WalletCoreBalance)> {
        self.wallet_infos.iter().map(|(id, info)| (*id, info.balance())).collect()
    }

    /// Emit `BalanceUpdated` events for wallets whose balance differs from the snapshot.
    pub(crate) fn emit_balance_changes(&self, old_balances: &[(WalletId, WalletCoreBalance)]) {
        for (wallet_id, old_balance) in old_balances {
            if let Some(info) = self.wallet_infos.get(wallet_id) {
                let new_balance = info.balance();
                if *old_balance != new_balance {
                    let event = WalletEvent::BalanceUpdated {
                        wallet_id: *wallet_id,
                        spendable: new_balance.spendable(),
                        unconfirmed: new_balance.unconfirmed(),
                        immature: new_balance.immature(),
                        locked: new_balance.locked(),
                    };
                    let _ = self.event_sender.send(event);
                }
            }
        }
    }

    /// Get all outpoints from wallet UTXOs across all managed wallets.
    /// Used for bloom filter construction to detect spends of our UTXOs.
    pub fn watched_outpoints(&self) -> Vec<dashcore::OutPoint> {
        let mut outpoints = Vec::new();
        for info in self.wallet_infos.values() {
            outpoints.extend(info.utxos().into_iter().map(|u| u.outpoint));
        }
        outpoints
    }
}

// ---------------------------------------------------------------------------
// apply_changeset — concrete-type wrapper for WalletManager<ManagedWalletInfo>.
// ---------------------------------------------------------------------------

impl WalletManager<key_wallet::wallet::managed_wallet_info::ManagedWalletInfo> {
    /// Apply a [`key_wallet::changeset::WalletChangeSet`] to the given
    /// wallet, replaying its deltas idempotently onto the in-memory state.
    ///
    /// This is the restore path: a persister reads a persisted changeset
    /// from disk and hands it here to converge the runtime state. Calling
    /// `apply_changeset` twice with the same changeset produces the same
    /// state as calling it once.
    ///
    /// - Returns [`WalletError::WalletNotFound`] if the wallet is not in
    ///   this manager. The wallet must have been inserted via
    ///   `insert_wallet` before apply can route into it.
    /// - Returns [`WalletError::ApplyChangeSet`] if re-deriving an account
    ///   from `cs.account_keys` fails (watch-only wallet without the xpub,
    ///   or network mismatch). Orphan UTXOs / transaction records that
    ///   fail to route are silently skipped, not reported.
    /// - Bumps the structural revision only when the changeset is
    ///   non-empty, so observers don't get poked for pure no-op restores.
    pub fn apply_changeset(
        &mut self,
        wallet_id: &WalletId,
        changeset: key_wallet::changeset::WalletChangeSet,
    ) -> Result<(), WalletError> {
        use key_wallet::changeset::Merge;
        // Capture is_empty before consuming so we can decide whether to
        // bump the structural revision. After this point `changeset` is
        // moved into the apply path; no clones happen anywhere on the
        // way down.
        let was_non_empty = !changeset.is_empty();
        let (wallet, info) = self
            .get_wallet_mut_and_info_mut(wallet_id)
            .ok_or(WalletError::WalletNotFound(*wallet_id))?;
        info.apply_changeset(wallet, changeset)?;
        if was_non_empty {
            self.bump_structural_revision();
        }
        Ok(())
    }
}

#[cfg(test)]
mod apply_tests {
    use super::*;
    use key_wallet::changeset::{BalanceChangeSet, WalletChangeSet};
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet::Network as KwNetwork;

    #[test]
    fn apply_changeset_returns_not_found_for_unknown_wallet() {
        let mut wm: WalletManager<ManagedWalletInfo> = WalletManager::new(KwNetwork::Testnet);
        let unknown_id = [0u8; 32];
        let cs = WalletChangeSet::default();

        let err = wm.apply_changeset(&unknown_id, cs).unwrap_err();
        assert!(matches!(err, WalletError::WalletNotFound(_)));
    }

    #[test]
    fn apply_empty_changeset_does_not_bump_revision() {
        let mut wm: WalletManager<ManagedWalletInfo> = WalletManager::new(KwNetwork::Testnet);
        let wallet = Wallet::new_random(KwNetwork::Testnet, WalletAccountCreationOptions::Default)
            .expect("wallet");
        let info = ManagedWalletInfo::from_wallet(&wallet);
        let wallet_id = wm.insert_wallet(wallet, info).expect("insert");

        let rev_before = wm.structural_revision;
        wm.apply_changeset(&wallet_id, WalletChangeSet::default()).expect("apply");
        assert_eq!(
            wm.structural_revision, rev_before,
            "empty changeset must not bump structural_revision"
        );
    }

    #[test]
    fn apply_non_empty_changeset_bumps_revision() {
        let mut wm: WalletManager<ManagedWalletInfo> = WalletManager::new(KwNetwork::Testnet);
        let wallet = Wallet::new_random(KwNetwork::Testnet, WalletAccountCreationOptions::Default)
            .expect("wallet");
        let info = ManagedWalletInfo::from_wallet(&wallet);
        let wallet_id = wm.insert_wallet(wallet, info).expect("insert");

        let rev_before = wm.structural_revision;
        // A BalanceChangeSet with any non-zero delta counts as non-empty.
        let cs = WalletChangeSet {
            balance: Some(BalanceChangeSet {
                spendable_delta: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        wm.apply_changeset(&wallet_id, cs).expect("apply");
        assert!(
            wm.structural_revision > rev_before,
            "non-empty changeset must bump structural_revision"
        );
    }
}
