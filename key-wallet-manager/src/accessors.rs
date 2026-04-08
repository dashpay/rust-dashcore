//! Accessor and query methods for WalletManager.

use crate::{
    current_timestamp, WalletCoreBalance, WalletError, WalletEvent, WalletId, WalletManager,
};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::TransactionRecord;
use key_wallet::{Account, Address, Network, Utxo};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

impl<T: WalletInfoInterface> WalletManager<T> {
    /// Get the shared `Arc<RwLock<T>>` for a wallet.
    ///
    /// Consumers can clone the returned `Arc` to hold a long-lived handle
    /// to the wallet state (e.g. `PlatformWallet` keeps a clone).
    pub fn get_wallet_arc(&self, wallet_id: &WalletId) -> Option<Arc<RwLock<T>>> {
        self.wallets.get(wallet_id).cloned()
    }

    /// Insert an externally-created `Arc<RwLock<T>>` into the manager.
    ///
    /// This allows a caller (e.g. platform-wallet) to create the state,
    /// wrap it in `Arc::new(RwLock::new(state))`, keep a clone for its own
    /// handle, and insert the same `Arc` into `WalletManager`.
    pub fn insert_wallet_state(
        &mut self,
        wallet_id: WalletId,
        state: Arc<RwLock<T>>,
    ) -> Result<(), WalletError> {
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }
        self.wallets.insert(wallet_id, state);
        self.bump_structural_revision();
        Ok(())
    }

    /// Remove a wallet and return its shared state Arc.
    pub fn remove_wallet(
        &mut self,
        wallet_id: &WalletId,
    ) -> Result<Arc<RwLock<T>>, WalletError> {
        let arc =
            self.wallets.remove(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        // Absorb the removed wallet's account-level revision so the total
        // stays monotonically increasing even though we lost a contributor.
        // Use try_read to get the revision without blocking.
        let removed_rev = arc
            .try_read()
            .map(|s| s.monitor_revision())
            .unwrap_or(0);
        self.structural_revision += removed_rev + 1;
        Ok(arc)
    }

    /// List all wallet IDs
    pub fn list_wallets(&self) -> Vec<&WalletId> {
        self.wallets.keys().collect()
    }

    /// Get all wallet state Arcs (immutable view of the map).
    pub fn get_all_wallet_arcs(
        &self,
    ) -> &std::collections::BTreeMap<WalletId, Arc<RwLock<T>>> {
        &self.wallets
    }

    /// Get wallet count
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Get all accounts in a specific wallet (async, acquires read lock).
    pub async fn get_accounts(
        &self,
        wallet_id: &WalletId,
    ) -> Result<Vec<Account>, WalletError> {
        let arc =
            self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let state = arc.read().await;
        Ok(state.wallet().all_accounts().into_iter().cloned().collect())
    }

    /// Get account by index in a specific wallet (async, acquires read lock).
    pub async fn get_account(
        &self,
        wallet_id: &WalletId,
        index: u32,
    ) -> Result<Option<Account>, WalletError> {
        let arc =
            self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let state = arc.read().await;
        Ok(state.wallet().get_bip44_account(index).cloned())
    }

    /// Get transaction history for a specific wallet (async, acquires read lock).
    pub async fn wallet_transaction_history(
        &self,
        wallet_id: &WalletId,
    ) -> Result<Vec<TransactionRecord>, WalletError> {
        let arc =
            self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let state = arc.read().await;
        Ok(state.transaction_history().into_iter().cloned().collect())
    }

    /// Get UTXOs for all wallets (sync, uses try_read).
    pub fn get_all_utxos(&self) -> Vec<Utxo> {
        let mut all_utxos = Vec::new();
        for arc in self.wallets.values() {
            if let Ok(state) = arc.try_read() {
                all_utxos.extend(state.utxos().into_iter().cloned());
            }
        }
        all_utxos
    }

    /// Get UTXOs for a specific wallet (async, acquires read lock).
    pub async fn wallet_utxos(
        &self,
        wallet_id: &WalletId,
    ) -> Result<BTreeSet<Utxo>, WalletError> {
        let arc =
            self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let state = arc.read().await;
        Ok(state.utxos().into_iter().cloned().collect())
    }

    /// Get total balance across all wallets (sync, uses try_read).
    pub fn get_total_balance(&self) -> u64 {
        self.wallets
            .values()
            .filter_map(|arc| arc.try_read().ok())
            .map(|s| s.balance().total())
            .sum()
    }

    /// Get balance for a specific wallet (async, acquires read lock).
    pub async fn get_wallet_balance(
        &self,
        wallet_id: &WalletId,
    ) -> Result<WalletCoreBalance, WalletError> {
        let arc =
            self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let state = arc.read().await;
        Ok(state.balance())
    }

    /// Update wallet metadata (async, acquires write lock).
    pub async fn update_wallet_metadata(
        &mut self,
        wallet_id: &WalletId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<(), WalletError> {
        let arc =
            self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        let mut state = arc.write().await;

        if let Some(new_name) = name {
            state.set_name(new_name);
        }

        if let Some(desc) = description {
            state.set_description(Some(desc));
        }

        state.update_last_synced(current_timestamp());

        Ok(())
    }

    /// Get the network this manager is configured for
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get monitored addresses for all wallets (async, acquires read lock).
    pub async fn monitored_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        for arc in self.wallets.values() {
            let state = arc.read().await;
            addresses.extend(state.monitored_addresses());
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
    /// Async method, acquires read locks.
    pub async fn monitor_revision(&self) -> u64 {
        let mut sum = 0u64;
        for arc in self.wallets.values() {
            let state = arc.read().await;
            sum += state.monitor_revision();
        }
        self.structural_revision + sum
    }

    /// Snapshot the current balance of every managed wallet (async, acquires read locks).
    pub(crate) async fn snapshot_balances(&self) -> Vec<(WalletId, WalletCoreBalance)> {
        let mut balances = Vec::with_capacity(self.wallets.len());
        for (id, arc) in self.wallets.iter() {
            let state = arc.read().await;
            balances.push((*id, state.balance()));
        }
        balances
    }

    /// Emit `BalanceUpdated` events for wallets whose balance differs from the snapshot.
    pub(crate) async fn emit_balance_changes(&self, old_balances: &[(WalletId, WalletCoreBalance)]) {
        for (wallet_id, old_balance) in old_balances {
            if let Some(arc) = self.wallets.get(wallet_id) {
                let state = arc.read().await;
                let new_balance = state.balance();
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
    /// Async method, acquires read locks.
    pub async fn watched_outpoints(&self) -> Vec<dashcore::OutPoint> {
        let mut outpoints = Vec::new();
        for arc in self.wallets.values() {
            let state = arc.read().await;
            outpoints.extend(state.utxos().into_iter().map(|u| u.outpoint));
        }
        outpoints
    }
}
