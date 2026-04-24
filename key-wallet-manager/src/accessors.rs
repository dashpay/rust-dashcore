//! Accessor and query methods for WalletManager.

use crate::{
    current_timestamp, WalletCoreBalance, WalletError, WalletEvent, WalletId, WalletManager,
};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::TransactionRecord;
use key_wallet::{Account, Address, Network, Utxo, Wallet};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::broadcast;

impl<T: WalletInfoInterface + Send + Sync + 'static> WalletManager<T> {
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
                        confirmed: new_balance.confirmed(),
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
