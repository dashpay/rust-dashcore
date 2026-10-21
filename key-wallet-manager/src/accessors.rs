//! Accessor and query methods for WalletManager.

use crate::{
    current_timestamp, WalletCoreBalance, WalletError, WalletEvent, WalletId, WalletManager,
};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::TransactionRecord;
use key_wallet::{Account, Address, Network, Utxo, Wallet};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::{broadcast, mpsc};

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

    /// Immutable wallet + mutable info — split borrow on two maps.
    pub fn get_wallet_and_info_mut(&mut self, wallet_id: &WalletId) -> Option<(&Wallet, &mut T)> {
        match (self.wallets.get(wallet_id), self.wallet_infos.get_mut(wallet_id)) {
            (Some(wallet), Some(info)) => Some((wallet, info)),
            _ => None,
        }
    }

    /// Mutable wallet + mutable info — split borrow on two maps.
    ///
    /// Used when the caller needs to mutate both the `Wallet` (e.g. to
    /// idempotently re-derive HD accounts via `Wallet::add_account` during
    /// changeset replay) and the associated info in the same scope.
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
    ///
    /// Errors with [`WalletError::WalletExists`] if a wallet with the same ID is
    /// already registered. On success bumps the structural revision.
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

    /// Install a durable persistence consumer and take its event receiver
    /// (dashpay/platform#4069).
    ///
    /// Persistence delivery is opt-in: the first call **creates** the lossless,
    /// unbounded persistence channel, installs the send half on the manager, and
    /// returns the receive half; every subsequent call returns `None`. Creating
    /// the channel only when a consumer asks for it means a manager that never
    /// installs a consumer never accumulates an undrained backlog of events (an
    /// unbounded `mpsc` with no reader would otherwise grow without limit).
    ///
    /// The platform durable consumer calls this before the manager is shared
    /// with any producer, then drains the stream losslessly (see the
    /// `persistence_sender` field docs). Because installation precedes emission,
    /// no events are emitted before the consumer is in place; unlike
    /// [`subscribe_events`](Self::subscribe_events) there is no
    /// subscribe-before-publish race, and unlike a `broadcast::Receiver` the
    /// unbounded `mpsc` never `Lagged`s a row-bearing or watermark event.
    pub fn take_persistence_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<WalletEvent>> {
        if self.persistence_sender.is_some() {
            // A consumer has already been installed; the receiver is taken once.
            return None;
        }
        // Installing after emission has begun violates the documented contract:
        // everything emitted so far reached only the lossy broadcast and is
        // permanently absent from the persistence stream, with no
        // `Lagged`-style marker to reveal the gap. The receiver is still
        // returned (delivery is lossless from this point on), but the gap must
        // not be silent — it is exactly the invisible-loss failure mode this
        // channel exists to eliminate.
        if self.events_emitted.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                "take_persistence_receiver called after wallet events were already emitted; \
                 earlier events are absent from the persistence stream. Install the persistence \
                 consumer before the manager is shared with any producer \
                 (dashpay/platform#4069)."
            );
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        self.persistence_sender = Some(sender);
        Some(receiver)
    }

    /// Return the total monitor revision (structural + per-wallet account revisions).
    pub fn monitor_revision(&self) -> u64 {
        self.structural_revision
            + self.wallet_infos.values().map(|w| w.monitor_revision()).sum::<u64>()
    }

    /// Snapshot the current balance of every managed wallet.
    pub(crate) fn snapshot_balances(&self) -> BTreeMap<WalletId, WalletCoreBalance> {
        self.wallet_infos.iter().map(|(id, info)| (*id, info.balance())).collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TEST_MNEMONIC;
    use key_wallet::mnemonic::Mnemonic;
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

    fn build_wallet() -> Wallet {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        Wallet::from_mnemonic(mnemonic, Network::Testnet, WalletAccountCreationOptions::Default)
            .expect("wallet from mnemonic")
    }

    #[test]
    fn insert_wallet_rejects_duplicate() {
        let mut manager: WalletManager<ManagedWalletInfo> = WalletManager::new(Network::Testnet);
        let wallet = build_wallet();
        let info = ManagedWalletInfo::from_wallet(&wallet, 0);

        let id =
            manager.insert_wallet(wallet.clone(), info.clone()).expect("first insert succeeds");

        match manager.insert_wallet(wallet, info) {
            Err(WalletError::WalletExists(dup_id)) => assert_eq!(dup_id, id),
            other => panic!("expected WalletExists, got {:?}", other),
        }
    }
}
