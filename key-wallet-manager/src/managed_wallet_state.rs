//! Combined wallet state that owns both the immutable `Wallet` and the
//! mutable `ManagedWalletInfo`, plus an optional persistence layer.
//!
//! `ManagedWalletState` implements all the traits that `WalletManager`
//! requires on its per-wallet type parameter (`WalletInfoInterface`,
//! `WalletTransactionChecker`, `ManagedAccountOperations`), delegating
//! to the appropriate inner field.

use std::collections::BTreeSet;

use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address as DashAddress, Transaction, Txid};

use key_wallet::account::AccountType;
use key_wallet::bip32::ExtendedPubKey;
use key_wallet::changeset::{Merge, UtxoChangeSet};
use key_wallet::managed_account::managed_account_collection::ManagedAccountCollection;
use key_wallet::transaction_checking::account_checker::TransactionCheckResult;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::{ManagedWalletInfo, TransactionRecord};
use key_wallet::transaction_checking::WalletTransactionChecker;
use key_wallet::{Network, Utxo, Wallet, WalletCoreBalance};

use crate::persistence::{NoPersistence, WalletPersistence};

/// Combined per-wallet state used by `WalletManager`.
///
/// Bundles the immutable key material (`Wallet`), the mutable runtime
/// state (`ManagedWalletInfo`), and an optional persistence layer.
/// This replaces the previous two-map design where `Wallet` and
/// `ManagedWalletInfo` were stored separately.
#[derive(Debug)]
pub struct ManagedWalletState<P: WalletPersistence = NoPersistence> {
    /// The immutable wallet containing keys and account structure.
    pub(crate) wallet: Wallet,
    /// The mutable wallet metadata, accounts, UTXOs, and balances.
    pub(crate) wallet_info: ManagedWalletInfo,
    /// Persistence backend for changesets produced by transaction processing.
    pub(crate) persister: P,
}

impl<P: WalletPersistence + std::fmt::Debug> ManagedWalletState<P> {
    /// Create a new `ManagedWalletState` from its components.
    pub fn new(wallet: Wallet, wallet_info: ManagedWalletInfo, persister: P) -> Self {
        Self {
            wallet,
            wallet_info,
            persister,
        }
    }

    /// Immutable access to the wallet key material.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Mutable access to the wallet key material.
    pub fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// Immutable access to the mutable wallet metadata / accounts / UTXOs.
    pub fn wallet_info(&self) -> &ManagedWalletInfo {
        &self.wallet_info
    }

    /// Mutable access to the mutable wallet metadata / accounts / UTXOs.
    pub fn wallet_info_mut(&mut self) -> &mut ManagedWalletInfo {
        &mut self.wallet_info
    }

    /// Immutable access to the persistence backend.
    pub fn persister(&self) -> &P {
        &self.persister
    }

    /// Mutable access to the persistence backend.
    pub fn persister_mut(&mut self) -> &mut P {
        &mut self.persister
    }

    /// Split borrow: returns `(&Wallet, &mut ManagedWalletInfo)` simultaneously.
    ///
    /// This avoids the borrow-checker conflict that arises when calling
    /// `wallet()` and `wallet_info_mut()` on the same `ManagedWalletState`,
    /// because both route through `&self` / `&mut self`.
    pub fn wallet_and_info_mut(&mut self) -> (&Wallet, &mut ManagedWalletInfo) {
        (&self.wallet, &mut self.wallet_info)
    }
}

// ---------------------------------------------------------------------------
// WalletInfoInterface — delegate to `self.wallet_info`, with `wallet()` /
// `wallet_mut()` returning `&self.wallet` / `&mut self.wallet`.
// ---------------------------------------------------------------------------

impl<P: WalletPersistence + std::fmt::Debug + Default> WalletInfoInterface for ManagedWalletState<P> {
    fn from_wallet(wallet: &Wallet) -> Self {
        let wallet_info = ManagedWalletInfo::from_wallet(wallet);
        Self {
            wallet: wallet.clone(),
            wallet_info,
            persister: P::default(),
        }
    }

    fn from_wallet_with_name(wallet: &Wallet, name: String) -> Self {
        let wallet_info = ManagedWalletInfo::from_wallet_with_name(wallet, name);
        Self {
            wallet: wallet.clone(),
            wallet_info,
            persister: P::default(),
        }
    }

    fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    fn network(&self) -> Network {
        self.wallet_info.network()
    }

    fn wallet_id(&self) -> [u8; 32] {
        self.wallet_info.wallet_id()
    }

    fn name(&self) -> Option<&str> {
        self.wallet_info.name()
    }

    fn set_name(&mut self, name: String) {
        self.wallet_info.set_name(name);
    }

    fn description(&self) -> Option<&str> {
        self.wallet_info.description()
    }

    fn set_description(&mut self, description: Option<String>) {
        self.wallet_info.set_description(description);
    }

    fn birth_height(&self) -> CoreBlockHeight {
        self.wallet_info.birth_height()
    }

    fn set_birth_height(&mut self, height: CoreBlockHeight) {
        self.wallet_info.set_birth_height(height);
    }

    fn first_loaded_at(&self) -> u64 {
        self.wallet_info.first_loaded_at()
    }

    fn set_first_loaded_at(&mut self, timestamp: u64) {
        self.wallet_info.set_first_loaded_at(timestamp);
    }

    fn update_last_synced(&mut self, timestamp: u64) {
        self.wallet_info.update_last_synced(timestamp);
    }

    fn monitored_addresses(&self) -> Vec<DashAddress> {
        self.wallet_info.monitored_addresses()
    }

    fn utxos(&self) -> BTreeSet<&Utxo> {
        self.wallet_info.utxos()
    }

    fn get_spendable_utxos(&self) -> BTreeSet<&Utxo> {
        self.wallet_info.get_spendable_utxos()
    }

    fn balance(&self) -> WalletCoreBalance {
        self.wallet_info.balance()
    }

    fn update_balance(&mut self) {
        self.wallet_info.update_balance();
    }

    fn transaction_history(&self) -> Vec<&TransactionRecord> {
        self.wallet_info.transaction_history()
    }

    fn accounts_mut(&mut self) -> &mut ManagedAccountCollection {
        self.wallet_info.accounts_mut()
    }

    fn accounts(&self) -> &ManagedAccountCollection {
        self.wallet_info.accounts()
    }

    fn immature_transactions(&self) -> Vec<Transaction> {
        self.wallet_info.immature_transactions()
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.wallet_info.synced_height()
    }

    fn update_synced_height(&mut self, current_height: u32) {
        self.wallet_info.update_synced_height(current_height);
    }

    fn mark_instant_send_utxos(&mut self, txid: &Txid) -> (bool, UtxoChangeSet) {
        self.wallet_info.mark_instant_send_utxos(txid)
    }

    fn monitor_revision(&self) -> u64 {
        self.wallet_info.monitor_revision()
    }
}

// ---------------------------------------------------------------------------
// WalletTransactionChecker — delegate to the extracted helper method on
// ManagedWalletInfo, then persist the changeset.
// ---------------------------------------------------------------------------

#[async_trait]
impl<P: WalletPersistence + std::fmt::Debug + Default> WalletTransactionChecker for ManagedWalletState<P> {
    async fn check_core_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        update_state: bool,
        update_balance: bool,
    ) -> TransactionCheckResult {
        let result = self
            .wallet_info
            .check_core_transaction_with_wallet(
                tx,
                context,
                &self.wallet,
                update_state,
                update_balance,
            )
            .await;

        // Persist non-empty changesets
        if !result.changeset.is_empty() {
            if let Err(e) = self.persister.store(result.changeset.clone()) {
                tracing::warn!("Failed to persist wallet changeset: {}", e);
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// ManagedAccountOperations — delegate to `self.wallet_info`, passing
// `&self.wallet` where the trait methods require it.
// ---------------------------------------------------------------------------

impl<P: WalletPersistence + std::fmt::Debug + Default> ManagedAccountOperations for ManagedWalletState<P> {
    fn add_managed_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> key_wallet::Result<()> {
        self.wallet_info.add_managed_account(wallet, account_type)
    }

    fn add_managed_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        passphrase: &str,
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_account_with_passphrase(wallet, account_type, passphrase)
    }

    fn add_managed_account_from_xpub(
        &mut self,
        account_type: AccountType,
        account_xpub: ExtendedPubKey,
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_account_from_xpub(account_type, account_xpub)
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_bls_account(wallet, account_type)
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        passphrase: &str,
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_bls_account_with_passphrase(wallet, account_type, passphrase)
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account_from_public_key(
        &mut self,
        account_type: AccountType,
        bls_public_key: [u8; 48],
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_bls_account_from_public_key(account_type, bls_public_key)
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_eddsa_account(wallet, account_type)
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        passphrase: &str,
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_eddsa_account_with_passphrase(wallet, account_type, passphrase)
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_from_public_key(
        &mut self,
        account_type: AccountType,
        ed25519_public_key: [u8; 32],
    ) -> key_wallet::Result<()> {
        self.wallet_info
            .add_managed_eddsa_account_from_public_key(account_type, ed25519_public_key)
    }
}
