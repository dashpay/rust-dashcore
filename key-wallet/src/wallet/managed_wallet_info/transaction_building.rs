//! Transaction building functionality for managed wallets

use super::coin_selection::{SelectionError, SelectionStrategy};
use super::fee::FeeLevel;
use super::transaction_builder::{BuilderError, TransactionBuilder};
use super::ManagedWalletInfo;
use crate::{Address, Network, Wallet};
use alloc::vec::Vec;
use dashcore::Transaction;

/// Account type preference for transaction building
#[derive(Debug, Clone, Copy)]
pub enum AccountTypePreference {
    /// Use BIP44 account only
    BIP44,
    /// Use BIP32 account only  
    BIP32,
    /// Prefer BIP44, fallback to BIP32
    PreferBIP44,
    /// Prefer BIP32, fallback to BIP44
    PreferBIP32,
}

/// Transaction creation error
#[derive(Debug)]
pub enum TransactionError {
    /// No account found for the specified type
    NoAccount,
    /// Insufficient funds
    InsufficientFunds,
    /// Failed to generate change address
    ChangeAddressGeneration(String),
    /// Transaction building failed
    BuildFailed(String),
    /// Coin selection failed
    CoinSelection(SelectionError),
}

impl ManagedWalletInfo {
    /// Create an unsigned payment transaction
    #[allow(clippy::too_many_arguments)]
    pub fn create_unsigned_payment_transaction(
        &mut self,
        wallet: &Wallet,
        network: Network,
        account_index: u32,
        account_type_pref: Option<AccountTypePreference>,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
        current_block_height: u32,
    ) -> Result<Transaction, TransactionError> {
        // Get the wallet's account collection for this network
        let wallet_collection = wallet.accounts.get(&network).ok_or(TransactionError::NoAccount)?;

        // Get the mutable account collection from managed info
        let managed_collection =
            self.accounts.get_mut(&network).ok_or(TransactionError::NoAccount)?;

        // Use BIP44 as default if no preference specified
        let pref = account_type_pref.unwrap_or(AccountTypePreference::BIP44);

        // Get the immutable account from wallet for address generation
        let wallet_account = match pref {
            AccountTypePreference::BIP44 => wallet_collection
                .standard_bip44_accounts
                .get(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::BIP32 => wallet_collection
                .standard_bip32_accounts
                .get(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP44 => wallet_collection
                .standard_bip44_accounts
                .get(&account_index)
                .or_else(|| wallet_collection.standard_bip32_accounts.get(&account_index))
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP32 => wallet_collection
                .standard_bip32_accounts
                .get(&account_index)
                .or_else(|| wallet_collection.standard_bip44_accounts.get(&account_index))
                .ok_or(TransactionError::NoAccount)?,
        };

        // Get the mutable managed account for UTXO access
        let managed_account = match pref {
            AccountTypePreference::BIP44 => managed_collection
                .standard_bip44_accounts
                .get_mut(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::BIP32 => managed_collection
                .standard_bip32_accounts
                .get_mut(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP44 => managed_collection
                .standard_bip44_accounts
                .get_mut(&account_index)
                .or_else(|| managed_collection.standard_bip32_accounts.get_mut(&account_index))
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP32 => managed_collection
                .standard_bip32_accounts
                .get_mut(&account_index)
                .or_else(|| managed_collection.standard_bip44_accounts.get_mut(&account_index))
                .ok_or(TransactionError::NoAccount)?,
        };

        // Generate change address using the wallet account
        let change_address = managed_account
            .get_next_change_address(&wallet_account.account_xpub, network)
            .map_err(|e| {
                TransactionError::ChangeAddressGeneration(format!(
                    "Failed to generate change address: {}",
                    e
                ))
            })?;

        if managed_account.utxos.is_empty() {
            return Err(TransactionError::InsufficientFunds);
        }

        // Get all UTXOs from the managed account as a vector
        let all_utxos: Vec<_> = managed_account.utxos.values().cloned().collect();

        // Use TransactionBuilder to create the transaction
        let mut builder = TransactionBuilder::new()
            .set_fee_level(fee_level)
            .set_change_address(change_address.clone());

        // Add outputs for recipients first
        for (address, amount) in recipients {
            builder = builder
                .add_output(&address, amount)
                .map_err(|e| TransactionError::BuildFailed(e.to_string()))?;
        }

        // Select inputs using OptimalConsolidation strategy
        // The target amount is calculated from the outputs already added
        // Note: We don't have private keys here since this is for unsigned transactions
        builder = builder
            .select_inputs(
                &all_utxos,
                SelectionStrategy::OptimalConsolidation,
                current_block_height,
                |_| None, // No private keys for unsigned transaction
            )
            .map_err(|e| match e {
                BuilderError::CoinSelection(err) => TransactionError::CoinSelection(err),
                _ => TransactionError::BuildFailed(e.to_string()),
            })?;

        // Build the unsigned transaction
        let transaction =
            builder.build().map_err(|e| TransactionError::BuildFailed(e.to_string()))?;

        // Mark the change address as used in the managed account
        managed_account.mark_address_used(&change_address);

        // Lock the UTXOs that were selected for this transaction
        for input in &transaction.input {
            if let Some(stored_utxo) = managed_account.utxos.get_mut(&input.previous_output) {
                stored_utxo.is_locked = true; // Lock the UTXO while transaction is pending
            }
        }

        Ok(transaction)
    }
}
