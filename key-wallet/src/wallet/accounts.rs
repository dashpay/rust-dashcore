//! Account management methods for wallets
//!
//! This module contains methods for creating and managing accounts within wallets.

use super::Wallet;
use crate::account::{Account, AccountType};
use crate::derivation::HDWallet;
use crate::error::{Error, Result};
use crate::Network;

impl Wallet {
    /// Add a new account to the wallet
    pub fn add_account(
        &mut self,
        index: u32,
        account_type: AccountType,
        network: Network,
    ) -> Result<&Account> {
        // Check if account already exists in either collection for this network
        let account_exists = match account_type {
            AccountType::CoinJoin { .. } => self.coinjoin_accounts.contains_key(network, index),
            AccountType::Standard { .. } => self.standard_accounts.contains_key(network, index),
            _ => false,
        };

        if account_exists {
            return Err(Error::InvalidParameter(format!(
                "Account {} already exists for network {:?}",
                index, network
            )));
        }

        // Get a unique wallet ID for this wallet
        let wallet_id = self.get_wallet_id();

        // Construct the proper AccountType with index
        let typed_account = match account_type {
            AccountType::Standard { .. } => AccountType::Standard { 
                index,
                standard_account_type: crate::account::types::StandardAccountType::BIP44Account,
            },
            AccountType::CoinJoin { .. } => AccountType::CoinJoin { index },
            _ => account_type,
        };

        // Get the derivation path from the account type
        let derivation_path = typed_account.derivation_path(network)?;

        // Derive the account key
        let root_key = self.root_extended_priv_key()?;
        let master_key = root_key.to_extended_priv_key(network);
        let hd_wallet = HDWallet::new(master_key);
        let account_key = hd_wallet.derive(&derivation_path)?;

        let account = Account::new(
            Some(wallet_id),
            typed_account.clone(),
            account_key,
            network,
        )?;

        // Insert into the appropriate collection based on account type
        match account.account_type {
            AccountType::CoinJoin { .. } => {
                self.coinjoin_accounts.insert(network, index, account);
                Ok(self.coinjoin_accounts.get(network, index).unwrap())
            }
            _ => {
                self.standard_accounts.insert(network, index, account);
                Ok(self.standard_accounts.get(network, index).unwrap())
            }
        }
    }

    /// Create a special purpose account (internal method returns Account)
    pub(crate) fn add_special_account_internal(
        &mut self,
        index: u32,
        account_type: AccountType,
        network: Network,
    ) -> Result<Account> {
        let wallet_id = self.get_wallet_id();

        // Get the derivation path from the account type
        let derivation_path = account_type.derivation_path(network)?;

        // Derive the account key
        let root_key = self.root_extended_priv_key()?;
        let master_key = root_key.to_extended_priv_key(network);
        let hd_wallet = HDWallet::new(master_key);
        let account_key = hd_wallet.derive(&derivation_path)?;

        Account::new(Some(wallet_id), account_type, account_key, network)
    }

    /// Add a special purpose account to the wallet
    pub fn add_special_account(
        &mut self,
        _index: u32,
        account_type: AccountType,
        network: Network,
    ) -> Result<&Account> {
        let account = self.add_special_account_internal(_index, account_type, network)?;
        self.special_accounts.entry(network).or_insert_with(Vec::new).push(account);
        Ok(self.special_accounts.get(&network).unwrap().last().unwrap())
    }

    /// Get the wallet ID for this wallet
    fn get_wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}
