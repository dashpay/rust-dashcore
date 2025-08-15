//! Account management methods for wallets
//!
//! This module contains methods for creating and managing accounts within wallets.

use super::Wallet;
use crate::account::{Account, AccountType, StandardAccountType};
use crate::account::account_collection::AccountCollection;
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
        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();
        
        // Derive the account key before accessing the collection
        let typed_account = match account_type {
            AccountType::Standard { standard_account_type, .. } => AccountType::Standard { 
                index,
                standard_account_type,
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
        
        // Now get or create the account collection for this network
        let collection = self.accounts.entry(network).or_insert_with(AccountCollection::new);
        
        // Check if account already exists
        let account_exists = match &typed_account {
            AccountType::CoinJoin { .. } => collection.coinjoin_accounts.contains_key(&index),
            AccountType::Standard { standard_account_type, .. } => {
                match standard_account_type {
                    StandardAccountType::BIP44Account => collection.standard_bip44_accounts.contains_key(&index),
                    StandardAccountType::BIP32Account => collection.standard_bip32_accounts.contains_key(&index),
                }
            },
            _ => false,
        };

        if account_exists {
            return Err(Error::InvalidParameter(format!(
                "Account {} already exists for network {:?}",
                index, network
            )));
        }

        // Insert into the collection
        collection.insert(account);
        
        // Return a reference to the newly inserted account
        match &typed_account {
            AccountType::CoinJoin { .. } => {
                Ok(collection.coinjoin_accounts.get(&index).unwrap())
            }
            AccountType::Standard { standard_account_type, .. } => {
                match standard_account_type {
                    StandardAccountType::BIP44Account => Ok(collection.standard_bip44_accounts.get(&index).unwrap()),
                    StandardAccountType::BIP32Account => Ok(collection.standard_bip32_accounts.get(&index).unwrap()),
                }
            },
            _ => {
                // For special account types, we need to return the correct reference
                match &typed_account {
                    AccountType::IdentityRegistration => Ok(collection.identity_registration.as_ref().unwrap()),
                    AccountType::IdentityTopUp { registration_index } => Ok(collection.identity_topup.get(registration_index).unwrap()),
                    AccountType::IdentityTopUpNotBoundToIdentity => Ok(collection.identity_topup_not_bound.as_ref().unwrap()),
                    AccountType::IdentityInvitation => Ok(collection.identity_invitation.as_ref().unwrap()),
                    AccountType::ProviderVotingKeys => Ok(collection.provider_voting_keys.as_ref().unwrap()),
                    AccountType::ProviderOwnerKeys => Ok(collection.provider_owner_keys.as_ref().unwrap()),
                    AccountType::ProviderOperatorKeys => Ok(collection.provider_operator_keys.as_ref().unwrap()),
                    AccountType::ProviderPlatformKeys => Ok(collection.provider_platform_keys.as_ref().unwrap()),
                    _ => unreachable!("All account types should be handled"),
                }
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
        let account = self.add_special_account_internal(_index, account_type.clone(), network)?;
        
        // Get or create the account collection for this network
        let collection = self.accounts.entry(network).or_insert_with(AccountCollection::new);
        
        // Insert the account into the collection
        collection.insert(account);
        
        // Return a reference to the newly inserted account
        match &account_type {
            AccountType::IdentityRegistration => Ok(collection.identity_registration.as_ref().unwrap()),
            AccountType::IdentityTopUp { registration_index } => Ok(collection.identity_topup.get(registration_index).unwrap()),
            AccountType::IdentityTopUpNotBoundToIdentity => Ok(collection.identity_topup_not_bound.as_ref().unwrap()),
            AccountType::IdentityInvitation => Ok(collection.identity_invitation.as_ref().unwrap()),
            AccountType::ProviderVotingKeys => Ok(collection.provider_voting_keys.as_ref().unwrap()),
            AccountType::ProviderOwnerKeys => Ok(collection.provider_owner_keys.as_ref().unwrap()),
            AccountType::ProviderOperatorKeys => Ok(collection.provider_operator_keys.as_ref().unwrap()),
            AccountType::ProviderPlatformKeys => Ok(collection.provider_platform_keys.as_ref().unwrap()),
            _ => Err(Error::InvalidParameter(format!("Account type {:?} is not a special account type", account_type))),
        }
    }

    /// Get the wallet ID for this wallet
    fn get_wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}
