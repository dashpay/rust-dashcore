//! Account management methods for wallets
//!
//! This module contains methods for creating and managing accounts within wallets.

use super::Wallet;
use crate::account::account_collection::AccountCollection;
use crate::account::{Account, AccountType, StandardAccountType};
use crate::bip32::ExtendedPubKey;
use crate::derivation::HDWallet;
use crate::error::{Error, Result};
use crate::Network;

impl Wallet {
    /// Add a new account to the wallet
    ///
    /// # Arguments
    /// * `account_type` - The type of account to create
    /// * `network` - The network for the account
    /// * `account_xpub` - Optional extended public key for the account. If not provided,
    ///   the account will be derived from the wallet's private key.
    ///   This will fail if the wallet doesn't have a private key
    ///   (watch-only wallets or externally managed wallets where
    ///   the private key is stored securely outside of the SDK).
    ///
    /// # Returns
    /// A reference to the newly created account
    pub fn add_account(
        &mut self,
        account_type: AccountType,
        network: Network,
        account_xpub: Option<ExtendedPubKey>,
    ) -> Result<&Account> {
        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();

        // Create the account based on whether we have an xpub or need to derive
        let account = if let Some(xpub) = account_xpub {
            // Use the provided extended public key
            Account::new(Some(wallet_id), account_type, xpub, network)?
        } else {
            // Derive from wallet's private key
            let derivation_path = account_type.derivation_path(network)?;

            // This will fail if the wallet doesn't have a private key (watch-only or externally managed)
            let root_key = self.root_extended_priv_key()?;
            let master_key = root_key.to_extended_priv_key(network);
            let hd_wallet = HDWallet::new(master_key);
            let account_xpriv = hd_wallet.derive(&derivation_path)?;

            Account::from_xpriv(Some(wallet_id), account_type, account_xpriv, network)?
        };

        // Now get or create the account collection for this network
        let collection = self.accounts.entry(network).or_insert_with(AccountCollection::new);

        // Check if account already exists
        if collection.contains_account_type(&account_type) {
            return Err(Error::InvalidParameter(format!(
                "Account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        collection.insert(account);

        // Return a reference to the newly inserted account
        match &account_type {
            AccountType::CoinJoin {
                index,
            } => Ok(collection.coinjoin_accounts.get(index).unwrap()),
            AccountType::Standard {
                index,
                standard_account_type,
            } => match standard_account_type {
                StandardAccountType::BIP44Account => {
                    Ok(collection.standard_bip44_accounts.get(index).unwrap())
                }
                StandardAccountType::BIP32Account => {
                    Ok(collection.standard_bip32_accounts.get(index).unwrap())
                }
            },
            _ => {
                // For special account types, we need to return the correct reference
                match &account_type {
                    AccountType::IdentityRegistration => {
                        Ok(collection.identity_registration.as_ref().unwrap())
                    }
                    AccountType::IdentityTopUp {
                        registration_index,
                    } => Ok(collection.identity_topup.get(registration_index).unwrap()),
                    AccountType::IdentityTopUpNotBoundToIdentity => {
                        Ok(collection.identity_topup_not_bound.as_ref().unwrap())
                    }
                    AccountType::IdentityInvitation => {
                        Ok(collection.identity_invitation.as_ref().unwrap())
                    }
                    AccountType::ProviderVotingKeys => {
                        Ok(collection.provider_voting_keys.as_ref().unwrap())
                    }
                    AccountType::ProviderOwnerKeys => {
                        Ok(collection.provider_owner_keys.as_ref().unwrap())
                    }
                    AccountType::ProviderOperatorKeys => {
                        Ok(collection.provider_operator_keys.as_ref().unwrap())
                    }
                    AccountType::ProviderPlatformKeys => {
                        Ok(collection.provider_platform_keys.as_ref().unwrap())
                    }
                    _ => unreachable!("All account types should be handled"),
                }
            }
        }
    }

    /// Get the wallet ID for this wallet
    fn get_wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}
