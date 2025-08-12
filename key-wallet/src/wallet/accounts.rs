//! Account management methods for wallets
//!
//! This module contains methods for creating and managing accounts within wallets.

use super::Wallet;
use crate::account::{Account, AccountType, SpecialPurposeType};
use crate::bip32::{ChildNumber, DerivationPath};
use crate::derivation::HDWallet;
use crate::dip9::DerivationPathReference;
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
            AccountType::CoinJoin => self.coinjoin_accounts.contains_key(network, index),
            AccountType::Standard => self.standard_accounts.contains_key(network, index),
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

        let account = match account_type {
            AccountType::Standard => {
                let root_key = self.root_extended_priv_key()?;
                let master_key = root_key.to_extended_priv_key(network);
                let hd_wallet = HDWallet::new(master_key);
                let account_key = hd_wallet.bip44_account(index)?;

                // Create the derivation path for this account
                let derivation_path = DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(44).map_err(Error::Bip32)?,
                    ChildNumber::from_hardened_idx(if network == Network::Dash {
                        5
                    } else {
                        1
                    })
                    .map_err(Error::Bip32)?,
                    ChildNumber::from_hardened_idx(index).map_err(Error::Bip32)?,
                ]);

                let account = Account::new(
                    Some(wallet_id),
                    index,
                    account_key,
                    network,
                    DerivationPathReference::BIP44,
                    derivation_path,
                )?;
                account
            }
            AccountType::CoinJoin => {
                let root_key = self.root_extended_priv_key()?;
                let master_key = root_key.to_extended_priv_key(network);
                let hd_wallet = HDWallet::new(master_key);
                let account_key = hd_wallet.coinjoin_account(index)?;

                // Create the derivation path for CoinJoin account
                let derivation_path = DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(Error::Bip32)?,
                    ChildNumber::from_hardened_idx(if network == Network::Dash {
                        5
                    } else {
                        1
                    })
                    .map_err(Error::Bip32)?,
                    ChildNumber::from_hardened_idx(index).map_err(Error::Bip32)?,
                ]);

                let mut account = Account::new(
                    Some(wallet_id),
                    index,
                    account_key,
                    network,
                    DerivationPathReference::BIP44CoinType,
                    derivation_path,
                )?;
                account.account_type = AccountType::CoinJoin;
                account
            }
            AccountType::SpecialPurpose(purpose) => {
                self.add_special_account_internal(index, purpose, network)?
            }
        };

        // Insert into the appropriate collection based on account type
        match account_type {
            AccountType::CoinJoin => {
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
        purpose: SpecialPurposeType,
        network: Network,
    ) -> Result<Account> {
        let wallet_id = self.get_wallet_id();

        let (path, path_ref) = match purpose {
            SpecialPurposeType::IdentityRegistration => match network {
                Network::Dash => (
                    crate::dip9::IDENTITY_REGISTRATION_PATH_MAINNET,
                    DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
                ),
                Network::Testnet => (
                    crate::dip9::IDENTITY_REGISTRATION_PATH_TESTNET,
                    DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
                ),
                _ => return Err(Error::InvalidNetwork),
            },
            SpecialPurposeType::IdentityTopUp => match network {
                Network::Dash => (
                    crate::dip9::IDENTITY_TOPUP_PATH_MAINNET,
                    DerivationPathReference::BlockchainIdentityCreditTopupFunding,
                ),
                Network::Testnet => (
                    crate::dip9::IDENTITY_TOPUP_PATH_TESTNET,
                    DerivationPathReference::BlockchainIdentityCreditTopupFunding,
                ),
                _ => return Err(Error::InvalidNetwork),
            },
            SpecialPurposeType::IdentityInvitation => match network {
                Network::Dash => (
                    crate::dip9::IDENTITY_INVITATION_PATH_MAINNET,
                    DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
                ),
                Network::Testnet => (
                    crate::dip9::IDENTITY_INVITATION_PATH_TESTNET,
                    DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
                ),
                _ => return Err(Error::InvalidNetwork),
            },
            _ => {
                // For other types, use standard BIP44 with special marking
                let root_key = self.root_extended_priv_key()?;
                let master_key = root_key.to_extended_priv_key(network);
                let hd_wallet = HDWallet::new(master_key);
                let account_key = hd_wallet.bip44_account(index)?;

                let derivation_path = DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(44).map_err(Error::Bip32)?,
                    ChildNumber::from_hardened_idx(if network == Network::Dash {
                        5
                    } else {
                        1
                    })
                    .map_err(Error::Bip32)?,
                    ChildNumber::from_hardened_idx(index).map_err(Error::Bip32)?,
                ]);

                let mut account = Account::new(
                    Some(wallet_id),
                    index,
                    account_key,
                    network,
                    DerivationPathReference::BIP44,
                    derivation_path,
                )?;
                account.account_type = AccountType::SpecialPurpose(purpose);
                return Ok(account);
            }
        };

        // Derive the account key from the special path
        let mut full_path = DerivationPath::from(path);
        full_path.push(ChildNumber::from_hardened_idx(index).map_err(Error::Bip32)?);

        let root_key = self.root_extended_priv_key()?;
        let master_key = root_key.to_extended_priv_key(network);
        let hd_wallet = HDWallet::new(master_key);
        let account_key = hd_wallet.derive(&full_path)?;

        let mut account =
            Account::new(Some(wallet_id), index, account_key, network, path_ref, full_path)?;

        account.account_type = AccountType::SpecialPurpose(purpose);
        Ok(account)
    }

    /// Add a special purpose account to the wallet
    pub fn add_special_account(
        &mut self,
        index: u32,
        purpose: SpecialPurposeType,
        network: Network,
    ) -> Result<&Account> {
        let account = self.add_special_account_internal(index, purpose, network)?;
        self.special_accounts.entry(network).or_insert_with(Vec::new).push(account);
        Ok(self.special_accounts.get(&network).unwrap().last().unwrap())
    }

    /// Get the wallet ID for this wallet
    fn get_wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}
