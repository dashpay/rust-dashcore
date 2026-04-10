//! Helper methods for ManagedWalletInfo

use super::ManagedWalletInfo;
use crate::account::account_collection::PlatformPaymentAccountKey;
use crate::account::ManagedCoreAccount;
use crate::managed_account::managed_platform_account::ManagedPlatformAccount;
use crate::Address;
use dashcore::{OutPoint, Txid};

impl ManagedWalletInfo {
    // BIP44 Account Helpers

    /// Get the first BIP44 managed account
    pub fn first_bip44_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.bip44_managed_account_at_index(0)
    }

    /// Get the first BIP44 managed account (mutable)
    pub fn first_bip44_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.bip44_managed_account_at_index_mut(0)
    }

    /// Get a BIP44 managed account at a specific index
    pub fn bip44_managed_account_at_index(&self, index: u32) -> Option<&ManagedCoreAccount> {
        self.accounts.standard_bip44_accounts.get(&index)
    }

    /// Get a BIP44 managed account at a specific index (mutable)
    pub fn bip44_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreAccount> {
        self.accounts.standard_bip44_accounts.get_mut(&index)
    }

    // BIP32 Account Helpers

    /// Get the first BIP32 managed account
    pub fn first_bip32_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.bip32_managed_account_at_index(0)
    }

    /// Get the first BIP32 managed account (mutable)
    pub fn first_bip32_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.bip32_managed_account_at_index_mut(0)
    }

    /// Get a BIP32 managed account at a specific index
    pub fn bip32_managed_account_at_index(&self, index: u32) -> Option<&ManagedCoreAccount> {
        self.accounts.standard_bip32_accounts.get(&index)
    }

    /// Get a BIP32 managed account at a specific index (mutable)
    pub fn bip32_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreAccount> {
        self.accounts.standard_bip32_accounts.get_mut(&index)
    }

    // CoinJoin Account Helpers

    /// Get the first CoinJoin managed account
    pub fn first_coinjoin_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.coinjoin_managed_account_at_index(0)
    }

    /// Get the first CoinJoin managed account (mutable)
    pub fn first_coinjoin_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.coinjoin_managed_account_at_index_mut(0)
    }

    /// Get a CoinJoin managed account at a specific index
    pub fn coinjoin_managed_account_at_index(&self, index: u32) -> Option<&ManagedCoreAccount> {
        self.accounts.coinjoin_accounts.get(&index)
    }

    /// Get a CoinJoin managed account at a specific index (mutable)
    pub fn coinjoin_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreAccount> {
        self.accounts.coinjoin_accounts.get_mut(&index)
    }

    // TopUp Account Helpers

    /// Get the first TopUp managed account
    pub fn first_topup_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.identity_topup.values().next()
    }

    /// Get the first TopUp managed account (mutable)
    pub fn first_topup_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.accounts.identity_topup.values_mut().next()
    }

    /// Get a TopUp managed account at a specific registration index
    pub fn topup_managed_account_at_registration_index(
        &self,
        registration_index: u32,
    ) -> Option<&ManagedCoreAccount> {
        self.accounts.identity_topup.get(&registration_index)
    }

    /// Get a TopUp managed account at a specific registration index (mutable)
    pub fn topup_managed_account_at_registration_index_mut(
        &mut self,
        registration_index: u32,
    ) -> Option<&mut ManagedCoreAccount> {
        self.accounts.identity_topup.get_mut(&registration_index)
    }

    // Identity Registration Account Helper

    /// Get the identity registration managed account
    pub fn identity_registration_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.identity_registration.as_ref()
    }

    /// Get the identity registration managed account (mutable)
    pub fn identity_registration_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.accounts.identity_registration.as_mut()
    }

    // Identity TopUp Not Bound Account Helper

    /// Get the identity top-up not bound managed account
    pub fn identity_topup_not_bound_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.identity_topup_not_bound.as_ref()
    }

    /// Get the identity top-up not bound managed account (mutable)
    pub fn identity_topup_not_bound_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreAccount> {
        self.accounts.identity_topup_not_bound.as_mut()
    }

    // Identity Invitation Account Helper

    /// Get the identity invitation managed account
    pub fn identity_invitation_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.identity_invitation.as_ref()
    }

    /// Get the identity invitation managed account (mutable)
    pub fn identity_invitation_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.accounts.identity_invitation.as_mut()
    }

    // Provider Voting Keys Account Helper

    /// Get the provider voting keys managed account
    pub fn provider_voting_keys_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.provider_voting_keys.as_ref()
    }

    /// Get the provider voting keys managed account (mutable)
    pub fn provider_voting_keys_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.accounts.provider_voting_keys.as_mut()
    }

    // Provider Owner Keys Account Helper

    /// Get the provider owner keys managed account
    pub fn provider_owner_keys_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.provider_owner_keys.as_ref()
    }

    /// Get the provider owner keys managed account (mutable)
    pub fn provider_owner_keys_managed_account_mut(&mut self) -> Option<&mut ManagedCoreAccount> {
        self.accounts.provider_owner_keys.as_mut()
    }

    // Provider Operator Keys Account Helper

    /// Get the provider operator keys managed account
    pub fn provider_operator_keys_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.provider_operator_keys.as_ref()
    }

    /// Get the provider operator keys managed account (mutable)
    pub fn provider_operator_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreAccount> {
        self.accounts.provider_operator_keys.as_mut()
    }

    // Provider Platform Keys Account Helper

    /// Get the provider platform keys managed account
    pub fn provider_platform_keys_managed_account(&self) -> Option<&ManagedCoreAccount> {
        self.accounts.provider_platform_keys.as_ref()
    }

    /// Get the provider platform keys managed account (mutable)
    pub fn provider_platform_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreAccount> {
        self.accounts.provider_platform_keys.as_mut()
    }

    // Platform Payment Account Helpers (DIP-17)

    /// Get the first platform payment managed account
    ///
    /// Returns the platform payment account with the lowest account index and key_class 0.
    pub fn first_platform_payment_managed_account(&self) -> Option<&ManagedPlatformAccount> {
        self.platform_payment_managed_account(0, 0)
    }

    /// Get the first platform payment managed account (mutable)
    ///
    /// Returns the platform payment account with account index 0 and key_class 0.
    pub fn first_platform_payment_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedPlatformAccount> {
        self.platform_payment_managed_account_mut(0, 0)
    }

    /// Get a platform payment managed account by account index (with default key_class 0)
    pub fn platform_payment_managed_account_at_index(
        &self,
        account_index: u32,
    ) -> Option<&ManagedPlatformAccount> {
        self.platform_payment_managed_account(account_index, 0)
    }

    /// Get a platform payment managed account by account index (mutable, with default key_class 0)
    pub fn platform_payment_managed_account_at_index_mut(
        &mut self,
        account_index: u32,
    ) -> Option<&mut ManagedPlatformAccount> {
        self.platform_payment_managed_account_mut(account_index, 0)
    }

    /// Get a platform payment managed account by account index and key class
    pub fn platform_payment_managed_account(
        &self,
        account_index: u32,
        key_class: u32,
    ) -> Option<&ManagedPlatformAccount> {
        let key = PlatformPaymentAccountKey {
            account: account_index,
            key_class,
        };
        self.accounts.platform_payment_accounts.get(&key)
    }

    /// Get a platform payment managed account by account index and key class (mutable)
    pub fn platform_payment_managed_account_mut(
        &mut self,
        account_index: u32,
        key_class: u32,
    ) -> Option<&mut ManagedPlatformAccount> {
        let key = PlatformPaymentAccountKey {
            account: account_index,
            key_class,
        };
        self.accounts.platform_payment_accounts.get_mut(&key)
    }

    /// Get all platform payment managed accounts
    pub fn all_platform_payment_managed_accounts(&self) -> Vec<&ManagedPlatformAccount> {
        self.accounts.platform_payment_accounts.values().collect()
    }

    /// Get all platform payment managed accounts (mutable)
    pub fn all_platform_payment_managed_accounts_mut(
        &mut self,
    ) -> Vec<&mut ManagedPlatformAccount> {
        self.accounts.platform_payment_accounts.values_mut().collect()
    }

    /// Get the number of platform payment accounts
    pub fn platform_payment_account_count(&self) -> usize {
        self.accounts.platform_payment_accounts.len()
    }

    /// Check if a platform payment account exists
    pub fn has_platform_payment_account(&self, account_index: u32, key_class: u32) -> bool {
        let key = PlatformPaymentAccountKey {
            account: account_index,
            key_class,
        };
        self.accounts.platform_payment_accounts.contains_key(&key)
    }

    // General Helpers

    /// Check if the wallet has any accounts
    pub fn has_accounts(&self) -> bool {
        !self.accounts.is_empty()
    }

    /// Get the total number of accounts across all types
    pub fn account_count(&self) -> usize {
        self.accounts.all_accounts().len()
    }

    /// Get all accounts
    pub fn all_managed_accounts(&self) -> Vec<&ManagedCoreAccount> {
        self.accounts.all_accounts()
    }

    // ------------------------------------------------------------------
    // Changeset routing helpers — used by WalletManager::apply()
    // ------------------------------------------------------------------

    /// Find the managed account whose address pool contains the given address.
    ///
    /// Used by `apply(changeset)` to route UTXO additions to the correct
    /// account via `UtxoEntry.address`.
    pub fn find_account_by_address_mut(
        &mut self,
        address: &Address,
    ) -> Option<&mut ManagedCoreAccount> {
        for account in self.accounts.all_accounts_mut() {
            if account.contains_address(address) {
                return Some(account);
            }
        }
        None
    }

    /// Find the managed account that holds the given outpoint as a UTXO.
    ///
    /// Used by `apply(changeset)` to route UTXO removals and instant-lock
    /// updates to the correct account.
    pub fn find_account_with_utxo_mut(
        &mut self,
        outpoint: &OutPoint,
    ) -> Option<&mut ManagedCoreAccount> {
        for account in self.accounts.all_accounts_mut() {
            if account.utxos.contains_key(outpoint) {
                return Some(account);
            }
        }
        None
    }

    /// Find the managed account that owns any address present on the given
    /// transaction record — either as an input (an address we spent from)
    /// or as an output (an address we're receiving at). Used by
    /// `apply(changeset)` to route [`TransactionRecord`] insertions.
    ///
    /// This single-pass address scan covers every relevant case: receives
    /// match on output addresses; sends-with-change match on change output;
    /// sends to all-external destinations match on input addresses (we
    /// owned the outputs we spent from); internal transfers match on
    /// either side.
    pub fn find_account_for_transaction_record_mut(
        &mut self,
        record: &crate::managed_account::transaction_record::TransactionRecord,
    ) -> Option<&mut ManagedCoreAccount> {
        // Collect candidate addresses from the record: input addresses
        // (we owned these — they're in some account's pool) plus output
        // addresses resolved from the raw transaction.
        let mut candidates: Vec<Address> =
            record.input_details.iter().map(|i| i.address.clone()).collect();
        for out in &record.output_details {
            if let Some(txout) = record.transaction.output.get(out.index as usize) {
                if let Ok(addr) = Address::from_script(&txout.script_pubkey, self.network) {
                    candidates.push(addr);
                }
            }
        }
        for account in self.accounts.all_accounts_mut() {
            if candidates.iter().any(|addr| account.contains_address(addr)) {
                return Some(account);
            }
        }
        None
    }

    /// Find the managed account that has already recorded a transaction
    /// with the given txid. Used by `apply(changeset)` to detect the
    /// "confirmation upgrade" case where the record already exists and we
    /// only need to overwrite its context.
    pub fn find_account_with_txid_mut(
        &mut self,
        txid: &Txid,
    ) -> Option<&mut ManagedCoreAccount> {
        for account in self.accounts.all_accounts_mut() {
            if account.transactions.contains_key(txid) {
                return Some(account);
            }
        }
        None
    }

    /// Find a managed account by its account index across every indexable
    /// account type (Standard, CoinJoin, DashpayReceivingFunds, …). Used
    /// by `apply(changeset)` to route `highest_used` restoration. Returns
    /// the first account whose `index()` matches.
    pub fn find_managed_account_by_index_mut(
        &mut self,
        account_index: u32,
    ) -> Option<&mut ManagedCoreAccount> {
        for account in self.accounts.all_accounts_mut() {
            if account.index() == Some(account_index) {
                return Some(account);
            }
        }
        None
    }
}
