//! Helper methods for ManagedWalletInfo

use super::ManagedWalletInfo;
use crate::account::ManagedAccount;
use crate::Network;

impl ManagedWalletInfo {
    // BIP44 Account Helpers

    /// Get the first BIP44 managed account for a given network
    pub fn first_bip44_managed_account(&self, network: Network) -> Option<&ManagedAccount> {
        self.bip44_managed_account_at_index(network, 0)
    }

    /// Get the first BIP44 managed account for a given network (mutable)
    pub fn first_bip44_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.bip44_managed_account_at_index_mut(network, 0)
    }

    /// Get a BIP44 managed account at a specific index
    pub fn bip44_managed_account_at_index(
        &self,
        network: Network,
        index: u32,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.standard_bip44_accounts.get(&index)
    }

    /// Get a BIP44 managed account at a specific index (mutable)
    pub fn bip44_managed_account_at_index_mut(
        &mut self,
        network: Network,
        index: u32,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.standard_bip44_accounts.get_mut(&index)
    }

    // BIP32 Account Helpers

    /// Get the first BIP32 managed account for a given network
    pub fn first_bip32_managed_account(&self, network: Network) -> Option<&ManagedAccount> {
        self.bip32_managed_account_at_index(network, 0)
    }

    /// Get the first BIP32 managed account for a given network (mutable)
    pub fn first_bip32_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.bip32_managed_account_at_index_mut(network, 0)
    }

    /// Get a BIP32 managed account at a specific index
    pub fn bip32_managed_account_at_index(
        &self,
        network: Network,
        index: u32,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.standard_bip32_accounts.get(&index)
    }

    /// Get a BIP32 managed account at a specific index (mutable)
    pub fn bip32_managed_account_at_index_mut(
        &mut self,
        network: Network,
        index: u32,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.standard_bip32_accounts.get_mut(&index)
    }

    // CoinJoin Account Helpers

    /// Get the first CoinJoin managed account for a given network
    pub fn first_coinjoin_managed_account(&self, network: Network) -> Option<&ManagedAccount> {
        self.coinjoin_managed_account_at_index(network, 0)
    }

    /// Get the first CoinJoin managed account for a given network (mutable)
    pub fn first_coinjoin_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.coinjoin_managed_account_at_index_mut(network, 0)
    }

    /// Get a CoinJoin managed account at a specific index
    pub fn coinjoin_managed_account_at_index(
        &self,
        network: Network,
        index: u32,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.coinjoin_accounts.get(&index)
    }

    /// Get a CoinJoin managed account at a specific index (mutable)
    pub fn coinjoin_managed_account_at_index_mut(
        &mut self,
        network: Network,
        index: u32,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.coinjoin_accounts.get_mut(&index)
    }

    // TopUp Account Helpers

    /// Get the first TopUp managed account for a given network
    pub fn first_topup_managed_account(&self, network: Network) -> Option<&ManagedAccount> {
        // TopUp accounts use registration_index, so we need to get the first one in the collection
        self.accounts.get(&network)?.identity_topup.values().next()
    }

    /// Get the first TopUp managed account for a given network (mutable)
    pub fn first_topup_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        // TopUp accounts use registration_index, so we need to get the first one in the collection
        self.accounts.get_mut(&network)?.identity_topup.values_mut().next()
    }

    /// Get a TopUp managed account at a specific registration index
    pub fn topup_managed_account_at_registration_index(
        &self,
        network: Network,
        registration_index: u32,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.identity_topup.get(&registration_index)
    }

    /// Get a TopUp managed account at a specific registration index (mutable)
    pub fn topup_managed_account_at_registration_index_mut(
        &mut self,
        network: Network,
        registration_index: u32,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.identity_topup.get_mut(&registration_index)
    }

    // Identity Registration Account Helper

    /// Get the identity registration managed account for a given network
    pub fn identity_registration_managed_account(
        &self,
        network: Network,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.identity_registration.as_ref()
    }

    /// Get the identity registration managed account for a given network (mutable)
    pub fn identity_registration_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.identity_registration.as_mut()
    }

    // Identity TopUp Not Bound Account Helper

    /// Get the identity top-up not bound managed account for a given network
    pub fn identity_topup_not_bound_managed_account(
        &self,
        network: Network,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.identity_topup_not_bound.as_ref()
    }

    /// Get the identity top-up not bound managed account for a given network (mutable)
    pub fn identity_topup_not_bound_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.identity_topup_not_bound.as_mut()
    }

    // Identity Invitation Account Helper

    /// Get the identity invitation managed account for a given network
    pub fn identity_invitation_managed_account(&self, network: Network) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.identity_invitation.as_ref()
    }

    /// Get the identity invitation managed account for a given network (mutable)
    pub fn identity_invitation_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.identity_invitation.as_mut()
    }

    // Provider Voting Keys Account Helper

    /// Get the provider voting keys managed account for a given network
    pub fn provider_voting_keys_managed_account(
        &self,
        network: Network,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.provider_voting_keys.as_ref()
    }

    /// Get the provider voting keys managed account for a given network (mutable)
    pub fn provider_voting_keys_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.provider_voting_keys.as_mut()
    }

    // Provider Owner Keys Account Helper

    /// Get the provider owner keys managed account for a given network
    pub fn provider_owner_keys_managed_account(&self, network: Network) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.provider_owner_keys.as_ref()
    }

    /// Get the provider owner keys managed account for a given network (mutable)
    pub fn provider_owner_keys_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.provider_owner_keys.as_mut()
    }

    // Provider Operator Keys Account Helper

    /// Get the provider operator keys managed account for a given network
    pub fn provider_operator_keys_managed_account(
        &self,
        network: Network,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.provider_operator_keys.as_ref()
    }

    /// Get the provider operator keys managed account for a given network (mutable)
    pub fn provider_operator_keys_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.provider_operator_keys.as_mut()
    }

    // Provider Platform Keys Account Helper

    /// Get the provider platform keys managed account for a given network
    pub fn provider_platform_keys_managed_account(
        &self,
        network: Network,
    ) -> Option<&ManagedAccount> {
        self.accounts.get(&network)?.provider_platform_keys.as_ref()
    }

    /// Get the provider platform keys managed account for a given network (mutable)
    pub fn provider_platform_keys_managed_account_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network)?.provider_platform_keys.as_mut()
    }

    // General Helpers

    /// Check if the wallet has any accounts for the given network
    pub fn has_accounts(&self, network: Network) -> bool {
        self.accounts.contains_key(&network)
    }

    /// Get the total number of accounts across all types for a given network
    pub fn account_count(&self, network: Network) -> usize {
        self.accounts.get(&network).map(|collection| collection.all_accounts().len()).unwrap_or(0)
    }

    /// Get the total number of accounts across all types for a given network
    pub fn all_accounts(&self, network: Network) -> Vec<&ManagedAccount> {
        self.accounts.get(&network).map(|collection| collection.all_accounts()).unwrap_or_default()
    }
}
