//! Looking up a wallet's provider (masternode) keys by hash.

use super::ManagedWalletInfo;
use crate::account::derivation::AccountDerivation;
use crate::error::Result;
use crate::managed_account::address_pool::{AddressPool, AddressPoolType, MAX_GAP_LIMIT};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::{AccountType, Address, ChildNumber, DerivationPath, Wallet};
use dashcore::address::Payload;
use dashcore::PubkeyHash;

/// A provider key role whose key a masternode registration identifies by hash160.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKeyRole {
    /// The owner key, from the `ProviderOwnerKeys` account.
    Owner,
    /// The voting key, from the `ProviderVotingKeys` account.
    Voting,
}

impl ProviderKeyRole {
    fn account_type(self) -> AccountType {
        match self {
            Self::Owner => AccountType::ProviderOwnerKeys,
            Self::Voting => AccountType::ProviderVotingKeys,
        }
    }
}

impl ManagedWalletInfo {
    /// Returns the index and derivation path of this wallet's `role` key whose hash160 is
    /// `key_hash`, or `None` when the wallet does not hold it.
    ///
    /// Needs no seed: keys are derived from the account xpub. The key at `index_hint` is
    /// checked first, then the account's address pool, then the keys past the pool below
    /// `min_window`, which is capped at [`MAX_GAP_LIMIT`]. Every match is derived from `wallet`,
    /// so a pool of another wallet matches nothing. [`DEFAULT_PROVIDER_KEY_WINDOW`] is the usual
    /// `min_window`. Fails only when the wallet has the account and `index_hint` is in the
    /// hardened range.
    ///
    /// [`DEFAULT_PROVIDER_KEY_WINDOW`]: crate::managed_account::address_pool::DEFAULT_PROVIDER_KEY_WINDOW
    pub fn find_provider_key(
        &self,
        wallet: &Wallet,
        role: ProviderKeyRole,
        key_hash: &PubkeyHash,
        index_hint: Option<u32>,
        min_window: u32,
    ) -> Result<Option<(u32, DerivationPath)>> {
        let Some(account) = wallet.accounts.account_of_type(role.account_type()) else {
            return Ok(None);
        };
        let derived_match = |index: u32| -> Result<Option<(u32, DerivationPath)>> {
            let public_key = account.derive_public_key_at(AddressPoolType::Absent, index, None)?;
            if public_key.pubkey_hash() != *key_hash {
                return Ok(None);
            }
            let path = account.derivation_path()?.child(ChildNumber::from_normal_idx(index)?);
            Ok(Some((index, path)))
        };

        if let Some(hint) = index_hint {
            if let Some(found) = derived_match(hint)? {
                return Ok(Some(found));
            }
        }

        let keys_account = match role {
            ProviderKeyRole::Owner => self.provider_owner_keys_managed_account(),
            ProviderKeyRole::Voting => self.provider_voting_keys_managed_account(),
        };
        let pool = keys_account
            .and_then(|account| account.managed_account_type().address_pools().into_iter().next());
        if let Some(pool) = pool {
            let address = Address::new(pool.network(), Payload::PubkeyHash(*key_hash));
            if let Some(index) = pool.address_index(&address) {
                if let Some(found) = derived_match(index)? {
                    return Ok(Some(found));
                }
            }
        }

        let first_underived = pool.and_then(AddressPool::highest_generated).map_or(0, |h| h + 1);
        for index in first_underived..min_window.min(MAX_GAP_LIMIT) {
            if let Some(found) = derived_match(index)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }
}
