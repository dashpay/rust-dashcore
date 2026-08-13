//! Helper methods for ManagedWalletInfo

use super::ManagedWalletInfo;
use crate::account::account_collection::PlatformPaymentAccountKey;
use crate::account::ManagedCoreFundsAccount;
use crate::managed_account::managed_account_ref::{ManagedAccountRef, ManagedAccountRefMut};
use crate::managed_account::managed_platform_account::ManagedPlatformAccount;
use crate::managed_account::ManagedCoreKeysAccount;
use dashcore::{OutPoint, Txid};
use std::collections::{BTreeMap, BTreeSet};

/// What [`ManagedWalletInfo::abandon_transaction`] removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonOutcome {
    /// Every transaction dropped: the root and its recorded descendants.
    pub abandoned: BTreeSet<Txid>,
    /// How many UTXOs those transactions had contributed.
    pub utxos_removed: usize,
}

impl AbandonOutcome {
    /// Whether anything was actually removed.
    pub fn is_empty(&self) -> bool {
        self.abandoned.is_empty() && self.utxos_removed == 0
    }
}

impl ManagedWalletInfo {
    /// Abandon `root` and every recorded transaction descending from it.
    ///
    /// A transaction the network never accepted still mutated this wallet:
    /// its outputs were credited and its inputs marked spent. Nothing reverses
    /// that on its own — the transaction is in no block, so no block
    /// processing revisits it — and further transactions can be built on its
    /// change, each inheriting the same fiction. Left alone the whole chain
    /// sits in the `unconfirmed` bucket permanently, as money the wallet
    /// displays and does not have.
    ///
    /// The walk is transitive and wallet-wide: pooled funding spreads a
    /// transaction's inputs across account families, so a descendant's change
    /// can land in an account that holds none of the root. Confirmed and
    /// finalized transactions are never followed — they are settled on chain,
    /// so whatever they spent was real.
    ///
    /// **This call asserts that the root is dead; it does not establish it.**
    /// The p2p network has no negative signal — modern Dash Core removed BIP61
    /// `reject` — so silence is not proof, and a transaction that merely went
    /// quiet may still be live in a miner's mempool. Abandoning such a
    /// transaction re-exposes its inputs to coin selection and invites a
    /// double-spend. Only call this where the death is known: a build that
    /// provably never reached the network, or an explicit user decision. The
    /// judgement belongs to the layer that owns broadcast policy.
    ///
    /// The coins the abandoned transactions consumed are released from the
    /// spent set so a rescan can rediscover them; see
    /// [`ManagedCoreFundsAccount::apply_abandon`] for why they are not
    /// re-credited directly.
    ///
    /// Does not recompute the balance — callers batching several abandons
    /// should run [`update_balance`](Self::update_balance) once at the end.
    pub fn abandon_transaction(&mut self, root: Txid) -> AbandonOutcome {
        self.abandon_transaction_with_spends(root, &BTreeMap::new())
    }

    /// [`abandon_transaction`](Self::abandon_transaction), with an external
    /// view of who spent what.
    ///
    /// The descendant walk normally reads recorded transactions, but a caller
    /// restoring a wallet may hold UTXOs whose creating transactions were
    /// never put back into the in-memory map — leaving the walk unable to see
    /// that one abandoned output funded the next transaction along. Callers
    /// with a persistence mirror can supply `external_spends`, mapping an
    /// outpoint to the transaction that spent it, and the walk follows both.
    pub fn abandon_transaction_with_spends(
        &mut self,
        root: Txid,
        external_spends: &BTreeMap<OutPoint, Txid>,
    ) -> AbandonOutcome {
        let mut abandoned = BTreeSet::from([root]);

        // Transitive closure over recorded spenders. Each pass can only add
        // txids, and the set is bounded by the recorded transactions, so this
        // terminates; a spend cycle is impossible anyway.
        loop {
            let mut found = BTreeSet::new();
            for account in self.accounts.all_accounts() {
                if let ManagedAccountRef::Funds(funds) = account {
                    funds.collect_spenders_of(&abandoned, &mut found);
                }
            }
            // Same step over the external view: anything spending an output of
            // an abandoned transaction is itself abandoned.
            for (outpoint, spender) in external_spends {
                if abandoned.contains(&outpoint.txid) {
                    found.insert(*spender);
                }
            }
            let before = abandoned.len();
            abandoned.extend(found);
            if abandoned.len() == before {
                break;
            }
        }

        let mut utxos_removed = 0;
        for account in self.accounts.all_accounts_mut() {
            if let ManagedAccountRefMut::Funds(funds) = account {
                utxos_removed += funds.apply_abandon(&abandoned);
            }
        }

        AbandonOutcome {
            abandoned,
            utxos_removed,
        }
    }
    // BIP44 Account Helpers

    /// Get the first BIP44 managed account
    pub fn first_bip44_managed_account(&self) -> Option<&ManagedCoreFundsAccount> {
        self.bip44_managed_account_at_index(0)
    }

    /// Get the first BIP44 managed account (mutable)
    pub fn first_bip44_managed_account_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        self.bip44_managed_account_at_index_mut(0)
    }

    /// Get a BIP44 managed account at a specific index
    pub fn bip44_managed_account_at_index(&self, index: u32) -> Option<&ManagedCoreFundsAccount> {
        self.accounts.standard_bip44_accounts.get(&index)
    }

    /// Get a BIP44 managed account at a specific index (mutable)
    pub fn bip44_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreFundsAccount> {
        self.accounts.standard_bip44_accounts.get_mut(&index)
    }

    // BIP32 Account Helpers

    /// Get the first BIP32 managed account
    pub fn first_bip32_managed_account(&self) -> Option<&ManagedCoreFundsAccount> {
        self.bip32_managed_account_at_index(0)
    }

    /// Get the first BIP32 managed account (mutable)
    pub fn first_bip32_managed_account_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        self.bip32_managed_account_at_index_mut(0)
    }

    /// Get a BIP32 managed account at a specific index
    pub fn bip32_managed_account_at_index(&self, index: u32) -> Option<&ManagedCoreFundsAccount> {
        self.accounts.standard_bip32_accounts.get(&index)
    }

    /// Get a BIP32 managed account at a specific index (mutable)
    pub fn bip32_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreFundsAccount> {
        self.accounts.standard_bip32_accounts.get_mut(&index)
    }

    // CoinJoin Account Helpers

    /// Get the first CoinJoin managed account
    pub fn first_coinjoin_managed_account(&self) -> Option<&ManagedCoreFundsAccount> {
        self.coinjoin_managed_account_at_index(0)
    }

    /// Get the first CoinJoin managed account (mutable)
    pub fn first_coinjoin_managed_account_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        self.coinjoin_managed_account_at_index_mut(0)
    }

    /// Get a CoinJoin managed account at a specific index
    pub fn coinjoin_managed_account_at_index(
        &self,
        index: u32,
    ) -> Option<&ManagedCoreFundsAccount> {
        self.accounts.coinjoin_accounts.get(&index)
    }

    /// Get a CoinJoin managed account at a specific index (mutable)
    pub fn coinjoin_managed_account_at_index_mut(
        &mut self,
        index: u32,
    ) -> Option<&mut ManagedCoreFundsAccount> {
        self.accounts.coinjoin_accounts.get_mut(&index)
    }

    // TopUp Account Helpers

    /// Get the first TopUp managed account
    pub fn first_topup_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_topup.values().next()
    }

    /// Get the first TopUp managed account (mutable)
    pub fn first_topup_managed_account_mut(&mut self) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_topup.values_mut().next()
    }

    /// Get a TopUp managed account at a specific registration index
    pub fn topup_managed_account_at_registration_index(
        &self,
        registration_index: u32,
    ) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_topup.get(&registration_index)
    }

    /// Get a TopUp managed account at a specific registration index (mutable)
    pub fn topup_managed_account_at_registration_index_mut(
        &mut self,
        registration_index: u32,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_topup.get_mut(&registration_index)
    }

    // Identity Registration Account Helper

    /// Get the identity registration managed account
    pub fn identity_registration_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_registration.as_ref()
    }

    /// Get the identity registration managed account (mutable)
    pub fn identity_registration_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_registration.as_mut()
    }

    // Identity TopUp Not Bound Account Helper

    /// Get the identity top-up not bound managed account
    pub fn identity_topup_not_bound_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_topup_not_bound.as_ref()
    }

    /// Get the identity top-up not bound managed account (mutable)
    pub fn identity_topup_not_bound_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_topup_not_bound.as_mut()
    }

    // Identity Invitation Account Helper

    /// Get the identity invitation managed account
    pub fn identity_invitation_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.identity_invitation.as_ref()
    }

    /// Get the identity invitation managed account (mutable)
    pub fn identity_invitation_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.identity_invitation.as_mut()
    }

    // Provider Voting Keys Account Helper

    /// Get the provider voting keys managed account
    pub fn provider_voting_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_voting_keys.as_ref()
    }

    /// Get the provider voting keys managed account (mutable)
    pub fn provider_voting_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.provider_voting_keys.as_mut()
    }

    // Provider Owner Keys Account Helper

    /// Get the provider owner keys managed account
    pub fn provider_owner_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_owner_keys.as_ref()
    }

    /// Get the provider owner keys managed account (mutable)
    pub fn provider_owner_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.provider_owner_keys.as_mut()
    }

    // Provider Operator Keys Account Helper

    /// Get the provider operator keys managed account
    pub fn provider_operator_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_operator_keys.as_ref()
    }

    /// Get the provider operator keys managed account (mutable)
    pub fn provider_operator_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
        self.accounts.provider_operator_keys.as_mut()
    }

    // Provider Platform Keys Account Helper

    /// Get the provider platform keys managed account
    pub fn provider_platform_keys_managed_account(&self) -> Option<&ManagedCoreKeysAccount> {
        self.accounts.provider_platform_keys.as_ref()
    }

    /// Get the provider platform keys managed account (mutable)
    pub fn provider_platform_keys_managed_account_mut(
        &mut self,
    ) -> Option<&mut ManagedCoreKeysAccount> {
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

    /// Get all accounts (mixed funds and keys variants).
    pub fn all_managed_accounts(&self) -> Vec<crate::managed_account::ManagedAccountRef<'_>> {
        self.accounts.all_accounts()
    }
}
