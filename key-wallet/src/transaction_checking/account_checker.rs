//! Account-level transaction checking
//!
//! This module provides methods for checking if transactions belong to
//! specific accounts within a ManagedAccountCollection.

use super::transaction_router::AccountTypeToCheck;
use crate::account::address_pool::{AddressInfo, PublicKeyType};
use crate::account::types::ManagedAccountType;
use crate::account::{ManagedAccount, ManagedAccountCollection};
use crate::Address;
use alloc::vec::Vec;
use dashcore::address::Payload;
use dashcore::blockdata::transaction::Transaction;
use dashcore::transaction::TransactionPayload;

/// Result of checking a transaction against accounts
#[derive(Debug, Clone)]
pub struct TransactionCheckResult {
    /// Whether the transaction belongs to any account
    pub is_relevant: bool,
    /// Accounts that the transaction affects
    pub affected_accounts: Vec<AccountMatch>,
    /// Total value received by our accounts
    pub total_received: u64,
    /// Total value sent from our accounts
    pub total_sent: u64,
    /// Total value received for Platform credit conversion
    pub total_received_for_credit_conversion: u64,
}

/// Information about a matched account
#[derive(Debug, Clone)]
pub struct AccountMatch {
    /// The type of account that matched
    pub account_type: AccountTypeToCheck,
    /// Index of the account (if applicable)
    pub account_index: Option<u32>,
    /// Address information for addresses involved in the transaction
    pub involved_addresses: Vec<AddressInfo>,
    /// Value received by this account
    pub received: u64,
    /// Value sent from this account
    pub sent: u64,
    /// Value received for Platform credit conversion (e.g., from AssetLock credit_outputs)
    pub received_for_credit_conversion: u64,
}

impl ManagedAccountCollection {
    /// Check if a transaction belongs to any accounts in the collection
    pub fn check_transaction(
        &self,
        tx: &Transaction,
        account_types: &[AccountTypeToCheck],
    ) -> TransactionCheckResult {
        let mut result = TransactionCheckResult {
            is_relevant: false,
            affected_accounts: Vec::new(),
            total_received: 0,
            total_sent: 0,
            total_received_for_credit_conversion: 0,
        };

        for account_type in account_types {
            let matches = self.check_account_type(tx, *account_type);
            for match_info in matches {
                result.is_relevant = true;
                result.total_received += match_info.received;
                result.total_sent += match_info.sent;
                result.total_received_for_credit_conversion +=
                    match_info.received_for_credit_conversion;
                result.affected_accounts.push(match_info);
            }
        }

        result
    }

    /// Check a specific account type for transaction involvement
    fn check_account_type(
        &self,
        tx: &Transaction,
        account_type: AccountTypeToCheck,
    ) -> Vec<AccountMatch> {
        match account_type {
            AccountTypeToCheck::StandardBIP44 => {
                Self::check_indexed_accounts(&self.standard_bip44_accounts, tx)
            }
            AccountTypeToCheck::StandardBIP32 => {
                Self::check_indexed_accounts(&self.standard_bip32_accounts, tx)
            }
            AccountTypeToCheck::CoinJoin => {
                Self::check_indexed_accounts(&self.coinjoin_accounts, tx)
            }
            AccountTypeToCheck::IdentityRegistration => self
                .identity_registration
                .as_ref()
                .and_then(|account| account.check_asset_lock_transaction_for_match(tx, None))
                .into_iter()
                .collect(),
            AccountTypeToCheck::IdentityTopUp => {
                Self::check_indexed_accounts(&self.identity_topup, tx)
            }
            AccountTypeToCheck::IdentityTopUpNotBound => self
                .identity_topup_not_bound
                .as_ref()
                .and_then(|account| account.check_asset_lock_transaction_for_match(tx, None))
                .into_iter()
                .collect(),
            AccountTypeToCheck::IdentityInvitation => self
                .identity_invitation
                .as_ref()
                .and_then(|account| account.check_asset_lock_transaction_for_match(tx, None))
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderVotingKeys => self
                .provider_voting_keys
                .as_ref()
                .and_then(|account| {
                    account.check_provider_voting_key_in_transaction_for_match(tx, None)
                })
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderOwnerKeys => self
                .provider_owner_keys
                .as_ref()
                .and_then(|account| {
                    account.check_provider_owner_key_in_transaction_for_match(tx, None)
                })
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderOperatorKeys => self
                .provider_operator_keys
                .as_ref()
                .and_then(|account| {
                    account.check_provider_operator_key_in_transaction_for_match(tx, None)
                })
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderPlatformKeys => self
                .provider_platform_keys
                .as_ref()
                .and_then(|account| {
                    account.check_provider_platform_key_in_transaction_for_match(tx, None)
                })
                .into_iter()
                .collect(),
        }
    }

    /// Check indexed accounts (BTreeMap of accounts)
    fn check_indexed_accounts(
        accounts: &alloc::collections::BTreeMap<u32, ManagedAccount>,
        tx: &Transaction,
    ) -> Vec<AccountMatch> {
        let mut matches = Vec::new();
        for (index, account) in accounts {
            if let Some(match_info) = account.check_transaction_for_match(tx, Some(*index)) {
                matches.push(match_info);
            }
        }
        matches
    }
}

impl ManagedAccount {
    /// Check a single account for transaction involvement
    pub fn check_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        // Then check regular outputs
        let mut involved_addresses = Vec::new();
        let mut received = 0u64;
        let sent = 0u64;

        // Check outputs (received)
        for output in &tx.output {
            if self.contains_script_pub_key(&output.script_pubkey) {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                    // Try to find the address info from the account
                    if let Some(address_info) = self.get_address_info(&address) {
                        involved_addresses.push(address_info.clone());
                    }
                }
                received += output.value;
            }
        }

        // Check inputs (sent) - would need UTXO information to properly calculate
        // For now, we just mark that addresses are involved
        // In a real implementation, we'd look up the previous outputs being spent

        if !involved_addresses.is_empty() {
            Some(AccountMatch {
                account_type: (&self.account_type).into(),
                account_index: index,
                involved_addresses,
                received,
                sent,
                received_for_credit_conversion: 0, // Regular transactions don't convert to credits
            })
        } else {
            None
        }
    }

    /// Check AssetLock transaction credit_outputs for account involvement
    pub fn check_asset_lock_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        use dashcore::transaction::TransactionPayload;

        if let Some(TransactionPayload::AssetLockPayloadType(ref payload)) =
            tx.special_transaction_payload
        {
            let mut involved_addresses = Vec::new();
            let mut received = 0u64;

            // Check credit_outputs in the AssetLock payload
            for credit_output in &payload.credit_outputs {
                if self.contains_script_pub_key(&credit_output.script_pubkey) {
                    if let Ok(address) =
                        Address::from_script(&credit_output.script_pubkey, self.network)
                    {
                        // Try to find the address info from the account
                        if let Some(address_info) = self.get_address_info(&address) {
                            involved_addresses.push(address_info.clone());
                        }
                    }
                    received += credit_output.value;
                }
            }

            if !involved_addresses.is_empty() {
                return Some(AccountMatch {
                    account_type: (&self.account_type).into(),
                    account_index: index,
                    involved_addresses,
                    received: 0,
                    sent: 0,
                    received_for_credit_conversion: received, // These funds are locked for Platform credits
                });
            }
        }

        None
    }

    /// Check if transaction contains provider voting key from this account
    pub fn check_provider_voting_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider voting keys account
        if let ManagedAccountType::ProviderVotingKeys {
            addresses,
        } = &self.account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let voting_key_hash = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => {
                        &reg.voting_key_hash
                    }
                    TransactionPayload::ProviderUpdateRegistrarPayloadType(update) => {
                        &update.voting_key_hash
                    }
                    _ => return None,
                };

                // Check if voting_key_hash matches any of our address hashes
                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == voting_key_hash {
                            // Get the address info
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type: (&self.account_type).into(),
                                    account_index: index,
                                    involved_addresses: vec![address_info.clone()],
                                    received: 0,
                                    sent: 0,
                                    received_for_credit_conversion: 0,
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains provider owner key from this account
    pub fn check_provider_owner_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider voting keys account
        if let ManagedAccountType::ProviderVotingKeys {
            addresses,
        } = &self.account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let owner_key_hash = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => &reg.owner_key_hash,
                    _ => return None,
                };

                // Check if owner_key_hash matches any of our address hashes
                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == owner_key_hash {
                            // Get the address info
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type: (&self.account_type).into(),
                                    account_index: index,
                                    involved_addresses: vec![address_info.clone()],
                                    received: 0,
                                    sent: 0,
                                    received_for_credit_conversion: 0,
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains provider operator key from this account
    pub fn check_provider_operator_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider voting keys account
        if let ManagedAccountType::ProviderVotingKeys {
            addresses,
        } = &self.account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let operator_public_key = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => {
                        &reg.operator_public_key
                    }
                    _ => return None,
                };

                // Check if operator_public_key matches any of our BLS public keys
                for address_info in addresses.addresses.values() {
                    if let Some(PublicKeyType::BLS(bls_key)) = &address_info.public_key {
                        // Compare the byte arrays - BLSPublicKey implements AsRef<[u8; 48]>
                        let operator_key_bytes: &[u8; 48] = operator_public_key.as_ref();
                        if bls_key.len() == 48 && bls_key.as_slice() == operator_key_bytes {
                            return Some(AccountMatch {
                                account_type: (&self.account_type).into(),
                                account_index: index,
                                involved_addresses: vec![address_info.clone()],
                                received: 0,
                                sent: 0,
                                received_for_credit_conversion: 0,
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains provider platform key from this account
    pub fn check_provider_platform_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider voting keys account
        if let ManagedAccountType::ProviderVotingKeys {
            addresses,
        } = &self.account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let platform_node_id = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => {
                        if let Some(platform_node_id) = &reg.platform_node_id {
                            platform_node_id
                        } else {
                            return None;
                        }
                    }
                    _ => return None,
                };

                // Check if platform_node_id matches any of our address hashes
                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == platform_node_id {
                            // Get the address info
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type: (&self.account_type).into(),
                                    account_index: index,
                                    involved_addresses: vec![address_info.clone()],
                                    received: 0,
                                    sent: 0,
                                    received_for_credit_conversion: 0,
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Helper to check regular outputs (used by provider key methods)
    fn check_regular_outputs_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        let mut involved_addresses = Vec::new();
        let mut received = 0u64;

        for output in &tx.output {
            if self.contains_script_pub_key(&output.script_pubkey) {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                    // Try to find the address info from the account
                    if let Some(address_info) = self.get_address_info(&address) {
                        involved_addresses.push(address_info.clone());
                    }
                }
                received += output.value;
            }
        }

        if !involved_addresses.is_empty() {
            Some(AccountMatch {
                account_type: (&self.account_type).into(),
                account_index: index,
                involved_addresses,
                received,
                sent: 0,
                received_for_credit_conversion: 0, // Regular outputs don't convert to credits
            })
        } else {
            None
        }
    }

    /// Check if an address belongs to any account in the collection
    pub fn find_address_account(
        collection: &ManagedAccountCollection,
        address: &Address,
    ) -> Option<(AccountTypeToCheck, Option<u32>)> {
        // Check standard BIP44 accounts
        for (index, account) in &collection.standard_bip44_accounts {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::StandardBIP44, Some(*index)));
            }
        }

        // Check standard BIP32 accounts
        for (index, account) in &collection.standard_bip32_accounts {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::StandardBIP32, Some(*index)));
            }
        }

        // Check CoinJoin accounts
        for (index, account) in &collection.coinjoin_accounts {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::CoinJoin, Some(*index)));
            }
        }

        // Check identity registration
        if let Some(account) = &collection.identity_registration {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityRegistration, None));
            }
        }

        // Check identity top-up accounts
        for (index, account) in &collection.identity_topup {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityTopUp, Some(*index)));
            }
        }

        // Check identity top-up not bound
        if let Some(account) = &collection.identity_topup_not_bound {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityTopUpNotBound, None));
            }
        }

        // Check identity invitation
        if let Some(account) = &collection.identity_invitation {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityInvitation, None));
            }
        }

        // Check provider accounts
        if let Some(account) = &collection.provider_voting_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderVotingKeys, None));
            }
        }

        if let Some(account) = &collection.provider_owner_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderOwnerKeys, None));
            }
        }

        if let Some(account) = &collection.provider_operator_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderOperatorKeys, None));
            }
        }

        if let Some(account) = &collection.provider_platform_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderPlatformKeys, None));
            }
        }

        None
    }
}
