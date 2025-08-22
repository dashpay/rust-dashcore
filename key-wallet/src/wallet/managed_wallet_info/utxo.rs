//! UTXO retrieval functionality for managed wallets
//!
//! This module provides methods to retrieve UTXOs from managed wallet accounts.

use crate::utxo::Utxo;
use crate::Network;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use dashcore::blockdata::transaction::OutPoint;

use super::ManagedWalletInfo;

/// Type alias for UTXOs grouped by account type
type UtxosByAccountType = BTreeMap<&'static str, Vec<(u32, Vec<(OutPoint, Utxo)>)>>;

impl ManagedWalletInfo {
    /// Get all UTXOs for a specific network
    ///
    /// Returns UTXOs from BIP44, BIP32, and CoinJoin accounts only.
    /// Does not include UTXOs from identity or provider accounts.
    pub fn get_utxos(&self, network: Network) -> Vec<(OutPoint, Utxo)> {
        let mut all_utxos = Vec::new();

        // Get the managed account collection for this network
        if let Some(account_collection) = self.accounts.get(&network) {
            // Collect UTXOs from standard BIP44 accounts
            for account in account_collection.standard_bip44_accounts.values() {
                for (outpoint, utxo) in &account.utxos {
                    all_utxos.push((*outpoint, utxo.clone()));
                }
            }

            // Collect UTXOs from standard BIP32 accounts
            for account in account_collection.standard_bip32_accounts.values() {
                for (outpoint, utxo) in &account.utxos {
                    all_utxos.push((*outpoint, utxo.clone()));
                }
            }

            // Collect UTXOs from CoinJoin accounts
            for account in account_collection.coinjoin_accounts.values() {
                for (outpoint, utxo) in &account.utxos {
                    all_utxos.push((*outpoint, utxo.clone()));
                }
            }
        }

        all_utxos
    }

    /// Get UTXOs grouped by account type for a specific network
    ///
    /// Returns a map where:
    /// - Keys are account type strings ("bip44", "bip32", "coinjoin")
    /// - Values are vectors of (account_index, Vec<(OutPoint, Utxo)>) tuples
    pub fn get_utxos_by_account_type(&self, network: Network) -> UtxosByAccountType {
        let mut utxos_by_type = BTreeMap::new();

        if let Some(account_collection) = self.accounts.get(&network) {
            // Collect BIP44 account UTXOs
            let mut bip44_utxos = Vec::new();
            for (index, account) in &account_collection.standard_bip44_accounts {
                let account_utxos: Vec<(OutPoint, Utxo)> = account
                    .utxos
                    .iter()
                    .map(|(outpoint, utxo)| (*outpoint, utxo.clone()))
                    .collect();
                if !account_utxos.is_empty() {
                    bip44_utxos.push((*index, account_utxos));
                }
            }
            if !bip44_utxos.is_empty() {
                utxos_by_type.insert("bip44", bip44_utxos);
            }

            // Collect BIP32 account UTXOs
            let mut bip32_utxos = Vec::new();
            for (index, account) in &account_collection.standard_bip32_accounts {
                let account_utxos: Vec<(OutPoint, Utxo)> = account
                    .utxos
                    .iter()
                    .map(|(outpoint, utxo)| (*outpoint, utxo.clone()))
                    .collect();
                if !account_utxos.is_empty() {
                    bip32_utxos.push((*index, account_utxos));
                }
            }
            if !bip32_utxos.is_empty() {
                utxos_by_type.insert("bip32", bip32_utxos);
            }

            // Collect CoinJoin account UTXOs
            let mut coinjoin_utxos = Vec::new();
            for (index, account) in &account_collection.coinjoin_accounts {
                let account_utxos: Vec<(OutPoint, Utxo)> = account
                    .utxos
                    .iter()
                    .map(|(outpoint, utxo)| (*outpoint, utxo.clone()))
                    .collect();
                if !account_utxos.is_empty() {
                    coinjoin_utxos.push((*index, account_utxos));
                }
            }
            if !coinjoin_utxos.is_empty() {
                utxos_by_type.insert("coinjoin", coinjoin_utxos);
            }
        }

        utxos_by_type
    }

    /// Get spendable UTXOs for a specific network at a given block height
    ///
    /// Returns only UTXOs that can be spent at the current height from
    /// BIP44, BIP32, and CoinJoin accounts.
    pub fn get_spendable_utxos(
        &self,
        network: Network,
        current_height: u32,
    ) -> Vec<(OutPoint, Utxo)> {
        self.get_utxos(network)
            .into_iter()
            .filter(|(_, utxo)| utxo.is_spendable(current_height))
            .collect()
    }

    /// Get total value of all UTXOs for a specific network
    ///
    /// Returns the sum of all UTXO values from BIP44, BIP32, and CoinJoin accounts
    pub fn get_total_utxo_value(&self, network: Network) -> u64 {
        self.get_utxos(network).iter().map(|(_, utxo)| utxo.value()).sum()
    }

    /// Get UTXO count for a specific network
    ///
    /// Returns the total number of UTXOs from BIP44, BIP32, and CoinJoin accounts
    pub fn get_utxo_count(&self, network: Network) -> usize {
        if let Some(account_collection) = self.accounts.get(&network) {
            let mut count = 0;

            // Count BIP44 account UTXOs
            for account in account_collection.standard_bip44_accounts.values() {
                count += account.utxos.len();
            }

            // Count BIP32 account UTXOs
            for account in account_collection.standard_bip32_accounts.values() {
                count += account.utxos.len();
            }

            // Count CoinJoin account UTXOs
            for account in account_collection.coinjoin_accounts.values() {
                count += account.utxos.len();
            }

            count
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::managed_account::ManagedAccount;
    use crate::account::managed_account_collection::ManagedAccountCollection;
    use crate::account::types::ManagedAccountType;
    use crate::bip32::DerivationPath;
    use crate::gap_limit::GapLimitManager;
    use dashcore::{Address, PublicKey, ScriptBuf, TxOut, Txid};
    use dashcore_hashes::Hash;
    use std::str::FromStr;

    #[test]
    fn test_get_utxos_empty() {
        let managed_info = ManagedWalletInfo::new([0u8; 32]);
        let utxos = managed_info.get_utxos(Network::Testnet);
        assert_eq!(utxos.len(), 0);
    }

    #[test]
    fn test_get_utxos_with_accounts() {
        let mut managed_info = ManagedWalletInfo::new([0u8; 32]);

        // Create a managed account collection for testnet
        let mut account_collection = ManagedAccountCollection::new();

        // Create a BIP44 account with some UTXOs
        let base_path = DerivationPath::from_str("m/44'/5'/0'").unwrap();
        let external_path = base_path.child(0.into());
        let internal_path = base_path.child(1.into());

        let mut bip44_account = ManagedAccount::new(
            ManagedAccountType::Standard {
                index: 0,
                standard_account_type: crate::account::types::StandardAccountType::BIP44Account,
                external_addresses: crate::account::address_pool::AddressPool::new(
                    external_path,
                    false,
                    20,
                    Network::Testnet,
                ),
                internal_addresses: crate::account::address_pool::AddressPool::new(
                    internal_path,
                    true,
                    20,
                    Network::Testnet,
                ),
            },
            Network::Testnet,
            GapLimitManager::default(),
            false,
        );

        // Add a test UTXO
        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };
        let txout = TxOut {
            value: 100000,
            script_pubkey: ScriptBuf::new(),
        };
        let address = Address::p2pkh(
            &PublicKey::from_slice(&[
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01,
            ])
            .unwrap(),
            Network::Testnet,
        );
        let utxo = Utxo::new(outpoint, txout, address, 0, false);

        bip44_account.utxos.insert(outpoint, utxo);
        account_collection.standard_bip44_accounts.insert(0, bip44_account);

        managed_info.accounts.insert(Network::Testnet, account_collection);

        // Test getting UTXOs
        let utxos = managed_info.get_utxos(Network::Testnet);
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].1.value(), 100000);
    }
}
