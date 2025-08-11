//! Key derivation functionality
//!
//! This module provides key derivation functionality with a builder pattern
//! for flexible path construction and derivation strategies.

use alloc::vec::Vec;
use secp256k1::Secp256k1;

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::error::{Error, Result};
use crate::{Network, AccountType};

/// Key derivation interface
pub trait KeyDerivation {
    /// Derive a child private key at the given path
    fn derive_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        path: &DerivationPath,
    ) -> Result<ExtendedPrivKey>;

    /// Derive a child public key at the given path
    fn derive_pub<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        path: &DerivationPath,
    ) -> Result<ExtendedPubKey>;
}

impl KeyDerivation for ExtendedPrivKey {
    fn derive_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        path: &DerivationPath,
    ) -> Result<ExtendedPrivKey> {
        self.derive_priv(secp, path).map_err(Error::Bip32)
    }

    fn derive_pub<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        path: &DerivationPath,
    ) -> Result<ExtendedPubKey> {
        let priv_key = self.derive_priv(secp, path)?;
        Ok(ExtendedPubKey::from_priv(secp, &priv_key))
    }
}

/// HD Wallet implementation
#[derive(Clone)]
pub struct HDWallet {
    master_key: ExtendedPrivKey,
    secp: Secp256k1<secp256k1::All>,
}

impl core::fmt::Debug for HDWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HDWallet")
            .field("master_key", &"<hidden>")
            .finish()
    }
}

impl HDWallet {
    /// Create a new HD wallet from a master key
    pub fn new(master_key: ExtendedPrivKey) -> Self {
        Self {
            master_key,
            secp: Secp256k1::new(),
        }
    }

    /// Create from a seed
    pub fn from_seed(seed: &[u8], network: crate::Network) -> Result<Self> {
        let master_key = ExtendedPrivKey::new_master(network, seed)?;
        Ok(Self::new(master_key))
    }

    /// Get the master extended private key
    pub fn master_key(&self) -> &ExtendedPrivKey {
        &self.master_key
    }

    /// Get the master extended public key
    pub fn master_pub_key(&self) -> ExtendedPubKey {
        ExtendedPubKey::from_priv(&self.secp, &self.master_key)
    }

    /// Derive a key at the given path
    pub fn derive(&self, path: &DerivationPath) -> Result<ExtendedPrivKey> {
        self.master_key.derive_priv(&self.secp, path).map_err(Error::Bip32)
    }

    /// Derive a public key at the given path
    pub fn derive_pub(&self, path: &DerivationPath) -> Result<ExtendedPubKey> {
        let priv_key = self.derive(path)?;
        Ok(ExtendedPubKey::from_priv(&self.secp, &priv_key))
    }

    /// Get a standard BIP44 account key
    pub fn bip44_account(&self, account: u32) -> Result<ExtendedPrivKey> {
        let path = match self.master_key.network {
            crate::Network::Dash => crate::dip9::DASH_BIP44_PATH_MAINNET,
            crate::Network::Testnet => crate::dip9::DASH_BIP44_PATH_TESTNET,
            _ => return Err(Error::InvalidNetwork),
        };

        // Convert to DerivationPath and append account index
        let mut full_path = crate::bip32::DerivationPath::from(path);
        let child_number = crate::bip32::ChildNumber::from_hardened_idx(account)
            .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
        full_path.push(child_number);

        self.derive(&full_path)
    }

    /// Get a CoinJoin account key
    pub fn coinjoin_account(&self, account: u32) -> Result<ExtendedPrivKey> {
        let path = match self.master_key.network {
            crate::Network::Dash => crate::dip9::COINJOIN_PATH_MAINNET,
            crate::Network::Testnet => crate::dip9::COINJOIN_PATH_TESTNET,
            _ => return Err(Error::InvalidNetwork),
        };

        // Convert to DerivationPath and append account index
        let mut full_path = crate::bip32::DerivationPath::from(path);
        let child_number = crate::bip32::ChildNumber::from_hardened_idx(account)
            .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
        full_path.push(child_number);

        self.derive(&full_path)
    }

    /// Get an identity authentication key
    pub fn identity_authentication_key(
        &self,
        identity_index: u32,
        key_index: u32,
    ) -> Result<ExtendedPrivKey> {
        let path = match self.master_key.network {
            crate::Network::Dash => crate::dip9::IDENTITY_AUTHENTICATION_PATH_MAINNET,
            crate::Network::Testnet => crate::dip9::IDENTITY_AUTHENTICATION_PATH_TESTNET,
            _ => return Err(Error::InvalidNetwork),
        };

        // Convert to DerivationPath and append indices
        let mut full_path = crate::bip32::DerivationPath::from(path);
        full_path.push(crate::bip32::ChildNumber::from_hardened_idx(identity_index).unwrap());
        full_path.push(crate::bip32::ChildNumber::from_hardened_idx(key_index).unwrap());

        self.derive(&full_path)
    }
}

/// Address derivation for a specific account
pub struct AccountDerivation {
    account_key: ExtendedPrivKey,
    secp: Secp256k1<secp256k1::All>,
}

impl AccountDerivation {
    /// Create a new account derivation
    pub fn new(account_key: ExtendedPrivKey) -> Self {
        Self {
            account_key,
            secp: Secp256k1::new(),
        }
    }

    /// Derive an external (receive) address at index
    pub fn receive_address(&self, index: u32) -> Result<ExtendedPubKey> {
        let path = format!("m/0/{}", index)
            .parse::<DerivationPath>()
            .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
        let priv_key = self.account_key.derive_priv(&self.secp, &path).map_err(Error::Bip32)?;
        Ok(ExtendedPubKey::from_priv(&self.secp, &priv_key))
    }

    /// Derive an internal (change) address at index
    pub fn change_address(&self, index: u32) -> Result<ExtendedPubKey> {
        let path = format!("m/1/{}", index)
            .parse::<DerivationPath>()
            .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
        let priv_key = self.account_key.derive_priv(&self.secp, &path).map_err(Error::Bip32)?;
        Ok(ExtendedPubKey::from_priv(&self.secp, &priv_key))
    }
}

/// Builder for constructing derivation paths
#[derive(Debug, Clone)]
pub struct DerivationPathBuilder {
    components: Vec<ChildNumber>,
    purpose: Option<u32>,
    coin_type: Option<u32>,
    account: Option<u32>,
    change: Option<u32>,
    address_index: Option<u32>,
}

impl DerivationPathBuilder {
    /// Create a new derivation path builder
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            purpose: None,
            coin_type: None,
            account: None,
            change: None,
            address_index: None,
        }
    }
    
    /// Set purpose (BIP44 = 44', BIP32 = 0, etc.)
    pub fn purpose(mut self, purpose: u32) -> Self {
        self.purpose = Some(purpose);
        self
    }
    
    /// Set coin type (5' for Dash)
    pub fn coin_type(mut self, coin_type: u32) -> Self {
        self.coin_type = Some(coin_type);
        self
    }
    
    /// Set account index
    pub fn account(mut self, account: u32) -> Self {
        self.account = Some(account);
        self
    }
    
    /// Set change (0 for external, 1 for internal)
    pub fn change(mut self, change: u32) -> Self {
        self.change = Some(change);
        self
    }
    
    /// Set address index
    pub fn address_index(mut self, index: u32) -> Self {
        self.address_index = Some(index);
        self
    }
    
    /// Add a hardened child number
    pub fn hardened(mut self, index: u32) -> Self {
        if let Ok(child) = ChildNumber::from_hardened_idx(index) {
            self.components.push(child);
        }
        self
    }
    
    /// Add a normal (non-hardened) child number
    pub fn normal(mut self, index: u32) -> Self {
        if let Ok(child) = ChildNumber::from_normal_idx(index) {
            self.components.push(child);
        }
        self
    }
    
    /// Add a child number
    pub fn child(mut self, child: ChildNumber) -> Self {
        self.components.push(child);
        self
    }
    
    /// Build a BIP44 path: m/44'/coin_type'/account'/change/address_index
    pub fn bip44(self) -> Result<DerivationPath> {
        let mut path = Vec::new();
        
        // Purpose (44' for BIP44)
        path.push(ChildNumber::from_hardened_idx(44).map_err(Error::Bip32)?);
        
        // Coin type (default to 5' for Dash)
        let coin_type = self.coin_type.unwrap_or(5);
        path.push(ChildNumber::from_hardened_idx(coin_type).map_err(Error::Bip32)?);
        
        // Account (default to 0')
        let account = self.account.unwrap_or(0);
        path.push(ChildNumber::from_hardened_idx(account).map_err(Error::Bip32)?);
        
        // Change (optional)
        if let Some(change) = self.change {
            path.push(ChildNumber::from_normal_idx(change).map_err(Error::Bip32)?);
            
            // Address index (optional, requires change to be set)
            if let Some(index) = self.address_index {
                path.push(ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?);
            }
        }
        
        Ok(DerivationPath::from(path))
    }
    
    /// Build a BIP32 path from the components
    pub fn build(self) -> Result<DerivationPath> {
        // If components were added directly, use them
        if !self.components.is_empty() {
            return Ok(DerivationPath::from(self.components));
        }
        
        // Otherwise, build from purpose/coin_type/account/change/index
        let mut path = Vec::new();
        
        if let Some(purpose) = self.purpose {
            path.push(ChildNumber::from_hardened_idx(purpose).map_err(Error::Bip32)?);
        }
        
        if let Some(coin_type) = self.coin_type {
            path.push(ChildNumber::from_hardened_idx(coin_type).map_err(Error::Bip32)?);
        }
        
        if let Some(account) = self.account {
            path.push(ChildNumber::from_hardened_idx(account).map_err(Error::Bip32)?);
        }
        
        if let Some(change) = self.change {
            path.push(ChildNumber::from_normal_idx(change).map_err(Error::Bip32)?);
        }
        
        if let Some(index) = self.address_index {
            path.push(ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?);
        }
        
        Ok(DerivationPath::from(path))
    }
    
    /// Build path for a specific network and account type
    pub fn for_network_and_type(
        self,
        network: Network,
        _account_type: AccountType,
        account_index: u32,
    ) -> Result<DerivationPath> {
        // For now, just use BIP44 derivation
        // m/44'/coin_type'/account'/0/0
        let coin_type = match network {
            Network::Dash => 5,
            Network::Testnet | Network::Devnet | Network::Regtest => 1,
            _ => 5, // Default to Dash
        };
        
        self.purpose(44)
            .coin_type(coin_type)
            .account(account_index)
            .change(0)
            .address_index(0)
            .bip44()
    }
}

impl Default for DerivationPathBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Advanced derivation strategies
pub struct DerivationStrategy {
    /// Base path for derivation
    base_path: DerivationPath,
    /// Gap limit for address discovery
    gap_limit: u32,
    /// Lookahead window
    lookahead: u32,
}

impl DerivationStrategy {
    /// Create a new derivation strategy
    pub fn new(base_path: DerivationPath) -> Self {
        Self {
            base_path,
            gap_limit: 20,
            lookahead: 20,
        }
    }
    
    /// Set the gap limit
    pub fn with_gap_limit(mut self, limit: u32) -> Self {
        self.gap_limit = limit;
        self
    }
    
    /// Set the lookahead window
    pub fn with_lookahead(mut self, lookahead: u32) -> Self {
        self.lookahead = lookahead;
        self
    }
    
    /// Derive a batch of addresses
    pub fn derive_batch<C: secp256k1::Signing>(
        &self,
        key: &ExtendedPrivKey,
        secp: &Secp256k1<C>,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<ExtendedPubKey>> {
        let mut keys = Vec::with_capacity(count as usize);
        
        for i in start_index..(start_index + count) {
            let mut path = self.base_path.clone();
            path.push(ChildNumber::from_normal_idx(i).map_err(Error::Bip32)?);
            
            let derived = key.derive_priv(secp, &path).map_err(Error::Bip32)?;
            keys.push(ExtendedPubKey::from_priv(secp, &derived));
        }
        
        Ok(keys)
    }
    
    /// Scan for used addresses
    pub fn scan_for_activity<C, F>(
        &self,
        key: &ExtendedPrivKey,
        secp: &Secp256k1<C>,
        check_fn: F,
    ) -> Result<Vec<u32>>
    where
        C: secp256k1::Signing,
        F: Fn(&ExtendedPubKey) -> bool,
    {
        let mut used_indices = Vec::new();
        let mut consecutive_unused = 0;
        let mut index = 0;
        
        loop {
            let mut path = self.base_path.clone();
            path.push(ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?);
            
            let derived = key.derive_priv(secp, &path).map_err(Error::Bip32)?;
            let pubkey = ExtendedPubKey::from_priv(secp, &derived);
            
            if check_fn(&pubkey) {
                used_indices.push(index);
                consecutive_unused = 0;
            } else {
                consecutive_unused += 1;
            }
            
            if consecutive_unused >= self.gap_limit {
                break;
            }
            
            index += 1;
        }
        
        Ok(used_indices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::{Language, Mnemonic};

    #[test]
    fn test_hd_wallet_derivation() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let wallet = HDWallet::from_seed(&seed, crate::Network::Dash).unwrap();

        // Test BIP44 account derivation
        let account0 = wallet.bip44_account(0).unwrap();
        assert_ne!(&account0.private_key[..], &wallet.master_key().private_key[..]);
    }
}
