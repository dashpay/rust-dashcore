//! Key derivation functionality
//!
//! This module provides key derivation functionality with a builder pattern
//! for flexible path construction and derivation strategies.

use alloc::vec::Vec;
use secp256k1::Secp256k1;

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::error::{Error, Result};
use crate::{AccountType, Network};

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
        f.debug_struct("HDWallet").field("master_key", &"<hidden>").finish()
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
    use dashcore_hashes::Hash;

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

    // ✓ Test BIP32 derivation with exact DashSync test vectors
    #[test]
    fn test_bip32_derivation_vectors() {
        use hex::FromHex;

        // Test vector from DashSync DSBIP32Tests.m - seed "000102030405060708090a0b0c0d0e0f"
        let seed = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let secp = secp256k1::Secp256k1::new();

        // Create master key
        let master_key = ExtendedPrivKey::new_master(crate::Network::Dash, &seed).unwrap();

        // Test m/0'/1/2' path (from DashSync test)
        let path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 0,
            },
            ChildNumber::Normal {
                index: 1,
            },
            ChildNumber::Hardened {
                index: 2,
            },
        ]);

        let derived_key = master_key.derive_priv(&secp, &path).unwrap();

        // The DashSync test expects this private key at m/0'/1/2':
        // DashSync includes a network prefix byte (0xCC for mainnet) before the key
        // "cccbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
        let expected_with_prefix =
            Vec::from_hex("cccbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca")
                .unwrap();
        // Skip the first byte (network prefix) and compare the actual 32-byte key
        assert_eq!(&derived_key.private_key.secret_bytes(), &expected_with_prefix[1..]);

        // Test m/0'/0/97 path for zero padding test (from DashSync)
        let path_zero_padding = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 0,
            },
            ChildNumber::Normal {
                index: 0,
            },
            ChildNumber::Normal {
                index: 97,
            },
        ]);

        let derived_key_zero = master_key.derive_priv(&secp, &path_zero_padding).unwrap();

        // DashSync expects: "00136c1ad038f9a00871895322a487ed14f1cdc4d22ad351cfa1a0d235975dd7"
        let expected_zero_padded =
            Vec::from_hex("00136c1ad038f9a00871895322a487ed14f1cdc4d22ad351cfa1a0d235975dd7")
                .unwrap();
        assert_eq!(&derived_key_zero.private_key.secret_bytes(), &expected_zero_padded[..]);
    }

    // ✓ Test extended key serialization (from DashSync DSBIP32Tests.m)
    #[test]
    fn test_extended_key_serialization() {
        use hex::FromHex;

        let seed = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let secp = secp256k1::Secp256k1::new();

        // Test master key serialization (m)
        let master_key = ExtendedPrivKey::new_master(crate::Network::Dash, &seed).unwrap();
        let master_xprv = master_key.to_string();
        let master_xpub = ExtendedPubKey::from_priv(&secp, &master_key).to_string();

        // DashSync expects these exact serializations for m
        assert_eq!(master_xpub, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
        assert_eq!(master_xprv, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");

        // Test m/0' (account 0)
        let path_m_0h = DerivationPath::from(vec![ChildNumber::Hardened {
            index: 0,
        }]);
        let key_m_0h = master_key.derive_priv(&secp, &path_m_0h).unwrap();
        let xprv_m_0h = key_m_0h.to_string();
        let xpub_m_0h = ExtendedPubKey::from_priv(&secp, &key_m_0h).to_string();

        // DashSync expects these for m/0'
        assert_eq!(xpub_m_0h, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
        assert_eq!(xprv_m_0h, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

        // Test m/0'/1
        let path_m_0h_1 = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 0,
            },
            ChildNumber::Normal {
                index: 1,
            },
        ]);
        let key_m_0h_1 = master_key.derive_priv(&secp, &path_m_0h_1).unwrap();
        let xprv_m_0h_1 = key_m_0h_1.to_string();
        let xpub_m_0h_1 = ExtendedPubKey::from_priv(&secp, &key_m_0h_1).to_string();

        // DashSync expects these for m/0'/1
        assert_eq!(xpub_m_0h_1, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
        assert_eq!(xprv_m_0h_1, "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");

        // Test m/0'/1/2'
        let path_m_0h_1_2h = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 0,
            },
            ChildNumber::Normal {
                index: 1,
            },
            ChildNumber::Hardened {
                index: 2,
            },
        ]);
        let key_m_0h_1_2h = master_key.derive_priv(&secp, &path_m_0h_1_2h).unwrap();
        let xprv_m_0h_1_2h = key_m_0h_1_2h.to_string();
        let xpub_m_0h_1_2h = ExtendedPubKey::from_priv(&secp, &key_m_0h_1_2h).to_string();

        // DashSync expects these for m/0'/1/2'
        assert_eq!(xpub_m_0h_1_2h, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");
        assert_eq!(xprv_m_0h_1_2h, "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");
    }

    // ✓ Test special derivation paths (from DashSync special purpose paths)
    #[test]
    fn test_special_derivation_paths() {
        let mnemonic = Mnemonic::from_phrase(
            "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow",
            crate::mnemonic::Language::English
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let wallet = HDWallet::from_seed(&seed, crate::Network::Dash).unwrap();
        let secp = secp256k1::Secp256k1::new();

        // Test identity authentication derivation (purpose 9' for Dash Platform)
        // m/9'/5'/1'/0 (DIP-9: Identity Authentication)
        let identity_auth_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 9,
            }, // DIP-9 purpose
            ChildNumber::Hardened {
                index: 5,
            }, // Dash coin type
            ChildNumber::Hardened {
                index: 1,
            }, // Identity index
            ChildNumber::Normal {
                index: 0,
            }, // Key index
        ]);

        let identity_key = wallet.master_key().derive_priv(&secp, &identity_auth_path).unwrap();
        assert_ne!(&identity_key.private_key[..], &wallet.master_key().private_key[..]);

        // Test identity registration derivation
        // m/9'/5'/1'/1 (DIP-9: Identity Registration)
        let identity_reg_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 9,
            },
            ChildNumber::Hardened {
                index: 5,
            },
            ChildNumber::Hardened {
                index: 1,
            },
            ChildNumber::Normal {
                index: 1,
            },
        ]);

        let reg_key = wallet.master_key().derive_priv(&secp, &identity_reg_path).unwrap();
        assert_ne!(&reg_key.private_key[..], &identity_key.private_key[..]);

        // Test identity top-up derivation
        // m/9'/5'/1'/2 (DIP-9: Identity Top-up)
        let identity_topup_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 9,
            },
            ChildNumber::Hardened {
                index: 5,
            },
            ChildNumber::Hardened {
                index: 1,
            },
            ChildNumber::Normal {
                index: 2,
            },
        ]);

        let topup_key = wallet.master_key().derive_priv(&secp, &identity_topup_path).unwrap();
        assert_ne!(&topup_key.private_key[..], &reg_key.private_key[..]);
        assert_ne!(&topup_key.private_key[..], &identity_key.private_key[..]);

        // Test provider voting derivation (masternode voting)
        // m/3'/1'/0' (Provider voting)
        let provider_voting_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 3,
            }, // Provider purpose
            ChildNumber::Hardened {
                index: 1,
            }, // Voting type
            ChildNumber::Hardened {
                index: 0,
            }, // Provider index
        ]);

        let voting_key = wallet.master_key().derive_priv(&secp, &provider_voting_path).unwrap();
        assert_ne!(&voting_key.private_key[..], &topup_key.private_key[..]);

        // Test provider operator derivation
        // m/3'/0'/0' (Provider operator)
        let provider_op_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 3,
            }, // Provider purpose
            ChildNumber::Hardened {
                index: 0,
            }, // Operator type
            ChildNumber::Hardened {
                index: 0,
            }, // Provider index
        ]);

        let operator_key = wallet.master_key().derive_priv(&secp, &provider_op_path).unwrap();
        assert_ne!(&operator_key.private_key[..], &voting_key.private_key[..]);
    }

    // ✓ Test derivation path builder pattern
    #[test]
    fn test_derivation_path_builder() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            crate::mnemonic::Language::English
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let wallet = HDWallet::from_seed(&seed, crate::Network::Testnet).unwrap();

        // Test builder for BIP44 path
        let bip44_path = DerivationPathBuilder::new()
            .coin_type(1) // Testnet
            .account(0)
            .change(0) // External
            .address_index(0)
            .bip44()
            .unwrap();

        // Should create m/44'/1'/0'/0/0
        let expected_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 44,
            },
            ChildNumber::Hardened {
                index: 1,
            },
            ChildNumber::Hardened {
                index: 0,
            },
            ChildNumber::Normal {
                index: 0,
            },
            ChildNumber::Normal {
                index: 0,
            },
        ]);

        assert_eq!(bip44_path, expected_path);

        // Test derivation with the built path
        let secp = secp256k1::Secp256k1::new();
        let derived = wallet.master_key().derive_priv(&secp, &bip44_path).unwrap();
        assert_ne!(&derived.private_key[..], &wallet.master_key().private_key[..]);
    }

    // ✓ Test key signing and verification
    #[test]
    fn test_key_signing_deterministic() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            crate::mnemonic::Language::English
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let wallet = HDWallet::from_seed(&seed, crate::Network::Testnet).unwrap();
        let secp = secp256k1::Secp256k1::new();

        // Derive a key for signing
        let path = DerivationPath::from(vec![ChildNumber::Hardened {
            index: 0,
        }]);
        let signing_key = wallet.master_key().derive_priv(&secp, &path).unwrap();

        // Test message
        let message = b"Hello Dash!";
        let message_hash = dashcore_hashes::sha256::Hash::hash(message);

        // Sign the message (deterministic signing)
        let signature1 = secp.sign_ecdsa(
            &secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &signing_key.private_key,
        );
        let signature2 = secp.sign_ecdsa(
            &secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &signing_key.private_key,
        );

        // Signatures should be the same (deterministic)
        assert_eq!(signature1, signature2);

        // Verify the signature
        let pubkey = ExtendedPubKey::from_priv(&secp, &signing_key);
        let verified = secp.verify_ecdsa(
            &secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &signature1,
            &pubkey.public_key,
        );
        assert!(verified.is_ok());
    }

    // ✓ Test key recovery from signature
    #[test]
    fn test_key_recovery_from_signature() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            crate::mnemonic::Language::English
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let wallet = HDWallet::from_seed(&seed, crate::Network::Testnet).unwrap();
        let secp = secp256k1::Secp256k1::new();

        // Derive a key for signing
        let path = DerivationPath::from(vec![ChildNumber::Normal {
            index: 0,
        }]);
        let signing_key = wallet.master_key().derive_priv(&secp, &path).unwrap();
        let public_key = ExtendedPubKey::from_priv(&secp, &signing_key);

        // Test message
        let message = b"Dash recovery test";
        let message_hash = dashcore_hashes::sha256::Hash::hash(message);

        // Create recoverable signature
        let signature = secp.sign_ecdsa_recoverable(
            &secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &signing_key.private_key,
        );

        // Recover the public key from signature
        let recovered_pubkey = secp
            .recover_ecdsa(
                &secp256k1::Message::from_digest(message_hash.to_byte_array()),
                &signature,
            )
            .unwrap();

        // Should match original public key
        assert_eq!(recovered_pubkey, public_key.public_key);
    }

    // ✓ Test DashPay contact key derivation - m/15'/5'/15'/accountNumber
    #[test]
    fn test_dashpay_derivation() {
        // Test data from DashSync DSDIP14Tests.m
        // DashPay uses FEATURE_PURPOSE = 9 and FEATURE_PURPOSE_DASHPAY = 15
        // Full path: m/9'/5'/15'/accountNumber for DashPay contacts

        let mnemonic = Mnemonic::from_phrase(
            "birth kingdom trash renew flavor utility donkey gasp regular alert pave layer",
            crate::mnemonic::Language::English,
        )
        .unwrap();

        let seed = mnemonic.to_seed("");
        let wallet = HDWallet::from_seed(&seed, crate::Network::Testnet).unwrap();
        let secp = secp256k1::Secp256k1::new();

        // Test DashPay contact derivation path: m/9'/5'/15'/0'
        // This is used for master identity contacts in DashPay
        let dashpay_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 9,
            }, // FEATURE_PURPOSE
            ChildNumber::Hardened {
                index: 5,
            }, // testnet coin type
            ChildNumber::Hardened {
                index: 15,
            }, // FEATURE_PURPOSE_DASHPAY
            ChildNumber::Hardened {
                index: 0,
            }, // account 0
        ]);

        let dashpay_key = wallet.master_key().derive_priv(&secp, &dashpay_path).unwrap();
        let dashpay_pubkey = ExtendedPubKey::from_priv(&secp, &dashpay_key);

        // Verify this produces a different key than other special paths
        // Test against identity authentication path
        let auth_path = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 9,
            },
            ChildNumber::Hardened {
                index: 5,
            },
            ChildNumber::Hardened {
                index: 1,
            },
            ChildNumber::Hardened {
                index: 0,
            },
        ]);
        let auth_key = wallet.master_key().derive_priv(&secp, &auth_path).unwrap();

        // Keys should be different
        assert_ne!(dashpay_key.private_key, auth_key.private_key);
        assert_ne!(
            dashpay_pubkey.public_key,
            ExtendedPubKey::from_priv(&secp, &auth_key).public_key
        );

        // Test multiple DashPay accounts
        let dashpay_account_1 = DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: 9,
            },
            ChildNumber::Hardened {
                index: 5,
            },
            ChildNumber::Hardened {
                index: 15,
            },
            ChildNumber::Hardened {
                index: 1,
            }, // account 1
        ]);

        let dashpay_key_1 = wallet.master_key().derive_priv(&secp, &dashpay_account_1).unwrap();

        // Different accounts should have different keys
        assert_ne!(dashpay_key.private_key, dashpay_key_1.private_key);

        // Verify we can derive contact-specific keys from the DashPay account
        // In DashPay, contact keys are derived further from the account key
        let contact_0 = dashpay_key
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![
                    ChildNumber::Normal {
                        index: 0,
                    }, // First contact
                ]),
            )
            .unwrap();

        let contact_1 = dashpay_key
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![
                    ChildNumber::Normal {
                        index: 1,
                    }, // Second contact
                ]),
            )
            .unwrap();

        // Contact keys should be different
        assert_ne!(contact_0.private_key, contact_1.private_key);

        // Verify the DashPay key can sign and verify messages
        let message = b"DashPay contact message";
        let message_hash = dashcore_hashes::sha256::Hash::hash(message);
        let signature = secp.sign_ecdsa(
            &secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &dashpay_key.private_key,
        );

        let verified = secp.verify_ecdsa(
            &secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &signature,
            &dashpay_pubkey.public_key,
        );
        assert!(verified.is_ok());
    }
}
