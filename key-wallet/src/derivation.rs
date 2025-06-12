//! Key derivation functionality

use secp256k1::Secp256k1;

use crate::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::error::{Error, Result};

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
        self.derive_priv(secp, path).map_err(Into::into)
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
pub struct HDWallet {
    master_key: ExtendedPrivKey,
    secp: Secp256k1<secp256k1::All>,
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
    pub fn from_seed(seed: &[u8], network: crate::address::Network) -> Result<Self> {
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
        self.master_key.derive_priv(&self.secp, path).map_err(Into::into)
    }

    /// Derive a public key at the given path
    pub fn derive_pub(&self, path: &DerivationPath) -> Result<ExtendedPubKey> {
        let priv_key = self.derive(path)?;
        Ok(ExtendedPubKey::from_priv(&self.secp, &priv_key))
    }

    /// Get a standard BIP44 account key
    pub fn bip44_account(&self, account: u32) -> Result<ExtendedPrivKey> {
        let path = match self.master_key.network {
            crate::address::Network::Dash => crate::dip9::DASH_BIP44_PATH_MAINNET,
            crate::address::Network::Testnet => crate::dip9::DASH_BIP44_PATH_TESTNET,
            _ => return Err(Error::InvalidNetwork),
        };

        // Convert to DerivationPath and append account index
        let mut full_path = crate::bip32::DerivationPath::from(path);
        full_path.push(crate::bip32::ChildNumber::from_hardened_idx(account).unwrap());

        self.derive(&full_path)
    }

    /// Get a CoinJoin account key
    pub fn coinjoin_account(&self, account: u32) -> Result<ExtendedPrivKey> {
        let path = match self.master_key.network {
            crate::address::Network::Dash => crate::dip9::COINJOIN_PATH_MAINNET,
            crate::address::Network::Testnet => crate::dip9::COINJOIN_PATH_TESTNET,
            _ => return Err(Error::InvalidNetwork),
        };

        // Convert to DerivationPath and append account index
        let mut full_path = crate::bip32::DerivationPath::from(path);
        full_path.push(crate::bip32::ChildNumber::from_hardened_idx(account).unwrap());

        self.derive(&full_path)
    }

    /// Get an identity authentication key
    pub fn identity_authentication_key(
        &self,
        identity_index: u32,
        key_index: u32,
    ) -> Result<ExtendedPrivKey> {
        let path = match self.master_key.network {
            crate::address::Network::Dash => crate::dip9::IDENTITY_AUTHENTICATION_PATH_MAINNET,
            crate::address::Network::Testnet => crate::dip9::IDENTITY_AUTHENTICATION_PATH_TESTNET,
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
        self.account_key.derive_pub(&self.secp, &path).map_err(Into::into)
    }

    /// Derive an internal (change) address at index
    pub fn change_address(&self, index: u32) -> Result<ExtendedPubKey> {
        let path = format!("m/1/{}", index)
            .parse::<DerivationPath>()
            .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
        self.account_key.derive_pub(&self.secp, &path).map_err(Into::into)
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
        let wallet = HDWallet::from_seed(&seed, crate::address::Network::Dash).unwrap();

        // Test BIP44 account derivation
        let account0 = wallet.bip44_account(0).unwrap();
        assert_ne!(&account0.private_key[..], &wallet.master_key().private_key[..]);
    }
}
