//! FFI bindings for key-wallet library

use std::str::FromStr;
use std::sync::Arc;

use key_wallet::{
    self as kw, derivation::HDWallet as KwHDWallet, mnemonic as kw_mnemonic, Address as KwAddress,
    AddressType as KwAddressType, DerivationPath as KwDerivationPath, ExtendedPrivKey,
    ExtendedPubKey, Network as KwNetwork,
};
use secp256k1::{PublicKey, Secp256k1};

// Include the UniFFI scaffolding
uniffi::include_scaffolding!("key_wallet");

#[cfg(test)]
mod lib_tests;

// Initialize function
pub fn initialize() {
    // Any global initialization if needed
}

// Re-export enums for UniFFI
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Dash = 0,
    Testnet = 1,
    Regtest = 2,
    Devnet = 3,
}

impl From<Network> for key_wallet::Network {
    fn from(n: Network) -> Self {
        match n {
            Network::Dash => key_wallet::Network::Dash,
            Network::Testnet => key_wallet::Network::Testnet,
            Network::Regtest => key_wallet::Network::Regtest,
            Network::Devnet => key_wallet::Network::Devnet,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    ChineseSimplified,
    ChineseTraditional,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

impl From<Language> for kw_mnemonic::Language {
    fn from(l: Language) -> Self {
        match l {
            Language::English => kw_mnemonic::Language::English,
            Language::ChineseSimplified => kw_mnemonic::Language::ChineseSimplified,
            Language::ChineseTraditional => kw_mnemonic::Language::ChineseTraditional,
            Language::French => kw_mnemonic::Language::French,
            Language::Italian => kw_mnemonic::Language::Italian,
            Language::Japanese => kw_mnemonic::Language::Japanese,
            Language::Korean => kw_mnemonic::Language::Korean,
            Language::Spanish => kw_mnemonic::Language::Spanish,
        }
    }
}

// Define address type for FFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    P2PKH,
    P2SH,
}

impl From<KwAddressType> for AddressType {
    fn from(t: KwAddressType) -> Self {
        match t {
            KwAddressType::P2pkh => AddressType::P2PKH,
            KwAddressType::P2sh => AddressType::P2SH,
            _ => AddressType::P2PKH, // Default to P2PKH for unknown types
        }
    }
}

impl From<AddressType> for KwAddressType {
    fn from(t: AddressType) -> Self {
        match t {
            AddressType::P2PKH => KwAddressType::P2pkh,
            AddressType::P2SH => KwAddressType::P2sh,
        }
    }
}

// Define derivation path type
pub struct DerivationPath {
    pub path: String,
}

impl DerivationPath {
    pub fn new(path: String) -> Result<Self, KeyWalletError> {
        // Validate the path by trying to parse it
        KwDerivationPath::from_str(&path).map_err(|e| KeyWalletError::InvalidDerivationPath {
            message: e.to_string(),
        })?;
        Ok(Self {
            path,
        })
    }
}

// Define account extended keys
pub struct AccountXPriv {
    pub derivation_path: String,
    pub xpriv: String,
}

#[derive(Clone)]
pub struct AccountXPub {
    pub derivation_path: String,
    pub xpub: String,
    pub pub_key: Option<Vec<u8>>,
}

impl AccountXPub {
    pub fn new(derivation_path: String, xpub: String) -> Self {
        Self {
            derivation_path,
            xpub,
            pub_key: None,
        }
    }
}

// Custom error type for FFI
#[derive(Debug, Clone, thiserror::Error)]
pub enum KeyWalletError {
    #[error("Invalid mnemonic: {message}")]
    InvalidMnemonic {
        message: String,
    },

    #[error("Invalid derivation path: {message}")]
    InvalidDerivationPath {
        message: String,
    },

    #[error("Key error: {message}")]
    KeyError {
        message: String,
    },

    #[error("Secp256k1 error: {message}")]
    Secp256k1Error {
        message: String,
    },

    #[error("Address error: {message}")]
    AddressError {
        message: String,
    },
}

impl From<kw::Error> for KeyWalletError {
    fn from(e: kw::Error) -> Self {
        match e {
            kw::Error::InvalidMnemonic(msg) => KeyWalletError::InvalidMnemonic {
                message: msg,
            },
            kw::Error::InvalidDerivationPath(msg) => KeyWalletError::InvalidDerivationPath {
                message: msg,
            },
            kw::Error::Bip32(err) => KeyWalletError::KeyError {
                message: err.to_string(),
            },
            kw::Error::Secp256k1(err) => KeyWalletError::Secp256k1Error {
                message: err.to_string(),
            },
            kw::Error::InvalidAddress(msg) => KeyWalletError::AddressError {
                message: msg,
            },
            kw::Error::Base58 => KeyWalletError::AddressError {
                message: "Base58 encoding error".into(),
            },
            kw::Error::InvalidNetwork => KeyWalletError::AddressError {
                message: "Invalid network".into(),
            },
            kw::Error::KeyError(msg) => KeyWalletError::KeyError {
                message: msg,
            },
            kw::Error::CoinJoinNotEnabled => KeyWalletError::KeyError {
                message: "CoinJoin not enabled".into(),
            },
            kw::Error::Serialization(msg) => KeyWalletError::KeyError {
                message: format!("Serialization error: {}", msg),
            },
            kw::Error::InvalidParameter(msg) => KeyWalletError::KeyError {
                message: format!("Invalid parameter: {}", msg),
            },
        }
    }
}

impl From<kw::bip32::Error> for KeyWalletError {
    fn from(e: kw::bip32::Error) -> Self {
        KeyWalletError::KeyError {
            message: e.to_string(),
        }
    }
}

impl From<kw::dashcore::address::Error> for KeyWalletError {
    fn from(e: kw::dashcore::address::Error) -> Self {
        KeyWalletError::AddressError {
            message: e.to_string(),
        }
    }
}

// Validate mnemonic function
pub fn validate_mnemonic(phrase: String, language: Language) -> Result<bool, KeyWalletError> {
    Ok(kw::Mnemonic::validate(&phrase, language.into()))
}

// Mnemonic wrapper
pub struct Mnemonic {
    inner: kw::Mnemonic,
}

impl Mnemonic {
    pub fn new(phrase: String, language: Language) -> Result<Self, KeyWalletError> {
        let inner = kw::Mnemonic::from_phrase(&phrase, language.into())
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(Self {
            inner,
        })
    }

    pub fn generate(language: Language, word_count: u8) -> Result<Self, KeyWalletError> {
        let inner = kw::Mnemonic::generate(word_count as usize, language.into())
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(Self {
            inner,
        })
    }

    pub fn phrase(&self) -> String {
        self.inner.phrase()
    }

    pub fn to_seed(&self, passphrase: String) -> Vec<u8> {
        self.inner.to_seed(&passphrase).to_vec()
    }
}

// HD Wallet wrapper
pub struct HDWallet {
    inner: KwHDWallet,
    network: Network,
}

impl HDWallet {
    pub fn from_mnemonic(
        mnemonic: Arc<Mnemonic>,
        passphrase: String,
        network: Network,
    ) -> Result<Self, KeyWalletError> {
        let seed = mnemonic.to_seed(passphrase);
        Self::from_seed(seed, network)
    }

    pub fn from_seed(seed: Vec<u8>, network: Network) -> Result<Self, KeyWalletError> {
        let inner =
            KwHDWallet::from_seed(&seed, network.into()).map_err(|e| KeyWalletError::from(e))?;
        Ok(Self {
            inner,
            network,
        })
    }

    pub fn get_account_xpriv(&self, account: u32) -> Result<AccountXPriv, KeyWalletError> {
        let account_key = self.inner.bip44_account(account).map_err(|e| KeyWalletError::from(e))?;

        // Use correct coin type based on network
        let coin_type = match self.network {
            Network::Dash => 5, // Dash mainnet
            _ => 1,             // Testnet/devnet/regtest
        };
        let derivation_path = format!("m/44'/{}'/{}'", coin_type, account);

        Ok(AccountXPriv {
            derivation_path,
            xpriv: account_key.to_string(),
        })
    }

    pub fn get_account_xpub(&self, account: u32) -> Result<AccountXPub, KeyWalletError> {
        let account_key = self.inner.bip44_account(account).map_err(|e| KeyWalletError::from(e))?;

        let secp = Secp256k1::new();
        let xpub = ExtendedPubKey::from_priv(&secp, &account_key);

        // Use correct coin type based on network
        let coin_type = match self.network {
            Network::Dash => 5, // Dash mainnet
            _ => 1,             // Testnet/devnet/regtest
        };
        let derivation_path = format!("m/44'/{}'/{}'", coin_type, account);

        Ok(AccountXPub {
            derivation_path,
            xpub: xpub.to_string(),
            pub_key: Some(xpub.public_key.serialize().to_vec()),
        })
    }

    pub fn get_identity_authentication_key_at_index(
        &self,
        identity_index: u32,
        key_index: u32,
    ) -> Result<Vec<u8>, KeyWalletError> {
        let key = self
            .inner
            .identity_authentication_key(identity_index, key_index)
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(key.private_key[..].to_vec())
    }

    pub fn derive_xpriv(&self, path: String) -> Result<String, KeyWalletError> {
        let derivation_path = KwDerivationPath::from_str(&path).map_err(|e| {
            KeyWalletError::InvalidDerivationPath {
                message: e.to_string(),
            }
        })?;

        let xpriv = self.inner.derive(&derivation_path).map_err(|e| KeyWalletError::from(e))?;

        Ok(xpriv.to_string())
    }

    pub fn derive_xpub(&self, path: String) -> Result<AccountXPub, KeyWalletError> {
        let derivation_path = KwDerivationPath::from_str(&path).map_err(|e| {
            KeyWalletError::InvalidDerivationPath {
                message: e.to_string(),
            }
        })?;

        let xpub = self.inner.derive_pub(&derivation_path).map_err(|e| KeyWalletError::from(e))?;

        Ok(AccountXPub {
            derivation_path: path,
            xpub: xpub.to_string(),
            pub_key: Some(xpub.public_key.serialize().to_vec()),
        })
    }
}

// Extended Private Key wrapper
pub struct ExtPrivKey {
    inner: ExtendedPrivKey,
}

impl ExtPrivKey {
    pub fn from_string(xpriv: String) -> Result<Self, KeyWalletError> {
        let inner = ExtendedPrivKey::from_str(&xpriv).map_err(|e| KeyWalletError::KeyError {
            message: e.to_string(),
        })?;
        Ok(Self {
            inner,
        })
    }

    pub fn get_xpub(&self) -> AccountXPub {
        let secp = Secp256k1::new();
        let xpub = ExtendedPubKey::from_priv(&secp, &self.inner);

        AccountXPub {
            derivation_path: String::new(),
            xpub: xpub.to_string(),
            pub_key: Some(xpub.public_key.serialize().to_vec()),
        }
    }

    pub fn derive_child(
        &self,
        index: u32,
        hardened: bool,
    ) -> Result<Arc<ExtPrivKey>, KeyWalletError> {
        let child_number = if hardened {
            kw::ChildNumber::from_hardened_idx(index)
        } else {
            kw::ChildNumber::from_normal_idx(index)
        }
        .map_err(|e| KeyWalletError::InvalidDerivationPath {
            message: e.to_string(),
        })?;

        let secp = Secp256k1::new();
        let child =
            self.inner.ckd_priv(&secp, child_number).map_err(|e| KeyWalletError::KeyError {
                message: e.to_string(),
            })?;

        Ok(Arc::new(ExtPrivKey {
            inner: child,
        }))
    }

    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }
}

// Extended Public Key wrapper
pub struct ExtPubKey {
    inner: ExtendedPubKey,
}

impl ExtPubKey {
    pub fn from_string(xpub: String) -> Result<Self, KeyWalletError> {
        let inner = ExtendedPubKey::from_str(&xpub).map_err(|e| KeyWalletError::KeyError {
            message: e.to_string(),
        })?;
        Ok(Self {
            inner,
        })
    }

    pub fn derive_child(&self, index: u32) -> Result<Arc<ExtPubKey>, KeyWalletError> {
        let child_number = kw::ChildNumber::from_normal_idx(index).map_err(|e| {
            KeyWalletError::InvalidDerivationPath {
                message: e.to_string(),
            }
        })?;

        let secp = Secp256k1::new();
        let child =
            self.inner.ckd_pub(&secp, child_number).map_err(|e| KeyWalletError::KeyError {
                message: e.to_string(),
            })?;

        Ok(Arc::new(ExtPubKey {
            inner: child,
        }))
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.inner.public_key.serialize().to_vec()
    }

    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }
}

// Address wrapper
pub struct Address {
    inner: KwAddress,
}

impl Address {
    pub fn from_string(address: String, network: Network) -> Result<Self, KeyWalletError> {
        let unchecked_addr = KwAddress::from_str(&address).map_err(|e| KeyWalletError::from(e))?;

        // Convert to expected network and require it
        let expected_network: KwNetwork = network.into();
        let inner = unchecked_addr.require_network(expected_network).map_err(|e| {
            KeyWalletError::AddressError {
                message: format!("Address network validation failed: {}", e),
            }
        })?;

        Ok(Self {
            inner,
        })
    }

    pub fn from_public_key(public_key: Vec<u8>, network: Network) -> Result<Self, KeyWalletError> {
        let secp_pubkey =
            PublicKey::from_slice(&public_key).map_err(|e| KeyWalletError::Secp256k1Error {
                message: e.to_string(),
            })?;
        let dashcore_pubkey = kw::dashcore::PublicKey::new(secp_pubkey);
        let inner = KwAddress::p2pkh(&dashcore_pubkey, network.into());
        Ok(Self {
            inner,
        })
    }

    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    pub fn get_type(&self) -> AddressType {
        self.inner.address_type().unwrap_or(KwAddressType::P2pkh).into()
    }

    pub fn get_network(&self) -> Network {
        match *self.inner.network() {
            KwNetwork::Dash => Network::Dash,
            KwNetwork::Testnet => Network::Testnet,
            KwNetwork::Regtest => Network::Regtest,
            KwNetwork::Devnet => Network::Devnet,
            unknown => unreachable!("Unhandled network variant: {:?}", unknown),
        }
    }

    pub fn get_script_pubkey(&self) -> Vec<u8> {
        self.inner.script_pubkey().into()
    }
}

// Address generator wrapper
pub struct AddressGenerator {
    network: Network,
}

impl AddressGenerator {
    pub fn new(network: Network) -> Self {
        Self {
            network,
        }
    }

    pub fn generate(
        &self,
        account_xpub: AccountXPub,
        external: bool,
        index: u32,
    ) -> Result<Arc<Address>, KeyWalletError> {
        // Parse the extended public key from string
        let xpub =
            ExtendedPubKey::from_str(&account_xpub.xpub).map_err(|e| KeyWalletError::KeyError {
                message: e.to_string(),
            })?;

        let secp = Secp256k1::new();

        // Derive child key: 0 for external (receiving), 1 for internal (change)
        let chain_code = if external {
            0
        } else {
            1
        };
        let child_chain = xpub
            .ckd_pub(
                &secp,
                kw::ChildNumber::from_normal_idx(chain_code).map_err(|e| {
                    KeyWalletError::InvalidDerivationPath {
                        message: e.to_string(),
                    }
                })?,
            )
            .map_err(|e| KeyWalletError::KeyError {
                message: e.to_string(),
            })?;

        // Derive specific index
        let child = child_chain
            .ckd_pub(
                &secp,
                kw::ChildNumber::from_normal_idx(index).map_err(|e| {
                    KeyWalletError::InvalidDerivationPath {
                        message: e.to_string(),
                    }
                })?,
            )
            .map_err(|e| KeyWalletError::KeyError {
                message: e.to_string(),
            })?;

        // Generate P2PKH address from the public key
        let dashcore_pubkey = kw::dashcore::PublicKey::new(child.public_key);
        let addr = KwAddress::p2pkh(&dashcore_pubkey, self.network.into());

        Ok(Arc::new(Address {
            inner: addr,
        }))
    }

    pub fn generate_range(
        &self,
        account_xpub: AccountXPub,
        external: bool,
        start: u32,
        count: u32,
    ) -> Result<Vec<Arc<Address>>, KeyWalletError> {
        let mut addresses = Vec::new();

        for i in 0..count {
            let addr = self.generate(account_xpub.clone(), external, start + i)?;
            addresses.push(addr);
        }

        Ok(addresses)
    }
}

#[cfg(test)]
mod network_compatibility_tests {
    use super::*;

    #[test]
    fn test_network_compatibility_with_dash_network_ffi() {
        // Ensure our Network enum values match dash-network-ffi
        // We can't directly compare with dash_network_ffi::Network because it's defined in the FFI lib.rs
        // But we can ensure the values are consistent
        assert_eq!(Network::Dash as u8, 0);
        assert_eq!(Network::Testnet as u8, 1);
        assert_eq!(Network::Regtest as u8, 2);
        assert_eq!(Network::Devnet as u8, 3);
    }

    #[test]
    fn test_network_conversion_to_key_wallet() {
        // Test conversion to key_wallet::Network
        let networks = vec![
            (Network::Dash, key_wallet::Network::Dash),
            (Network::Testnet, key_wallet::Network::Testnet),
            (Network::Devnet, key_wallet::Network::Devnet),
            (Network::Regtest, key_wallet::Network::Regtest),
        ];

        for (ffi_network, expected_kw_network) in networks {
            let kw_network: key_wallet::Network = ffi_network.into();
            assert_eq!(kw_network, expected_kw_network);
        }
    }
}
