//! FFI bindings for key-wallet library

use std::str::FromStr;
use std::sync::Arc;

use key_wallet::{
    self as kw, address as kw_address, derivation::HDWallet as KwHDWallet, mnemonic as kw_mnemonic,
    DerivationPath, ExtendedPrivKey, ExtendedPubKey,
};
use secp256k1::{PublicKey, Secp256k1};

// Include the UniFFI scaffolding
uniffi::include_scaffolding!("key_wallet");

// Initialize function
pub fn initialize() {
    // Any global initialization if needed
}

// Re-export enums for UniFFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Dash,
    Testnet,
    Regtest,
    Devnet,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    P2PKH,
    P2SH,
}

impl From<kw_address::AddressType> for AddressType {
    fn from(t: kw_address::AddressType) -> Self {
        match t {
            kw_address::AddressType::P2PKH => AddressType::P2PKH,
            kw_address::AddressType::P2SH => AddressType::P2SH,
        }
    }
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum KeyWalletError {
    #[error("Invalid mnemonic: {message}")]
    InvalidMnemonic {
        message: String,
    },
    #[error("Invalid derivation path: {message}")]
    InvalidDerivationPath {
        message: String,
    },
    #[error("Invalid address: {message}")]
    InvalidAddress {
        message: String,
    },
    #[error("BIP32 error: {message}")]
    Bip32Error {
        message: String,
    },
    #[error("Key error: {message}")]
    KeyError {
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
            kw::Error::InvalidAddress(msg) => KeyWalletError::InvalidAddress {
                message: msg,
            },
            kw::Error::Bip32(e) => KeyWalletError::Bip32Error {
                message: e.to_string(),
            },
            kw::Error::KeyError(msg) => KeyWalletError::KeyError {
                message: msg,
            },
            _ => KeyWalletError::KeyError {
                message: e.to_string(),
            },
        }
    }
}

// Mnemonic wrapper
pub struct Mnemonic {
    inner: kw_mnemonic::Mnemonic,
}

impl Mnemonic {
    pub fn new(word_count: u32, language: Language) -> Result<Self, KeyWalletError> {
        let mnemonic = kw_mnemonic::Mnemonic::generate(word_count as usize, language.into())
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(Self {
            inner: mnemonic,
        })
    }

    pub fn from_phrase(phrase: String, language: Language) -> Result<Self, KeyWalletError> {
        let mnemonic = kw_mnemonic::Mnemonic::from_phrase(&phrase, language.into())
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(Self {
            inner: mnemonic,
        })
    }

    pub fn get_phrase(&self) -> String {
        self.inner.phrase().to_string()
    }

    pub fn get_word_count(&self) -> u32 {
        self.inner.word_count() as u32
    }

    pub fn to_seed(&self, passphrase: String) -> Vec<u8> {
        self.inner.to_seed(&passphrase).to_vec()
    }
}

// Namespace-level function for validating mnemonics
pub fn validate_mnemonic(phrase: String, language: Language) -> Result<bool, KeyWalletError> {
    Ok(kw_mnemonic::Mnemonic::validate(&phrase, language.into()))
}

// Extended key wrapper
pub struct ExtendedKey {
    priv_key: Option<ExtendedPrivKey>,
    pub_key: Option<ExtendedPubKey>,
}

impl ExtendedKey {
    fn from_priv(key: ExtendedPrivKey) -> Self {
        Self {
            priv_key: Some(key),
            pub_key: None,
        }
    }

    fn from_pub(key: ExtendedPubKey) -> Self {
        Self {
            priv_key: None,
            pub_key: Some(key),
        }
    }

    pub fn get_fingerprint(&self) -> Vec<u8> {
        let secp = Secp256k1::new();
        if let Some(ref priv_key) = self.priv_key {
            priv_key.fingerprint(&secp).as_ref().to_vec()
        } else if let Some(ref pub_key) = self.pub_key {
            pub_key.fingerprint().as_ref().to_vec()
        } else {
            vec![]
        }
    }

    pub fn get_chain_code(&self) -> Vec<u8> {
        if let Some(ref priv_key) = self.priv_key {
            priv_key.chain_code.as_ref().to_vec()
        } else if let Some(ref pub_key) = self.pub_key {
            pub_key.chain_code.as_ref().to_vec()
        } else {
            vec![]
        }
    }

    pub fn get_depth(&self) -> u8 {
        if let Some(ref priv_key) = self.priv_key {
            priv_key.depth
        } else if let Some(ref pub_key) = self.pub_key {
            pub_key.depth
        } else {
            0
        }
    }

    pub fn get_child_number(&self) -> u32 {
        if let Some(ref priv_key) = self.priv_key {
            u32::from(priv_key.child_number)
        } else if let Some(ref pub_key) = self.pub_key {
            u32::from(pub_key.child_number)
        } else {
            0
        }
    }

    pub fn to_string(&self) -> String {
        if let Some(ref priv_key) = self.priv_key {
            priv_key.to_string()
        } else if let Some(ref pub_key) = self.pub_key {
            pub_key.to_string()
        } else {
            String::new()
        }
    }
}

// HD Wallet wrapper
pub struct HDWallet {
    inner: KwHDWallet,
}

impl HDWallet {
    pub fn from_seed(seed: Vec<u8>, network: Network) -> Result<Self, KeyWalletError> {
        let wallet =
            KwHDWallet::from_seed(&seed, network.into()).map_err(|e| KeyWalletError::from(e))?;
        Ok(Self {
            inner: wallet,
        })
    }

    pub fn from_mnemonic(
        mnemonic: Arc<Mnemonic>,
        passphrase: String,
        network: Network,
    ) -> Result<Self, KeyWalletError> {
        let seed = mnemonic.inner.to_seed(&passphrase);
        Self::from_seed(seed.to_vec(), network)
    }

    pub fn get_master_key(&self) -> Result<Arc<ExtendedKey>, KeyWalletError> {
        Ok(Arc::new(ExtendedKey::from_priv(self.inner.master_key().clone())))
    }

    pub fn get_master_pub_key(&self) -> Result<Arc<ExtendedKey>, KeyWalletError> {
        Ok(Arc::new(ExtendedKey::from_pub(self.inner.master_pub_key())))
    }

    pub fn derive(&self, path: String) -> Result<Arc<ExtendedKey>, KeyWalletError> {
        let derivation_path =
            DerivationPath::from_str(&path).map_err(|e| KeyWalletError::InvalidDerivationPath {
                message: e.to_string(),
            })?;
        let key = self.inner.derive(&derivation_path).map_err(|e| KeyWalletError::from(e))?;
        Ok(Arc::new(ExtendedKey::from_priv(key)))
    }

    pub fn derive_pub(&self, path: String) -> Result<Arc<ExtendedKey>, KeyWalletError> {
        let derivation_path =
            DerivationPath::from_str(&path).map_err(|e| KeyWalletError::InvalidDerivationPath {
                message: e.to_string(),
            })?;
        let key = self.inner.derive_pub(&derivation_path).map_err(|e| KeyWalletError::from(e))?;
        Ok(Arc::new(ExtendedKey::from_pub(key)))
    }

    pub fn get_bip44_account(&self, account: u32) -> Result<Arc<ExtendedKey>, KeyWalletError> {
        let key = self.inner.bip44_account(account).map_err(|e| KeyWalletError::from(e))?;
        Ok(Arc::new(ExtendedKey::from_priv(key)))
    }

    pub fn get_coinjoin_account(&self, account: u32) -> Result<Arc<ExtendedKey>, KeyWalletError> {
        let key = self.inner.coinjoin_account(account).map_err(|e| KeyWalletError::from(e))?;
        Ok(Arc::new(ExtendedKey::from_priv(key)))
    }

    pub fn get_identity_authentication_key(
        &self,
        identity_index: u32,
        key_index: u32,
    ) -> Result<Arc<ExtendedKey>, KeyWalletError> {
        let key = self
            .inner
            .identity_authentication_key(identity_index, key_index)
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(Arc::new(ExtendedKey::from_priv(key)))
    }
}

// Address wrapper
pub struct Address {
    inner: kw_address::Address,
}

impl Address {
    pub fn p2pkh(pubkey: Vec<u8>, network: Network) -> Result<Self, KeyWalletError> {
        let pk = PublicKey::from_slice(&pubkey).map_err(|e| KeyWalletError::KeyError {
            message: e.to_string(),
        })?;
        let addr = kw_address::Address::p2pkh(&pk, network.into());
        Ok(Self {
            inner: addr,
        })
    }

    pub fn from_string(address: String, network: Network) -> Result<Self, KeyWalletError> {
        let addr = kw_address::Address::from_str(&address, network.into())
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(Self {
            inner: addr,
        })
    }

    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    pub fn get_type(&self) -> AddressType {
        self.inner.address_type.into()
    }

    pub fn get_network(&self) -> Network {
        match self.inner.network {
            kw_address::Network::Dash => Network::Dash,
            kw_address::Network::Testnet => Network::Testnet,
            kw_address::Network::Regtest => Network::Regtest,
            kw_address::Network::Devnet => Network::Devnet,
        }
    }

    pub fn get_script_pubkey(&self) -> Vec<u8> {
        self.inner.script_pubkey()
    }
}

// Address generator wrapper
pub struct AddressGenerator {
    inner: kw_address::AddressGenerator,
}

impl AddressGenerator {
    pub fn new(network: Network) -> Self {
        Self {
            inner: kw_address::AddressGenerator::new(network.into()),
        }
    }

    pub fn generate_p2pkh(&self, xpub: Arc<ExtendedKey>) -> Result<Arc<Address>, KeyWalletError> {
        let pub_key = xpub.pub_key.as_ref().ok_or_else(|| KeyWalletError::KeyError {
            message: "Expected public key".into(),
        })?;
        let addr = self.inner.generate_p2pkh(pub_key);
        Ok(Arc::new(Address {
            inner: addr,
        }))
    }

    pub fn generate_range(
        &self,
        account_xpub: Arc<ExtendedKey>,
        external: bool,
        start: u32,
        count: u32,
    ) -> Result<Vec<Arc<Address>>, KeyWalletError> {
        let pub_key = account_xpub.pub_key.as_ref().ok_or_else(|| KeyWalletError::KeyError {
            message: "Expected public key".into(),
        })?;
        let addrs = self
            .inner
            .generate_range(pub_key, external, start, count)
            .map_err(|e| KeyWalletError::from(e))?;
        Ok(addrs
            .into_iter()
            .map(|addr| {
                Arc::new(Address {
                    inner: addr,
                })
            })
            .collect())
    }
}
