//! BIP39 Mnemonic implementation

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use bip39 as bip39_crate;

use crate::bip32::ExtendedPrivKey;
use crate::error::{Error, Result};

/// Language for mnemonic generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    ChineseSimplified,
    ChineseTraditional,
    Czech,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

impl From<Language> for bip39_crate::Language {
    fn from(lang: Language) -> Self {
        match lang {
            Language::English => bip39_crate::Language::English,
            Language::ChineseSimplified => bip39_crate::Language::SimplifiedChinese,
            Language::ChineseTraditional => bip39_crate::Language::TraditionalChinese,
            Language::Czech => bip39_crate::Language::Czech,
            Language::French => bip39_crate::Language::French,
            Language::Italian => bip39_crate::Language::Italian,
            Language::Japanese => bip39_crate::Language::Japanese,
            Language::Korean => bip39_crate::Language::Korean,
            Language::Spanish => bip39_crate::Language::Spanish,
        }
    }
}

/// BIP39 Mnemonic phrase
pub struct Mnemonic {
    inner: bip39_crate::Mnemonic,
}

impl Mnemonic {
    /// Generate a new mnemonic with the specified word count
    #[cfg(feature = "getrandom")]
    pub fn generate(word_count: usize, language: Language) -> Result<Self> {
        // Validate word count and get entropy size
        let entropy_bytes = match word_count {
            12 => 16, // 128 bits / 8
            15 => 20, // 160 bits / 8
            18 => 24, // 192 bits / 8
            21 => 28, // 224 bits / 8
            24 => 32, // 256 bits / 8
            _ => return Err(Error::InvalidMnemonic("Invalid word count".into())),
        };

        // Generate random entropy
        let mut entropy = vec![0u8; entropy_bytes];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| Error::InvalidMnemonic(format!("Failed to generate entropy: {}", e)))?;

        // Create mnemonic from entropy with specified language
        let mnemonic = bip39_crate::Mnemonic::from_entropy_in(language.into(), &entropy)
            .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

        Ok(Self {
            inner: mnemonic,
        })
    }

    /// Generate a new mnemonic with the specified word count
    #[cfg(not(feature = "getrandom"))]
    pub fn generate(word_count: usize, _language: Language) -> Result<Self> {
        let _entropy_bits = match word_count {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => return Err(Error::InvalidMnemonic("Invalid word count".into())),
        };

        Err(Error::InvalidMnemonic("Mnemonic generation requires getrandom feature".into()))
    }

    /// Create a mnemonic from a phrase
    pub fn from_phrase(phrase: &str, language: Language) -> Result<Self> {
        let mnemonic = bip39_crate::Mnemonic::parse_in(language.into(), phrase)
            .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

        Ok(Self {
            inner: mnemonic,
        })
    }

    /// Get the mnemonic phrase as a string
    pub fn phrase(&self) -> String {
        self.inner.words().collect::<Vec<_>>().join(" ")
    }

    /// Get the word count
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }

    /// Create a mnemonic from entropy bytes
    pub fn from_entropy(entropy: &[u8], language: Language) -> Result<Self> {
        let mnemonic = bip39_crate::Mnemonic::from_entropy_in(language.into(), entropy)
            .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

        Ok(Self {
            inner: mnemonic,
        })
    }

    /// Convert to seed with optional passphrase
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&self.inner.to_seed(passphrase));
        seed
    }

    /// Derive extended private key from this mnemonic
    pub fn to_extended_key(
        &self,
        passphrase: &str,
        network: crate::Network,
    ) -> Result<ExtendedPrivKey> {
        let seed = self.to_seed(passphrase);
        ExtendedPrivKey::new_master(network, &seed).map_err(Into::into)
    }

    /// Validate a mnemonic phrase
    pub fn validate(phrase: &str, language: Language) -> bool {
        bip39_crate::Mnemonic::parse_in(language.into(), phrase).is_ok()
    }
}

impl FromStr for Mnemonic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // Try English by default
        Self::from_phrase(s, Language::English)
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.phrase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_mnemonic_generation() {
        let mnemonic = Mnemonic::generate(12, Language::English).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
    }

    #[test]
    fn test_mnemonic_validation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(Mnemonic::validate(phrase, Language::English));
    }
}
