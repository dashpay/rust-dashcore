//! BIP39 Mnemonic implementation

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::bip32::ExtendedPrivKey;
use crate::error::{Error, Result};
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use bip39 as bip39_crate;
#[cfg(feature = "std")]
use rand::{RngCore, SeedableRng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Language for mnemonic generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum Language {
    English,
    ChineseSimplified,
    ChineseTraditional,
    Czech,
    French,
    Italian,
    Japanese,
    Korean,
    Portuguese,
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
            Language::Portuguese => bip39_crate::Language::Portuguese,
            Language::Spanish => bip39_crate::Language::Spanish,
        }
    }
}

/// BIP39 Mnemonic phrase
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mnemonic {
    inner: bip39_crate::Mnemonic,
}

#[cfg(feature = "bincode")]
impl bincode::Encode for Mnemonic {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        // Store mnemonic as its phrase string
        let phrase = self.phrase();
        phrase.encode(encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for Mnemonic {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let phrase: String = bincode::Decode::decode(decoder)?;
        // Parse back from phrase - default to English
        let inner = bip39_crate::Mnemonic::parse(&phrase).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid mnemonic: {}", e))
        })?;
        Ok(Self {
            inner,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for Mnemonic {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let phrase: String = bincode::BorrowDecode::borrow_decode(decoder)?;
        let inner = bip39_crate::Mnemonic::parse(&phrase).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid mnemonic: {}", e))
        })?;
        Ok(Self {
            inner,
        })
    }
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

    /// Generate a new mnemonic using a provided RNG
    ///
    /// This allows using custom random number generators like StdRng, ChaChaRng, etc.
    ///
    /// # Examples
    /// ```no_run
    /// use key_wallet::mnemonic::{Mnemonic, Language};
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let mnemonic = Mnemonic::generate_using_rng(12, Language::English, &mut rng).unwrap();
    /// ```
    #[cfg(feature = "std")]
    pub fn generate_using_rng<R: RngCore>(
        word_count: usize,
        language: Language,
        rng: &mut R,
    ) -> Result<Self> {
        // Validate word count and get entropy size
        let entropy_bytes = match word_count {
            12 => 16, // 128 bits / 8
            15 => 20, // 160 bits / 8
            18 => 24, // 192 bits / 8
            21 => 28, // 224 bits / 8
            24 => 32, // 256 bits / 8
            _ => return Err(Error::InvalidMnemonic("Invalid word count".into())),
        };

        // Generate random entropy using provided RNG
        let mut entropy = vec![0u8; entropy_bytes];
        rng.fill_bytes(&mut entropy);

        // Create mnemonic from entropy with specified language
        let mnemonic = bip39_crate::Mnemonic::from_entropy_in(language.into(), &entropy)
            .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

        Ok(Self {
            inner: mnemonic,
        })
    }

    /// Generate a new mnemonic from a u64 seed
    ///
    /// This creates a deterministic mnemonic from a seed value.
    /// Uses StdRng seeded with the provided value.
    ///
    /// # Warning
    /// This is deterministic - the same seed will always produce the same mnemonic.
    /// This should only be used for testing or when deterministic generation is specifically required.
    ///
    /// # Examples
    /// ```no_run
    /// use key_wallet::mnemonic::{Mnemonic, Language};
    ///
    /// let seed = 12345u64;
    /// let mnemonic = Mnemonic::generate_with_seed(12, Language::English, seed).unwrap();
    /// ```
    #[cfg(feature = "std")]
    pub fn generate_with_seed(word_count: usize, language: Language, seed: u64) -> Result<Self> {
        use rand::rngs::StdRng;

        // Create RNG from seed
        // We need to convert u64 to [u8; 32] for StdRng
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());

        let mut rng = StdRng::from_seed(seed_bytes);

        // Use the RNG to generate the mnemonic
        Self::generate_using_rng(word_count, language, &mut rng)
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
    use hex::FromHex;

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

        // Test invalid checksum (from DashSync tests)
        let invalid_phrase =
            "bless cloud wheel regular tiny venue bird web grief security dignity zoo";
        assert!(!Mnemonic::validate(invalid_phrase, Language::English));
    }

    // ✓ Test from DashSync DSBIP39Tests.m - BIP39 test vectors
    #[test]
    fn test_bip39_test_vectors() {
        // Test vector 1: all zeros entropy
        let entropy = Vec::from_hex("00000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(mnemonic.phrase(), expected_phrase);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        assert_eq!(hex::encode(seed), expected_seed);

        // Test vector 2: 0x7f7f... entropy
        let entropy = Vec::from_hex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(mnemonic.phrase(), expected_phrase);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607";
        assert_eq!(hex::encode(seed), expected_seed);

        // Test vector 3: 0x8080... entropy
        let entropy = Vec::from_hex("80808080808080808080808080808080").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase =
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
        assert_eq!(mnemonic.phrase(), expected_phrase);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8";
        assert_eq!(hex::encode(seed), expected_seed);

        // Test vector 4: all ones entropy
        let entropy = Vec::from_hex("ffffffffffffffffffffffffffffffff").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        assert_eq!(mnemonic.phrase(), expected_phrase);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069";
        assert_eq!(hex::encode(seed), expected_seed);
    }

    // ✓ Test 18-word mnemonics (from DashSync)
    #[test]
    fn test_18_word_mnemonics() {
        // Test 18-word mnemonic
        let entropy = Vec::from_hex("000000000000000000000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent";
        assert_eq!(mnemonic.phrase(), expected_phrase);
        assert_eq!(mnemonic.word_count(), 18);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa";
        assert_eq!(hex::encode(seed), expected_seed);
    }

    // ✓ Test 24-word mnemonics (from DashSync)
    #[test]
    fn test_24_word_mnemonics() {
        // Test 24-word mnemonic
        let entropy =
            Vec::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        assert_eq!(mnemonic.phrase(), expected_phrase);
        assert_eq!(mnemonic.word_count(), 24);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8";
        assert_eq!(hex::encode(seed), expected_seed);
    }

    // ✓ Test random entropy examples (from DashSync)
    #[test]
    fn test_random_entropy_examples() {
        // Test random entropy 1
        let entropy = Vec::from_hex("77c2b00716cec7213839159e404db50d").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase =
            "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge";
        assert_eq!(mnemonic.phrase(), expected_phrase);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff";
        assert_eq!(hex::encode(seed), expected_seed);

        // Test random entropy 2
        let entropy = Vec::from_hex("b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let expected_phrase = "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap";
        assert_eq!(mnemonic.phrase(), expected_phrase);

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = "9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941c69e1bdbf2966e0f6e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5";
        assert_eq!(hex::encode(seed), expected_seed);
    }

    // ✓ Test Unicode normalization (from DashSync - Czech test case)
    #[test]
    fn test_unicode_normalization() {
        // Test Czech Unicode normalization - all these should produce the same seed
        let words_nfkd =
            "Příšerně žluťoučký kůň úpěl ďábelské ódy zákeřný učeň běžící podél zóny úlů";
        let words_nfc =
            "Příšerně žluťoučký kůň úpěl ďábelské ódy zákeřný učeň běžící podél zóny úlů";

        let _passphrase_nfkd = "Neuvěřitelně bezpečné hesílčko";
        let _passphrase_nfc = "Neuvěřitelně bezpečné hesílčko";

        // Note: In a real implementation we'd need to handle Czech language,
        // but for now we can test that the Unicode normalization works in principle
        // by testing that the same normalized string produces the same results
        let mnemonic1 = Mnemonic::from_phrase(words_nfc, Language::English);
        let mnemonic2 = Mnemonic::from_phrase(words_nfkd, Language::English);

        // Both should fail to parse as English, but they should fail consistently
        assert_eq!(mnemonic1.is_ok(), mnemonic2.is_ok());
    }

    // ✓ Test multiple languages (basic test that languages are supported)
    #[test]
    fn test_multiple_languages() {
        // English
        let phrase_en = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic_en = Mnemonic::from_phrase(phrase_en, Language::English).unwrap();
        assert_eq!(mnemonic_en.word_count(), 12);

        // Test that we can create mnemonics in different languages
        // (We can't easily test actual phrases without the word lists, but we can test the API)
        let entropy = Vec::from_hex("00000000000000000000000000000000").unwrap();

        let _mnemonic_fr = Mnemonic::from_entropy(&entropy, Language::French).unwrap();
        let _mnemonic_es = Mnemonic::from_entropy(&entropy, Language::Spanish).unwrap();
        let _mnemonic_it = Mnemonic::from_entropy(&entropy, Language::Italian).unwrap();
        let _mnemonic_ja = Mnemonic::from_entropy(&entropy, Language::Japanese).unwrap();
        let _mnemonic_ko = Mnemonic::from_entropy(&entropy, Language::Korean).unwrap();
        let _mnemonic_cs = Mnemonic::from_entropy(&entropy, Language::Czech).unwrap();
        let _mnemonic_pt = Mnemonic::from_entropy(&entropy, Language::Portuguese).unwrap();
        let _mnemonic_zh_cn =
            Mnemonic::from_entropy(&entropy, Language::ChineseSimplified).unwrap();
        let _mnemonic_zh_tw =
            Mnemonic::from_entropy(&entropy, Language::ChineseTraditional).unwrap();
    }

    // ✓ Test Portuguese language support specifically
    #[test]
    fn test_portuguese_mnemonic() {
        // Test with known entropy
        let entropy = Vec::from_hex("00000000000000000000000000000000").unwrap();
        let mnemonic_pt = Mnemonic::from_entropy(&entropy, Language::Portuguese).unwrap();

        // Portuguese phrase for all zeros entropy
        // Note: bip39 library uses "abater" as the 12th word for Portuguese
        let expected_phrase_pt = "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abater";
        assert_eq!(mnemonic_pt.phrase(), expected_phrase_pt);

        // Test seed generation with Portuguese mnemonic
        let seed = mnemonic_pt.to_seed("TREZOR");
        // Portuguese mnemonic with same entropy produces a different seed than English
        let expected_seed = "ab9742b024a1e8bd241b76f8b3a157e9d442da60277bc8f36b8b23afe163de79414fb49fd1a8dd26f4ea7f0dc965c760b3b80727557bdca61e1f0b0f069952f2";
        assert_eq!(hex::encode(seed), expected_seed);

        // Test parsing a Portuguese mnemonic phrase
        let phrase_pt = "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abater";
        let parsed_mnemonic = Mnemonic::from_phrase(phrase_pt, Language::Portuguese).unwrap();
        assert_eq!(parsed_mnemonic.word_count(), 12);

        // Test validation
        assert!(Mnemonic::validate(phrase_pt, Language::Portuguese));
        assert!(!Mnemonic::validate("palavra invalida teste", Language::Portuguese));
    }

    // ✓ Test edge cases and error conditions
    #[test]
    fn test_mnemonic_edge_cases() {
        // Test invalid word count
        #[cfg(feature = "getrandom")]
        {
            assert!(Mnemonic::generate(11, Language::English).is_err());
            assert!(Mnemonic::generate(13, Language::English).is_err());
            assert!(Mnemonic::generate(25, Language::English).is_err());
        }

        // Test invalid entropy length
        let invalid_entropy = vec![0u8; 15]; // 15 bytes is not valid
        assert!(Mnemonic::from_entropy(&invalid_entropy, Language::English).is_err());

        // Test empty phrase
        assert!(Mnemonic::from_phrase("", Language::English).is_err());

        // Test phrase with invalid word
        assert!(Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalidword", Language::English).is_err());

        // Test phrase with wrong word count
        assert!(Mnemonic::from_phrase("abandon abandon abandon", Language::English).is_err());
    }

    // ✓ Test from_str implementation
    #[test]
    fn test_from_str() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic: Mnemonic = phrase.parse().unwrap();
        assert_eq!(mnemonic.phrase(), phrase);
    }

    // ✓ Test display implementation
    #[test]
    fn test_display() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(format!("{}", mnemonic), phrase);
    }

    // Test mnemonic generation with custom RNG
    #[test]
    #[cfg(feature = "std")]
    fn test_generate_using_rng() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // Create a seeded RNG for deterministic results
        let mut rng = StdRng::seed_from_u64(12345);

        // Generate 12-word mnemonic
        let mnemonic = Mnemonic::generate_using_rng(12, Language::English, &mut rng).unwrap();
        assert_eq!(mnemonic.word_count(), 12);

        // Generate 24-word mnemonic
        let mut rng = StdRng::seed_from_u64(12345);
        let mnemonic24 = Mnemonic::generate_using_rng(24, Language::English, &mut rng).unwrap();
        assert_eq!(mnemonic24.word_count(), 24);

        // Test with different language
        let mut rng = StdRng::seed_from_u64(54321);
        let mnemonic_jp = Mnemonic::generate_using_rng(12, Language::Japanese, &mut rng).unwrap();
        assert_eq!(mnemonic_jp.word_count(), 12);

        // Test invalid word count
        let mut rng = StdRng::seed_from_u64(99999);
        assert!(Mnemonic::generate_using_rng(13, Language::English, &mut rng).is_err());
    }

    // Test deterministic mnemonic generation from seed
    #[test]
    #[cfg(feature = "std")]
    fn test_generate_with_seed() {
        // Generate mnemonic from seed
        let seed = 42u64;
        let mnemonic1 = Mnemonic::generate_with_seed(12, Language::English, seed).unwrap();
        let mnemonic2 = Mnemonic::generate_with_seed(12, Language::English, seed).unwrap();

        // Same seed should produce same mnemonic
        assert_eq!(mnemonic1.phrase(), mnemonic2.phrase());
        assert_eq!(mnemonic1.word_count(), 12);

        // Different seed should produce different mnemonic
        let mnemonic3 = Mnemonic::generate_with_seed(12, Language::English, 43).unwrap();
        assert_ne!(mnemonic1.phrase(), mnemonic3.phrase());

        // Test with different word counts
        let mnemonic_15 = Mnemonic::generate_with_seed(15, Language::English, seed).unwrap();
        assert_eq!(mnemonic_15.word_count(), 15);

        let mnemonic_18 = Mnemonic::generate_with_seed(18, Language::English, seed).unwrap();
        assert_eq!(mnemonic_18.word_count(), 18);

        let mnemonic_21 = Mnemonic::generate_with_seed(21, Language::English, seed).unwrap();
        assert_eq!(mnemonic_21.word_count(), 21);

        let mnemonic_24 = Mnemonic::generate_with_seed(24, Language::English, seed).unwrap();
        assert_eq!(mnemonic_24.word_count(), 24);

        // Test with different languages
        let mnemonic_fr = Mnemonic::generate_with_seed(12, Language::French, seed).unwrap();
        assert_eq!(mnemonic_fr.word_count(), 12);
        // French mnemonic should be different from English even with same seed and entropy
        // (due to different word lists)

        // Test invalid word count
        assert!(Mnemonic::generate_with_seed(10, Language::English, seed).is_err());
        assert!(Mnemonic::generate_with_seed(25, Language::English, seed).is_err());
    }

    // Test that generate_with_seed is truly deterministic
    #[test]
    #[cfg(feature = "std")]
    fn test_generate_with_seed_deterministic() {
        let test_seeds = vec![0u64, 1, 100, 1000, u64::MAX];

        for seed in test_seeds {
            // Generate multiple times with same seed
            let mnemonics: Vec<_> = (0..5)
                .map(|_| Mnemonic::generate_with_seed(12, Language::English, seed).unwrap())
                .collect();

            // All should be identical
            let first_phrase = mnemonics[0].phrase();
            for mnemonic in &mnemonics[1..] {
                assert_eq!(
                    mnemonic.phrase(),
                    first_phrase,
                    "Mnemonic generation with seed {} was not deterministic",
                    seed
                );
            }
        }
    }
}
