//! BIP39 Mnemonic implementation

use core::fmt;
use core::str::FromStr;

use crate::bip32::ExtendedPrivKey;
use crate::error::{Error, Result};
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use bip39 as bip39_crate;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;
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

impl Language {
    /// Raw BIP-39 wordlist (2048 words) for this language.
    ///
    /// Low-level primitive for callers that need direct wordlist access —
    /// e.g. building membership sets for recover-flow word validation.
    /// Membership against these lists is exact (no normalization).
    /// [`Mnemonic::normalize_phrase`] helps with case folding, whitespace
    /// normalization, and NFC/NFD equivalence, but it does not remove
    /// diacritics — so a caller checking "cafe" against "café" still misses.
    pub fn word_list(&self) -> &'static [&'static str] {
        bip39_crate::Language::from(*self).word_list()
    }
}

/// Ideographic space (U+3000), inserted between CJK words by
/// [`Mnemonic::cleanup_phrase`].
const IDEO_SP: &str = "\u{3000}";

/// All wordlist languages key-wallet supports; [`word_in_any_list`] and
/// [`phrase_is_valid_any`] check their union.
const ALL_LANGUAGES: [Language; 10] = [
    Language::English,
    Language::ChineseSimplified,
    Language::ChineseTraditional,
    Language::Czech,
    Language::French,
    Language::Italian,
    Language::Japanese,
    Language::Korean,
    Language::Portuguese,
    Language::Spanish,
];

/// `true` if `word` is a member of *any* supported language's wordlist.
/// Exact membership; caller pre-normalizes.
fn word_in_any_list(word: &str) -> bool {
    ALL_LANGUAGES.iter().any(|l| l.word_list().contains(&word))
}

/// `true` if the (already-normalized) phrase decodes (all words present +
/// valid checksum) in *some* supported language. Per-language loop, never
/// autodetect. [`Mnemonic::validate`] re-runs NFKD internally (idempotent on
/// an already-normalized phrase). Note this enforces the BIP-39 ≥12-word
/// floor; inert here — its only caller is [`Mnemonic::cleanup_phrase`]'s
/// early-return gate.
fn phrase_is_valid_any(normalized: &str) -> bool {
    ALL_LANGUAGES.iter().any(|&l| Mnemonic::validate(normalized, l))
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

    /// Normalize a phrase for lenient validation / wordlist-membership input:
    /// NFKD + lowercase + collapse every whitespace run to a single ASCII
    /// space (ends trimmed). This is **input tolerance** for user-typed
    /// phrases, NOT BIP39 seed normalization — [`Self::to_seed`] performs the
    /// BIP39 (NFKD-only) normalization required for seed derivation.
    pub fn normalize_phrase(input: &str) -> String {
        input
            .nfkd()
            .collect::<String>()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Minimal cleanup of user-typed recover input for display/editing, plus
    /// CJK ideographic auto-splitting (parity with DashSync's
    /// `cleanupPhrase:`): strips characters outside (letter ∪ combining mark
    /// ∪ whitespace), converts newlines to spaces, collapses double spaces and
    /// trims leading whitespace; then, if the phrase doesn't already validate
    /// in some supported language, splits no-space CJK input by wrapping
    /// wordlist matches in ideographic spaces (U+3000). Returns the cleaned,
    /// pre-[`Self::normalize_phrase`] string.
    ///
    /// Index note: DashSync indexes UTF-16 units (`characterAtIndex:`); we use
    /// Unicode scalars (`char`). Every BIP-39 CJK word is in the BMP (1 char =
    /// 1 UTF-16 unit), so the two indexings agree.
    pub fn cleanup_phrase(phrase: &str) -> String {
        // (0) Bound pathological input: a real BIP-39 phrase is <= 24 words,
        //     well under 1 KiB. Past a generous byte cap, skip the superlinear
        //     CJK scan and return the input verbatim — a long no-space CJK
        //     paste would otherwise drive large allocations on the caller's
        //     (typically UI) thread. The UI enforces the real phrase length.
        const MAX_CLEANUP_BYTES: usize = 4096;
        if phrase.len() > MAX_CLEANUP_BYTES {
            return phrase.to_string();
        }

        // (1) remove chars not in (letter ∪ mark ∪ whitespace). DashSync uses
        //     `letterCharacterSet` (Unicode L* AND M*) ∪ whitespaceAndNewline,
        //     inverted. We mirror M* via `is_combining_mark` so NFKD-decomposed
        //     input keeps its combining marks (e.g. Japanese voiced kana か+゙,
        //     Latin diacritics) instead of being corrupted.
        let mut s: String = phrase
            .chars()
            .filter(|&c| c.is_alphabetic() || is_combining_mark(c) || c.is_whitespace())
            .collect();

        // (2) canonicalize every Unicode whitespace to an ASCII space — not
        //     just '\n'. Step (1) keeps all whitespace, and the valid-phrase
        //     early return below returns this string verbatim, so a pasted
        //     CRLF/tab-delimited phrase would otherwise come back with '\r' /
        //     '\t' still in it. (Seed-equivalent: BIP-39 NFKD maps U+3000 and
        //     friends to U+0020 anyway.)
        s = s
            .chars()
            .map(|c| {
                if c.is_whitespace() {
                    ' '
                } else {
                    c
                }
            })
            .collect();

        // (3) collapse "  " -> " "
        while s.contains("  ") {
            s = s.replace("  ", " ");
        }

        // (4) trim leading whitespace only (DashSync deletes index-0 ws in a loop)
        let mut s = s.trim_start().to_string();

        // (5) normalize + validity check; if valid, return the cleaned (pre-
        //     normalize) string verbatim — DashSync `return s;`
        let normalized = Self::normalize_phrase(&s);
        if phrase_is_valid_any(&normalized) {
            return s;
        }

        // (6) CJK auto-split: walk the words of the *normalized* phrase; for
        //     each word starting at/after U+3000 that isn't already a whole
        //     valid word, scan substrings (len ≤ 8) and wrap valid matches in
        //     `s` with U+3000.
        //
        //     `s` still holds the caller's original Unicode form (e.g. NFC,
        //     which iOS Japanese IMEs emit), but the candidates below are
        //     sliced from `normalized` (NFKD). `String::replace` is exact-byte,
        //     so an NFKD candidate never matches an NFC `s` and nothing would
        //     be wrapped — the no-space phrase would come back unsplit. NFKD
        //     `s` here so the replace can hit. NFKD is the BIP-39 canonical
        //     form (the wordlist + `to_seed` use it), so emitting it from the
        //     split path is correct. (DSBIP39Mnemonic has the same
        //     original-vs-NFKD mismatch; this fixes it.)
        s = s.nfkd().collect::<String>();

        let dbl_ideo = format!("{IDEO_SP}{IDEO_SP}");
        for word in normalized.split(' ') {
            let wchars: Vec<char> = word.chars().collect();
            if wchars.is_empty() {
                continue;
            }
            if (wchars[0] as u32) < 0x3000 || word_in_any_list(word) {
                continue;
            }

            let wlen = wchars.len();
            let mut i = 0usize;
            while i < wlen {
                let mut j = core::cmp::min(8, wlen - i);
                while j >= 1 {
                    let candidate: String = wchars[i..i + j].iter().collect();
                    if word_in_any_list(&candidate) {
                        let wrapped = format!("{IDEO_SP}{candidate}{IDEO_SP}");
                        s = s.replace(&candidate, &wrapped);
                        while s.contains(&dbl_ideo) {
                            s = s.replace(&dbl_ideo, IDEO_SP);
                        }
                        // CFStringTrimWhitespace strips leading/trailing ws,
                        // incl. U+3000 (which `str::trim` also treats as ws).
                        s = s.trim().to_string();
                        i += j - 1; // outer `i += 1` advances past the match
                        break;
                    }
                    j -= 1;
                }
                i += 1;
            }
        }

        s
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
    fn test_validate_real_phrase_each_language() {
        // A real 12-word phrase in each bundled language validates in that
        // language. Closes the gap where validate() was exercised only for
        // English (test_mnemonic_validation) and Portuguese
        // (test_portuguese_mnemonic); the other languages were only built via
        // from_entropy in test_multiple_languages, never validate()'d.
        let entropy = Vec::from_hex("00000000000000000000000000000000").unwrap();
        for language in [
            Language::French,
            Language::Spanish,
            Language::Italian,
            Language::Japanese,
            Language::Korean,
            Language::Czech,
            Language::ChineseSimplified,
            Language::ChineseTraditional,
        ] {
            let phrase = Mnemonic::from_entropy(&entropy, language).unwrap().phrase();
            assert!(
                Mnemonic::validate(&phrase, language),
                "{language:?} phrase should validate in its own language"
            );
        }

        // Cross-language negative: a French phrase is not valid as Japanese
        // (disjoint wordlists).
        let french = Mnemonic::from_entropy(&entropy, Language::French).unwrap().phrase();
        assert!(!Mnemonic::validate(&french, Language::Japanese));
    }

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

    // Test helper: generate a mnemonic using a provided RNG
    fn generate_using_rng<R: rand::RngCore>(
        word_count: usize,
        language: Language,
        rng: &mut R,
    ) -> Result<Mnemonic> {
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(Error::InvalidMnemonic("Invalid word count".into())),
        };

        let mut entropy = vec![0u8; entropy_bytes];
        rng.fill_bytes(&mut entropy);
        Mnemonic::from_entropy(&entropy, language)
    }

    // Test helper: generate a deterministic mnemonic from a u64 seed
    fn generate_with_seed(word_count: usize, language: Language, seed: u64) -> Result<Mnemonic> {
        use rand::SeedableRng;

        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let mut rng = rand::rngs::StdRng::from_seed(seed_bytes);
        generate_using_rng(word_count, language, &mut rng)
    }

    #[test]
    fn test_generate_using_rng() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // Create a seeded RNG for deterministic results
        let mut rng = StdRng::seed_from_u64(12345);

        // Generate 12-word mnemonic
        let mnemonic = generate_using_rng(12, Language::English, &mut rng).unwrap();
        assert_eq!(mnemonic.word_count(), 12);

        // Generate 24-word mnemonic
        let mut rng = StdRng::seed_from_u64(12345);
        let mnemonic24 = generate_using_rng(24, Language::English, &mut rng).unwrap();
        assert_eq!(mnemonic24.word_count(), 24);

        // Test with different language
        let mut rng = StdRng::seed_from_u64(54321);
        let mnemonic_jp = generate_using_rng(12, Language::Japanese, &mut rng).unwrap();
        assert_eq!(mnemonic_jp.word_count(), 12);

        // Test invalid word count
        let mut rng = StdRng::seed_from_u64(99999);
        assert!(generate_using_rng(13, Language::English, &mut rng).is_err());
    }

    // Test deterministic mnemonic generation from seed
    #[test]
    fn test_generate_with_seed() {
        // Generate mnemonic from seed
        let seed = 42u64;
        let mnemonic1 = generate_with_seed(12, Language::English, seed).unwrap();
        let mnemonic2 = generate_with_seed(12, Language::English, seed).unwrap();

        // Same seed should produce same mnemonic
        assert_eq!(mnemonic1.phrase(), mnemonic2.phrase());
        assert_eq!(mnemonic1.word_count(), 12);

        // Different seed should produce different mnemonic
        let mnemonic3 = generate_with_seed(12, Language::English, 43).unwrap();
        assert_ne!(mnemonic1.phrase(), mnemonic3.phrase());

        // Test with different word counts
        let mnemonic_15 = generate_with_seed(15, Language::English, seed).unwrap();
        assert_eq!(mnemonic_15.word_count(), 15);

        let mnemonic_18 = generate_with_seed(18, Language::English, seed).unwrap();
        assert_eq!(mnemonic_18.word_count(), 18);

        let mnemonic_21 = generate_with_seed(21, Language::English, seed).unwrap();
        assert_eq!(mnemonic_21.word_count(), 21);

        let mnemonic_24 = generate_with_seed(24, Language::English, seed).unwrap();
        assert_eq!(mnemonic_24.word_count(), 24);

        // Test with different languages
        let mnemonic_fr = generate_with_seed(12, Language::French, seed).unwrap();
        assert_eq!(mnemonic_fr.word_count(), 12);
        // French mnemonic should be different from English even with same seed and entropy
        // (due to different word lists)

        // Test invalid word count
        assert!(generate_with_seed(10, Language::English, seed).is_err());
        assert!(generate_with_seed(25, Language::English, seed).is_err());
    }

    // Test that generate_with_seed is truly deterministic
    #[test]
    fn test_generate_with_seed_deterministic() {
        let test_seeds = vec![0u64, 1, 100, 1000, u64::MAX];

        for seed in test_seeds {
            // Generate multiple times with same seed
            let mnemonics: Vec<_> =
                (0..5).map(|_| generate_with_seed(12, Language::English, seed).unwrap()).collect();

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

    #[test]
    fn test_normalize_phrase() {
        assert_eq!(
            Mnemonic::normalize_phrase("  ABANDON\tabout \n legal  "),
            "abandon about legal"
        );
        assert_eq!(Mnemonic::normalize_phrase(""), "");
        assert_eq!(Mnemonic::normalize_phrase("   "), "");
        // Idempotent.
        let once = Mnemonic::normalize_phrase("  ABANDON\tAbout ");
        assert_eq!(Mnemonic::normalize_phrase(&once), once);
    }

    #[test]
    fn test_normalize_phrase_unicode_forms_converge() {
        use unicode_normalization::UnicodeNormalization;
        // NFC and NFD of the same accented text both normalize (NFKD) identically.
        let nfc = "café au lait";
        let nfd: String = nfc.nfd().collect();
        assert_ne!(nfc, nfd.as_str());
        assert_eq!(Mnemonic::normalize_phrase(nfc), Mnemonic::normalize_phrase(&nfd));
    }

    // --- word_list + cleanup_phrase (recover-flow primitives) ---

    /// First word of a language's all-zero-entropy 12-word phrase — a real
    /// wordlist entry for that language.
    fn first_word(lang: Language) -> String {
        Mnemonic::from_entropy(&[0u8; 16], lang)
            .unwrap()
            .phrase()
            .split(' ')
            .next()
            .unwrap()
            .to_string()
    }

    fn word_in_english(w: &str) -> bool {
        Language::English.word_list().contains(&w)
    }

    #[test]
    fn word_list_has_expected_shape() {
        // Every supported language exposes the full 2048-word BIP-39 list.
        for lang in ALL_LANGUAGES {
            assert_eq!(lang.word_list().len(), 2048, "{lang:?} wordlist must be 2048 words");
        }
        // Known English endpoints (BIP-39 English is the canonical reference).
        let en = Language::English.word_list();
        assert_eq!(en[0], "abandon");
        assert_eq!(en[2047], "zoo");
        // Cross-script disjointness: a Japanese entry isn't an English word.
        let jp0 = Language::Japanese.word_list()[0];
        assert!(!en.contains(&jp0));
    }

    #[test]
    fn every_language_word_validates_in_union() {
        // A representative word from each supported language is a member of the
        // all-language union; only English words are English-local.
        for lang in ALL_LANGUAGES {
            let w = first_word(lang);
            assert!(word_in_any_list(&w), "{lang:?} word should be in the union");
        }
        assert!(word_in_english(&first_word(Language::English)));
        assert!(!word_in_english(&first_word(Language::Japanese)));
        assert!(!word_in_english(&first_word(Language::ChineseSimplified)));
    }

    #[test]
    fn cleanup_strips_punctuation_and_passes_valid_through() {
        let dirty = "abandon, abandon. abandon abandon abandon abandon abandon abandon abandon abandon abandon about!";
        let cleaned = Mnemonic::cleanup_phrase(dirty);
        assert!(!cleaned.contains(','));
        assert!(!cleaned.contains('.'));
        assert!(!cleaned.contains('!'));
        // valid branch returns a string that normalizes to the valid phrase
        assert!(phrase_is_valid_any(&Mnemonic::normalize_phrase(&cleaned)));
    }

    #[test]
    fn cleanup_canonicalizes_crlf_and_tabs() {
        // A valid English phrase pasted with CRLF / tab separators must come
        // back as a single-space phrase — control whitespace must not survive
        // into the returned string via the valid-phrase early return.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let words: Vec<&str> = phrase.split(' ').collect();
        for dirty in [words.join("\r\n"), words.join("\t"), words.join(" \t ")] {
            let cleaned = Mnemonic::cleanup_phrase(&dirty);
            assert!(!cleaned.contains('\r'), "no CR survives: {cleaned:?}");
            assert!(!cleaned.contains('\t'), "no tab survives: {cleaned:?}");
            assert!(!cleaned.contains('\n'), "no LF survives: {cleaned:?}");
            assert_eq!(cleaned, phrase, "canonicalizes to the single-space phrase");
        }
    }

    #[test]
    fn cjk_passthrough_and_autosplit() {
        // Distinct-word valid Japanese phrase (varied entropy avoids the
        // repeated-word ambiguity that defeats any greedy re-splitter).
        let entropy = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
            0x69, 0x78,
        ];
        let spaced = Mnemonic::from_entropy(&entropy, Language::Japanese).unwrap().phrase();
        assert!(
            phrase_is_valid_any(&Mnemonic::normalize_phrase(&spaced)),
            "fixture must be a valid Japanese phrase"
        );

        // (a) a space-separated valid CJK phrase passes the valid branch through
        assert!(phrase_is_valid_any(&Mnemonic::normalize_phrase(&Mnemonic::cleanup_phrase(
            &spaced
        ))));

        // (b) a no-space CJK phrase gets ideographic spaces inserted
        let nospace: String = spaced.split(' ').collect();
        assert!(
            Mnemonic::cleanup_phrase(&nospace).contains(IDEO_SP),
            "cleanup should insert ideographic spaces into a no-space CJK phrase"
        );
    }

    #[test]
    fn nfc_japanese_no_space_autosplit() {
        // Regression guard for the NFC/NFKD mismatch in cleanup_phrase: iOS
        // Japanese IMEs emit precomposed (NFC) text, the BIP-39 wordlist is
        // NFKD. A no-space NFC Japanese phrase must still auto-split — the CJK
        // loop NFKDs the working buffer so the exact-byte replace can hit.
        use unicode_normalization::UnicodeNormalization;
        let entropy = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
            0x69, 0x78,
        ];
        let phrase = Mnemonic::from_entropy(&entropy, Language::Japanese).unwrap().phrase();
        let nfkd_nospace: String = phrase.split(' ').collect();
        let nfc_nospace: String = nfkd_nospace.nfc().collect();
        // The fixture must actually be NFC (different bytes) to exercise the bug.
        assert_ne!(
            nfc_nospace, nfkd_nospace,
            "fixture must be NFC (distinct from NFKD) to cover the bug"
        );

        let from_nfc = Mnemonic::cleanup_phrase(&nfc_nospace);
        let from_nfkd = Mnemonic::cleanup_phrase(&nfkd_nospace);
        assert!(
            from_nfc.contains(IDEO_SP),
            "NFC no-space Japanese phrase should still get ideographic spaces"
        );
        // NFC input must auto-split *identically* to the equivalent NFKD input;
        // `.contains(IDEO_SP)` alone is too weak (unvoiced words split anyway).
        assert_eq!(from_nfc, from_nfkd, "NFC input must auto-split the same as NFKD input");
    }

    #[test]
    fn chinese_no_space_autosplit() {
        // Simplified-Chinese words are single ideographs; a no-space phrase
        // must get ideographic spaces inserted by cleanup.
        let entropy = [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
            0x8f, 0x90,
        ];
        let nospace: String = Mnemonic::from_entropy(&entropy, Language::ChineseSimplified)
            .unwrap()
            .phrase()
            .split(' ')
            .collect();
        assert!(
            Mnemonic::cleanup_phrase(&nospace).contains(IDEO_SP),
            "no-space Chinese phrase should get ideographic spaces"
        );
    }

    #[test]
    fn cleanup_strips_punctuation_around_cjk() {
        // Punctuation removal and CJK auto-split must both fire on a no-space
        // CJK phrase that arrives with ASCII punctuation interleaved.
        let entropy = [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
            0x8f, 0x90,
        ];
        let phrase =
            Mnemonic::from_entropy(&entropy, Language::ChineseSimplified).unwrap().phrase();
        let dirty = phrase.split(' ').collect::<Vec<_>>().join(",");
        let cleaned = Mnemonic::cleanup_phrase(&dirty);
        assert!(!cleaned.contains(','), "punctuation must be stripped: {cleaned:?}");
        assert!(
            cleaned.contains(IDEO_SP),
            "CJK split should insert ideographic spaces: {cleaned:?}"
        );
    }

    #[test]
    fn cleanup_wraps_all_occurrences_of_repeated_cjk_word() {
        // The CJK split uses a global String::replace, so every occurrence of a
        // repeated word is wrapped; the loop must terminate without panic.
        let cw = first_word(Language::ChineseSimplified); // a single valid ideograph
        let nospace = format!("{cw}{cw}{cw}");
        let cleaned = Mnemonic::cleanup_phrase(&nospace);
        assert!(
            cleaned.contains(IDEO_SP),
            "repeated CJK word should get ideographic spaces: {cleaned:?}"
        );
        assert_eq!(
            cleaned.matches(cw.as_str()).count(),
            3,
            "all occurrences preserved (wrap-all, no loss/dup): {cleaned:?}"
        );
    }

    #[test]
    fn cleanup_phrase_caps_pathological_input() {
        // Past the byte cap, input is returned verbatim instead of driving the
        // superlinear CJK scan.
        let huge = "あ".repeat(5000); // ~15 KB, well over MAX_CLEANUP_BYTES
        assert_eq!(
            Mnemonic::cleanup_phrase(&huge),
            huge,
            "input past the cap is returned unchanged"
        );
        // A normal-length phrase is still processed (not capped).
        let entropy = [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
            0x8f, 0x90,
        ];
        let nospace: String = Mnemonic::from_entropy(&entropy, Language::ChineseSimplified)
            .unwrap()
            .phrase()
            .split(' ')
            .collect();
        assert!(Mnemonic::cleanup_phrase(&nospace).contains(IDEO_SP));
    }
}
