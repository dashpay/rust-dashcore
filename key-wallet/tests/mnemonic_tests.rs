//! Mnemonic tests

use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::{ExtendedPrivKey, Network};

#[test]
fn test_mnemonic_validation() {
    // Valid 12-word mnemonic
    let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(Mnemonic::validate(valid_phrase, Language::English));

    // Invalid mnemonic (wrong checksum)
    let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(!Mnemonic::validate(invalid_phrase, Language::English));
}

#[test]
fn test_mnemonic_from_phrase() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();

    assert_eq!(mnemonic.word_count(), 12);
    assert_eq!(mnemonic.phrase(), phrase);
}

#[test]
fn test_mnemonic_to_seed() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();

    // Test with empty passphrase
    let seed1 = mnemonic.to_seed("");
    assert_eq!(seed1.len(), 64);

    // Test with passphrase
    let seed2 = mnemonic.to_seed("TREZOR");
    assert_eq!(seed2.len(), 64);

    // Seeds should be different
    assert_ne!(seed1, seed2);
}

#[test]
fn test_mnemonic_to_extended_key() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();

    let xprv = mnemonic.to_extended_key("", Network::Dash).unwrap();
    assert_eq!(xprv.network, Network::Dash);
    assert_eq!(xprv.depth, 0);
}

#[test]
#[ignore] // Generation requires getrandom
fn test_mnemonic_generation() {
    // Test different word counts
    for word_count in &[12, 15, 18, 21, 24] {
        let mnemonic = Mnemonic::generate(*word_count, Language::English).unwrap();
        assert_eq!(mnemonic.word_count(), *word_count);

        // Generated mnemonic should be valid
        assert!(Mnemonic::validate(&mnemonic.phrase(), Language::English));
    }
}

#[test]
fn test_different_languages() {
    let phrase_en = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Test English
    let mnemonic_en = Mnemonic::from_phrase(phrase_en, Language::English).unwrap();
    assert!(mnemonic_en.word_count() == 12);

    // Same seed regardless of language (for same phrase)
    let seed_en = mnemonic_en.to_seed("");
    assert_eq!(seed_en.len(), 64);
}
