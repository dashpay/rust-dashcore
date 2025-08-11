//! Comprehensive tests for mnemonic functionality
//!
//! Tests BIP39 mnemonic generation, validation, recovery, and multi-language support.

#[cfg(test)]
mod tests {
    use crate::{Mnemonic, Error};
    use crate::mnemonic::Language;

    #[test]
    fn test_mnemonic_generation() {
        // Test generation with default word count (12 words)
        let mnemonic = Mnemonic::generate();
        let words: Vec<&str> = mnemonic.phrase().split_whitespace().collect();
        assert_eq!(words.len(), 12);
        
        // Verify the mnemonic is valid
        assert!(Mnemonic::validate(mnemonic.phrase()));
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        // Test with a known valid mnemonic
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English);
        assert!(mnemonic.is_ok());
        
        let mnemonic = mnemonic.unwrap();
        assert_eq!(mnemonic.phrase(), phrase);
    }

    #[test]
    fn test_invalid_mnemonic() {
        // Test with invalid mnemonics
        let invalid_phrases = vec![
            "invalid words that are not in wordlist",
            "abandon abandon abandon", // Too short
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", // Missing last word
        ];
        
        for phrase in invalid_phrases {
            let result = Mnemonic::from_phrase(phrase, Language::English);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_mnemonic_to_seed() {
        // Test seed generation with known test vector
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        
        // Test without passphrase
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.len(), 64);
        
        // Test with passphrase
        let seed_with_pass = mnemonic.to_seed("TREZOR");
        assert_eq!(seed_with_pass.len(), 64);
        assert_ne!(&seed[..], &seed_with_pass[..]);
    }

    #[test]
    fn test_mnemonic_word_count() {
        // Test different word counts
        let test_cases = vec![
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", 12),
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent", 18),
            ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", 24),
        ];
        
        for (phrase, expected_words) in test_cases {
            let mnemonic = Mnemonic::from_phrase(phrase, Language::English);
            assert!(mnemonic.is_ok());
            
            let words: Vec<&str> = mnemonic.unwrap().phrase().split_whitespace().collect();
            assert_eq!(words.len(), expected_words);
        }
    }

    #[test]
    fn test_mnemonic_validation() {
        // Valid mnemonics
        let valid_phrases = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ];
        
        for phrase in valid_phrases {
            assert!(Mnemonic::validate(phrase), "Failed to validate: {}", phrase);
        }
        
        // Invalid mnemonics
        let invalid_phrases = vec![
            "invalid words here",
            "",
            "   ",
        ];
        
        for phrase in invalid_phrases {
            assert!(!Mnemonic::validate(phrase), "Should not validate: {}", phrase);
        }
    }

    #[test]
    fn test_mnemonic_recovery() {
        // Generate a mnemonic and recover wallet from it
        let original = Mnemonic::generate();
        let phrase = original.phrase().to_string();
        
        // Recover from the phrase
        let recovered = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        
        // They should produce the same seed
        let original_seed = original.to_seed("");
        let recovered_seed = recovered.to_seed("");
        assert_eq!(original_seed, recovered_seed);
        
        // And the same phrase
        assert_eq!(original.phrase(), recovered.phrase());
    }

    #[test]
    fn test_mnemonic_with_different_passphrases() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English
        ).unwrap();
        
        // Different passphrases should produce different seeds
        let seed1 = mnemonic.to_seed("");
        let seed2 = mnemonic.to_seed("password");
        let seed3 = mnemonic.to_seed("another password");
        
        assert_ne!(seed1, seed2);
        assert_ne!(seed2, seed3);
        assert_ne!(seed1, seed3);
        
        // Same passphrase should produce same seed
        let seed4 = mnemonic.to_seed("password");
        assert_eq!(seed2, seed4);
    }

    #[test]
    fn test_mnemonic_deterministic() {
        // Same phrase should always produce same seed
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let mnemonic1 = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let mnemonic2 = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        
        let seed1 = mnemonic1.to_seed("test");
        let seed2 = mnemonic2.to_seed("test");
        
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_mnemonic_entropy_uniqueness() {
        // Generate multiple mnemonics and ensure they're different
        let mnemonics: Vec<Mnemonic> = (0..10).map(|_| Mnemonic::generate()).collect();
        
        // Check that all phrases are unique
        let mut phrases: Vec<String> = mnemonics.iter().map(|m| m.phrase().to_string()).collect();
        phrases.sort();
        phrases.dedup();
        
        // Should have 10 unique phrases
        assert_eq!(phrases.len(), 10);
    }

    #[test]
    fn test_mnemonic_phrase_immutability() {
        let mnemonic = Mnemonic::generate();
        let phrase1 = mnemonic.phrase();
        let phrase2 = mnemonic.phrase();
        
        // Multiple calls should return the same phrase
        assert_eq!(phrase1, phrase2);
    }
}