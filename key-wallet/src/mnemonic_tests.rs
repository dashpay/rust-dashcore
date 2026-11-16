//! Comprehensive tests for mnemonic functionality
//!
//! Tests BIP39 mnemonic generation, validation, recovery, and multi-language support.

#[cfg(test)]
mod tests {
    use crate::mnemonic::Language;
    use crate::Mnemonic;
    use bip39::Mnemonic as Bip39Mnemonic;
    use hex_conservative::decode_to_vec;

    // The complete Japanese BIP-39 vector set, as the bip39 3.0.0 crate (CC0-1.0) carries
    // it. The English set is in mnemonic.rs's test_bip39_test_vectors.
    const JAPANESE_SEED_VECTORS: &[(&str, &str, &str)] = &[
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
        ),
        (
            "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "aee025cbe6ca256862f889e48110a6a382365142f7d16f2b9545285b3af64e542143a577e9c144e101a6bdca18f8d97ec3366ebf5b088b1c1af9bc31346e60d9",
        ),
        (
            "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あかちゃん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "e51736736ebdf77eda23fa17e31475fa1d9509c78f1deb6b4aacfbd760a7e2ad769c714352c95143b5c1241985bcb407df36d64e75dd5a2b78ca5d2ba82a3544",
        ),
        (
            "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　ろんぶん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "4cd2ef49b479af5e1efbbd1e0bdc117f6a29b1010211df4f78e2ed40082865793e57949236c43b9fe591ec70e5bb4298b8b71dc4b267bb96ed4ed282c8f7761c",
        ),
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あらいぐま",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "d99e8f1ce2d4288d30b9c815ae981edd923c01aa4ffdc5dee1ab5fe0d4a3e13966023324d119105aff266dac32e5cd11431eeca23bbd7202ff423f30d6776d69",
        ),
        (
            "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れいぎ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "eaaf171efa5de4838c758a93d6c86d2677d4ccda4a064a7136344e975f91fe61340ec8a615464b461d67baaf12b62ab5e742f944c7bd4ab6c341fbafba435716",
        ),
        (
            "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　いきなり",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "aec0f8d3167a10683374c222e6e632f2940c0826587ea0a73ac5d0493b6a632590179a6538287641a9fc9df8e6f24e01bf1be548e1f74fd7407ccd72ecebe425",
        ),
        (
            "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　りんご",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "f0f738128a65b8d1854d68de50ed97ac1831fc3a978c569e415bbcb431a6a671d4377e3b56abd518daa861676c4da75a19ccb41e00c37d086941e471a4374b95",
        ),
        (
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　いってい",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "23f500eec4a563bf90cfda87b3e590b211b959985c555d17e88f46f7183590cd5793458b094a4dccc8f05807ec7bd2d19ce269e20568936a751f6f1ec7c14ddd",
        ),
        (
            "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　まんきつ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "cd354a40aa2e241e8f306b3b752781b70dfd1c69190e510bc1297a9c5738e833bcdc179e81707d57263fb7564466f73d30bf979725ff783fb3eb4baa86560b05",
        ),
        (
            "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　うめる",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "6b7cd1b2cdfeeef8615077cadd6a0625f417f287652991c80206dbd82db17bf317d5c50a80bd9edd836b39daa1b6973359944c46d3fcc0129198dc7dc5cd0e68",
        ),
        (
            "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　らいう",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "a44ba7054ac2f9226929d56505a51e13acdaa8a9097923ca07ea465c4c7e294c038f3f4e7e4b373726ba0057191aced6e48ac8d183f3a11569c426f0de414623",
        ),
        (
            "せまい　うちがわ　あずき　かろう　めずらしい　だんち　ますく　おさめる　ていぼう　あたる　すあな　えしゃく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "344cef9efc37d0cb36d89def03d09144dd51167923487eec42c487f7428908546fa31a3c26b7391a2b3afe7db81b9f8c5007336b58e269ea0bd10749a87e0193",
        ),
        (
            "ぬすむ　ふっかつ　うどん　こうりつ　しつじ　りょうり　おたがい　せもたれ　あつめる　いちりゅう　はんしゃ　ごますり　そんけい　たいちょう　らしんばん　ぶんせき　やすみ　ほいく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "b14e7d35904cb8569af0d6a016cee7066335a21c1c67891b01b83033cadb3e8a034a726e3909139ecd8b2eb9e9b05245684558f329b38480e262c1d6bc20ecc4",
        ),
        (
            "くのう　てぬぐい　そんかい　すろっと　ちきゅう　ほあん　とさか　はくしゅ　ひびく　みえる　そざい　てんすう　たんぴん　くしょう　すいようび　みけん　きさらぎ　げざん　ふくざつ　あつかう　はやい　くろう　おやゆび　こすう",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "32e78dce2aff5db25aa7a4a32b493b5d10b4089923f3320c8b287a77e512455443298351beb3f7eb2390c4662a2e566eec5217e1a37467af43b46668d515e41b",
        ),
        (
            "あみもの　いきおい　ふいうち　にげる　ざんしょ　じかん　ついか　はたん　ほあん　すんぽう　てちがい　わかめ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "0acf902cd391e30f3f5cb0605d72a4c849342f62bd6a360298c7013d714d7e58ddf9c7fdf141d0949f17a2c9c37ced1d8cb2edabab97c4199b142c829850154b",
        ),
        (
            "すろっと　にくしみ　なやむ　たとえる　へいこう　すくう　きない　けってい　とくべつ　ねっしん　いたみ　せんせい　おくりがな　まかい　とくい　けあな　いきおい　そそぐ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "9869e220bec09b6f0c0011f46e1f9032b269f096344028f5006a6e69ea5b0b8afabbb6944a23e11ebd021f182dd056d96e4e3657df241ca40babda532d364f73",
        ),
        (
            "かほご　きうい　ゆたか　みすえる　もらう　がっこう　よそう　ずっと　ときどき　したうけ　にんか　はっこう　つみき　すうじつ　よけい　くげん　もくてき　まわり　せめる　げざい　にげる　にんたい　たんそく　ほそく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "713b7e70c9fbc18c831bfd1f03302422822c3727a93a5efb9659bec6ad8d6f2c1b5c8ed8b0b77775feaf606e9d1cc0a84ac416a85514ad59f5541ff5e0382481",
        ),
        (
            "めいえん　さのう　めだつ　すてる　きぬごし　ろんぱ　はんこ　まける　たいおう　さかいし　ねんいり　はぶらし",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "06e1d5289a97bcc95cb4a6360719131a786aba057d8efd603a547bd254261c2a97fcd3e8a4e766d5416437e956b388336d36c7ad2dba4ee6796f0249b10ee961",
        ),
        (
            "せんぱい　おしえる　ぐんかん　もらう　きあい　きぼう　やおや　いせえび　のいず　じゅしん　よゆう　きみつ　さといも　ちんもく　ちわわ　しんせいじ　とめる　はちみつ",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "1fef28785d08cbf41d7a20a3a6891043395779ed74503a5652760ee8c24dfe60972105ee71d5168071a35ab7b5bd2f8831f75488078a90f0926c8e9171b2bc4a",
        ),
        (
            "こころ　いどう　きあつ　そうがんきょう　へいあん　せつりつ　ごうせい　はいち　いびき　きこく　あんい　おちつく　きこえる　けんとう　たいこ　すすめる　はっけん　ていど　はんおん　いんさつ　うなぎ　しねま　れいぼう　みつかる",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "43de99b502e152d4c198542624511db3007c8f8f126a30818e856b2d8a20400d29e7a7e3fdd21f909e23be5e3c8d9aee3a739b0b65041ff0b8637276703f65c2",
        ),
        (
            "うりきれ　さいせい　じゆう　むろん　とどける　ぐうたら　はいれつ　ひけつ　いずれ　うちあわせ　おさめる　おたく",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "3d711f075ee44d8b535bb4561ad76d7d5350ea0b1f5d2eac054e869ff7963cdce9581097a477d697a2a9433a0c6884bea10a2193647677977c9820dd0921cbde",
        ),
        (
            "うりきれ　うねる　せっさたくま　きもち　めんきょ　へいたく　たまご　ぜっく　びじゅつかん　さんそ　むせる　せいじ　ねくたい　しはらい　せおう　ねんど　たんまつ　がいけん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "753ec9e333e616e9471482b4b70a18d413241f1e335c65cd7996f32b66cf95546612c51dcf12ead6f805f9ee3d965846b894ae99b24204954be80810d292fcdd",
        ),
        (
            "うちゅう　ふそく　ひしょ　がちょう　うけもつ　めいそう　みかん　そざい　いばる　うけとる　さんま　さこつ　おうさま　ぱんつ　しひょう　めした　たはつ　いちぶ　つうじょう　てさぎょう　きつね　みすえる　いりぐち　かめれおん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "346b7321d8c04f6f37b49fdf062a2fddc8e1bf8f1d33171b65074531ec546d1d3469974beccb1a09263440fc92e1042580a557fdce314e27ee4eabb25fa5e5fe",
        ),
    ];

    // Seed hex computed with Python hashlib.pbkdf2_hmac and unicodedata NFKD normalization.
    // The last three phrases are 127, 128 and 129 bytes, around the HMAC key block size.
    const ADDITIONAL_SEED_VECTORS: &[(&str, &str, &str)] = &[
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "Åé",
            "c95759e30618e65a305b1fea65760d2da1d0758763bdbf07bc8a840716c5a391a0ffdbd2f834cb861bcb68d6124991a80c28f5e8769829f88d66beff6c0b2b69",
        ),
        (
            "someone memory charge laptop enact artefact polar section wreck uniform salad drum divorce insect excuse forward ecology regret",
            "TREZOR",
            "cf37c10684dae28c8e0070736b21787a21700419913d4b95e9e192fccf09468347982da637574fda30c9ccc4509cb7eb5bad0e12d447fe281964a4bec23f8d89",
        ),
        (
            "inside resource lens rural weird length scatter dilemma cruise vehicle inherit broccoli maple rabbit remain drama obscure employ",
            "TREZOR",
            "a4b146f5263418985510d0d050c3781546e47257b3788bb69f8258ee888fdfef12a5e466f226a06e8a9e943ee0c0d3717b2f750b41dbe1170e536fe388218704",
        ),
        (
            "chief mosquito surround donate lawsuit disease food evil strike only midnight enact thing practice erosion resource reward engage",
            "TREZOR",
            "758b0a2a587dc55cd51a46bc7765a2c869489f13a0b5abf0e80fbf8de827263c22409e0f210311c538450d5db916a84d99849f388d65434a30dfd1e428f0a29e",
        ),
    ];

    #[test]
    fn test_mnemonic_generation() {
        // Test generation with default word count (12 words)
        let mnemonic = Mnemonic::generate(12, Language::English).unwrap();
        let phrase = mnemonic.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);

        // Verify the mnemonic is valid
        assert!(Mnemonic::validate(&mnemonic.phrase()));
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        // Test with a known valid mnemonic
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase);
        assert!(mnemonic.is_ok());

        let mnemonic = mnemonic.unwrap();
        assert_eq!(mnemonic.phrase().as_str(), phrase);
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
            let result = Mnemonic::from_phrase(phrase);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_mnemonic_to_seed() {
        // Test seed generation with known test vector
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        // Test without passphrase
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.len(), 64);

        // Test with passphrase
        let seed_with_pass = mnemonic.to_seed("TREZOR");
        assert_eq!(seed_with_pass.len(), 64);
        assert_ne!(&seed[..], &seed_with_pass[..]);
    }

    // These tests pin the seed bytes. Whether bip39_seed wipes its buffers is not observable
    // from a test.
    fn assert_seed_vectors(vectors: &[(&str, &str, &str)]) {
        for &(phrase, passphrase, seed_hex) in vectors {
            let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
            let expected = decode_to_vec(seed_hex).unwrap();
            assert_eq!(&mnemonic.to_seed(passphrase)[..], expected, "{phrase}");
        }
    }

    #[test]
    fn test_bip39_seed_japanese_vectors() {
        assert_seed_vectors(JAPANESE_SEED_VECTORS);
    }

    #[test]
    fn test_bip39_seed_additional_vectors() {
        assert_seed_vectors(ADDITIONAL_SEED_VECTORS);
    }

    #[test]
    fn test_bip39_seed_matches_the_bip39_crate() {
        let long_english = Mnemonic::from_entropy(&[0xa5; 32], Language::English).unwrap();
        assert!(long_english.phrase().len() > 128);

        for language in Language::ALL {
            for entropy in [&[0; 16][..], &[0xa5; 32][..]] {
                let mnemonic = Mnemonic::from_entropy(entropy, language).unwrap();
                let phrase = mnemonic.phrase();
                let reference = Bip39Mnemonic::parse_in(language.into(), phrase.as_str()).unwrap();
                for passphrase in [
                    "",
                    "TREZOR",
                    "\u{c5}\u{e9}",
                    "\u{ff21}\u{fb01}",
                    "\u{1f600}",
                    &"p".repeat(300),
                ] {
                    assert_eq!(
                        *mnemonic.to_seed(passphrase),
                        reference.to_seed(passphrase),
                        "{language:?}"
                    );
                }
            }
        }
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
            let mnemonic = Mnemonic::from_phrase(phrase);
            assert!(mnemonic.is_ok());

            let mnemonic = mnemonic.unwrap();
            let phrase = mnemonic.phrase();
            let words: Vec<&str> = phrase.split_whitespace().collect();
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
        let invalid_phrases = vec!["invalid words here", "", "   "];

        for phrase in invalid_phrases {
            assert!(!Mnemonic::validate(phrase), "Should not validate: {}", phrase);
        }
    }

    #[test]
    fn test_mnemonic_recovery() {
        // Generate a mnemonic and recover wallet from it
        let original = Mnemonic::generate(12, Language::English).unwrap();
        let phrase = original.phrase().to_string();

        // Recover from the phrase
        let recovered = Mnemonic::from_phrase(&phrase).unwrap();

        // They should produce the same seed
        let original_seed = original.to_seed("");
        let recovered_seed = recovered.to_seed("");
        assert_eq!(original_seed, recovered_seed);

        // And the same phrase
        assert_eq!(original.phrase(), recovered.phrase());
    }

    #[test]
    fn test_mnemonic_with_different_passphrases() {
        let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

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

        let mnemonic1 = Mnemonic::from_phrase(phrase).unwrap();
        let mnemonic2 = Mnemonic::from_phrase(phrase).unwrap();

        let seed1 = mnemonic1.to_seed("test");
        let seed2 = mnemonic2.to_seed("test");

        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_mnemonic_entropy_uniqueness() {
        // Generate multiple mnemonics and ensure they're different
        let mnemonics: Vec<Mnemonic> =
            (0..10).map(|_| Mnemonic::generate(12, Language::English).unwrap()).collect();

        // Check that all phrases are unique
        let mut phrases: Vec<String> = mnemonics.iter().map(|m| m.phrase().to_string()).collect();
        phrases.sort();
        phrases.dedup();

        // Should have 10 unique phrases
        assert_eq!(phrases.len(), 10);
    }

    #[test]
    fn test_mnemonic_phrase_immutability() {
        let mnemonic = Mnemonic::generate(12, Language::English).unwrap();
        let phrase1 = mnemonic.phrase();
        let phrase2 = mnemonic.phrase();

        // Multiple calls should return the same phrase
        assert_eq!(phrase1, phrase2);
    }
}
