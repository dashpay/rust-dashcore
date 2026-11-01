//! `{:?}` and `{:#?}` of the private key types show no phrase word, chain code or private key.

use key_wallet::bip32::ChildNumber;
use key_wallet::derivation_bls_bip32::ExtendedBLSPrivKey;
use key_wallet::derivation_slip10::ExtendedEd25519PrivKey;
use key_wallet::wallet::root_extended_keys::RootExtendedPrivKey;
use key_wallet::{DerivationPath, ExtendedPrivKey, Mnemonic, Network};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn debug_outputs(value: &dyn std::fmt::Debug) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

/// The forms a 32-byte secret could take in a `Debug` output: hex, or a decimal byte array.
fn secret_forms(bytes: &[u8]) -> [String; 2] {
    [hex_conservative::DisplayHex::to_lower_hex_string(bytes), format!("{bytes:?}")]
}

fn assert_hides(value: &dyn std::fmt::Debug, secrets: &[&[u8]]) {
    for output in debug_outputs(value) {
        for secret in secrets {
            for form in secret_forms(secret) {
                assert!(!output.contains(&form), "{output} shows {form}");
            }
        }
    }
}

#[test]
fn extended_priv_key_debug_hides_the_chain_code_and_key() {
    let seed = Mnemonic::from_phrase(PHRASE).unwrap().to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed[..]).unwrap();
    let path: DerivationPath = "m/44'/1'/0'".parse().unwrap();
    let child = master.derive_priv(&path).unwrap();
    for key in [master, child] {
        assert_hides(&key, &[&key.chain_code.to_bytes(), &*key.private_key.to_bytes()]);
        assert!(format!("{key:?}").contains("child_number"));
    }
}

#[test]
fn extended_bls_priv_key_debug_hides_the_chain_code_and_key() {
    let seed = Mnemonic::from_phrase(PHRASE).unwrap().to_seed("");
    let master = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed[..]).unwrap();
    let child = master.derive_priv(ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
    for key in [master, child] {
        assert_hides(&key, &[&key.chain_code.to_bytes(), key.private_key().as_bytes()]);
        assert!(format!("{key:?}").contains("child_number"));
    }
}

#[test]
fn extended_ed25519_priv_key_debug_hides_the_chain_code_and_key() {
    let seed = Mnemonic::from_phrase(PHRASE).unwrap().to_seed("");
    let master = ExtendedEd25519PrivKey::new_master(Network::Testnet, &seed[..]).unwrap();
    let child = master.ckd_priv(ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
    for key in [master, child] {
        assert_hides(&key, &[&key.chain_code.to_bytes(), key.private_key.as_bytes()]);
        assert!(format!("{key:?}").contains("child_number"));
    }
}

#[test]
fn root_extended_priv_key_debug_hides_the_chain_code_and_key() {
    let seed = Mnemonic::from_phrase(PHRASE).unwrap().to_seed("");
    let root = RootExtendedPrivKey::new_master(&seed[..]).unwrap();
    let key = root.to_extended_priv_key(Network::Testnet);
    assert_hides(&root, &[&key.chain_code.to_bytes(), &*key.private_key.to_bytes()]);
}

#[test]
fn mnemonic_debug_hides_the_words() {
    let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
    for output in debug_outputs(&mnemonic) {
        assert!(!output.contains("abandon"), "{output}");
        assert!(!output.contains("about"), "{output}");
        // bip39 2.2.0's `Debug` lists the word indices ("abandon" is index 0, "about" index 3);
        // later bip39 versions print only the language.
        assert!(!output.contains("[0, 0"), "{output}");
    }
    assert_eq!(format!("{mnemonic:?}"), "Mnemonic { language: English, word_count: 12 }");
}
