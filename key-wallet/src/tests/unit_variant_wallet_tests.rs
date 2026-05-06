//! Tests for the `WalletType::WatchOnly` and `WalletType::ExternalSignable`
//! unit variants + their `new_*` constructors.
//!
//! These variants carry no root key material. Identity lives on `Wallet.wallet_id`
//! and per-account xpubs live in `AccountCollection`; nothing else is needed for
//! the host to track addresses or route signing requests to an external device.

use crate::account::account_collection::AccountCollection;
use crate::mnemonic::{Language, Mnemonic};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::{Wallet, WalletType};
use crate::Network;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn built_full_wallet() -> Wallet {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    Wallet::from_mnemonic(mnemonic, Network::Testnet, WalletAccountCreationOptions::Default)
        .unwrap()
}

// -------- constructors --------------------------------------------------

#[test]
fn new_watch_only_sets_unit_variant_and_preserves_inputs() {
    let full = built_full_wallet();
    let accounts = full.accounts.clone();

    let watch = Wallet::new_watch_only(Network::Testnet, full.wallet_id, accounts);

    assert!(matches!(watch.wallet_type, WalletType::WatchOnly));
    assert!(watch.is_watch_only());
    assert!(!watch.can_sign());
    assert!(!watch.is_external_signable());
    assert!(!watch.has_mnemonic());
    assert!(!watch.has_seed());
    assert_eq!(watch.wallet_id, full.wallet_id);
    assert_eq!(watch.compute_wallet_id(), full.wallet_id);
    assert_eq!(watch.network, Network::Testnet);
    // compute_wallet_id must not re-derive from a fabricated pub key.
    // Changing wallet_id without touching accounts must change compute_wallet_id.
    let mut tampered = watch.clone();
    tampered.wallet_id = [9u8; 32];
    assert_eq!(tampered.compute_wallet_id(), [9u8; 32]);
}

#[test]
fn new_external_signable_sets_unit_variant_and_can_sign_externally() {
    let full = built_full_wallet();
    let accounts = full.accounts.clone();

    let ext = Wallet::new_external_signable(Network::Testnet, full.wallet_id, accounts);

    assert!(matches!(ext.wallet_type, WalletType::ExternalSignable));
    assert!(ext.is_external_signable());
    // can_sign reports true for external-signable wallets: signing is routed to
    // the external device, not blocked locally.
    assert!(ext.can_sign());
    assert!(!ext.is_watch_only());
    assert!(!ext.has_mnemonic());
    assert_eq!(ext.wallet_id, full.wallet_id);
    assert_eq!(ext.compute_wallet_id(), full.wallet_id);
}

// -------- root_extended_pub_key* unavailable ---------------------------

#[test]
fn root_extended_pub_key_is_err_for_unit_variants() {
    let full = built_full_wallet();

    let watch = Wallet::new_watch_only(Network::Testnet, full.wallet_id, AccountCollection::new());
    let ext =
        Wallet::new_external_signable(Network::Testnet, full.wallet_id, AccountCollection::new());

    assert!(watch.root_extended_pub_key().is_err());
    assert!(watch.root_extended_pub_key_cow().is_err());
    assert!(ext.root_extended_pub_key().is_err());
    assert!(ext.root_extended_pub_key_cow().is_err());
}

// -------- signing-path errors shaped the same --------------------------

#[test]
fn signing_paths_report_cannot_sign_for_unit_variants() {
    use crate::DerivationPath;

    let full = built_full_wallet();
    let watch = Wallet::new_watch_only(Network::Testnet, full.wallet_id, AccountCollection::new());
    let ext =
        Wallet::new_external_signable(Network::Testnet, full.wallet_id, AccountCollection::new());

    let path: DerivationPath = "m/44'/1'/0'/0/0".parse().unwrap();

    // derive_private_key / derive_extended_private_key go through the same
    // "no private key" error path for both unit variants.
    assert!(watch.derive_private_key(&path).is_err());
    assert!(watch.derive_extended_private_key(&path).is_err());
    assert!(watch.derive_private_key_as_wif(&path).is_err());
    assert!(ext.derive_private_key(&path).is_err());
    assert!(ext.derive_extended_private_key(&path).is_err());
}

// -------- round-trip: full wallet -> watch-only preserves addresses ----

#[test]
fn round_trip_full_to_watch_only_has_address_parity_per_account() {
    let full = built_full_wallet();
    let wallet_id = full.wallet_id;
    let accounts_snapshot = full.accounts.clone();

    let watch = Wallet::new_watch_only(Network::Testnet, wallet_id, accounts_snapshot);

    // Every account's extended public key — and therefore every address it
    // will ever generate — must match its full-wallet counterpart.
    assert_eq!(watch.accounts.count(), full.accounts.count());

    for full_acct in full.all_accounts() {
        let matched = watch
            .all_accounts()
            .into_iter()
            .find(|w| w.account_type == full_acct.account_type)
            .expect("every full-wallet account must appear in the watch-only snapshot");
        assert_eq!(
            matched.extended_public_key(),
            full_acct.extended_public_key(),
            "account xpub mismatch for {:?}",
            full_acct.account_type
        );
    }
}

// -------- derive_extended_public_key surfaces actionable guidance -----

#[test]
fn derive_extended_public_key_error_points_to_per_account_xpub() {
    use crate::DerivationPath;

    let full = built_full_wallet();
    let watch = Wallet::new_watch_only(Network::Testnet, full.wallet_id, AccountCollection::new());
    let ext =
        Wallet::new_external_signable(Network::Testnet, full.wallet_id, AccountCollection::new());

    // Non-hardened path: the generic "root pub key unavailable" error should
    // be replaced with call-site-specific guidance pointing at per-account
    // xpubs, which is the actual escape hatch for watch-only callers.
    let non_hardened: DerivationPath = "m/0/0".parse().unwrap();
    let err = watch.derive_extended_public_key(&non_hardened).unwrap_err().to_string();
    assert!(
        err.contains("extended_public_key") && err.contains("account"),
        "watch-only derive error should recommend per-account xpubs; got: {err}"
    );
    let err = ext.derive_extended_public_key(&non_hardened).unwrap_err().to_string();
    assert!(
        err.contains("extended_public_key") && err.contains("account"),
        "external-signable derive error should recommend per-account xpubs; got: {err}"
    );

    // Hardened path: the existing "no private key" error shape is preserved.
    let hardened: DerivationPath = "m/44'/1'/0'".parse().unwrap();
    assert!(watch.derive_extended_public_key(&hardened).is_err());
}

// -------- bincode round-trip -------------------------------------------

#[test]
fn bincode_round_trip_watch_only() {
    let full = built_full_wallet();
    let original = Wallet::new_watch_only(Network::Testnet, full.wallet_id, full.accounts.clone());

    let bytes = bincode::encode_to_vec(&original, bincode::config::standard()).expect("encode");
    let (decoded, _): (Wallet, usize) =
        bincode::decode_from_slice(&bytes, bincode::config::standard()).expect("decode");

    assert!(matches!(decoded.wallet_type, WalletType::WatchOnly));
    assert!(decoded.is_watch_only());
    assert_eq!(decoded.wallet_id, original.wallet_id);
    assert_eq!(decoded.network, original.network);
    assert_eq!(decoded.accounts.count(), original.accounts.count());
}

#[test]
fn bincode_round_trip_external_signable() {
    let full = built_full_wallet();
    let original =
        Wallet::new_external_signable(Network::Testnet, full.wallet_id, full.accounts.clone());

    let bytes = bincode::encode_to_vec(&original, bincode::config::standard()).expect("encode");
    let (decoded, _): (Wallet, usize) =
        bincode::decode_from_slice(&bytes, bincode::config::standard()).expect("decode");

    assert!(matches!(decoded.wallet_type, WalletType::ExternalSignable));
    assert!(decoded.is_external_signable());
    assert_eq!(decoded.wallet_id, original.wallet_id);
    assert_eq!(decoded.network, original.network);
    assert_eq!(decoded.accounts.count(), original.accounts.count());
}
