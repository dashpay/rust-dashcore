//! End-to-end tests for provider (masternode) key derivation.
//!
//! These pin the wallet-level BLS operator key and Ed25519 platform node key
//! flows to reference vectors produced by the implementations DashSync uses
//! (dashbls `ExtendedPrivateKey` with `fLegacy = true` for BLS, SLIP-0010 for
//! Ed25519), so the keys match dashwallet-ios / DashSync for the same
//! mnemonic. See <https://github.com/dashpay/rust-dashcore/issues/878>.

use crate::account::derivation::AccountDerivation;
use crate::account::AccountType;
use crate::mnemonic::{Language, Mnemonic};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::Wallet;
use crate::{ChildNumber, Network};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// BIP39 seed for [`TEST_MNEMONIC`] with an empty passphrase.
const TEST_SEED_HEX: &str =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

fn test_wallet(network: Network) -> Wallet {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    Wallet::from_mnemonic(mnemonic, network, WalletAccountCreationOptions::Default).unwrap()
}

#[cfg(feature = "bls")]
#[test]
fn bls_operator_keys_match_dashbls_reference() {
    // Reference vectors generated with dashbls (dashpay/bls-signatures @
    // 0842b17): ExtendedPrivateKey::FromSeed(seed) then PrivateChild(i,
    // fLegacy=true) along m/9'/5'/3'/3', then child i (non-hardened).
    let wallet = test_wallet(Network::Mainnet);
    let account = wallet
        .accounts
        .bls_account_of_type(AccountType::ProviderOperatorKeys)
        .expect("operator account should be auto-created for mnemonic wallets");

    // The stored account xpub must be the account-level key at m/9'/5'/3'/3'.
    assert_eq!(
        hex::encode(account.bls_public_key.to_bytes_legacy()),
        "8d794d053504db3727c1f51aea2112e440fadbade687a9c0243b61523c8ab8eb64061f0a5ec5d8df4b7ec8bdfe722c19"
    );

    // Operator key 0 via watch-side (non-hardened public) derivation.
    let key0_pub =
        account.bls_public_key.derive_pub(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    assert_eq!(
        hex::encode(key0_pub.to_bytes_legacy()),
        "078cad04aae29eb76171937eb7101452b401b026efbc27db840f130374e6a9ec8443d917277f8921e0ba6678a7709875"
    );
    // Same point in modern/IETF (basic-scheme) serialization, as it appears in
    // v19+ ProRegTx payloads.
    assert_eq!(
        hex::encode(key0_pub.to_bytes()),
        "878cad04aae29eb76171937eb7101452b401b026efbc27db840f130374e6a9ec8443d917277f8921e0ba6678a7709875"
    );

    // Operator secret key 0 via the seed-based signing path.
    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let sk0 = account.derive_from_seed_private_key_at(&seed, 0).unwrap();
    assert_eq!(
        hex::encode(sk0.to_be_bytes()),
        "11122e1ad656d0610ce0f80d40da874d67ea656a3e66ed371c915ec3a488a43a"
    );
    let sk1 = account.derive_from_seed_private_key_at(&seed, 1).unwrap();
    assert_eq!(
        hex::encode(sk1.to_be_bytes()),
        "1a4e3318640cd4e50222184d0ea111abf8a0c18a0e5dc3ed45dad85009db4e31"
    );
}

#[cfg(feature = "bls")]
#[test]
fn bls_operator_keys_testnet_match_dashbls_reference() {
    // Testnet uses coin type 1: m/9'/1'/3'/3'.
    let wallet = test_wallet(Network::Testnet);
    let account = wallet
        .accounts
        .bls_account_of_type(AccountType::ProviderOperatorKeys)
        .expect("operator account should be auto-created for mnemonic wallets");

    let key0_pub =
        account.bls_public_key.derive_pub(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    assert_eq!(
        hex::encode(key0_pub.to_bytes_legacy()),
        "09d8beabae708de1638487f1aff44b38e8c07d9b09f22d76329d6c8ec01e2ad4d030b660bca40ddbd222373a72c5bcef"
    );

    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let sk0 = account.derive_from_seed_private_key_at(&seed, 0).unwrap();
    assert_eq!(
        hex::encode(sk0.to_be_bytes()),
        "3346dfd71627f9f31cad3ee66fe7b673c32cb077b2eb38c621d7e61c30e46dbd"
    );
}

#[cfg(feature = "eddsa")]
#[test]
fn ed25519_platform_node_keys_match_slip10_reference() {
    // Reference vectors computed with an independent SLIP-0010 implementation:
    // master from the BIP39 seed, then hardened path m/9'/5'/3'/4' and child 0'.
    let wallet = test_wallet(Network::Mainnet);
    let account = wallet
        .accounts
        .eddsa_account_of_type(AccountType::ProviderPlatformKeys)
        .expect("platform node account should be auto-created for mnemonic wallets");

    // The stored account key must be the account-level key at m/9'/5'/3'/4'.
    let expected_account_sk =
        hex::decode("80035d9c2f89971a9c9fad826bba8be9328f1686ae555e912949c2c32800c379").unwrap();
    let expected_account_pk = dashcore::ed25519_dalek::SigningKey::from_bytes(
        expected_account_sk.as_slice().try_into().unwrap(),
    )
    .verifying_key();
    assert_eq!(account.ed25519_public_key.public_key, expected_account_pk);

    // Platform node key 0 (hardened child 0') via the seed-based signing path.
    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let sk0 = account.derive_from_seed_private_key_at(&seed, 0).unwrap();
    assert_eq!(
        hex::encode(sk0.to_bytes()),
        "5fa238b12be77347abf9b5957bd902d16c6aaca28d25c4267ffacbd7458dceb1"
    );
}

/// Wallets created from a bare extended private key carry no seed, so
/// DashSync-compatible BLS/Ed25519 provider keys cannot be derived for them.
/// Default account creation must skip those accounts rather than fabricate
/// keys that never correspond to anything on-chain, and explicit account
/// creation without a seed must fail.
#[cfg(all(feature = "bls", feature = "eddsa"))]
#[test]
fn seedless_wallet_skips_provider_operator_and_platform_accounts() {
    use crate::bip32::ExtendedPrivKey;
    use crate::Error;

    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let mut wallet =
        Wallet::from_extended_key(master, WalletAccountCreationOptions::Default).unwrap();

    assert!(wallet.accounts.bls_account_of_type(AccountType::ProviderOperatorKeys).is_none());
    assert!(wallet.accounts.eddsa_account_of_type(AccountType::ProviderPlatformKeys).is_none());

    // Explicit creation without a seed fails with a typed error...
    assert!(matches!(
        wallet.add_bls_account(AccountType::ProviderOperatorKeys, None),
        Err(Error::KeylessWalletRequiresAccountKey { .. })
    ));
    assert!(matches!(
        wallet.add_eddsa_account(AccountType::ProviderPlatformKeys, None),
        Err(Error::KeylessWalletRequiresAccountKey { .. })
    ));

    // ...but works when the seed is supplied explicitly.
    wallet.add_bls_account(AccountType::ProviderOperatorKeys, Some(&seed)).unwrap();
    wallet.add_eddsa_account(AccountType::ProviderPlatformKeys, Some(&seed)).unwrap();
    assert!(wallet.accounts.bls_account_of_type(AccountType::ProviderOperatorKeys).is_some());
    assert!(wallet.accounts.eddsa_account_of_type(AccountType::ProviderPlatformKeys).is_some());
}
