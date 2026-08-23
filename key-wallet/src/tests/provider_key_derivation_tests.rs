//! End-to-end tests for provider (masternode) key derivation.
//!
//! These pin the wallet-level BLS operator key and Ed25519 platform node key
//! flows to reference vectors produced by the implementations DashSync uses
//! (dashbls `ExtendedPrivateKey` with `fLegacy = true` for BLS, SLIP-0010 for
//! Ed25519), so the keys match dashwallet-ios / DashSync for the same
//! mnemonic. See <https://github.com/dashpay/rust-dashcore/issues/878>.

use crate::account::derivation::AccountDerivation;
use crate::account::AccountType;
use crate::mnemonic::Mnemonic;
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::Wallet;
use crate::{ChildNumber, Network};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// BIP39 seed for [`TEST_MNEMONIC`] with an empty passphrase.
const TEST_SEED_HEX: &str =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

fn test_wallet(network: Network) -> Wallet {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
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
        account.bls_public_key.derive_pub_legacy(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
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
        account.bls_public_key.derive_pub_legacy(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
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

/// The platform node id must follow the Tenderdash/CometBFT convention —
/// `SHA256(pubkey)[0..20]` — not hash160, or wallet-side matching can never
/// hit on-chain evonode registrations. See
/// <https://github.com/dashpay/rust-dashcore/issues/883>.
#[cfg(feature = "eddsa")]
#[test]
fn ed25519_platform_node_id_matches_tenderdash_convention() {
    use crate::account::eddsa_account::EdDSAAccount;
    use crate::derivation_slip10::tenderdash_node_id;

    // Platform node key 0 (m/9'/5'/3'/4'/0') for TEST_SEED — the same key the
    // SLIP-0010 vector above pins. Public key and node id cross-checked with
    // an independent Ed25519 implementation (pyca/cryptography).
    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let sk0 = EdDSAAccount::platform_node_key_at(&seed, Network::Mainnet, 0).unwrap();
    let pubkey = sk0.verifying_key();
    assert_eq!(
        hex::encode(pubkey.to_bytes()),
        "3130c14339391cf26a68d86879e180ee9a16b660f5aa91f560f67c0abe8cf789"
    );
    assert_eq!(
        hex::encode(tenderdash_node_id(&pubkey.to_bytes())),
        "302f2615e6955cce8ed3cff81e8011bfd3a2991f"
    );
}

/// The managed ProviderPlatformKeys pool must key its entries by the
/// Tenderdash node id, since that payload is what ProRegTx matching compares
/// against the on-chain `platform_node_id` field.
#[cfg(feature = "eddsa")]
#[test]
fn platform_pool_entries_are_keyed_by_tenderdash_node_id() {
    use crate::derivation_slip10::ExtendedEd25519PrivKey;
    use crate::managed_account::managed_account_trait::ManagedAccountTrait;
    use crate::wallet::managed_wallet_info::ManagedWalletInfo;
    use dashcore::hashes::Hash;

    let wallet = test_wallet(Network::Mainnet);
    let mut info = ManagedWalletInfo::from_wallet_with_name(&wallet, "node-id".to_string(), 0);

    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let master = ExtendedEd25519PrivKey::new_master(Network::Mainnet, &seed).unwrap();
    let account_xpriv = master
        .derive_priv(&AccountType::ProviderPlatformKeys.derivation_path(Network::Mainnet).unwrap())
        .unwrap();

    let (verifying_key, entry) = info
        .provider_platform_keys_managed_account_mut()
        .expect("platform managed account")
        .next_eddsa_platform_key(account_xpriv, true)
        .expect("derive platform key 0");

    assert_eq!(
        hex::encode(verifying_key.to_bytes()),
        "3130c14339391cf26a68d86879e180ee9a16b660f5aa91f560f67c0abe8cf789"
    );
    // The pool entry's payload is the Tenderdash node id — the value a real
    // ProRegTx carries — so registration matching can hit it.
    let dashcore::address::Payload::PubkeyHash(hash) = entry.address.payload() else {
        panic!("platform pool entries use P2PKH-style payloads");
    };
    assert_eq!(hex::encode(hash.to_byte_array()), "302f2615e6955cce8ed3cff81e8011bfd3a2991f");
}

/// The gate-free provider-key entry points must work identically on resident
/// (non-watch-only) and watch-only accounts, and must match the dashbls
/// reference vectors. See
/// <https://github.com/dashpay/rust-dashcore/issues/880>.
#[cfg(feature = "bls")]
#[test]
fn operator_key_at_is_wallet_state_agnostic() {
    use crate::account::bls_account::BLSAccount;

    let wallet = test_wallet(Network::Mainnet);
    let resident = wallet
        .accounts
        .bls_account_of_type(AccountType::ProviderOperatorKeys)
        .expect("operator account should be auto-created for mnemonic wallets");
    assert!(!resident.is_watch_only);

    // A restored / externally-signable wallet stores the same account xpub but
    // flags it watch-only (`BLSAccount::new` sets `is_watch_only: true`).
    let watch_only = resident.to_watch_only();
    assert!(watch_only.is_watch_only);

    // The legacy-gated wrapper fails on the resident account — the new entry
    // point must not.
    assert!(resident.derive_bls_key_at_index(0).is_err());

    for account in [resident, &watch_only] {
        let key0 = account.operator_public_key_at(0).expect("gate-free derivation must succeed");
        assert_eq!(
            hex::encode(key0.to_bytes_legacy()),
            "078cad04aae29eb76171937eb7101452b401b026efbc27db840f130374e6a9ec8443d917277f8921e0ba6678a7709875"
        );
        assert_eq!(
            hex::encode(key0.to_bytes()),
            "878cad04aae29eb76171937eb7101452b401b026efbc27db840f130374e6a9ec8443d917277f8921e0ba6678a7709875"
        );
    }

    // Seed-based private derivation needs no account state at all.
    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let sk0 = BLSAccount::operator_private_key_at(&seed, Network::Mainnet, 0).unwrap();
    assert_eq!(
        hex::encode(sk0.to_be_bytes()),
        "11122e1ad656d0610ce0f80d40da874d67ea656a3e66ed371c915ec3a488a43a"
    );
    let sk1 = BLSAccount::operator_private_key_at(&seed, Network::Mainnet, 1).unwrap();
    assert_eq!(
        hex::encode(sk1.to_be_bytes()),
        "1a4e3318640cd4e50222184d0ea111abf8a0c18a0e5dc3ed45dad85009db4e31"
    );

    // Testnet vectors (coin type 1: m/9'/1'/3'/3').
    let sk0_testnet = BLSAccount::operator_private_key_at(&seed, Network::Testnet, 0).unwrap();
    assert_eq!(
        hex::encode(sk0_testnet.to_be_bytes()),
        "3346dfd71627f9f31cad3ee66fe7b673c32cb077b2eb38c621d7e61c30e46dbd"
    );
}

/// `operator_public_key_at` refuses non-operator accounts so a mixed-up
/// account lookup fails loudly instead of yielding valid-looking wrong keys.
#[cfg(feature = "bls")]
#[test]
fn operator_public_key_at_rejects_non_operator_accounts() {
    use crate::account::bls_account::BLSAccount;

    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let account =
        BLSAccount::from_seed(None, AccountType::IdentityRegistration, &seed, Network::Mainnet)
            .unwrap();
    assert!(account.operator_public_key_at(0).is_err());
}

#[cfg(feature = "eddsa")]
#[test]
fn platform_node_key_at_is_wallet_state_agnostic() {
    use crate::account::eddsa_account::EdDSAAccount;

    // Seed-based hardened derivation, pinned to the SLIP-0010 reference
    // vector for m/9'/5'/3'/4'/0'. No account state is involved.
    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let sk0 = EdDSAAccount::platform_node_key_at(&seed, Network::Mainnet, 0).unwrap();
    assert_eq!(
        hex::encode(sk0.to_bytes()),
        "5fa238b12be77347abf9b5957bd902d16c6aaca28d25c4267ffacbd7458dceb1"
    );

    // Cross-check against the account stored in a resident wallet: the
    // seed-based path must agree with the account-based path.
    let wallet = test_wallet(Network::Mainnet);
    let account = wallet
        .accounts
        .eddsa_account_of_type(AccountType::ProviderPlatformKeys)
        .expect("platform node account should be auto-created for mnemonic wallets");
    let via_account = account.derive_from_seed_private_key_at(&seed, 0).unwrap();
    assert_eq!(sk0.to_bytes(), via_account.to_bytes());
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
