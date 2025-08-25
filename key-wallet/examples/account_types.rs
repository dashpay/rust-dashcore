//! Example demonstrating different account types (ECDSA, BLS, EdDSA)

use key_wallet::account::derivation::AccountDerivation;
use key_wallet::account::{
    Account, AccountTrait, AccountType, BLSAccount, ECDSAAddressDerivation, EdDSAAccount,
    StandardAccountType,
};
use key_wallet::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use key_wallet::managed_account::address_pool::AddressPoolType;
use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::Network;
use secp256k1::Secp256k1;

#[cfg(feature = "bls")]
use key_wallet::derivation_bls_bip32::ExtendedBLSPrivKey;
#[cfg(feature = "eddsa")]
use key_wallet::derivation_slip10::ExtendedEd25519PrivKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a mnemonic for testing
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )?;
    let seed = mnemonic.to_seed("");

    // Create master key
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed)?;
    let secp = Secp256k1::new();

    // 1. Standard ECDSA Account (traditional HD wallet)
    println!("=== ECDSA Account (Standard HD Wallet) ===");
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44)?,
        ChildNumber::from_hardened_idx(1)?,
        ChildNumber::from_hardened_idx(0)?,
    ]);
    let account_xpriv = master.derive_priv(&secp, &path)?;
    let account_xpub = ExtendedPubKey::from_priv(&secp, &account_xpriv);

    let ecdsa_account = Account::new(
        None,
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        account_xpub,
        Network::Testnet,
    )?;

    // ECDSA accounts can derive standard addresses
    println!("Network: {:?}", ecdsa_account.network());
    println!("Is watch-only: {}", ecdsa_account.is_watch_only());
    println!("Account index: {:?}", ecdsa_account.index());

    // Derive some addresses
    let addr1 = ecdsa_account.derive_receive_address(0)?;
    let addr2 = ecdsa_account.derive_change_address(0)?;
    println!("First receive address: {}", addr1);
    println!("First change address: {}", addr2);
    println!();

    // 2. BLS Account (for masternode/Platform operations)
    #[cfg(feature = "bls")]
    {
        println!("=== BLS Account (Masternode/Platform) ===");
        let bls_seed = [42u8; 32]; // Example BLS seed
        let bls_account = BLSAccount::from_seed(
            None,
            AccountType::ProviderVotingKeys,
            bls_seed,
            Network::Testnet,
        )?;

        println!("Network: {:?}", bls_account.network());
        println!("Is watch-only: {}", bls_account.is_watch_only());
        println!("Account type: {:?}", bls_account.account_type());
        println!("BLS public key length: {} bytes", bls_account.get_public_key_bytes().len());

        // BLS accounts can derive public keys (for non-hardened paths)
        // For public key derivation from watch-only account
        let pubkey_result = bls_account.derive_public_key_at(AddressPoolType::External, 0, None);
        match pubkey_result {
            Ok(_pubkey) => println!("Successfully derived BLS public key at index 0"),
            Err(e) => println!("Could not derive public key without private key: {}", e),
        }

        // For hardened derivation, we need the private key
        let bls_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &bls_seed)?;
        let pubkey_with_priv =
            bls_account.derive_public_key_at(AddressPoolType::External, 0, Some(bls_priv))?;
        println!(
            "Derived BLS public key with private key: {} bytes",
            pubkey_with_priv.to_bytes().len()
        );
        println!();
    }
    #[cfg(not(feature = "bls"))]
    {
        println!("=== BLS Account (Masternode/Platform) ===");
        println!("BLS feature not enabled, skipping BLS account demo");
        println!();
    }

    // 3. EdDSA Account (for Platform identities)
    #[cfg(feature = "eddsa")]
    {
        println!("=== EdDSA Account (Platform Identity) ===");
        let ed25519_seed = [99u8; 32]; // Example Ed25519 seed
        let eddsa_account = EdDSAAccount::from_seed(
            None,
            AccountType::IdentityRegistration,
            ed25519_seed,
            Network::Testnet,
        )?;

        println!("Network: {:?}", eddsa_account.network());
        println!("Is watch-only: {}", eddsa_account.is_watch_only());
        println!("Account type: {:?}", eddsa_account.account_type());
        println!("Ed25519 public key length: {} bytes", eddsa_account.get_public_key_bytes().len());

        // EdDSA accounts require private key for derivation (only hardened paths supported)
        let ed25519_priv = ExtendedEd25519PrivKey::new_master(Network::Testnet, &ed25519_seed)?;

        // Try to derive without private key (should fail)
        match eddsa_account.derive_public_key_at(AddressPoolType::External, 0, None) {
            Err(e) => println!("Expected error without private key: {}", e),
            Ok(_) => println!("Unexpected success!"),
        }

        // Derive with private key (should succeed)
        let pubkey_with_priv = eddsa_account.derive_public_key_at(
            AddressPoolType::External,
            0,
            Some(ed25519_priv.clone()),
        )?;
        println!(
            "Derived Ed25519 public key with private key: {} bytes",
            pubkey_with_priv.to_bytes().len()
        );

        // Can also derive addresses using hash160 of the public key
        let address =
            eddsa_account.derive_address_at(AddressPoolType::External, 0, Some(ed25519_priv))?;
        println!("Derived P2PKH address from Ed25519 key: {}", address);
        println!();
    }
    #[cfg(not(feature = "eddsa"))]
    {
        println!("=== EdDSA Account (Platform Identity) ===");
        println!("EdDSA feature not enabled, skipping EdDSA account demo");
        println!();
    }

    // 4. Demonstrate watch-only versions
    println!("=== Watch-Only Accounts ===");

    let watch_only_ecdsa = ecdsa_account.to_watch_only();
    println!("ECDSA watch-only: {}", watch_only_ecdsa.is_watch_only());

    #[cfg(feature = "bls")]
    {
        let bls_seed = [42u8; 32];
        let bls_account = BLSAccount::from_seed(
            None,
            AccountType::ProviderVotingKeys,
            bls_seed,
            Network::Testnet,
        )?;
        let watch_only_bls = bls_account.to_watch_only();
        println!("BLS watch-only: {}", watch_only_bls.is_watch_only());
    }

    #[cfg(feature = "eddsa")]
    {
        let ed25519_seed = [99u8; 32];
        let eddsa_account = EdDSAAccount::from_seed(
            None,
            AccountType::IdentityRegistration,
            ed25519_seed,
            Network::Testnet,
        )?;
        let watch_only_eddsa = eddsa_account.to_watch_only();
        println!("EdDSA watch-only: {}", watch_only_eddsa.is_watch_only());
    }

    println!("\n✅ All account types demonstrated successfully!");

    Ok(())
}
