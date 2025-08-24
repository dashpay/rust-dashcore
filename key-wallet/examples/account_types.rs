//! Example demonstrating different account types (ECDSA, BLS, EdDSA)

use key_wallet::account::{
    Account, AccountTrait, AccountType, BLSAccount, EdDSAAccount, StandardAccountType,
};
use key_wallet::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::Network;
use secp256k1::Secp256k1;

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
    println!("=== BLS Account (Masternode/Platform) ===");
    let bls_seed = [42u8; 32]; // Example BLS seed
    let bls_account =
        BLSAccount::from_seed(None, AccountType::ProviderVotingKeys, bls_seed, Network::Testnet)?;

    println!("Network: {:?}", bls_account.network());
    println!("Is watch-only: {}", bls_account.is_watch_only());
    println!("Account type: {:?}", bls_account.account_type());
    println!("BLS public key length: {} bytes", bls_account.get_public_key_bytes().len());

    // BLS accounts don't support standard address derivation
    match bls_account.derive_address_at(false, 0) {
        Err(e) => println!("Expected error for address derivation: {}", e),
        Ok(_) => println!("Unexpected success!"),
    }
    println!();

    // 3. EdDSA Account (for Platform identities)
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

    // EdDSA accounts are for Platform identities, not blockchain addresses
    match eddsa_account.derive_address_at(false, 0) {
        Err(e) => println!("Expected error for address derivation: {}", e),
        Ok(_) => println!("Unexpected success!"),
    }

    // But they can derive identity keys
    let identity_key = eddsa_account.derive_identity_key(0)?;
    println!("Derived identity key at index 0");
    println!();

    // 4. Demonstrate watch-only versions
    println!("=== Watch-Only Accounts ===");

    let watch_only_ecdsa = ecdsa_account.to_watch_only();
    println!("ECDSA watch-only: {}", watch_only_ecdsa.is_watch_only());

    let watch_only_bls = bls_account.to_watch_only();
    println!("BLS watch-only: {}", watch_only_bls.is_watch_only());

    let watch_only_eddsa = eddsa_account.to_watch_only();
    println!("EdDSA watch-only: {}", watch_only_eddsa.is_watch_only());

    println!("\n✅ All account types demonstrated successfully!");

    Ok(())
}
