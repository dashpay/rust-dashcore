//! Basic usage example for key-wallet

use key_wallet::address::AddressGenerator;
use key_wallet::derivation::{AccountDerivation, HDWallet};
use key_wallet::mnemonic::Language;
use key_wallet::prelude::*;
use key_wallet::Network;

fn main() -> core::result::Result<(), Box<dyn std::error::Error>> {
    println!("Key Wallet Example\n");

    // 1. Create a mnemonic
    println!("1. Creating mnemonic...");
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English
    )?;
    println!("   Mnemonic: {}", mnemonic.phrase());
    println!("   Word count: {}", mnemonic.word_count());

    // 2. Generate seed
    println!("\n2. Generating seed...");
    let seed = mnemonic.to_seed("");
    println!("   Seed: {}", hex::encode(&seed[..32])); // Show first 32 bytes

    // 3. Create HD wallet
    println!("\n3. Creating HD wallet...");
    let wallet = HDWallet::from_seed(&seed, Network::Dash)?;
    let master_pub = wallet.master_pub_key();
    println!("   Master public key: {}", master_pub);

    // 4. Derive BIP44 account
    println!("\n4. Deriving BIP44 account 0...");
    let account = wallet.bip44_account(0)?;
    println!("   Account xprv: {}", account);

    // 5. Create account derivation
    println!("\n5. Deriving addresses...");
    let account_derivation = AccountDerivation::new(account);

    // Derive first 5 receive addresses
    println!("   Receive addresses:");
    for i in 0..5 {
        let addr_xpub = account_derivation.receive_address(i)?;
        let addr = key_wallet::address::Address::p2pkh(&addr_xpub.public_key, Network::Dash);
        println!("     {}: {}", i, addr);
    }

    // Derive first 2 change addresses
    println!("\n   Change addresses:");
    for i in 0..2 {
        let addr_xpub = account_derivation.change_address(i)?;
        let addr = key_wallet::address::Address::p2pkh(&addr_xpub.public_key, Network::Dash);
        println!("     {}: {}", i, addr);
    }

    // 6. Demonstrate CoinJoin derivation
    println!("\n6. CoinJoin account...");
    let coinjoin_account = wallet.coinjoin_account(0)?;
    println!("   CoinJoin account depth: {}", coinjoin_account.depth);

    // 7. Demonstrate identity key derivation
    println!("\n7. Identity authentication key...");
    let identity_key = wallet.identity_authentication_key(0, 0)?;
    println!("   Identity key depth: {}", identity_key.depth);

    // 8. Address parsing example
    println!("\n8. Address parsing...");
    let test_address = "XyPvhVmhWKDgvMJLwfFfMwhxpxGgd3TBxq";
    match test_address.parse::<key_wallet::address::Address>() {
        Ok(parsed) => {
            println!("   Parsed address: {}", parsed);
            println!("   Type: {:?}", parsed.address_type);
            println!("   Network: {:?}", parsed.network);
        }
        Err(e) => println!("   Failed to parse: {}", e),
    }

    Ok(())
}

#[allow(dead_code)]
fn demonstrate_address_generation() -> core::result::Result<(), Box<dyn std::error::Error>> {
    // This demonstrates bulk address generation
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash)?;
    let path = key_wallet::DerivationPath::from(vec![
        key_wallet::ChildNumber::from_hardened_idx(44).unwrap(),
        key_wallet::ChildNumber::from_hardened_idx(5).unwrap(),
        key_wallet::ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_xpub = wallet.derive_pub(&path)?;

    let generator = AddressGenerator::new(Network::Dash);
    let addresses = generator.generate_range(&account_xpub, true, 0, 100)?;

    println!("Generated {} addresses", addresses.len());

    Ok(())
}
