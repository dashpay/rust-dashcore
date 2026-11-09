//! Basic usage example for key-wallet

use core::str::FromStr;
use dashcore::{Address, Network as DashNetwork};
use key_wallet::bip32::{ChildIndex, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use key_wallet::prelude::*;
use key_wallet::Network;

fn main() -> core::result::Result<(), Box<dyn std::error::Error>> {
    println!("Key Wallet Example\n");

    // 1. Create a mnemonic
    println!("1. Creating mnemonic...");
    let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")?;
    println!("   Mnemonic: {}", mnemonic.phrase().as_str());
    println!("   Word count: {}", mnemonic.word_count());

    // 2. Generate seed
    println!("\n2. Generating seed...");
    let seed = mnemonic.to_seed("");
    println!("   Seed: {}", seed[..32].to_lower_hex_string()); // Show first 32 bytes

    // 3. Create master key
    println!("\n3. Creating master key...");
    let master = ExtendedPrivKey::new_master(Network::Mainnet, &seed[..])?;
    let master_pub = ExtendedPubKey::from_priv(&master);
    println!("   Master public key: {}", master_pub);

    // 4. Derive BIP44 account
    println!("\n4. Deriving BIP44 account 0...");
    let path = DerivationPath::from(vec![
        ChildNumber::Hardened(ChildIndex::new_const(44)), // Purpose
        ChildNumber::Hardened(ChildIndex::new_const(5)),  // Dash coin type
        ChildNumber::Hardened(ChildIndex::ZERO),          // Account 0
    ]);
    let account = master.derive_priv(&path)?;
    println!("   Account xprv: {}", account);

    // 5. Derive addresses
    println!("\n5. Deriving addresses...");

    // Derive first 5 receive addresses
    println!("   Receive addresses:");
    for i in 0..5 {
        let receive_path = DerivationPath::from(vec![
            ChildNumber::Normal(ChildIndex::ZERO), // External chain
            ChildNumber::Normal(ChildIndex::new(i)?),
        ]);
        let addr_key = account.derive_priv(&receive_path)?;
        let addr_xpub = ExtendedPubKey::from_priv(&addr_key);
        let addr =
            Address::p2pkh(&dashcore::PublicKey::new(addr_xpub.public_key), DashNetwork::Mainnet);
        println!("     {}: {}", i, addr);
    }

    // Derive first 2 change addresses
    println!("\n   Change addresses:");
    for i in 0..2 {
        let change_path = DerivationPath::from(vec![
            ChildNumber::Normal(ChildIndex::new_const(1)), // Internal chain
            ChildNumber::Normal(ChildIndex::new(i)?),
        ]);
        let addr_key = account.derive_priv(&change_path)?;
        let addr_xpub = ExtendedPubKey::from_priv(&addr_key);
        let addr =
            Address::p2pkh(&dashcore::PublicKey::new(addr_xpub.public_key), DashNetwork::Mainnet);
        println!("     {}: {}", i, addr);
    }

    // 6. Demonstrate CoinJoin derivation
    println!("\n6. CoinJoin account...");
    let coinjoin_path = DerivationPath::from(vec![
        ChildNumber::Hardened(ChildIndex::new_const(9)), // CoinJoin purpose
        ChildNumber::Hardened(ChildIndex::new_const(5)), // Dash coin type
        ChildNumber::Hardened(ChildIndex::ZERO),         // Account 0
    ]);
    let coinjoin_account = master.derive_priv(&coinjoin_path)?;
    println!("   CoinJoin account depth: {}", coinjoin_account.depth);

    // 7. Demonstrate identity key derivation
    println!("\n7. Identity authentication key...");
    let identity_path = DerivationPath::from(vec![
        ChildNumber::Hardened(ChildIndex::new_const(13)), // Identity purpose
        ChildNumber::Hardened(ChildIndex::new_const(5)),  // Dash coin type
        ChildNumber::Hardened(ChildIndex::new_const(3)),  // Authentication feature
        ChildNumber::Hardened(ChildIndex::ZERO),          // Identity index
        ChildNumber::Hardened(ChildIndex::ZERO),          // Key index
    ]);
    let identity_key = master.derive_priv(&identity_path)?;
    println!("   Identity key depth: {}", identity_key.depth);

    // 8. Address parsing example
    println!("\n8. Address parsing...");
    let test_address = "XyPvhVmhWKDgvMJLwfFfMwhxpxGgd3TBxq";
    match Address::<dashcore::address::NetworkUnchecked>::from_str(test_address) {
        Ok(parsed) => {
            // NetworkUnchecked addresses need to be converted to check network
            if let Ok(checked) = parsed.clone().require_network(DashNetwork::Mainnet) {
                println!("   Parsed address: {}", checked);
                println!("   Type: {:?}", checked.address_type());
                println!("   Network: Dash");
            } else if let Ok(checked) = parsed.require_network(DashNetwork::Testnet) {
                println!("   Parsed address: {}", checked);
                println!("   Type: {:?}", checked.address_type());
                println!("   Network: Testnet");
            }
        }
        Err(e) => println!("   Failed to parse: {}", e),
    }

    Ok(())
}
