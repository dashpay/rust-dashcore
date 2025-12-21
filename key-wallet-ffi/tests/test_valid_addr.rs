#[test]
fn test_valid_testnet_address() {
    use std::str::FromStr;

    // Generate a valid testnet address
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::{Mnemonic, Network, Wallet};

    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic =
        Mnemonic::from_phrase(mnemonic_str, key_wallet::mnemonic::Language::English).unwrap();

    let wallet =
        Wallet::from_mnemonic(mnemonic, Network::Testnet, WalletAccountCreationOptions::Default)
            .unwrap();

    if let Some(account) = wallet.get_bip44_account(0) {
        use key_wallet::ChildNumber;
        use secp256k1::Secp256k1;
        let secp = Secp256k1::new();

        let child_external = ChildNumber::from_normal_idx(0).unwrap();
        let child_index = ChildNumber::from_normal_idx(0).unwrap();

        let derived_key =
            account.account_xpub.derive_pub(&secp, &[child_external, child_index]).unwrap();
        let public_key = derived_key.public_key;
        let dash_pubkey = dashcore::PublicKey::new(public_key);
        let address = key_wallet::Address::p2pkh(&dash_pubkey, dashcore::Network::Testnet);

        println!("Generated testnet address: {}", address);

        // Now try to validate it
        let addr_str = address.to_string();
        match key_wallet::Address::from_str(&addr_str) {
            Ok(parsed) => {
                println!("Successfully parsed generated address");
                match parsed.require_network(dashcore::Network::Testnet) {
                    Ok(_) => println!("✓ Address is valid for testnet"),
                    Err(e) => println!("✗ Address not valid for testnet: {}", e),
                }
            }
            Err(e) => {
                println!("Failed to parse generated address: {}", e);
            }
        }
    }
}
