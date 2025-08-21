#[test]
fn test_debug_address() {
    use std::str::FromStr;

    let addr_str = "yTw7Kn5CrQvpBQy5dNMT8A3PQnU3kEj7jJ";

    println!("Parsing address: {}", addr_str);

    match key_wallet::Address::from_str(addr_str) {
        Ok(addr) => {
            println!("Address parsed successfully!");

            // Try different networks
            for network in &[
                dashcore::Network::Dash,
                dashcore::Network::Testnet,
                dashcore::Network::Regtest,
                dashcore::Network::Devnet,
            ] {
                match addr.clone().require_network(*network) {
                    Ok(checked) => {
                        println!("✓ Valid for {:?}: {}", network, checked);
                    }
                    Err(e) => {
                        println!("✗ Not valid for {:?}: {}", network, e);
                    }
                }
            }
        }
        Err(e) => {
            println!("Failed to parse address: {}", e);
        }
    }
}
