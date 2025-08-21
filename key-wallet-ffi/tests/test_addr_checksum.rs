#[test]
fn test_address_checksum() {
    // The test uses this address - let's see if it's valid
    let test_addr = "yTw7Kn5CrQvpBQy5dNMT8A3PQnU3kEj7jJ";

    // Try decoding with base58
    use dashcore::base58;

    match base58::decode_check(test_addr) {
        Ok(data) => {
            println!("Base58 decode successful, {} bytes", data.len());
            if data.len() > 0 {
                println!("Version byte: 0x{:02x}", data[0]);
            }
        }
        Err(e) => {
            println!("Base58 decode failed: {:?}", e);
        }
    }

    // Compare with a known good address
    let good_addr = "yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt";
    match base58::decode_check(good_addr) {
        Ok(data) => {
            println!("Good address decoded, {} bytes, version: 0x{:02x}", data.len(), data[0]);
        }
        Err(e) => {
            println!("Good address decode failed: {:?}", e);
        }
    }
}
