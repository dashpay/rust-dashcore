use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::network::message_blockdata::GetHeadersMessage;
use dashcore::consensus::encode::serialize;
use dashcore::BlockHash;
use dashcore_hashes::Hash;

#[test]
fn test_getheaders2_message_encoding() {
    // Create a GetHeaders2 message with genesis hash
    let genesis_hash = BlockHash::from_byte_array([
        0x2c, 0xbc, 0xf8, 0x3b, 0x62, 0x91, 0x3d, 0x56, 
        0xf6, 0x05, 0xc0, 0xe5, 0x81, 0xa4, 0x88, 0x72, 
        0x83, 0x94, 0x28, 0xc9, 0x2e, 0x5e, 0xb7, 0x6c, 
        0xd7, 0xad, 0x94, 0xbc, 0xaf, 0x0b, 0x00, 0x00
    ]);
    
    let getheaders_msg = GetHeadersMessage::new(
        vec![genesis_hash],
        BlockHash::all_zeros()
    );
    
    // Create GetHeaders2 network message
    let msg = NetworkMessage::GetHeaders2(getheaders_msg.clone());
    
    // Create raw network message to test full encoding
    let raw_msg = RawNetworkMessage {
        magic: dashcore::Network::Testnet.magic(),
        payload: msg.clone(),
    };
    
    // Serialize raw message
    let raw_serialized = serialize(&raw_msg);
    println!("Raw GetHeaders2 message length: {}", raw_serialized.len());
    println!("Raw GetHeaders2 first 50 bytes: {:02x?}", &raw_serialized[..50.min(raw_serialized.len())]);
    
    // Extract command string from the message
    if raw_serialized.len() >= 24 {
        let command_bytes = &raw_serialized[4..16];
        let command_str = std::str::from_utf8(command_bytes).unwrap_or("unknown");
        println!("Command string: {:?}", command_str);
    }
}

#[test]
fn test_getheaders2_vs_getheaders_encoding() {
    let genesis_hash = BlockHash::from_byte_array([
        0x2c, 0xbc, 0xf8, 0x3b, 0x62, 0x91, 0x3d, 0x56, 
        0xf6, 0x05, 0xc0, 0xe5, 0x81, 0xa4, 0x88, 0x72, 
        0x83, 0x94, 0x28, 0xc9, 0x2e, 0x5e, 0xb7, 0x6c, 
        0xd7, 0xad, 0x94, 0xbc, 0xaf, 0x0b, 0x00, 0x00
    ]);
    
    let msg_data = GetHeadersMessage::new(
        vec![genesis_hash],
        BlockHash::all_zeros()
    );
    
    // Create both message types in raw format
    let getheaders = RawNetworkMessage {
        magic: dashcore::Network::Testnet.magic(),
        payload: NetworkMessage::GetHeaders(msg_data.clone()),
    };
    let getheaders2 = RawNetworkMessage {
        magic: dashcore::Network::Testnet.magic(),
        payload: NetworkMessage::GetHeaders2(msg_data),
    };
    
    // Serialize both
    let ser_getheaders = serialize(&getheaders);
    let ser_getheaders2 = serialize(&getheaders2);
    
    println!("\nGetHeaders vs GetHeaders2 comparison:");
    println!("GetHeaders length: {}", ser_getheaders.len());
    println!("GetHeaders2 length: {}", ser_getheaders2.len());
    
    // Compare command strings
    if ser_getheaders.len() >= 16 && ser_getheaders2.len() >= 16 {
        let cmd1 = std::str::from_utf8(&ser_getheaders[4..16]).unwrap_or("unknown");
        let cmd2 = std::str::from_utf8(&ser_getheaders2[4..16]).unwrap_or("unknown");
        println!("GetHeaders command: {:?}", cmd1);
        println!("GetHeaders2 command: {:?}", cmd2);
    }
}

#[test]
fn test_empty_locator_getheaders2() {
    // Test with empty locator as we tried
    let msg_data = GetHeadersMessage::new(
        vec![],
        BlockHash::all_zeros()
    );
    
    let raw_msg = RawNetworkMessage {
        magic: dashcore::Network::Testnet.magic(),
        payload: NetworkMessage::GetHeaders2(msg_data),
    };
    
    let serialized = serialize(&raw_msg);
    
    println!("\nEmpty locator GetHeaders2:");
    println!("Message length: {}", serialized.len());
    println!("First 40 bytes: {:02x?}", &serialized[..40.min(serialized.len())]);
}