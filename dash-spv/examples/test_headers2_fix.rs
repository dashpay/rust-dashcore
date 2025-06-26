use dashcore::Network;
use dash_spv::{
    network::{HandshakeManager, TcpConnection},
    client::config::MempoolStrategy,
};
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::GetHeadersMessage;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use std::time::Duration;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    let _ = tracing_subscriber::fmt::try_init();

    println!("\n🧪 Testing headers2 fix...\n");

    let addr = "192.168.1.163:19999".parse().unwrap();
    let network = Network::Testnet;

    // Create connection
    let mut connection = TcpConnection::connect(addr, 30, Duration::from_millis(100), network).await?;

    // Perform handshake
    let mut handshake = HandshakeManager::new(network, MempoolStrategy::Selective);
    handshake.perform_handshake(&mut connection).await?;

    println!("✅ Handshake complete!");
    
    // Check if we can request headers2 immediately
    println!("Can request headers2: {}", connection.can_request_headers2());
    
    // Wait a bit to see if peer sends SendHeaders2
    println!("\n⏳ Waiting for any additional handshake messages...");
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Process any pending messages
    for _ in 0..10 {
        match connection.receive_message().await {
            Ok(Some(msg)) => {
                println!("📨 Received: {:?}", msg.cmd());
                if matches!(msg, NetworkMessage::SendHeaders2) {
                    connection.set_peer_sent_sendheaders2(true);
                    println!("✅ Peer sent SendHeaders2!");
                }
            }
            Ok(None) => break,
            Err(e) => {
                println!("❌ Error: {}", e);
                break;
            }
        }
    }
    
    // Now check again
    println!("\nAfter processing messages:");
    println!("Can request headers2: {}", connection.can_request_headers2());
    println!("Peer sent sendheaders2: {}", connection.peer_sent_sendheaders2());
    
    // Test sending GetHeaders2
    println!("\n📤 Sending GetHeaders2 with genesis hash...");
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

    connection.send_message(NetworkMessage::GetHeaders2(getheaders_msg)).await?;
    
    // Wait for response
    println!("⏳ Waiting for response...");
    let start_time = tokio::time::Instant::now();
    let timeout = Duration::from_secs(5);

    while start_time.elapsed() < timeout {
        match connection.receive_message().await {
            Ok(Some(msg)) => {
                println!("📨 Received: {:?}", msg.cmd());
                if matches!(msg, NetworkMessage::Headers2(_)) {
                    println!("🎉 SUCCESS: Received Headers2 response!");
                    connection.disconnect().await?;
                    return Ok(());
                }
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                println!("❌ Connection error: {}", e);
                break;
            }
        }
    }
    
    println!("⏰ Timeout - no Headers2 response received");
    connection.disconnect().await?;
    
    Ok(())
}