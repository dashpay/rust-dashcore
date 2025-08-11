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

#[tokio::test]
#[ignore] // This test requires a live Dash testnet node
async fn test_headers2_protocol_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    let _ = tracing_subscriber::fmt::try_init();

    // Test with multiple peers
    let test_peers = vec![
        "54.68.235.201:19999",
        "52.40.219.41:19999",
        "34.214.48.68:19999",
    ];

    for peer_addr in test_peers {
        println!("\n\n========================================");
        println!("Testing headers2 protocol with peer: {}", peer_addr);
        println!("========================================\n");

        let addr = peer_addr.parse().unwrap();
        let network = Network::Testnet;

        // Create connection with longer timeout for debugging
        let mut connection = TcpConnection::connect(addr, 30, Duration::from_millis(100), network).await?;

        // Perform handshake
        let mut handshake = HandshakeManager::new(network, MempoolStrategy::Selective);
        handshake.perform_handshake(&mut connection).await?;

        println!("✅ Handshake complete!");
        let peer_info = connection.peer_info();
        println!("Peer version: {:?}", peer_info.version);
        println!("Peer services: {:?}", peer_info.services);
        println!("Peer user agent: {:?}", peer_info.user_agent);
        println!("Peer supports headers2: {}", handshake.peer_supports_headers2());

        if !handshake.peer_supports_headers2() {
            println!("⚠️  Peer doesn't support headers2, skipping...");
            connection.disconnect().await?;
            continue;
        }

        // Wait a bit to ensure all handshake messages are processed
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Test 1: Try GetHeaders2 with genesis hash in locator
        println!("\n📤 Test 1: Sending GetHeaders2 with genesis hash in locator...");
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

        let msg = NetworkMessage::GetHeaders2(getheaders_msg);
        
        match connection.send_message(msg).await {
            Ok(_) => println!("✅ GetHeaders2 sent successfully"),
            Err(e) => {
                println!("❌ Failed to send GetHeaders2: {}", e);
                connection.disconnect().await?;
                continue;
            }
        }

        // Wait for response
        println!("⏳ Waiting for response...");
        let start_time = tokio::time::Instant::now();
        let timeout = Duration::from_secs(10);
        let mut received_headers2 = false;
        let mut disconnected = false;

        while start_time.elapsed() < timeout && !received_headers2 && !disconnected {
            match connection.receive_message().await {
                Ok(Some(msg)) => {
                    println!("📨 Received message: {:?}", msg.cmd());
                    match msg {
                        NetworkMessage::Headers2(headers2) => {
                            println!("🎉 Received Headers2 with {} compressed headers!", headers2.headers.len());
                            received_headers2 = true;
                        }
                        NetworkMessage::Headers(headers) => {
                            println!("📋 Received regular Headers with {} headers", headers.len());
                        }
                        NetworkMessage::Ping(nonce) => {
                            println!("🏓 Responding to ping...");
                            connection.send_message(NetworkMessage::Pong(nonce)).await?;
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    // No message available, continue waiting
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => {
                    println!("❌ Connection error: {}", e);
                    disconnected = true;
                    break;
                }
            }
        }

        if !received_headers2 && !disconnected {
            println!("⏰ Timeout - no Headers2 response received");
        }

        if disconnected {
            println!("💔 Peer disconnected after GetHeaders2 with genesis");
            
            // Try to reconnect for second test
            println!("\n🔄 Reconnecting for second test...");
            connection = TcpConnection::connect(addr, 30, Duration::from_millis(100), network).await?;
            handshake = HandshakeManager::new(network, MempoolStrategy::Selective);
            handshake.perform_handshake(&mut connection).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Test 2: Try GetHeaders2 with empty locator
        println!("\n📤 Test 2: Sending GetHeaders2 with empty locator...");
        let getheaders_msg_empty = GetHeadersMessage::new(
            vec![],
            BlockHash::all_zeros()
        );

        let msg_empty = NetworkMessage::GetHeaders2(getheaders_msg_empty);
        
        match connection.send_message(msg_empty).await {
            Ok(_) => println!("✅ GetHeaders2 (empty locator) sent successfully"),
            Err(e) => {
                println!("❌ Failed to send GetHeaders2: {}", e);
                connection.disconnect().await?;
                continue;
            }
        }

        // Wait for response
        println!("⏳ Waiting for response to empty locator...");
        let start_time = tokio::time::Instant::now();
        received_headers2 = false;
        disconnected = false;

        while start_time.elapsed() < timeout && !received_headers2 && !disconnected {
            match connection.receive_message().await {
                Ok(Some(msg)) => {
                    println!("📨 Received message: {:?}", msg.cmd());
                    match msg {
                        NetworkMessage::Headers2(headers2) => {
                            println!("🎉 Received Headers2 with {} compressed headers!", headers2.headers.len());
                            received_headers2 = true;
                        }
                        NetworkMessage::Headers(headers) => {
                            println!("📋 Received regular Headers with {} headers", headers.len());
                        }
                        NetworkMessage::Ping(nonce) => {
                            println!("🏓 Responding to ping...");
                            connection.send_message(NetworkMessage::Pong(nonce)).await?;
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => {
                    println!("❌ Connection error: {}", e);
                    disconnected = true;
                    break;
                }
            }
        }

        if !received_headers2 && !disconnected {
            println!("⏰ Timeout - no Headers2 response received for empty locator");
        }

        // Test 3: Try regular GetHeaders for comparison
        println!("\n📤 Test 3: Sending regular GetHeaders for comparison...");
        let getheaders_regular = GetHeadersMessage::new(
            vec![genesis_hash],
            BlockHash::all_zeros()
        );

        let msg_regular = NetworkMessage::GetHeaders(getheaders_regular);
        
        match connection.send_message(msg_regular).await {
            Ok(_) => println!("✅ GetHeaders sent successfully"),
            Err(e) => {
                println!("❌ Failed to send GetHeaders: {}", e);
            }
        }

        // Wait for response
        println!("⏳ Waiting for regular headers response...");
        let start_time = tokio::time::Instant::now();
        let mut received_headers = false;

        while start_time.elapsed() < Duration::from_secs(5) && !received_headers {
            match connection.receive_message().await {
                Ok(Some(msg)) => {
                    println!("📨 Received message: {:?}", msg.cmd());
                    match msg {
                        NetworkMessage::Headers(headers) => {
                            println!("✅ Received regular Headers with {} headers", headers.len());
                            received_headers = true;
                        }
                        NetworkMessage::Ping(nonce) => {
                            connection.send_message(NetworkMessage::Pong(nonce)).await?;
                        }
                        _ => {}
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

        connection.disconnect().await?;
        println!("\n✅ Test complete for peer {}", peer_addr);
    }

    Ok(())
}