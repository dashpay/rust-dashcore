use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dash_spv::client::ClientConfig;
use dash_spv::network::{MessageType, NetworkManager, PeerNetworkManager};
use dashcore::consensus::encode::serialize;
use dashcore::network::address::Address;
use dashcore::network::constants::{ServiceFlags, PROTOCOL_VERSION};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::network::message_headers2::{CompressionState, Headers2Message};
use dashcore::network::message_network::VersionMessage;
use dashcore::{Header, Network};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

async fn send_message(stream: &mut TcpStream, message: NetworkMessage) {
    let raw = RawNetworkMessage {
        magic: Network::Regtest.magic(),
        payload: message,
    };
    stream.write_all(&serialize(&raw)).await.unwrap();
}

fn version_message(peer: SocketAddr) -> VersionMessage {
    let local = "127.0.0.1:0".parse().unwrap();
    VersionMessage {
        version: PROTOCOL_VERSION,
        services: ServiceFlags::NODE_HEADERS_COMPRESSED,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        receiver: Address::new(&peer, ServiceFlags::NETWORK),
        sender: Address::new(&local, ServiceFlags::NODE_HEADERS_COMPRESSED),
        nonce: 1,
        user_agent: "/header-order-test:0.1/".to_owned(),
        start_height: 2,
        relay: false,
        mn_auth_challenge: [0; 32],
        masternode_connection: false,
    }
}

#[test]
fn peer_reader_preserves_compressed_then_regular_header_order() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();

    runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let (send_headers_tx, send_headers_rx) = oneshot::channel();
        let (headers_sent_tx, headers_sent_rx) = oneshot::channel();
        let (close_tx, close_rx) = oneshot::channel();

        let first = Header::dummy(1);
        let second = Header::dummy(2);
        let mut compression = CompressionState::default();
        let compressed = compression.compress(&first);

        let server = tokio::spawn(async move {
            let (mut stream, client_addr) = listener.accept().await.unwrap();
            send_message(&mut stream, NetworkMessage::Version(version_message(client_addr))).await;
            send_message(&mut stream, NetworkMessage::Verack).await;

            send_headers_rx.await.unwrap();
            let headers2 = NetworkMessage::Headers2(Headers2Message::new(vec![compressed]));
            let regular = NetworkMessage::Headers(vec![second]);
            let mut messages = serialize(&RawNetworkMessage {
                magic: Network::Regtest.magic(),
                payload: headers2,
            });
            messages.extend(serialize(&RawNetworkMessage {
                magic: Network::Regtest.magic(),
                payload: regular,
            }));
            messages.extend(serialize(&RawNetworkMessage {
                magic: Network::Regtest.magic(),
                payload: NetworkMessage::Inv(vec![]),
            }));
            stream.write_all(&messages).await.unwrap();
            headers_sent_tx.send(()).unwrap();

            let _ = close_rx.await;
        });

        let storage = TempDir::new().unwrap();
        let mut config = ClientConfig::new(Network::Regtest);
        config.storage_path = storage.path().to_path_buf();
        config.max_peers = 1;
        config.peers = vec![peer_addr];
        config.restrict_to_configured_peers = true;
        config.enable_filters = false;
        config.enable_masternodes = false;

        let mut manager = PeerNetworkManager::new(&config).await.unwrap();
        let mut headers = manager.message_receiver(&[MessageType::Headers]).await;
        let mut marker = manager.message_receiver(&[MessageType::Inv]).await;
        manager.start().await.unwrap();
        timeout(Duration::from_secs(5), async {
            while manager.peer_count() == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("peer handshake did not complete");

        // Occupy the only blocking worker before the peer sends both messages. Headers2
        // decompression must queue while the reader handles the following regular message.
        let (blocking_started_tx, blocking_started_rx) = oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            blocking_started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        blocking_started_rx.await.unwrap();

        send_headers_tx.send(()).unwrap();
        headers_sent_rx.await.unwrap();
        timeout(Duration::from_secs(2), marker.recv())
            .await
            .expect("peer reader did not reach the marker after both header messages")
            .unwrap();
        assert!(
            headers.try_recv().is_err(),
            "regular headers overtook the blocked headers2 message"
        );

        release_tx.send(()).unwrap();
        blocker.await.unwrap();

        let first_message = timeout(Duration::from_secs(2), headers.recv()).await.unwrap().unwrap();
        assert_eq!(first_message.inner(), &NetworkMessage::Headers(vec![first]));

        let second_message =
            timeout(Duration::from_secs(2), headers.recv()).await.unwrap().unwrap();
        assert_eq!(second_message.inner(), &NetworkMessage::Headers(vec![second]));

        manager.shutdown().await;
        close_tx.send(()).unwrap();
        server.await.unwrap();
    });
}
