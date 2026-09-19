use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dash_spv::client::ClientConfig;
use dash_spv::network::{MessageType, PeerNetworkManager};
use dashcore::consensus::encode::{deserialize_partial, serialize};
use dashcore::network::address::Address;
use dashcore::network::constants::{ServiceFlags, PROTOCOL_VERSION};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::network::message_headers2::{CompressionState, Headers2Message};
use dashcore::network::message_network::VersionMessage;
use dashcore::{Header, Network};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

/// What the fake peer advertises. The network manager drops any peer missing what
/// the config implies it needs — `NETWORK` always, plus `BLOOM` for the mempool
/// tracking this config leaves on. `NODE_HEADERS_COMPRESSED` is what makes it
/// negotiate `sendheaders2`.
fn peer_services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::BLOOM | ServiceFlags::NODE_HEADERS_COMPRESSED
}

async fn send_message<W: AsyncWriteExt + Unpin>(stream: &mut W, message: NetworkMessage) {
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
        services: peer_services(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        receiver: Address::new(&peer, ServiceFlags::NETWORK),
        sender: Address::new(&local, peer_services()),
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
            let (stream, client_addr) = listener.accept().await.unwrap();
            let (mut reader, mut stream) = stream.into_split();
            send_message(&mut stream, NetworkMessage::Version(version_message(client_addr))).await;
            send_message(&mut stream, NetworkMessage::Verack).await;

            // Answer the handshake ping. The supervisor measures round-trip lag
            // there and treats an unanswered ping (lag 0) as unmeasurable, stashing
            // the peer as a backup instead of connecting it — so without this the
            // client never reaches one connected peer.
            let mut pending = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut send_headers_rx = send_headers_rx;
            loop {
                tokio::select! {
                    read = reader.read(&mut chunk) => {
                        match read {
                            Ok(0) | Err(_) => break,
                            Ok(n) => pending.extend_from_slice(&chunk[..n]),
                        }
                        while let Ok((raw, used)) =
                            deserialize_partial::<RawNetworkMessage>(&pending)
                        {
                            pending.drain(..used);
                            if let NetworkMessage::Ping(nonce) = raw.payload {
                                send_message(&mut stream, NetworkMessage::Pong(nonce)).await;
                            }
                        }
                    }
                    _ = &mut send_headers_rx => break,
                }
            }

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

        let manager = PeerNetworkManager::new(&config).await;
        let mut headers = manager.subscribe(&[MessageType::Headers]).await;
        let mut marker = manager.subscribe(&[MessageType::Inv]).await;
        manager.start();
        timeout(Duration::from_secs(5), async {
            while manager.connected_count().await == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("peer handshake did not complete");

        // Occupy the only blocking worker before the peer sends both messages, so
        // `headers2` decompression has to queue for it while the reader carries on
        // to the plain `headers` behind it.
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

        let (_, first_message) =
            timeout(Duration::from_secs(2), headers.recv()).await.unwrap().unwrap();
        assert_eq!(**first_message, NetworkMessage::Headers(vec![first]));
        assert_eq!(
            first_message.header_hashes(),
            Some([first.block_hash()].as_slice()),
            "decompression computed this hash; it must reach the sync layer"
        );

        let (_, second_message) =
            timeout(Duration::from_secs(2), headers.recv()).await.unwrap().unwrap();
        assert_eq!(**second_message, NetworkMessage::Headers(vec![second]));
        assert_eq!(
            second_message.header_hashes(),
            None,
            "uncompressed headers carry no free hashes"
        );

        manager.stop();
        close_tx.send(()).unwrap();
        server.await.unwrap();
    });
}
