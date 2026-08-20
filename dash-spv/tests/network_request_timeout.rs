//! The request timeout against a real socket.
//!
//! The unit tests in `network::manager` drive the monitor on a paused clock with
//! no peers, which pins the threshold and the re-queue but stops at the point
//! where a connection has to be dropped. This runs the whole stack — handshake,
//! router, reader, monitor, supervisor — against a peer that accepts a request
//! and then says nothing, which is the case the machinery exists for.
//!
//! Real time, because the handshake is real I/O and a paused clock would race it.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dash_spv::client::ClientConfig;
use dash_spv::network::{NetworkEvent, PeerNetworkManager};
use dashcore::consensus::encode::{deserialize_partial, serialize};
use dashcore::network::address::Address;
use dashcore::network::constants::{ServiceFlags, PROTOCOL_VERSION};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::network::message_filter::GetCFilters;
use dashcore::network::message_network::VersionMessage;
use dashcore::{BlockHash, Network};
use dashcore_hashes::Hash;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// What the peer advertises. The manager drops any peer missing what the config
/// implies it needs: `NETWORK` always, plus `BLOOM` for the mempool tracking this
/// config leaves on.
fn peer_services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::BLOOM
}

async fn send_message<W: AsyncWriteExt + Unpin>(stream: &mut W, message: NetworkMessage) {
    let raw = RawNetworkMessage {
        magic: Network::Regtest.magic(),
        payload: message,
    };
    stream.write_all(&serialize(&raw)).await.unwrap();
}

fn version_message(peer: SocketAddr) -> VersionMessage {
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    VersionMessage {
        version: PROTOCOL_VERSION,
        services: peer_services(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        receiver: Address::new(&peer, ServiceFlags::NETWORK),
        sender: Address::new(&local, peer_services()),
        nonce: 1,
        user_agent: "/silent-peer-test:0.1/".to_owned(),
        start_height: 2,
        relay: false,
        mn_auth_challenge: [0; 32],
        masternode_connection: false,
    }
}

fn get_cfilters() -> NetworkMessage {
    NetworkMessage::GetCFilters(GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash: BlockHash::all_zeros(),
    })
}

/// A peer that completes the handshake and then never answers anything must be
/// dropped once it is sitting on a request, and the request must come back for
/// somebody else to serve.
///
/// This is the whole point of the timeout monitor: such a peer looks perfectly
/// healthy at the socket level — connected, no error, no close — so nothing else
/// in the stack would ever notice, and the in-flight slots it holds would be lost
/// for the life of the connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_stops_answering_is_dropped_and_its_request_re_queued() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let (requests_tx, mut requests_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();

    // The peer: accepts repeatedly, and every connection completes the handshake,
    // answers the lag ping, and then goes silent forever. It keeps the socket open
    // and keeps reading, so nothing fails at the TCP level — such a connection is
    // indistinguishable from a healthy one except that no bytes ever come back.
    // Each `getcfilters` it receives is reported with the connection it arrived on.
    let server = tokio::spawn(async move {
        let mut connection = 0usize;
        loop {
            let Ok((stream, client_addr)) = listener.accept().await else {
                return;
            };
            let index = connection;
            connection += 1;
            let requests_tx = requests_tx.clone();
            tokio::spawn(async move {
                let (mut reader, mut stream) = stream.into_split();
                send_message(&mut stream, NetworkMessage::Version(version_message(client_addr)))
                    .await;
                send_message(&mut stream, NetworkMessage::Verack).await;

                let mut pending = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match reader.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    }
                    while let Ok((raw, used)) = deserialize_partial::<RawNetworkMessage>(&pending) {
                        pending.drain(..used);
                        match raw.payload {
                            // The supervisor measures lag here and benches a peer
                            // whose ping went unanswered, so this one reply is
                            // required to get connected at all.
                            NetworkMessage::Ping(nonce) => {
                                send_message(&mut stream, NetworkMessage::Pong(nonce)).await;
                            }
                            NetworkMessage::GetCFilters(_) => {
                                let _ = requests_tx.send(index);
                            }
                            _ => {}
                        }
                    }
                }
            });
        }
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
    let mut events = manager.events();
    manager.start();

    timeout(Duration::from_secs(10), async {
        while manager.connected_count().await == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("peer handshake did not complete");

    manager.send(get_cfilters()).await;
    let first = timeout(Duration::from_secs(10), requests_rx.recv())
        .await
        .expect("the router never routed the request to the peer")
        .expect("peer task died");
    assert_eq!(first, 0, "the first connection should have received the request");

    // Nothing comes back from here on. The monitor is the only thing that can
    // notice, and what it has to do is twofold: drop the peer, and give the
    // request back so it is not stranded with it.
    let dropped = timeout(Duration::from_secs(25), async {
        loop {
            match events.recv().await {
                Ok(NetworkEvent::PeerDisconnected(addr)) if addr == peer_addr => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    })
    .await
    .expect("the silent peer was never dropped");
    assert!(dropped, "expected the silent peer to be disconnected");

    // The retry: the supervisor reconnects and the SAME request goes out again.
    // Without the re-queue the request would be lost with the connection, and the
    // pipeline that declared it would wait forever for a response nobody owes.
    let retried = timeout(Duration::from_secs(30), requests_rx.recv())
        .await
        .expect("the request was never retried after the peer was dropped")
        .expect("peer task died");
    assert!(retried > 0, "the retry must go out on a fresh connection, got {retried}");

    manager.stop();
    server.abort();
}
