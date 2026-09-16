//! In-flight accounting against a real socket.
//!
//! `PeerHandle::send` charges a peer one in-flight unit per pipeline request
//! before the write, and only the broker's registry can release it. A request
//! settled while its message still sits on the queue loses that registry entry,
//! so the send that follows is charged to nobody — and the unit is held for the
//! life of the connection. Two of those reach the per-peer floor, the router runs
//! out of capacity for that peer, and it goes silent with a full queue behind it.
//!
//! Real time, because the handshake is real I/O.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dash_spv::client::ClientConfig;
use dash_spv::network::{PeerNetworkManager, RequestKey};
use dashcore::consensus::encode::{deserialize_partial, serialize};
use dashcore::network::address::Address;
use dashcore::network::constants::{ServiceFlags, PROTOCOL_VERSION};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::network::message_filter::{CFilter, GetCFilters};
use dashcore::network::message_network::VersionMessage;
use dashcore::{BlockHash, Network};
use dashcore_hashes::Hash;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;

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
        user_agent: "/accounting-test:0.1/".to_owned(),
        start_height: 2,
        relay: false,
        mn_auth_challenge: [0; 32],
        masternode_connection: false,
    }
}

fn get_cfilters(start: u32) -> NetworkMessage {
    NetworkMessage::GetCFilters(GetCFilters {
        filter_type: 0,
        start_height: start,
        stop_hash: BlockHash::all_zeros(),
    })
}

async fn next_request(rx: &mut UnboundedReceiver<u32>) -> u32 {
    timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the router never routed the request to the peer")
        .expect("peer task died")
}

/// Settle a request that is still waiting on the queue, then let it go out: the
/// send is charged to the peer with no registry entry left to release it.
async fn strand_one_unit(manager: &PeerNetworkManager, rx: &mut UnboundedReceiver<u32>, base: u32) {
    // Two to fill the peer's cap, a third to sit on the queue behind them.
    for i in 0..3 {
        manager.send(get_cfilters(base + i)).await;
    }
    next_request(rx).await;
    next_request(rx).await;

    manager.request_answered(RequestKey::CFilters(base + 2)).await;
    manager.request_answered(RequestKey::CFilters(base)).await;
    manager.request_answered(RequestKey::CFilters(base + 1)).await;

    // The freed capacity lets the third one out, now untracked.
    next_request(rx).await;
}

/// A peer whose sends were charged but never registered must not lose that
/// capacity permanently. Strand two units — the per-peer floor — and the peer
/// must still be reachable.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_the_registry_never_saw_does_not_cost_the_peer_capacity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let (requests_tx, mut requests_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();

    // Answers every `getcfilters` with one `cfilter`, so bytes keep arriving and
    // the timeout monitor has no reason to drop the connection. What frees an
    // in-flight unit is the broker being told the request was answered, which the
    // test drives itself.
    let server = tokio::spawn(async move {
        let (stream, client_addr) = listener.accept().await.unwrap();
        let (mut reader, mut stream) = stream.into_split();
        send_message(&mut stream, NetworkMessage::Version(version_message(client_addr))).await;
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
                    NetworkMessage::Ping(nonce) => {
                        send_message(&mut stream, NetworkMessage::Pong(nonce)).await;
                    }
                    NetworkMessage::GetCFilters(m) => {
                        send_message(
                            &mut stream,
                            NetworkMessage::CFilter(CFilter {
                                filter_type: 0,
                                block_hash: BlockHash::all_zeros(),
                                filter: vec![0u8; 4],
                            }),
                        )
                        .await;
                        let _ = requests_tx.send(m.start_height);
                    }
                    _ => {}
                }
            }
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
    manager.start();

    timeout(Duration::from_secs(10), async {
        while manager.connected_count().await == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("peer handshake did not complete");

    strand_one_unit(&manager, &mut requests_rx, 1000).await;
    strand_one_unit(&manager, &mut requests_rx, 2000).await;

    manager.send(get_cfilters(9000)).await;
    assert_eq!(
        next_request(&mut requests_rx).await,
        9000,
        "the peer still has capacity for a request"
    );

    manager.stop();
    server.abort();
}
