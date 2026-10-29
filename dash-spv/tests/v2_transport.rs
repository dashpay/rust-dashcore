//! Loopback tests for the BIP324 V2 transport.
//!
//! A `PeerNetworkManager` with a given [`TransportPreference`] connects to a mock
//! peer on a local socket. The mock speaks V2 through the same transport module, or
//! V1 through dashcore's codec, so the real handshake and cipher run on both ends
//! without a Dash Core node.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bip324::{OutboundCipher, PacketType};
use dash_spv::client::ClientConfig;
use dash_spv::network::transport::{
    encrypt_message, V2Decoder, V2HandshakeManager, V2HandshakeResult, V2Session,
};
use dash_spv::network::{MessageType, NetworkManager, PeerNetworkManager, TransportPreference};
use dashcore::consensus::encode::serialize;
use dashcore::network::address::Address;
use dashcore::network::constants::{ServiceFlags, PROTOCOL_VERSION};
use dashcore::network::message::{
    CommandString, NetworkMessage, RawNetworkMessage, RawNetworkMessageCodec,
};
use dashcore::network::message_network::VersionMessage;
use dashcore::network::message_sml::GetMnListDiff;
use dashcore::{BlockHash, Network};
use dashcore_hashes::Hash;
use futures::StreamExt;
use tempfile::TempDir;
use test_case::test_case;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use tokio_util::codec::FramedRead;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// `NETWORK` and `BLOOM` are required or the peer is dropped.
fn peer_services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::BLOOM
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
        user_agent: "/v2-transport-test:0.1/".to_owned(),
        start_height: 0,
        relay: false,
        mn_auth_challenge: [0; 32],
        masternode_connection: false,
    }
}

fn v1_frame(network: Network, payload: NetworkMessage) -> Vec<u8> {
    serialize(&RawNetworkMessage {
        magic: network.magic(),
        payload,
    })
}

enum Reader {
    V1(FramedRead<OwnedReadHalf, RawNetworkMessageCodec>),
    V2(FramedRead<OwnedReadHalf, V2Decoder>),
}

enum Framing {
    V1(Network),
    V2(OutboundCipher),
}

/// The mock node's side of one accepted connection.
struct MockPeer {
    client: SocketAddr,
    reader: Reader,
    writer: OwnedWriteHalf,
    framing: Framing,
}

impl MockPeer {
    fn v1(stream: TcpStream, client: SocketAddr, network: Network) -> Self {
        let (read_half, writer) = stream.into_split();
        MockPeer {
            client,
            reader: Reader::V1(FramedRead::new(read_half, RawNetworkMessageCodec)),
            writer,
            framing: Framing::V1(network),
        }
    }

    async fn accept_v1(listener: &TcpListener, network: Network) -> Self {
        let (stream, client) = listener.accept().await.unwrap();
        Self::v1(stream, client, network)
    }

    /// Accept one connection and complete the BIP324 handshake as the responder.
    async fn accept_v2(listener: &TcpListener, network: Network) -> Self {
        let (stream, client) = listener.accept().await.unwrap();
        let handshake =
            V2HandshakeManager::new_responder(network, client).perform_handshake(stream);
        let V2HandshakeResult::Success(session) = handshake.await.expect("responder handshake")
        else {
            panic!("responder unexpectedly saw V1 magic");
        };
        let V2Session {
            stream,
            cipher,
            pending,
            ..
        } = *session;
        let (inbound, outbound) = cipher.into_split();
        let (read_half, writer) = stream.into_split();
        let mut reader = FramedRead::new(read_half, V2Decoder::new(network.magic(), inbound));
        reader.read_buffer_mut().extend_from_slice(&pending);
        MockPeer {
            client,
            reader: Reader::V2(reader),
            writer,
            framing: Framing::V2(outbound),
        }
    }

    fn cipher(&mut self) -> &mut OutboundCipher {
        match &mut self.framing {
            Framing::V2(cipher) => cipher,
            Framing::V1(_) => panic!("not a V2 connection"),
        }
    }

    fn frame(&mut self, message: NetworkMessage) -> Vec<u8> {
        match &mut self.framing {
            Framing::V1(network) => v1_frame(*network, message),
            Framing::V2(cipher) => encrypt_message(cipher, &message),
        }
    }

    async fn write(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.unwrap();
    }

    async fn send(&mut self, message: NetworkMessage) {
        let bytes = self.frame(message);
        self.write(&bytes).await;
    }

    /// Next message from the client, answering pings; `None` once it closes.
    async fn recv(&mut self) -> Option<NetworkMessage> {
        let message = match &mut self.reader {
            Reader::V1(reader) => reader.next().await?.ok()?,
            Reader::V2(reader) => reader.next().await?.ok()?.0,
        }
        .payload;
        if let NetworkMessage::Ping(nonce) = message {
            self.send(NetworkMessage::Pong(nonce)).await;
        }
        Some(message)
    }

    async fn expect(&mut self, wanted: impl Fn(&NetworkMessage) -> bool) -> NetworkMessage {
        loop {
            let message = self.recv().await.expect("client closed the connection");
            if wanted(&message) {
                return message;
            }
        }
    }

    /// Run the version handshake up to the client's latency ping, which marks it done.
    async fn handshake(&mut self) {
        self.send(NetworkMessage::Version(version_message(self.client))).await;
        self.send(NetworkMessage::Verack).await;
        self.expect(|m| matches!(m, NetworkMessage::Ping(_))).await;
    }

    /// Wait for the client to close the connection.
    async fn until_closed(&mut self) {
        while self.recv().await.is_some() {}
    }
}

async fn manager(
    peer: SocketAddr,
    network: Network,
    preference: TransportPreference,
    storage: &TempDir,
) -> PeerNetworkManager {
    let mut config = ClientConfig::new(network);
    config.storage_path = storage.path().to_path_buf();
    config.max_peers = 1;
    config.peers = vec![peer];
    config.restrict_to_configured_peers = true;
    config.enable_filters = false;
    config.enable_masternodes = false;
    config.transport_preference = preference;
    PeerNetworkManager::new(&config).await
}

async fn wait_for_peers(manager: &PeerNetworkManager, count: u32) {
    timeout(TEST_TIMEOUT, async {
        while manager.connected_count().await != count {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("connected peer count never reached {}", count));
}

#[test_case(Network::Mainnet; "mainnet")]
#[test_case(Network::Testnet; "testnet")]
#[test_case(Network::Regtest; "regtest")]
#[tokio::test]
async fn v2_only_loopback_round_trips_short_extended_and_unknown_messages(network: Network) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mn_list_request = GetMnListDiff {
        base_block_hash: BlockHash::all_zeros(),
        block_hash: BlockHash::from_byte_array([7u8; 32]),
    };
    let unknown = NetworkMessage::Unknown {
        command: CommandString::try_from_static("custom").unwrap(),
        payload: vec![0xaa, 0xbb, 0xcc, 0xdd],
    };
    let (close_tx, close_rx) = oneshot::channel::<()>();

    let expected = (mn_list_request, unknown.clone());
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::accept_v2(&listener, network).await;
        // `version` goes out in the extended format, `verack` and `ping` with short IDs.
        peer.handshake().await;

        // A Dash-specific short ID (128+ range).
        let mn = peer.expect(|m| matches!(m, NetworkMessage::GetMnListD(_))).await;
        assert_eq!(mn, NetworkMessage::GetMnListD(expected.0));
        // An unknown command must arrive with its real name, not "unknown".
        let custom = peer.expect(|m| matches!(m, NetworkMessage::Unknown { .. })).await;
        assert_eq!(custom, expected.1);

        // A decoy and an unassigned short ID are skipped without disconnecting.
        let decoy = peer.cipher().encrypt_to_vec(&[0u8; 8], PacketType::Decoy, None);
        peer.write(&decoy).await;
        let unassigned = peer.cipher().encrypt_to_vec(&[29u8, 1, 2], PacketType::Genuine, None);
        peer.write(&unassigned).await;
        // One byte at a time, so the client decodes a packet across many reads.
        let inv = peer.frame(NetworkMessage::Inv(vec![]));
        for byte in inv {
            peer.write(&[byte]).await;
            tokio::task::yield_now().await;
        }

        let _ = close_rx.await;
    });

    let storage = TempDir::new().unwrap();
    let manager = manager(addr, network, TransportPreference::V2Only, &storage).await;
    let mut inv = manager.subscribe(&[MessageType::Inv]).await;
    manager.start().await;
    wait_for_peers(&manager, 1).await;

    assert!(manager.send_to(addr, NetworkMessage::GetMnListD(mn_list_request)).await);
    assert!(manager.send_to(addr, unknown).await);

    let (_, message) = timeout(TEST_TIMEOUT, inv.recv())
        .await
        .expect("inv never arrived")
        .expect("subscription closed");
    assert_eq!(**message, NetworkMessage::Inv(vec![]));
    assert_eq!(manager.connected_count().await, 1);

    manager.stop().await;
    close_tx.send(()).unwrap();
    server.await.unwrap();
}

#[test_case(Network::Mainnet; "mainnet")]
#[test_case(Network::Testnet; "testnet")]
#[test_case(Network::Regtest; "regtest")]
#[tokio::test]
async fn v2_tampered_packet_disconnects(network: Network) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (sent_tx, sent_rx) = oneshot::channel();
    let (go_tx, go_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let mut peer = MockPeer::accept_v2(&listener, network).await;
        peer.handshake().await;
        // Wait until the manager has registered the peer: a reader that dies before
        // then leaves it counted as connected (true for V1 peers too).
        go_rx.await.unwrap();
        // A packet whose authentication tag doesn't verify.
        let mut packet = peer.frame(NetworkMessage::Ping(1));
        *packet.last_mut().unwrap() ^= 0x01;
        peer.write(&packet).await;
        sent_tx.send(()).unwrap();
        // The inbound cipher state is unusable now, so the client must hang up.
        peer.until_closed().await;
    });

    let storage = TempDir::new().unwrap();
    let manager = manager(addr, network, TransportPreference::V2Only, &storage).await;
    manager.start().await;
    wait_for_peers(&manager, 1).await;
    go_tx.send(()).unwrap();
    sent_rx.await.unwrap();
    wait_for_peers(&manager, 0).await;

    timeout(TEST_TIMEOUT, server).await.expect("client kept the connection open").unwrap();
    manager.stop().await;
}

#[test_case(Network::Mainnet; "mainnet")]
#[test_case(Network::Testnet; "testnet")]
#[test_case(Network::Regtest; "regtest")]
#[tokio::test]
async fn v2_preferred_falls_back_when_peer_replies_with_v1_magic(network: Network) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (close_tx, close_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        // First connection: a V1-only node answers our ElligatorSwift key with a V1
        // message. The client should notice the network magic and give up on V2.
        let (mut first, _) = listener.accept().await.unwrap();
        first.write_all(&v1_frame(network, NetworkMessage::Verack)).await.unwrap();
        // Hold it open until the client has reconnected, so its peek sees the magic.
        let mut peer = MockPeer::accept_v1(&listener, network).await;
        drop(first);
        peer.handshake().await;
        let _ = close_rx.await;
    });

    let storage = TempDir::new().unwrap();
    let manager = manager(addr, network, TransportPreference::V2Preferred, &storage).await;
    manager.start().await;
    wait_for_peers(&manager, 1).await;

    manager.stop().await;
    close_tx.send(()).unwrap();
    server.await.unwrap();
}

#[test_case(Network::Mainnet; "mainnet")]
#[test_case(Network::Testnet; "testnet")]
#[test_case(Network::Regtest; "regtest")]
#[tokio::test]
async fn v2_preferred_falls_back_when_peer_hangs_up_on_v2_key(network: Network) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (close_tx, close_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        // First connection: mimic Dash Core's V1-only behaviour of reading the header,
        // seeing no magic, and closing the socket without replying.
        let (mut first, _) = listener.accept().await.unwrap();
        let mut key = [0u8; 64];
        first.read_exact(&mut key).await.unwrap();
        assert_ne!(key[..4], network.magic().to_le_bytes(), "client sent V1 magic on V2 probe");
        drop(first);

        let mut peer = MockPeer::accept_v1(&listener, network).await;
        peer.handshake().await;
        let _ = close_rx.await;
    });

    let storage = TempDir::new().unwrap();
    let manager = manager(addr, network, TransportPreference::V2Preferred, &storage).await;
    manager.start().await;
    wait_for_peers(&manager, 1).await;

    manager.stop().await;
    close_tx.send(()).unwrap();
    server.await.unwrap();
}

#[test_case(Network::Mainnet; "mainnet")]
#[test_case(Network::Testnet; "testnet")]
#[test_case(Network::Regtest; "regtest")]
#[tokio::test]
async fn v2_only_fails_against_v1_only_peer(network: Network) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, client) = listener.accept().await.unwrap();
        let mut peer = MockPeer::v1(stream, client, network);
        peer.send(NetworkMessage::Verack).await;
        // The client must hang up on seeing the magic rather than speak V1.
        peer.until_closed().await;
    });

    let storage = TempDir::new().unwrap();
    let manager = manager(addr, network, TransportPreference::V2Only, &storage).await;
    manager.start().await;
    timeout(TEST_TIMEOUT, server).await.expect("client kept the connection open").unwrap();
    assert_eq!(manager.connected_count().await, 0, "V2Only must not fall back to V1");
    manager.stop().await;
}

#[test_case(Network::Mainnet; "mainnet")]
#[test_case(Network::Testnet; "testnet")]
#[test_case(Network::Regtest; "regtest")]
#[tokio::test]
async fn v1_only_never_sends_v2_key(network: Network) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (close_tx, close_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        // The very first bytes on the wire must be a V1 frame, not a 64-byte key.
        let (stream, client) = listener.accept().await.unwrap();
        let mut magic = [0u8; 4];
        while stream.peek(&mut magic).await.unwrap() < magic.len() {
            tokio::task::yield_now().await;
        }
        assert_eq!(magic, network.magic().to_le_bytes());
        let mut peer = MockPeer::v1(stream, client, network);
        peer.handshake().await;
        let _ = close_rx.await;
    });

    let storage = TempDir::new().unwrap();
    let manager = manager(addr, network, TransportPreference::V1Only, &storage).await;
    manager.start().await;
    wait_for_peers(&manager, 1).await;

    manager.stop().await;
    close_tx.send(()).unwrap();
    server.await.unwrap();
}

/// Relay one connection to `upstream`, holding the server's bytes after its 64-byte
/// key until `release` fires and then delivering them in one write, so the client's
/// handshake reads them together with the server's version packet.
async fn coalescing_proxy(
    listener: TcpListener,
    upstream: SocketAddr,
    release: oneshot::Receiver<()>,
) {
    let (client, _) = listener.accept().await.unwrap();
    let server = TcpStream::connect(upstream).await.unwrap();
    let (mut client_rx, mut client_tx) = client.into_split();
    let (mut server_rx, mut server_tx) = server.into_split();
    tokio::spawn(async move { tokio::io::copy(&mut client_rx, &mut server_tx).await });

    let mut key = [0u8; 64];
    server_rx.read_exact(&mut key).await.unwrap();
    client_tx.write_all(&key).await.unwrap();

    let mut held = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut release = release;
    let mut released = false;
    loop {
        // After the release, drain what is still in flight before delivering.
        let read = if released {
            match timeout(Duration::from_millis(100), server_rx.read(&mut chunk)).await {
                Ok(read) => read,
                Err(_) => break,
            }
        } else {
            tokio::select! {
                _ = &mut release => {
                    released = true;
                    continue;
                }
                read = server_rx.read(&mut chunk) => read,
            }
        };
        match read.unwrap() {
            0 => break,
            n => held.extend_from_slice(&chunk[..n]),
        }
    }
    client_tx.write_all(&held).await.unwrap();
    let _ = tokio::io::copy(&mut server_rx, &mut client_tx).await;
}

#[tokio::test]
async fn v2_messages_read_during_the_handshake_are_not_stalled() {
    let network = Network::Regtest;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let (close_tx, close_rx) = oneshot::channel::<()>();

    let relay = tokio::spawn(coalescing_proxy(proxy, upstream_addr, release_rx));
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::accept_v2(&upstream, network).await;
        // Send our side of the version handshake before the client has received the
        // end of the BIP324 handshake. Once these bytes are in, nothing more comes
        // until the client answers, so they must be decoded from the overshoot.
        let client = peer.client;
        peer.send(NetworkMessage::Version(version_message(client))).await;
        peer.send(NetworkMessage::Verack).await;
        release_tx.send(()).unwrap();
        peer.expect(|m| matches!(m, NetworkMessage::Ping(_))).await;
        let _ = close_rx.await;
    });

    let storage = TempDir::new().unwrap();
    let manager = manager(addr, network, TransportPreference::V2Only, &storage).await;
    manager.start().await;
    wait_for_peers(&manager, 1).await;

    manager.stop().await;
    close_tx.send(()).unwrap();
    server.await.unwrap();
    relay.abort();
}
