//! Loopback tests for the BIP324 V2 transport.
//!
//! These exercise the real handshake and cipher code end to end over a local TCP
//! socket, without needing a Dash Core node: one side is a `Peer` connecting with a
//! given [`TransportPreference`], the other is either a V2 responder built from the
//! same transport module or a hand-rolled V1-only mock.

use std::net::SocketAddr;
use std::time::Duration;

use dash_spv::network::transport::{V2HandshakeManager, V2HandshakeResult, V2Transport};
use dash_spv::network::{Peer, Transport, TransportPreference};
use dashcore::consensus::encode::{deserialize, serialize};
use dashcore::network::message::{CommandString, NetworkMessage, RawNetworkMessage};
use dashcore::network::message_sml::GetMnListDiff;
use dashcore::{BlockHash, Network};
use dashcore_hashes::Hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const NETWORK: Network = Network::Regtest;
const CONNECT_TIMEOUT_SECS: u64 = 5;
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept one connection and complete a V2 handshake as the responder, returning
/// the encrypted transport for the server side.
async fn accept_v2(listener: &TcpListener) -> V2Transport {
    let (stream, client_addr) = listener.accept().await.unwrap();
    stream.set_nodelay(true).unwrap();
    let manager = V2HandshakeManager::new_responder(NETWORK, client_addr);
    match manager.perform_handshake(stream).await.expect("responder handshake failed") {
        V2HandshakeResult::Success(session) => V2Transport::new(*session, client_addr),
        V2HandshakeResult::FallbackToV1 => panic!("responder unexpectedly saw V1 magic"),
    }
}

/// Read one V1-framed message from a raw stream.
async fn read_v1_message(stream: &mut TcpStream) -> NetworkMessage {
    const HEADER_LEN: usize = 24;
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await.unwrap();
    let payload_len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    let mut frame = header.to_vec();
    frame.resize(HEADER_LEN + payload_len, 0);
    stream.read_exact(&mut frame[HEADER_LEN..]).await.unwrap();
    let raw: RawNetworkMessage = deserialize(&frame).unwrap();
    assert_eq!(raw.magic, NETWORK.magic());
    raw.payload
}

/// Write one V1-framed message to a raw stream.
async fn write_v1_message(stream: &mut TcpStream, message: NetworkMessage) {
    let raw = RawNetworkMessage {
        magic: NETWORK.magic(),
        payload: message,
    };
    stream.write_all(&serialize(&raw)).await.unwrap();
}

/// Serve a single V1 ping/pong exchange on an already-accepted stream.
async fn serve_v1_ping_pong(mut stream: TcpStream) {
    match read_v1_message(&mut stream).await {
        NetworkMessage::Ping(nonce) => {
            write_v1_message(&mut stream, NetworkMessage::Pong(nonce)).await
        }
        other => panic!("expected V1 ping, got {:?}", other.cmd()),
    }
}

/// Drive a connected peer through a ping/pong exchange and assert the pong matches.
async fn assert_ping_pong(peer: &mut Peer, nonce: u64) {
    peer.send_message(NetworkMessage::Ping(nonce)).await.unwrap();
    let reply = timeout(TEST_TIMEOUT, peer.receive_message())
        .await
        .expect("timed out waiting for pong")
        .unwrap()
        .expect("connection closed before pong");
    assert_eq!(reply.inner(), &NetworkMessage::Pong(nonce));
}

#[tokio::test]
async fn v2_only_loopback_round_trips_short_extended_and_unknown_messages() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let mut transport = accept_v2(&listener).await;
        assert_eq!(transport.protocol_version(), 2);

        // Short-ID message (BIP324 table).
        match transport.receive_message().await.unwrap().unwrap() {
            NetworkMessage::Ping(nonce) => {
                transport.send_message(NetworkMessage::Pong(nonce)).await.unwrap();
            }
            other => panic!("expected ping, got {:?}", other.cmd()),
        }

        // Dash-specific short ID (128+ range) and an extended-format command.
        let mn = transport.receive_message().await.unwrap().unwrap();
        assert!(matches!(mn, NetworkMessage::GetMnListD(_)), "got {:?}", mn.cmd());
        transport.send_message(NetworkMessage::SendHeaders).await.unwrap();

        // Unknown command must arrive with its real name, not "unknown".
        match transport.receive_message().await.unwrap().unwrap() {
            NetworkMessage::Unknown {
                command,
                payload,
            } => {
                assert_eq!(command.as_ref(), "custom");
                assert_eq!(payload, vec![0xaa, 0xbb, 0xcc, 0xdd]);
            }
            other => panic!("expected unknown message, got {:?}", other.cmd()),
        }
        transport.send_message(NetworkMessage::Verack).await.unwrap();

        assert!(transport.bytes_sent() > 0);
        assert!(transport.bytes_received() > 0);
        transport.shutdown().await.unwrap();
    });

    let mut peer = timeout(
        TEST_TIMEOUT,
        Peer::connect(addr, CONNECT_TIMEOUT_SECS, NETWORK, TransportPreference::V2Only),
    )
    .await
    .expect("connect timed out")
    .expect("V2Only connect failed");
    assert_eq!(peer.transport_version(), 2);
    assert!(peer.is_connected());

    assert_ping_pong(&mut peer, 0x0123_4567_89ab_cdef).await;

    peer.send_message(NetworkMessage::GetMnListD(GetMnListDiff {
        base_block_hash: BlockHash::all_zeros(),
        block_hash: BlockHash::from_byte_array([7u8; 32]),
    }))
    .await
    .unwrap();
    let reply = timeout(TEST_TIMEOUT, peer.receive_message()).await.unwrap().unwrap().unwrap();
    assert_eq!(reply.inner(), &NetworkMessage::SendHeaders);

    peer.send_message(NetworkMessage::Unknown {
        command: CommandString::try_from_static("custom").unwrap(),
        payload: vec![0xaa, 0xbb, 0xcc, 0xdd],
    })
    .await
    .unwrap();
    let reply = timeout(TEST_TIMEOUT, peer.receive_message()).await.unwrap().unwrap().unwrap();
    assert_eq!(reply.inner(), &NetworkMessage::Verack);

    let (sent, received) = peer.stats();
    assert!(sent > 0 && received > 0, "transport byte counters should be non-zero");

    // Server shut down the socket; the next read must surface as a disconnect.
    let eof = timeout(TEST_TIMEOUT, peer.receive_message()).await.unwrap();
    assert!(eof.is_err(), "expected disconnect after server shutdown, got {:?}", eof.ok());
    assert!(!peer.is_connected());

    server.await.unwrap();
}

#[tokio::test]
async fn v2_preferred_falls_back_when_peer_replies_with_v1_magic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        // First connection: a V1-only node answers our ElligatorSwift key with a V1
        // message. The client should notice the network magic and give up on V2.
        let (mut stream, _) = listener.accept().await.unwrap();
        write_v1_message(&mut stream, NetworkMessage::Verack).await;
        // Hold the stream open until the client has reconnected, so the peek sees data.
        let (second, _) = listener.accept().await.unwrap();
        drop(stream);
        serve_v1_ping_pong(second).await;
    });

    let mut peer = timeout(
        TEST_TIMEOUT,
        Peer::connect(addr, CONNECT_TIMEOUT_SECS, NETWORK, TransportPreference::V2Preferred),
    )
    .await
    .expect("connect timed out")
    .expect("V2Preferred connect failed");
    assert_eq!(peer.transport_version(), 1, "should have fallen back to V1");

    assert_ping_pong(&mut peer, 42).await;
    server.await.unwrap();
}

#[tokio::test]
async fn v2_preferred_falls_back_when_peer_hangs_up_on_v2_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        // First connection: mimic Dash Core's V1-only behaviour of reading the header,
        // seeing no magic, and closing the socket without replying.
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut key = [0u8; 64];
        stream.read_exact(&mut key).await.unwrap();
        assert_ne!(&key[..4], &NETWORK.magic().to_le_bytes(), "client sent V1 magic on V2 probe");
        drop(stream);

        let (second, _) = listener.accept().await.unwrap();
        serve_v1_ping_pong(second).await;
    });

    let mut peer = timeout(
        TEST_TIMEOUT,
        Peer::connect(addr, CONNECT_TIMEOUT_SECS, NETWORK, TransportPreference::V2Preferred),
    )
    .await
    .expect("connect timed out")
    .expect("V2Preferred connect failed");
    assert_eq!(peer.transport_version(), 1, "should have fallen back to V1");

    assert_ping_pong(&mut peer, 7).await;
    server.await.unwrap();
}

#[tokio::test]
async fn v2_only_fails_against_v1_only_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        write_v1_message(&mut stream, NetworkMessage::Verack).await;
        // Keep the socket open until the client has read the magic and bailed.
        let mut sink = [0u8; 64];
        let _ = stream.read(&mut sink).await;
    });

    let result = timeout(
        TEST_TIMEOUT,
        Peer::connect(addr, CONNECT_TIMEOUT_SECS, NETWORK, TransportPreference::V2Only),
    )
    .await
    .expect("connect timed out");
    assert!(
        matches!(result, Err(dash_spv::error::NetworkError::V2NotSupported)),
        "V2Only must not fall back to V1"
    );
    drop(result);
    server.abort();
}

#[tokio::test]
async fn v1_only_never_sends_v2_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        // The very first bytes on the wire must be a V1 frame, not a 64-byte key.
        serve_v1_ping_pong(stream).await;
    });

    let mut peer = timeout(
        TEST_TIMEOUT,
        Peer::connect(addr, CONNECT_TIMEOUT_SECS, NETWORK, TransportPreference::V1Only),
    )
    .await
    .expect("connect timed out")
    .expect("V1Only connect failed");
    assert_eq!(peer.transport_version(), 1);

    assert_ping_pong(&mut peer, 99).await;
    server.await.unwrap();
}
