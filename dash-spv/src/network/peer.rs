use dashcore::{
    consensus::encode,
    network::{
        address::Address,
        constants::{ServiceFlags, NODE_HEADERS_COMPRESSED},
        message::{NetworkMessage, RawNetworkMessage, RawNetworkMessageCodec},
        message_headers2::CompressionState,
        message_network::VersionMessage,
    },
    Network,
};
use futures::lock::Mutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::OwnedSemaphorePermit;
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use tokio_stream::StreamExt;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, FramedRead};
use tokio_util::sync::CancellationToken;

use crate::network::bans::Ban;
use crate::network::costs::Ledger;
use crate::network::manager::{InboundMessage, NetworkState, OrderedHeaderResults};
use crate::{error::NetworkResult, NetworkError};

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(0);

/// Identifies one connection, not one address: a late close event from an old
/// connection must not evict a newer live connection to the same address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PeerId {
    addr: SocketAddr,
    connection: u64,
}

impl PeerId {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[cfg(test)]
    pub fn for_test(addr: SocketAddr, connection: u64) -> Self {
        PeerId {
            addr,
            connection,
        }
    }

    /// Not a real connection: the sentinel `dispatch_local` injects under.
    pub fn synthetic(addr: SocketAddr) -> Self {
        PeerId {
            addr,
            connection: u64::MAX,
        }
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(120);
/// A new peer's in-flight byte cap until the controller has measured it.
pub const INITIAL_CAP_BYTES: u64 = 256 * 1024;

/// Counts bytes read, globally and per peer, to size the in-flight budgets from
/// measured throughput.
struct CountingReader<R> {
    inner: R,
    state: Arc<NetworkState>,
    peer_bytes: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &r {
            let n = (buf.filled().len() - before) as u64;
            self.state.bytes.fetch_add(n, Ordering::Relaxed);
            self.peer_bytes.fetch_add(n, Ordering::Relaxed);
        }
        r
    }
}

struct SizedCodec;

impl Decoder for SizedCodec {
    type Item = (RawNetworkMessage, u64);
    type Error = encode::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let before = src.len();
        let raw = RawNetworkMessageCodec.decode(src)?;
        Ok(raw.map(|raw| (raw, (before - src.len()) as u64)))
    }
}

type PeerReader = FramedRead<CountingReader<OwnedReadHalf>, SizedCodec>;

// Boxing every message would penalise the common small ones.
#[allow(clippy::large_enum_variant)]
pub enum PeerEvent {
    Message(PeerId, InboundMessage),
    Disconnected(PeerId),
}

/// Cloneable view of a peer, so the router can write without holding the peer-set lock.
#[derive(Clone)]
pub struct PeerHandle {
    id: PeerId,
    network: Network,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    ledger: Arc<Ledger>,
    /// Response bytes this peer can have in flight before they queue (its
    /// bandwidth-delay product), sized by the controller from its byte rate and
    /// service time.
    cap: Arc<AtomicU64>,
    /// Bytes/s this peer serves while it has work, 0 until measured.
    serving_rate: Arc<AtomicU64>,
    headers2: bool,
    /// Child of the global shutdown; cancelling it stops the reader and closes the socket.
    token: CancellationToken,
}

impl PeerHandle {
    pub fn addr(&self) -> SocketAddr {
        self.id.addr()
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    pub fn in_flight_bytes(&self) -> u64 {
        self.ledger.in_flight_bytes()
    }

    pub fn cap(&self) -> u64 {
        self.cap.load(Ordering::Relaxed)
    }

    pub async fn send(&self, msg: &NetworkMessage) -> NetworkResult<()> {
        // The sync layer always declares plain `getheaders` since it doesn't know
        // the peer; upgrade here. The reader decompresses `Headers2` back to `Headers`.
        let upgraded = match msg {
            NetworkMessage::GetHeaders(m) if self.headers2 => {
                Some(NetworkMessage::GetHeaders2(m.clone()))
            }
            _ => None,
        };
        let msg = upgraded.as_ref().unwrap_or(msg);

        // TODO: Take a reference to msg instead of cloning it
        let raw = RawNetworkMessage {
            magic: self.network.magic(),
            payload: msg.clone(),
        };
        let serialized = encode::serialize(&raw);

        self.ledger.charge(msg).await;

        let write = async {
            let mut writer = self.writer.lock().await;
            writer.write_all(&serialized).await
        };
        let outcome = match tokio::time::timeout(WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("Write failed: {}", e)),
            // The peer stopped reading; treat it as a failed write.
            Err(_) => Err(format!("Write stalled for {}s", WRITE_TIMEOUT.as_secs())),
        };
        if let Err(reason) = outcome {
            tracing::warn!("Disconnecting {} due to write error: {}", self.id, reason);
            self.token.cancel();
            return Err(NetworkError::ConnectionFailed(reason));
        }
        Ok(())
    }
}

pub struct ConnectedPeer {
    handle: PeerHandle,
    version: VersionMessage,
    lag_ms: AtomicU32,
    bytes: Arc<AtomicU64>,
}

pub struct DisconnectedPeer {
    network: Network,
    addr: SocketAddr,
    /// Handshake ping from the last connection, used to rank backups.
    lag_ms: Option<u32>,
}

impl ConnectedPeer {
    pub fn addr(&self) -> SocketAddr {
        self.handle.addr()
    }

    pub fn id(&self) -> PeerId {
        self.handle.id()
    }

    pub fn version(&self) -> &VersionMessage {
        &self.version
    }

    pub fn handle(&self) -> PeerHandle {
        self.handle.clone()
    }

    pub fn disconnect(self) -> DisconnectedPeer {
        DisconnectedPeer {
            network: self.handle.network,
            addr: self.handle.addr(),
            lag_ms: (self.lag_ms() > 0).then(|| self.lag_ms()),
        }
    }

    /// (completed requests, average ms, worst ms).
    pub fn latency_stats(&self) -> (u64, f64, f64) {
        self.handle.ledger.latency_stats()
    }

    pub fn take_min_latency(&self) -> Option<f64> {
        self.handle.ledger.take_min_latency()
    }

    /// Handshake round-trip latency in ms (0 if unmeasured).
    pub fn lag_ms(&self) -> u32 {
        self.lag_ms.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.handle.token.cancel();
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    pub fn in_flight_bytes(&self) -> u64 {
        self.handle.in_flight_bytes()
    }

    pub fn set_cap(&self, bytes: u64) {
        self.handle.cap.store(bytes, Ordering::Relaxed);
    }

    pub fn cap(&self) -> u64 {
        self.handle.cap()
    }

    pub fn serving_rate(&self) -> u64 {
        self.handle.serving_rate.load(Ordering::Relaxed)
    }

    pub fn set_serving_rate(&self, bytes_per_sec: u64) {
        self.handle.serving_rate.store(bytes_per_sec, Ordering::Relaxed);
    }
}

impl DisconnectedPeer {
    pub fn new(addr: SocketAddr, network: Network) -> Self {
        DisconnectedPeer {
            network,
            addr,
            lag_ms: None,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `None` (never probed) sorts as worst when ranking backups.
    pub fn lag_ms(&self) -> Option<u32> {
        self.lag_ms
    }

    pub async fn connect(
        self,
        state: Arc<NetworkState>,
        shutdown: CancellationToken,
    ) -> NetworkResult<ConnectedPeer> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.addr))
            .await
            .map_err(|_| {
                NetworkError::ConnectionFailed(format!(
                    "Connection to {} timed out after {}s",
                    self.addr,
                    CONNECT_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("Failed to connect to {}: {}", self.addr, e))
            })?;

        let peer_bytes = Arc::new(AtomicU64::new(0));
        let (read_half, mut writer) = stream.into_split();
        let mut reader = FramedRead::new(
            CountingReader {
                inner: read_half,
                state: state.clone(),
                peer_bytes: peer_bytes.clone(),
            },
            SizedCodec,
        );
        let magic = self.network.magic();

        handshake_send(
            &mut writer,
            magic,
            NetworkMessage::Version(build_version(self.addr, &state.user_agent)),
        )
        .await?;

        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        let mut peer_version: Option<VersionMessage> = None;
        let mut got_verack = false;

        while !(peer_version.is_some() && got_verack) {
            let raw = match tokio::time::timeout_at(deadline, reader.next()).await {
                Err(_) => return Err(NetworkError::Timeout),
                Ok(None) => return Err(NetworkError::PeerDisconnected),
                Ok(Some(Err(e))) => return Err(e.into()),
                Ok(Some(Ok((raw, _)))) => raw,
            };
            if raw.magic != magic {
                return Err(NetworkError::ProtocolError("wrong network magic".into()));
            }
            match raw.payload {
                NetworkMessage::Version(v) => {
                    // BIP155: sendaddrv2 must be sent BEFORE verack.
                    handshake_send(&mut writer, magic, NetworkMessage::SendAddrV2).await?;
                    handshake_send(&mut writer, magic, NetworkMessage::Verack).await?;
                    peer_version = Some(v);
                }
                NetworkMessage::Verack => got_verack = true,
                NetworkMessage::Ping(n) => {
                    handshake_send(&mut writer, magic, NetworkMessage::Pong(n)).await?
                }
                _ => {}
            }
        }

        let version = peer_version.ok_or(NetworkError::PeerDisconnected)?;

        // A peer lacking a service silently ignores those requests, stalling its
        // slots until timeout, so drop it now.
        let required_services = state.required_services;
        if !version.services.has(required_services) {
            tracing::warn!(
                target: "dash_spv::network",
                "dropping {}: lacks required services {:?} (advertises {:?})",
                self.addr, required_services, version.services
            );
            return Err(NetworkError::ConnectionFailed(format!(
                "peer {} lacks required services {:?}",
                self.addr, required_services
            )));
        }

        // Announce sendheaders only after the handshake is fully complete, compressed
        // (DIP-25, ~half the bytes) if the peer advertises it.
        let headers2 = version.services.has(NODE_HEADERS_COMPRESSED);
        let announce = if headers2 {
            NetworkMessage::SendHeaders2
        } else {
            NetworkMessage::SendHeaders
        };
        handshake_send(&mut writer, magic, announce).await?;

        // Pinging before the handshake completes makes some peers drop us.
        let mut lag_ms: u32 = 0;
        let ping_nonce: u64 = rand::random();
        let ping_sent = tokio::time::Instant::now();
        if handshake_send(&mut writer, magic, NetworkMessage::Ping(ping_nonce)).await.is_ok() {
            let deadline = ping_sent + HANDSHAKE_TIMEOUT;
            while let Ok(Some(Ok((raw, _)))) =
                tokio::time::timeout_at(deadline, reader.next()).await
            {
                if raw.magic != magic {
                    continue;
                }
                match raw.payload {
                    NetworkMessage::Pong(n) if n == ping_nonce => {
                        lag_ms = ping_sent.elapsed().as_millis().clamp(1, u32::MAX as u128) as u32;
                        break;
                    }
                    NetworkMessage::Ping(n) => {
                        let _ = handshake_send(&mut writer, magic, NetworkMessage::Pong(n)).await;
                    }
                    _ => {}
                }
            }
        }

        let id = PeerId {
            addr: self.addr,
            connection: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
        };
        let writer = Arc::new(Mutex::new(writer));
        let ledger = Arc::new(Ledger::new(state.costs.clone()));
        // The controller grows it from the peer's measured serving rate.
        let cap = Arc::new(AtomicU64::new(INITIAL_CAP_BYTES));
        let token = shutdown.child_token();
        spawn_reader(id, magic, reader, writer.clone(), state, token.clone(), ledger.clone());

        tracing::debug!(
            target: "dash_spv::network",
            "peer connected: {} | lag={}ms height={}",
            self.addr,
            lag_ms,
            version.start_height,
        );

        Ok(ConnectedPeer {
            handle: PeerHandle {
                id,
                network: self.network,
                writer,
                ledger,
                cap,
                serving_rate: Arc::new(AtomicU64::new(0)),
                headers2,
                token,
            },
            version,
            lag_ms: AtomicU32::new(lag_ms),
            bytes: peer_bytes,
        })
    }
}

/// A header message in the reorder buffer. Holding the permit until dispatch is
/// what bounds the buffer. `None` for a failed batch, which must still complete
/// its sequence or everything behind it waits forever.
type HeaderSlot = (Option<InboundMessage>, OwnedSemaphorePermit);

/// Returns whether the receiver is still there.
fn dispatch_headers(
    inbound: &UnboundedSender<PeerEvent>,
    addr: PeerId,
    ready: Vec<HeaderSlot>,
) -> bool {
    ready
        .into_iter()
        .filter_map(|(msg, _permit)| msg)
        .all(|msg| inbound.send(PeerEvent::Message(addr, msg)).is_ok())
}

fn spawn_reader(
    addr: PeerId,
    magic: u32,
    mut reader: PeerReader,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    state: Arc<NetworkState>,
    shutdown: CancellationToken,
    ledger: Arc<Ledger>,
) {
    tokio::spawn(async move {
        let inbound = &state.inbound;
        // Header messages leave this reader in wire order even though the
        // compressed ones are decoded off-thread and finish out of order.
        let header_order = Arc::new(Mutex::new(OrderedHeaderResults::default()));
        let mut header_sequence = 0_u64;
        let mut ping =
            tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
        let mut last_ping = None;
        let mut last_seen = tokio::time::Instant::now();
        loop {
            let next = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ping.tick() => {
                    if last_ping.is_some_and(|sent| last_seen < sent) {
                        tracing::warn!("NETWORK: {} did not answer a ping in {}s", addr, PING_INTERVAL.as_secs());
                        break;
                    }
                    last_ping = Some(tokio::time::Instant::now());
                    let ping = RawNetworkMessage {
                        magic,
                        payload: NetworkMessage::Ping(rand::random()),
                    };
                    if writer.lock().await.write_all(&encode::serialize(&ping)).await.is_err() {
                        break;
                    }
                    continue;
                }
                next = reader.next() => next,
            };
            last_seen = tokio::time::Instant::now();
            match next {
                None => break,
                Some(Err(e)) => {
                    tracing::error!("NETWORK: reader {} stopped: {}", addr, e);
                    if !matches!(e, encode::Error::Io(_)) {
                        state.bans.ban(addr.addr(), Ban::Misbehaved).await;
                    }
                    break;
                }
                Some(Ok((raw, size))) => {
                    if raw.magic != magic {
                        continue;
                    }
                    ledger.settle(&raw.payload, size).await;
                    match raw.payload {
                        NetworkMessage::Ping(nonce) => {
                            let pong = RawNetworkMessage {
                                magic,
                                payload: NetworkMessage::Pong(nonce),
                            };
                            if writer
                                .lock()
                                .await
                                .write_all(&encode::serialize(&pong))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        NetworkMessage::Headers2(compressed) => {
                            // CPU-bound, so decoded on the blocking pool, several at
                            // once. DIP-25 resets compression state per `headers2`, so
                            // batches are independent. The permit, held until the batch
                            // is dispatched, bounds the reorder buffer.
                            let permit = tokio::select! {
                                permit = state.headers2_semaphore.clone().acquire_owned() => match permit {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                },
                                _ = shutdown.cancelled() => break,
                            };
                            let sequence = header_sequence;
                            header_sequence += 1;

                            let order = header_order.clone();
                            let state = state.clone();
                            let shutdown = shutdown.clone();
                            tokio::spawn(async move {
                                let decoded = tokio::task::spawn_blocking(move || {
                                    CompressionState::default()
                                        .process_headers_with_hashes(&compressed.headers)
                                })
                                .await;
                                if shutdown.is_cancelled() {
                                    return;
                                }
                                let decompressed = match decoded {
                                    Ok(Ok(decompressed)) => {
                                        tracing::debug!(
                                            target: "dash_spv::network",
                                            "decompressed {} headers from {}",
                                            decompressed.len(),
                                            addr
                                        );
                                        Some(InboundMessage::new_headers(decompressed))
                                    }
                                    Ok(Err(e)) => {
                                        tracing::warn!(
                                            target: "dash_spv::network",
                                            "headers2 from {} failed to decompress: {}",
                                            addr,
                                            e
                                        );
                                        state.bans.ban(addr.addr(), Ban::Misbehaved).await;
                                        shutdown.cancel();
                                        None
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            target: "dash_spv::network",
                                            "headers2 decompression task for {} failed: {}",
                                            addr,
                                            e
                                        );
                                        None
                                    }
                                };
                                // Hold the lock through dispatch so another batch
                                // cannot overtake this one.
                                let mut order = order.lock().await;
                                let ready = order.complete(sequence, (decompressed, permit));
                                dispatch_headers(&state.inbound, addr, ready);
                            });
                        }
                        NetworkMessage::Headers(headers) => {
                            // Same queue as `headers2`, else a plain reply could
                            // overtake a batch still decoding (the pipeline matches by
                            // the tip it extends). Takes a permit to keep it bounded.
                            let permit = tokio::select! {
                                permit = state.headers2_semaphore.clone().acquire_owned() => match permit {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                },
                                _ = shutdown.cancelled() => break,
                            };
                            let sequence = header_sequence;
                            header_sequence += 1;
                            let mut order = header_order.lock().await;
                            let ready = order.complete(
                                sequence,
                                (Some(NetworkMessage::Headers(headers).into()), permit),
                            );
                            if !dispatch_headers(inbound, addr, ready) {
                                break;
                            }
                        }
                        payload => {
                            if inbound.send(PeerEvent::Message(addr, payload.into())).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        tracing::info!("NETWORK: peer {} disconnected", addr);
        let _ = inbound.send(PeerEvent::Disconnected(addr));
    });
}

fn build_version(peer: SocketAddr, user_agent: &str) -> VersionMessage {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let unspecified: SocketAddr = ([0u8, 0, 0, 0], 0).into();
    VersionMessage::new(
        // Needed for peers to honour our `sendheaders2`; we serve nothing else.
        ServiceFlags::NONE | NODE_HEADERS_COMPRESSED,
        now,
        Address::new(&peer, ServiceFlags::NETWORK),
        Address::new(&unspecified, ServiceFlags::NONE),
        rand::random(),
        user_agent.to_string(),
        0,
        false,
        [0u8; 32],
    )
}

async fn handshake_send(
    writer: &mut OwnedWriteHalf,
    magic: u32,
    payload: NetworkMessage,
) -> NetworkResult<()> {
    let raw = RawNetworkMessage {
        magic,
        payload,
    };
    writer
        .write_all(&encode::serialize(&raw))
        .await
        .map_err(|e| NetworkError::ConnectionFailed(format!("handshake write failed: {}", e)))?;
    writer
        .flush()
        .await
        .map_err(|e| NetworkError::ConnectionFailed(format!("handshake flush failed: {}", e)))?;
    Ok(())
}
