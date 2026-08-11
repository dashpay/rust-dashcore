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
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tokio_util::sync::CancellationToken;

use crate::{error::NetworkResult, NetworkError};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = concat!("/dash-spv:", env!("CARGO_PKG_VERSION"), "/");

/// Per-peer response-latency tracker: the time each pipeline request spends in
/// flight, from send to the response that completes it. Send times are queued
/// FIFO; each completing response pops the oldest and folds the elapsed time
/// into running total/count/max (so we can report avg and worst per peer).
#[derive(Default)]
pub(crate) struct Latency {
    pending: Mutex<VecDeque<Instant>>,
    total_ns: AtomicU64,
    count: AtomicU64,
    max_ns: AtomicU64,
}

impl Latency {
    async fn on_send(&self) {
        self.pending.lock().await.push_back(Instant::now());
    }

    /// Undo an `on_send` whose write then failed, so the queue does not drift.
    async fn cancel_one(&self) {
        self.pending.lock().await.pop_back();
    }

    /// Pop the oldest pending send and record its round-trip.
    async fn complete_one(&self) {
        let sent = self.pending.lock().await.pop_front();
        if let Some(sent) = sent {
            let ns = sent.elapsed().as_nanos() as u64;
            self.total_ns.fetch_add(ns, Ordering::Relaxed);
            self.count.fetch_add(1, Ordering::Relaxed);
            self.max_ns.fetch_max(ns, Ordering::Relaxed);
        }
    }

    /// (completed request count, average ms, worst ms).
    fn snapshot(&self) -> (u64, f64, f64) {
        let count = self.count.load(Ordering::Relaxed);
        let total = self.total_ns.load(Ordering::Relaxed);
        let max = self.max_ns.load(Ordering::Relaxed);
        let avg_ms = if count > 0 {
            total as f64 / count as f64 / 1e6
        } else {
            0.0
        };
        (count, avg_ms, max as f64 / 1e6)
    }

    /// Cumulative (completed request count, total service-time nanoseconds).
    /// The bandwidth controller diffs these across a window to get THIS peer's
    /// completion rate and service time, sizing its in-flight cap by Little's Law.
    fn totals(&self) -> (u64, u64) {
        (self.count.load(Ordering::Relaxed), self.total_ns.load(Ordering::Relaxed))
    }
}

/// Wraps a socket read half and adds every byte read into a shared counter, so
/// the network manager can estimate download throughput (and size the global
/// in-flight budget to ~90% of it).
struct CountingReader<R> {
    inner: R,
    /// Host-wide download counter (all peers), the global bandwidth signal.
    bytes: Arc<AtomicU64>,
    /// This connection's own download counter, so the controller can measure
    /// per-peer throughput.
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
            self.bytes.fetch_add(n, Ordering::Relaxed);
            self.peer_bytes.fetch_add(n, Ordering::Relaxed);
        }
        r
    }
}

type PeerReader = FramedRead<CountingReader<OwnedReadHalf>, RawNetworkMessageCodec>;

// `NetworkMessage` is a large enum (unboxed to mirror upstream `dashcore`); wrapping it
// here by value trips `large_enum_variant`. The event lives briefly on the inbound channel
// and boxing every message would penalise the common small ones, so allow the size skew.
#[allow(clippy::large_enum_variant)]
pub enum PeerEvent {
    Message(SocketAddr, NetworkMessage),
    Disconnected(SocketAddr),
}

/// Everything the router needs to pick a peer and write to it, detached from the
/// peer set so it can be cloned, releasing the lock on the peer itself
#[derive(Clone)]
pub(crate) struct PeerHandle {
    addr: SocketAddr,
    network: Network,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    in_flight: Arc<AtomicUsize>,
    /// This peer's measured serving capacity — the number of requests it can have
    /// in flight before ITS responses start queuing (its bandwidth-delay product).
    /// Sized continuously by the bandwidth controller from the peer's own
    /// completion rate and service time, mirroring how the global budget is sized
    /// from our download rate. Fast peers earn a high cap, slow peers a low one.
    cap: Arc<AtomicUsize>,
    latency: Arc<Latency>,
    /// Whether to ask THIS peer for compressed headers (DIP-25). Set when it
    /// advertises `NODE_HEADERS_COMPRESSED`, cleared by the reader if its
    /// `headers2` ever fails to decompress, so the peer transparently falls back
    /// to uncompressed `headers` instead of stalling the header pipeline.
    /// Shared with the reader task, which is the only writer after connect.
    headers2: Arc<AtomicBool>,
}

impl PeerHandle {
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub(crate) fn cap(&self) -> usize {
        self.cap.load(Ordering::Relaxed)
    }

    pub(crate) async fn send(&self, msg: &NetworkMessage) -> NetworkResult<()> {
        // Upgrade a header request to its compressed form for peers that support
        // it. The sync layer always declares a plain `getheaders` because it has
        // no idea which peer the router will pick; the choice belongs here, where
        // the peer is known. `Headers2` is decompressed back into `Headers` by the
        // reader, so nothing above this layer sees the difference.
        let upgraded = match msg {
            NetworkMessage::GetHeaders(m) if self.headers2.load(Ordering::Relaxed) => {
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

        // A pipeline request counts as one unit of in-flight work for this peer, and
        // it must be counted BEFORE the write: the peer can reply before this task is
        // scheduled again, and the reader's decrement saturates at zero. Counting
        // afterwards loses that decrement and leaks the slot for the connection's
        // lifetime — with a starting cap of 2, one leak halves the peer's capacity.
        let accounted = is_pipeline_request(msg);
        if accounted {
            self.in_flight.fetch_add(1, Ordering::Relaxed);
            self.latency.on_send().await;
        }

        let write = async {
            let mut writer = self.writer.lock().await;
            writer.write_all(&serialized).await
        };
        let outcome = match tokio::time::timeout(WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("Write failed: {}", e)),
            // A write that never completes means the peer stopped reading. Treat
            // it exactly like a failed write: give the unit back and let the
            // caller re-queue, rather than waiting on a socket that will not move.
            Err(_) => Err(format!("Write stalled for {}s", WRITE_TIMEOUT.as_secs())),
        };
        if let Err(reason) = outcome {
            // Nothing reached the peer, so no response will free this unit.
            if accounted {
                self.in_flight.fetch_sub(1, Ordering::Relaxed);
                self.latency.cancel_one().await;
            }
            tracing::warn!("Disconnecting {} due to write error: {}", self.addr, reason);
            return Err(NetworkError::ConnectionFailed(reason));
        }
        Ok(())
    }
}

pub struct ConnectedPeer {
    handle: PeerHandle,
    version: VersionMessage,
    lag_ms: AtomicU32,
    /// Cumulative bytes downloaded from THIS peer, for per-peer throughput.
    bytes: Arc<AtomicU64>,
    /// Per-connection cancel token (child of the global shutdown). Cancelling it
    /// stops this peer's reader and closes the socket. Used to drop peers we
    /// probed but don't keep, so we only hold connections we actually use.
    token: CancellationToken,
}

pub struct DisconnectedPeer {
    network: Network,
    addr: SocketAddr,
    /// Handshake ping measured the last time we were connected to this peer, if any.
    /// Lets the supervisor rank backups by measured quality instead of treating every
    /// disconnected address as an unknown. `None` for an address we have never probed.
    lag_ms: Option<u32>,
}

impl ConnectedPeer {
    pub fn addr(&self) -> SocketAddr {
        self.handle.addr()
    }

    pub fn version(&self) -> &VersionMessage {
        &self.version
    }

    /// A detached view of this peer for the router: routing decisions and writes
    /// without holding the peer set's lock.
    pub(crate) fn handle(&self) -> PeerHandle {
        self.handle.clone()
    }

    /// Net in-flight to this peer: `+1` per message we send it, `-1` per message
    /// we read from it (managed internally by `send` and the reader task). The
    /// router reads this to send to the least-loaded peer.
    pub fn in_flight(&self) -> usize {
        self.handle.in_flight()
    }

    pub fn disconnect(self) -> DisconnectedPeer {
        DisconnectedPeer {
            network: self.handle.network,
            addr: self.handle.addr,
            // Carry the measured handshake ping (0 means unmeasured) so the supervisor
            // can rank this address against others without re-probing it.
            lag_ms: (self.lag_ms() > 0).then(|| self.lag_ms()),
        }
    }

    pub async fn send(&self, msg: &NetworkMessage) -> NetworkResult<()> {
        self.handle().send(msg).await
    }

    /// Note that `n` earlier pipeline requests have fully completed, freeing that
    /// much in-flight work. Used for streaming responses (`getcfilters` -> many
    /// `cfilter`s) that the reader can't attribute to a finished request on its
    /// own; single-response requests are decremented directly in the reader.
    pub(crate) async fn response_completed(&self, n: usize) {
        let _ = self
            .handle
            .in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(n)));
        for _ in 0..n {
            self.handle.latency.complete_one().await;
        }
    }

    /// Per-peer response latency: (completed requests, average ms, worst ms).
    pub(crate) fn latency_stats(&self) -> (u64, f64, f64) {
        self.handle.latency.snapshot()
    }

    /// Cumulative (completed request count, total service-time ns) for this peer.
    /// The bandwidth controller diffs these across a window to size this peer's
    /// in-flight cap independently by Little's Law.
    pub(crate) fn latency_totals(&self) -> (u64, u64) {
        self.handle.latency.totals()
    }

    /// Handshake round-trip latency in ms (0 if unmeasured).
    pub(crate) fn lag_ms(&self) -> u32 {
        self.lag_ms.load(Ordering::Relaxed)
    }

    /// Close this connection: cancel its reader so the socket shuts down. Used to
    /// drop probed-but-unselected peers instead of leaking their readers.
    pub(crate) fn close(&self) {
        self.token.cancel();
    }

    /// Cumulative bytes downloaded from this peer. The controller diffs it across
    /// a window for this peer's throughput.
    pub(crate) fn bytes_read(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Update this peer's measured in-flight capacity (called by the controller).
    pub(crate) fn set_cap(&self, n: usize) {
        self.handle.cap.store(n, Ordering::Relaxed);
    }
}

/// Pipeline requests we send and expect a response for (each adds one in-flight).
fn is_pipeline_request(msg: &NetworkMessage) -> bool {
    match msg {
        NetworkMessage::GetHeaders(_)
        | NetworkMessage::GetHeaders2(_)
        | NetworkMessage::GetCFHeaders(_)
        | NetworkMessage::GetCFilters(_) => true,
        // Block `getdata` is paced like any other request: the blocks pipeline
        // sends ONE block per message, so a request is exactly one in-flight unit
        // and one `block` in reply. Other `getdata` (chainlocks, islocks, txs) is
        // control traffic — it carries several inventory items whose replies the
        // reader cannot attribute one-for-one, so counting it would leak slots.
        NetworkMessage::GetData(inv) => {
            !inv.is_empty()
                && inv
                    .iter()
                    .all(|i| matches!(i, dashcore::network::message_blockdata::Inventory::Block(_)))
        }
        _ => false,
    }
}

/// Single-message responses: the reader decrements one in-flight per message.
/// `cfilter` is excluded — one `getcfilters` yields up to 1000 `cfilter`s, so its
/// unit is freed once per batch by the filters pipeline via `response_completed`.
fn is_single_response(msg: &NetworkMessage) -> bool {
    matches!(
        msg,
        NetworkMessage::Headers(_)
            | NetworkMessage::Headers2(_)
            | NetworkMessage::CFHeaders(_)
            | NetworkMessage::Block(_)
    )
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

    /// Handshake ping measured on a prior connection, if this address has been probed
    /// before. `None` sorts as worst (unknown) when ranking backups.
    pub(crate) fn lag_ms(&self) -> Option<u32> {
        self.lag_ms
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        self,
        inbound: UnboundedSender<PeerEvent>,
        shutdown: CancellationToken,
        bytes: Arc<AtomicU64>,
        required_services: ServiceFlags,
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
                bytes,
                peer_bytes: peer_bytes.clone(),
            },
            RawNetworkMessageCodec,
        );
        let magic = self.network.magic();

        handshake_send(&mut writer, magic, NetworkMessage::Version(build_version(self.addr)))
            .await?;

        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        let mut peer_version: Option<VersionMessage> = None;
        let mut got_verack = false;

        while !(peer_version.is_some() && got_verack) {
            let raw = match tokio::time::timeout_at(deadline, reader.next()).await {
                Err(_) => return Err(NetworkError::Timeout),
                Ok(None) => return Err(NetworkError::PeerDisconnected),
                Ok(Some(Err(e))) => return Err(e.into()),
                Ok(Some(Ok(raw))) => raw,
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

        // Only keep peers that advertise the services we need (see `new` in `manager`
        // for how the set is composed). A peer missing one of them doesn't fail loudly:
        // it stays connected and simply ignores the requests it can't serve, so its
        // slots stall until the request times out. Drop it now rather than waste it.
        if !version.services.has(required_services) {
            tracing::debug!(
                target: "dash_spv::network",
                "dropping {}: lacks required services {:?} (advertises {:?})",
                self.addr, required_services, version.services
            );
            return Err(NetworkError::ConnectionFailed(format!(
                "peer {} lacks required services {:?}",
                self.addr, required_services
            )));
        }

        // Announce sendheaders only after the handshake is fully complete.
        //
        // Prefer the compressed variant when this peer advertises
        // `NODE_HEADERS_COMPRESSED`: DIP-25 headers drop the fields that repeat
        // from the previous header, which is roughly half the bytes of an initial
        // header sync. Peers without the bit get plain `sendheaders`, so this is
        // opportunistic — we never look for a peer that supports it.
        let headers2 = Arc::new(AtomicBool::new(version.services.has(NODE_HEADERS_COMPRESSED)));
        let announce = if headers2.load(Ordering::Relaxed) {
            NetworkMessage::SendHeaders2
        } else {
            NetworkMessage::SendHeaders
        };
        handshake_send(&mut writer, magic, announce).await?;

        handshake_send(&mut writer, magic, NetworkMessage::GetAddr).await?;

        // Measure round-trip lag with a post-handshake ping/pong. Sending a ping
        // before the handshake completes makes some peers drop us, so we do it here.
        let mut lag_ms: u32 = 0;
        let ping_nonce: u64 = rand::random();
        let ping_sent = tokio::time::Instant::now();
        if handshake_send(&mut writer, magic, NetworkMessage::Ping(ping_nonce)).await.is_ok() {
            let deadline = ping_sent + HANDSHAKE_TIMEOUT;
            while let Ok(Some(Ok(raw))) = tokio::time::timeout_at(deadline, reader.next()).await {
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

        let writer = Arc::new(Mutex::new(writer));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let latency = Arc::new(Latency::default());
        // Start with a tiny in-flight capacity; the controller grows it from this
        // peer's measured serving rate.
        let cap = Arc::new(AtomicUsize::new(2));
        // Per-connection token: cancelled by the global shutdown (parent) OR by
        // `close()` to drop just this peer.
        let token = shutdown.child_token();
        spawn_reader(
            self.addr,
            magic,
            reader,
            writer.clone(),
            inbound,
            in_flight.clone(),
            latency.clone(),
            token.clone(),
            headers2.clone(),
        );

        tracing::debug!(
            target: "dash_spv::network",
            "peer connected: {} | lag={}ms height={}",
            self.addr,
            lag_ms,
            version.start_height,
        );

        Ok(ConnectedPeer {
            handle: PeerHandle {
                addr: self.addr,
                network: self.network,
                writer,
                in_flight,
                cap,
                latency,
                headers2,
            },
            version,
            lag_ms: AtomicU32::new(lag_ms),
            bytes: peer_bytes,
            token,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_reader(
    addr: SocketAddr,
    magic: u32,
    mut reader: PeerReader,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    inbound: UnboundedSender<PeerEvent>,
    in_flight: Arc<AtomicUsize>,
    latency: Arc<Latency>,
    shutdown: CancellationToken,
    headers2: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        // DIP-25 compression is a delta against the previously received header, so
        // the state is per connection and must persist across `headers2` messages.
        let mut compression = CompressionState::default();
        loop {
            let next = tokio::select! {
                _ = shutdown.cancelled() => break,
                next = reader.next() => next,
            };
            match next {
                None => break,
                Some(Err(e)) => {
                    tracing::error!("NETWORK: reader {} stopped: {}", addr, e);
                    break;
                }
                Some(Ok(raw)) => {
                    if raw.magic != magic {
                        continue;
                    }
                    // A single-message response completes one unit of in-flight
                    // work. Streaming responses (cfilter) are freed per batch by
                    // the filters pipeline instead.
                    if is_single_response(&raw.payload) {
                        let _ = in_flight.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(1))
                        });
                        latency.complete_one().await;
                    }
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
                            // Decompress here and hand the sync layer plain
                            // `Headers`, so compression stays entirely inside the
                            // network module.
                            match compression.process_headers(&compressed.headers) {
                                Ok(headers) => {
                                    tracing::debug!(
                                        target: "dash_spv::network",
                                        "decompressed {} headers from {}",
                                        headers.len(),
                                        addr
                                    );
                                    if inbound
                                        .send(PeerEvent::Message(
                                            addr,
                                            NetworkMessage::Headers(headers),
                                        ))
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    // Stop asking this peer for compressed headers.
                                    // The request goes unanswered, so the broker
                                    // times it out and re-sends it — as a plain
                                    // `getheaders` now that the flag is off.
                                    tracing::warn!(
                                        target: "dash_spv::network",
                                        "headers2 from {} failed to decompress ({}); \
                                         falling back to uncompressed headers for this peer",
                                        addr,
                                        e
                                    );
                                    headers2.store(false, Ordering::Relaxed);
                                    compression = CompressionState::default();
                                }
                            }
                        }
                        payload => {
                            if inbound.send(PeerEvent::Message(addr, payload)).is_err() {
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

fn build_version(peer: SocketAddr) -> VersionMessage {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let unspecified: SocketAddr = ([0u8, 0, 0, 0], 0).into();
    VersionMessage::new(
        // Advertise that we understand compressed headers (DIP-25) so peers that
        // support them will honour our `sendheaders2`. We serve nothing, hence no
        // other service bit.
        ServiceFlags::NONE | NODE_HEADERS_COMPRESSED,
        now,
        Address::new(&peer, ServiceFlags::NETWORK),
        Address::new(&unspecified, ServiceFlags::NONE),
        rand::random(),
        USER_AGENT.to_string(),
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
