use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

// Tokio's clock, so tests can pause time to drive the request-timeout machinery.
use tokio::time::Instant;

use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::{BlockHash, Header};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Bounded concurrent handshakes per probe round.
const CONNECT_CHUNK: usize = 16;

/// A peer is "very bad", taken only as a last resort when the set would otherwise be
/// empty, at a handshake ping of this multiple of the best ping seen, and never below
/// [`BAD_LAG_FLOOR_MS`]. Relative, so a slow link (every peer far away) still fills
/// the set instead of probing forever for a peer that does not exist.
const BAD_LAG_MULTIPLIER: u32 = 3;
const BAD_LAG_FLOOR_MS: u32 = 1000;

/// Shortest time between two slow-peer swaps.
const SWAP_COOLDOWN: Duration = Duration::from_secs(60);

/// How often the supervisor re-checks a below-cap set and probes to keep filling.
const FILL_TICK: Duration = Duration::from_secs(2);

const DIAL_MARGIN: usize = 2;
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);

/// How long the router sleeps on a full-capacity stall before re-evaluating. It
/// wakes early whenever a response frees a slot or the timeout monitor kicks a
/// peer; this is just a backstop so it never sleeps on a notify that never comes.
const STALL_CHECK: Duration = Duration::from_secs(5);

/// A request unanswered this long is stalled. Its peer becomes a culprit, and [`StallJudge`]
/// kicks it and re-queues its work unless our own link may be the one stalled. Deliberately
/// aggressive: replacing a peer that stopped answering is faster than waiting for it, and
/// merely slow peers are already throttled by their per-peer cap.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A far peer gets this many handshake pings instead, when that is longer: its round
/// trip alone can eat most of [`REQUEST_TIMEOUT`], leaving no room to queue work there.
const REQUEST_TIMEOUT_LAGS: u32 = 6;

/// The request timeout for a peer with handshake ping `lag_ms`.
fn request_timeout(lag_ms: u32) -> Duration {
    REQUEST_TIMEOUT.max(Duration::from_millis(lag_ms as u64) * REQUEST_TIMEOUT_LAGS)
}

const MAX_ADDR_PER_MESSAGE: usize = 1000;

/// How often the timeout monitor scans the outstanding-request registry.
const TIMEOUT_CHECK: Duration = Duration::from_secs(1);

/// How many request timeouts of our link's downtime a silent peer is held for: the part of
/// its silence in which no peer received anything. With the 10 s base timeout that is 60 s,
/// enough for the 40 s outages seen on testnet.
const LINK_STALL_TIMEOUTS: u32 = 6;

use crate::error::{NetworkError, NetworkResult};
use crate::network::bans::{Ban, Bans};
use crate::network::broker::{Broker, RequestKey, ANSWER_TIMEOUTS};
use crate::network::peer_set::{Admission, PeerSet};
use crate::network::NetworkManager;
use crate::network::TransportPreference;
use crate::{
    network::{
        costs::ResponseCosts,
        discovery::PeerDiscoverer,
        peer::{ConnectedPeer, DisconnectedPeer, PeerEvent, PeerHandle, PeerId, INITIAL_CAP_BYTES},
    },
    ClientConfig,
};
use async_trait::async_trait;

/// A peer message plus whatever the network layer worked out while decoding it.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    msg: NetworkMessage,
    header_hashes: Option<Vec<BlockHash>>,
}

impl InboundMessage {
    pub fn new(msg: NetworkMessage) -> Self {
        Self {
            msg,
            header_hashes: None,
        }
    }

    /// Headers message carrying the hashes computed during DIP-25 decompression (which
    /// must hash every header to rebuild `prev_blockhash`), so they are not hashed twice.
    pub fn new_headers(headers_with_hashes: Vec<(Header, BlockHash)>) -> Self {
        let (headers, hashes) = headers_with_hashes.into_iter().unzip();
        Self {
            msg: NetworkMessage::Headers(headers),
            header_hashes: Some(hashes),
        }
    }

    pub fn header_hashes(&self) -> Option<&[BlockHash]> {
        self.header_hashes.as_deref()
    }

    pub fn into_inner(self) -> NetworkMessage {
        self.msg
    }
}

impl std::ops::Deref for InboundMessage {
    type Target = NetworkMessage;

    fn deref(&self) -> &Self::Target {
        &self.msg
    }
}

impl From<NetworkMessage> for InboundMessage {
    fn from(msg: NetworkMessage) -> Self {
        Self::new(msg)
    }
}

/// An inbound message on its way to its subscribers. `Arc` so the pump does not
/// deep-copy a `block`/`cfilter` payload per subscriber.
pub type Inbound = (SocketAddr, Arc<InboundMessage>);
type Subscribers = Mutex<HashMap<MessageType, Vec<UnboundedSender<Inbound>>>>;

/// Message kinds a sync manager can subscribe to; the pump routes by mapping `cmd()` back to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    Headers,
    Inv,
    CfHeaders,
    CFilter,
    Block,
    MnListDiff,
    QrInfo,
    Tx,
    IsDLock,
    ChainLock,
}

impl MessageType {
    pub fn cmd(self) -> &'static str {
        match self {
            MessageType::Headers => "headers",
            MessageType::Inv => "inv",
            MessageType::CfHeaders => "cfheaders",
            MessageType::CFilter => "cfilter",
            MessageType::Block => "block",
            MessageType::MnListDiff => "mnlistdiff",
            MessageType::QrInfo => "qrinfo",
            MessageType::Tx => "tx",
            MessageType::IsDLock => "isdlock",
            MessageType::ChainLock => "clsig",
        }
    }

    pub fn from_cmd(cmd: &str) -> Option<MessageType> {
        Some(match cmd {
            "headers" => MessageType::Headers,
            "inv" => MessageType::Inv,
            "cfheaders" => MessageType::CfHeaders,
            "cfilter" => MessageType::CFilter,
            "block" => MessageType::Block,
            "mnlistdiff" => MessageType::MnListDiff,
            "qrinfo" => MessageType::QrInfo,
            "tx" => MessageType::Tx,
            "isdlock" => MessageType::IsDLock,
            "clsig" => MessageType::ChainLock,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkEvent {
    PeersUpdated {
        /// Addresses of every connected peer.
        addresses: Vec<SocketAddr>,
        /// Best tip height advertised across those peers.
        best_height: u32,
    },
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
}

pub struct NetworkState {
    pub(crate) connected: PeerSet,
    pub discoverer: Mutex<PeerDiscoverer>,
    pub bans: Bans,
    pub broker: Broker,
    pub subscribers: Subscribers,
    pub inbound: UnboundedSender<PeerEvent>,
    pub bytes: AtomicU64,
    pub global_cap: AtomicU64,
    pub peer_wake: Notify,
    pub costs: Arc<ResponseCosts>,
    pub max_peers: usize,
    pub required_services: ServiceFlags,
    pub user_agent: String,
    pub transport_preference: TransportPreference,
    /// Whether the timeout monitor sees our own link stalled.
    link_stalled: AtomicBool,
}

pub struct PeerNetworkManager {
    state: Arc<NetworkState>,
    shutdown: CancellationToken,
    session: Mutex<CancellationToken>,
}

impl Drop for PeerNetworkManager {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl PeerNetworkManager {
    pub async fn new(config: &ClientConfig) -> Self {
        let max_peers = config.max_peers.max(1) as usize;
        // NETWORK is unconditional: the block pipeline asks for full blocks at
        // arbitrary historical heights (and the gap-limit rescan far more so), which
        // a NETWORK_LIMITED peer stops serving past its last ~288 blocks.
        let mut required_services = ServiceFlags::NETWORK;
        // A filter-syncing client can only use peers that serve compact filters
        // (BIP157 — the same flag also covers compact filter headers).
        if config.enable_filters {
            required_services |= ServiceFlags::COMPACT_FILTERS;
        }
        // Mempool tracking sends `mempool` to every activated peer, and `filterload`
        // too under the BloomFilter strategy. A peer with bloom filters disabled
        // answers the first by dropping us and the second, per BIP111, by banning us.
        if config.enable_mempool_tracking {
            required_services |= ServiceFlags::BLOOM;
        }

        let (inbound, inbound_rx) = mpsc::unbounded_channel();
        let state = Arc::new(NetworkState {
            connected: PeerSet::new(30),
            discoverer: Mutex::new(PeerDiscoverer::new(config)),
            bans: Bans::new(config.peers.iter().copied()),
            broker: Broker::new(),
            subscribers: Mutex::new(HashMap::new()),
            inbound,
            bytes: AtomicU64::new(0),
            global_cap: AtomicU64::new(MIN_CAP_BYTES * max_peers as u64),
            peer_wake: Notify::new(),
            costs: Arc::new(ResponseCosts::new()),
            max_peers,
            required_services,
            user_agent: config.user_agent.clone(),
            transport_preference: config.transport_preference,
            link_stalled: AtomicBool::new(false),
        });
        let shutdown = CancellationToken::new();

        spawn_pump(state.clone(), inbound_rx, shutdown.clone());
        spawn_router(state.clone(), shutdown.clone());
        spawn_timeout_monitor(state.clone(), shutdown.clone());
        spawn_flow_controller(state.clone(), shutdown.clone());

        PeerNetworkManager {
            state,
            session: Mutex::new(shutdown.child_token()),
            shutdown,
        }
    }
}

#[async_trait]
impl NetworkManager for PeerNetworkManager {
    /// Connect to peers and announce them. Separate from `new` so `PeerConnected` and
    /// `PeersUpdated` fire only after the sync managers have subscribed; otherwise they
    /// are lost and e.g. the mempool never sends `filterload`.
    async fn start(&self) {
        let session = {
            let mut session = self.session.lock().await;
            if session.is_cancelled() {
                *session = self.shutdown.child_token();
            }
            session.clone()
        };
        // Non-blocking: the supervisor connects peers in the background and announces each,
        // so sync starts on the first decent one.
        spawn_peer_supervisor(self.state.clone(), session);
    }

    /// Disconnect and announce every peer, and forget the requests in play, so none
    /// of them reaches the peers of the next `start()`.
    async fn stop(&self) {
        tracing::info!(target: "dash_spv::network", "network manager stopping: cancelling peers");
        self.session.lock().await.cancel();
        let disconnected = self.state.connected.clear().await;
        tracing::info!(
            target: "dash_spv::network",
            "network manager stopping: disconnected {} peer(s) {:?}",
            disconnected.len(),
            disconnected,
        );
        self.state.broker.clear().await;
    }

    /// Ask the broker to make a request. De-duplicated by [`RequestKey`]: a request already
    /// queued, on the wire or answered but not yet released is a no-op, so pipelines can
    /// re-declare their whole wanted set every tick. Keyless messages (tx, mempool,
    /// control `getdata`) are queued untracked.
    async fn enqueue(&self, height: u32, msg: NetworkMessage) {
        self.state.broker.enqueue(height, msg).await;
    }

    /// Send to one specific peer, bypassing the router. Needed for messages that set
    /// state on that remote node (`filterload`/`filterclear`/`mempool` enable relay for
    /// THAT peer). Returns false if the peer is not connected or the write failed.
    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        // Drop the peer-set lock before writing: holding it across a socket write blocks
        // the router, monitor, supervisor and bandwidth controller for up to `WRITE_TIMEOUT`.
        let handle = {
            let peers = self.state.connected.read().await;
            peers.iter().find(|p| p.addr() == addr).map(|p| p.handle())
        };
        let Some(peer) = handle else {
            return false;
        };

        match peer.send(&msg).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(target: "dash_spv::network", "send to {addr} failed: {e}");
                false
            }
        }
    }

    async fn release_request(&self, key: RequestKey) {
        self.state.broker.release(&key).await;
    }

    /// Broadcast a message to all connected peers
    async fn broadcast(&self, msg: NetworkMessage) -> NetworkResult<()> {
        let handles: Vec<PeerHandle> =
            self.state.connected.read().await.iter().map(|p| p.handle()).collect();
        if handles.is_empty() {
            return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
        }

        let mut writes: FuturesUnordered<_> = handles.iter().map(|peer| peer.send(&msg)).collect();
        let mut delivered = 0;
        while let Some(result) = writes.next().await {
            if result.is_ok() {
                delivered += 1;
            }
        }
        if delivered == 0 {
            return Err(NetworkError::ConnectionFailed("All broadcast sends failed".to_string()));
        }
        Ok(())
    }

    /// Inject a message into the local pump as if it arrived from a peer, so
    /// managers process it through the same path. Uses the `0.0.0.0:0` sentinel
    /// address that managers treat as locally-originated.
    async fn dispatch_local(&self, msg: NetworkMessage) {
        let local: SocketAddr = ([0, 0, 0, 0], 0).into();
        let _ = self.state.inbound.send(PeerEvent::Message(PeerId::synthetic(local), msg.into()));
    }

    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut subscribers = self.state.subscribers.lock().await;
        for kind in kinds.iter().copied().collect::<HashSet<_>>() {
            subscribers.entry(kind).or_default().push(tx.clone());
        }
        rx
    }

    fn tip(&self) -> u32 {
        self.state.connected.best_tip()
    }

    async fn connected_count(&self) -> u32 {
        self.state.connected.len().await as u32
    }

    async fn ban_peer(&self, addr: SocketAddr) {
        self.state.bans.ban(addr, Ban::Misbehaved).await;
        for peer in self.state.connected.read().await.iter().filter(|p| p.addr() == addr) {
            peer.close();
        }
    }

    fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.state.connected.subscribe()
    }
}

fn spawn_router(state: Arc<NetworkState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let NetworkState {
            broker,
            connected,
            costs,
            global_cap,
            ..
        } = &*state;
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            // Wait for work. `notify` fires both when a message is queued and
            // when a response frees a peer slot.
            if broker.len() == 0 {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = broker.notified() => continue,
                }
            }

            let peers: Vec<PeerHandle> =
                connected.read().await.iter().map(|p| p.handle()).collect();
            let sent = broker.route(&peers, global_cap.load(Ordering::Relaxed), costs).await;
            drop(peers);

            if sent == 0 {
                // Every peer is at its in-flight cap: wait for a response or a kicked peer to free
                // a slot (both notify). The sleep is only a backstop against a missed wake.
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = broker.notified() => {},
                    _ = tokio::time::sleep(STALL_CHECK) => {},
                }
            }
        }
    })
}

/// How often the flow controller re-measures rates and re-sizes the byte caps.
const FLOW_TICK: Duration = Duration::from_millis(250);

/// Weight of a new tick in the rate and in-flight averages (~1 s horizon).
const FLOW_EMA_ALPHA: f64 = 0.25;

/// Ticks of round-trip samples the base round trip is the minimum of (30 s).
const BASE_RTT_TICKS: u64 = 120;

/// Shortest period between adjustments, in ticks; otherwise two round trips.
const MIN_PERIOD_TICKS: u32 = 4;

/// Smallest cap of a peer (and of the link, per peer): one response always fits.
const MIN_CAP_BYTES: u64 = INITIAL_CAP_BYTES;

/// Linear probe per second, per peer: linear in time, not per adjustment, so a far
/// peer (adjusted once per two long round trips) ramps as fast as a near one.
const CAP_STEP_BYTES_PER_SEC: f64 = 512.0 * 1024.0;

/// Added in-flight must buy at least this share of a proportional rate gain, or the
/// path is full and the addition only queued.
const MIN_ELASTICITY: f64 = 0.3;

/// In-flight growth below this is noise, not an experiment to judge.
const MIN_GROWTH: f64 = 0.05;

/// Queue at the bottleneck, as a fraction of the bandwidth-delay product, above which
/// the cap is cut by the excess (TCP Vegas' beta) whatever the rate did.
const QUEUE_HIGH: f64 = 1.0;

/// Queue floor in bytes: responses are lumpy (a filter batch can be 1 MB), so a small
/// bandwidth-delay product must still absorb a couple.
const QUEUE_FLOOR_BYTES: f64 = 1024.0 * 1024.0;

/// Ticks a peer must have been bandwidth bound before its rate is compared, and the
/// span its serving rate is averaged over, so a momentary dip never condemns it.
const SERVING_SAMPLE_TICKS: u32 = 120;

/// A peer serving below this fraction of the best connected peer's rate is slow.
const SLOW_RATE_FRACTION: f64 = 0.25;

/// Sizes a byte cap from throughput alone. Grows it linearly while each addition of
/// in-flight bytes still buys proportionally more bytes/s; once the rate stops
/// following, scales it back by how much of the addition did not pay. As a guard,
/// by Little's law the round trip is `in_flight / rate` and its 30 s minimum the
/// path's base, so `in_flight - rate · base_rtt` is what sits queued (TCP Vegas):
/// more than a bandwidth-delay product of it cuts the cap by the excess.
struct ByteLimiter {
    cap: f64,
    min_cap: f64,
    /// Bytes/s and bytes in flight, averaged over ticks.
    rate: f64,
    in_flight: f64,
    last_bytes: u64,
    /// Monotonic window of (tick, round trip) giving the minimum over the last
    /// [`BASE_RTT_TICKS`].
    rtts: VecDeque<(u64, f64)>,
    ticks: u64,
    base_rtt: f64,
    /// Rate and in-flight at the last adjustment, to judge what it bought.
    prev_rate: f64,
    prev_in_flight: f64,
    since_adjust: u32,
    /// Whether the cap was ever cut: until then it is still ramping, and the rate it
    /// allows says nothing about the peer.
    found_ceiling: bool,
}

impl ByteLimiter {
    fn new(cap: u64, last_bytes: u64) -> Self {
        Self {
            cap: cap as f64,
            min_cap: cap as f64,
            rate: 0.0,
            in_flight: 0.0,
            last_bytes,
            rtts: VecDeque::new(),
            ticks: 0,
            base_rtt: 0.0,
            prev_rate: 0.0,
            prev_in_flight: 0.0,
            since_adjust: 0,
            found_ceiling: false,
        }
    }

    fn rtt(&self) -> f64 {
        self.in_flight / self.rate.max(1.0)
    }

    /// One tick with the cumulative bytes received and the bytes in flight now;
    /// `step` is the linear growth per second.
    fn tick(&mut self, bytes: u64, in_flight: u64, step: f64) -> u64 {
        let tick_s = FLOW_TICK.as_secs_f64();
        let got = bytes.saturating_sub(self.last_bytes) as f64;
        self.last_bytes = bytes;
        self.rate += FLOW_EMA_ALPHA * (got / tick_s - self.rate);
        self.in_flight += FLOW_EMA_ALPHA * (in_flight as f64 - self.in_flight);
        self.ticks += 1;

        // Nothing asked or nothing arriving says nothing about the path.
        if in_flight == 0 || self.rate < 1.0 || self.in_flight < 1.0 {
            return self.cap as u64;
        }
        let rtt = self.rtt();
        while self.rtts.back().is_some_and(|&(_, r)| r >= rtt) {
            self.rtts.pop_back();
        }
        self.rtts.push_back((self.ticks, rtt));
        while self.rtts.front().is_some_and(|&(t, _)| t + BASE_RTT_TICKS < self.ticks) {
            self.rtts.pop_front();
        }
        self.base_rtt = self.rtts.front().map_or(rtt, |&(_, r)| r);

        // One adjustment per two round trips, so each judges the last one's effect.
        self.since_adjust += 1;
        let period = ((2.0 * rtt / tick_s).ceil() as u32).max(MIN_PERIOD_TICKS);
        if self.since_adjust < period {
            return self.cap as u64;
        }
        let step = step * self.since_adjust as f64 * tick_s;
        self.since_adjust = 0;
        let (prev_rate, prev_in_flight) = (self.prev_rate, self.prev_in_flight);
        self.prev_rate = self.rate;
        self.prev_in_flight = self.in_flight;

        let bdp = self.rate * self.base_rtt;
        let queued = self.in_flight - bdp;
        let high = (bdp * QUEUE_HIGH).max(QUEUE_FLOOR_BYTES);
        let growth = if prev_in_flight > 0.0 {
            self.in_flight / prev_in_flight - 1.0
        } else {
            0.0
        };
        let gain = if prev_rate > 0.0 {
            self.rate / prev_rate - 1.0
        } else {
            0.0
        };
        // Growth needs the cap to be what limits us; an under-used cap proves nothing.
        let limited = in_flight as f64 + step >= self.cap;
        if queued > high {
            self.cap -= queued - high;
            self.found_ceiling = true;
        } else if growth > MIN_GROWTH && gain < growth * MIN_ELASTICITY {
            self.cap *= (1.0 + gain.max(0.0)) / (1.0 + growth);
            self.found_ceiling = true;
        } else if limited {
            self.cap += step;
        }
        self.cap = self.cap.max(self.min_cap);
        self.cap as u64
    }
}

/// A peer's limiter plus how fast it serves while bandwidth bound, for eviction.
struct PeerFlow {
    limiter: ByteLimiter,
    serving_rate: f64,
    serving_ticks: u32,
}

impl PeerFlow {
    fn new(bytes: u64) -> Self {
        Self {
            limiter: ByteLimiter::new(MIN_CAP_BYTES, bytes),
            serving_rate: 0.0,
            serving_ticks: 0,
        }
    }

    /// One tick with the peer's cumulative bytes received, its bytes in flight now,
    /// whether the client's own cap holds back work and whether our link is stalled.
    /// Returns its new cap.
    fn tick(&mut self, bytes: u64, in_flight: u64, link_full: bool, link_stalled: bool) -> u64 {
        // The router sends a peer work until it reaches its cap or the link cap binds.
        // Short of both, its rate shows how much it was asked for, not its bandwidth.
        let bound = in_flight > 0 && (in_flight >= self.limiter.cap as u64 || link_full);
        let cap = self.limiter.tick(bytes, in_flight, CAP_STEP_BYTES_PER_SEC);
        // A stall of our own link says nothing about the peer and would drag its average
        // for 30 s, so ticks are skipped once the timeout monitor sees one.
        if bound && !link_stalled {
            self.serving_ticks += 1;
            let alpha = 1.0 / self.serving_ticks.min(SERVING_SAMPLE_TICKS) as f64;
            self.serving_rate += alpha * (self.limiter.rate - self.serving_rate);
        }
        cap
    }

    /// Returns the peer's serving rate in bytes/s, 0 until measured.
    fn serving_rate(&self) -> u64 {
        let measured = self.limiter.found_ceiling && self.serving_ticks >= SERVING_SAMPLE_TICKS;
        if measured {
            self.serving_rate as u64
        } else {
            0
        }
    }
}

/// Sizes the byte caps of every peer and of the client's own link, each with a
/// [`ByteLimiter`] on its own throughput: the router sends while both have room.
/// Also reports how fast each peer serves while bandwidth bound, for [`underserving_peer`].
fn spawn_flow_controller(state: Arc<NetworkState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let NetworkState {
            bytes,
            global_cap,
            connected,
            peer_wake,
            broker,
            costs,
            link_stalled,
            ..
        } = &*state;
        let mut global = ByteLimiter::new(MIN_CAP_BYTES, bytes.load(Ordering::Relaxed));
        let mut peers: HashMap<PeerId, PeerFlow> = HashMap::new();
        let mut last_underserving: Option<SocketAddr> = None;
        // Bytes read, in flight and cap at each peer's last `peer_speed` line. A peer is
        // reported again only once one of them changes, so an idle client stays quiet.
        let mut reported: HashMap<PeerId, (u64, u64, u64)> = HashMap::new();
        let mut reported_bandwidth = None;
        let mut ticks = 0u64;
        let mut ticker = tokio::time::interval(FLOW_TICK);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }
            ticks += 1;

            let g = connected.read().await;
            if g.is_empty() {
                continue;
            }
            let live: HashSet<PeerId> = g.iter().map(|p| p.id()).collect();
            peers.retain(|id, _| live.contains(id));

            let in_flights: Vec<u64> = g.iter().map(ConnectedPeer::in_flight_bytes).collect();
            let total_in_flight: u64 = in_flights.iter().sum();
            let link_full = total_in_flight >= global_cap.load(Ordering::Relaxed);
            let stalled = link_stalled.load(Ordering::Relaxed);
            for (p, &in_flight) in g.iter().zip(&in_flights) {
                let flow = peers.entry(p.id()).or_insert_with(|| PeerFlow::new(p.bytes_read()));
                p.set_cap(flow.tick(p.bytes_read(), in_flight, link_full, stalled));
                p.set_serving_rate(flow.serving_rate());
            }

            global.min_cap = (MIN_CAP_BYTES * g.len() as u64) as f64;
            global.cap = global.cap.max(global.min_cap);
            let step = CAP_STEP_BYTES_PER_SEC * g.len() as f64;
            let cap = global.tick(bytes.load(Ordering::Relaxed), total_in_flight, step);
            global_cap.store(cap, Ordering::Relaxed);

            if ticks.is_multiple_of(2) {
                let caps: u64 = g.iter().map(|p| p.cap()).sum();
                reported.retain(|id, _| live.contains(id));
                let mut any_reported = false;
                for p in g.iter() {
                    let flow = &peers[&p.id()];
                    let snapshot = (p.bytes_read(), p.in_flight_bytes(), p.cap());
                    if reported.insert(p.id(), snapshot) == Some(snapshot) {
                        continue;
                    }
                    any_reported = true;
                    tracing::debug!(
                        target: "peer_speed",
                        "peer {}: cap={} KB in_flight={} KB rate={:.2} MB/s rtt={:.0}ms base={:.0}ms lag={}ms total={:.1} MB",
                        p.addr(),
                        p.cap() >> 10,
                        p.in_flight_bytes() >> 10,
                        flow.limiter.rate / 1e6,
                        flow.limiter.rtt() * 1e3,
                        flow.limiter.base_rtt * 1e3,
                        p.lag_ms(),
                        p.bytes_read() as f64 / 1e6,
                    );
                }
                let bind = if total_in_flight >= cap.min(caps) {
                    if cap <= caps {
                        "global"
                    } else {
                        "peers"
                    }
                } else {
                    "work"
                };
                let snapshot =
                    Some((bytes.load(Ordering::Relaxed), total_in_flight, cap, caps, g.len()));
                if any_reported || reported_bandwidth != snapshot {
                    reported_bandwidth = snapshot;
                    tracing::debug!(
                        target: "peer_speed",
                        "bandwidth: {:.1} MB/s bind={} | global_cap={} sum_peer_cap={} in_flight={} KB | rtt={:.0}ms base={:.0}ms | peers={} | resp KB {:?}",
                        global.rate / 1e6,
                        bind,
                        cap >> 10,
                        caps >> 10,
                        total_in_flight >> 10,
                        global.rtt() * 1e3,
                        global.base_rtt * 1e3,
                        g.len(),
                        costs.expected_kb(),
                    );
                }
            }

            // Only the transition wakes the supervisor, so a peer with no replacement
            // is not re-probed every tick. A stall of our own link drags every rate down
            // unevenly, so nobody is underserving during one.
            let underserving = (!stalled).then(|| underserving_peer(&g)).flatten();
            let handles: Vec<PeerHandle> = g.iter().map(|p| p.handle()).collect();
            drop(g);
            if broker.len() == 0 {
                if let Some(height) = broker.hedge(&handles).await {
                    tracing::debug!(target: "dash_spv::network", "endgame: hedged block {}", height);
                }
            }
            if let Some(slow) = underserving.filter(|slow| Some(slow.addr) != last_underserving) {
                tracing::debug!(
                    target: "dash_spv::network",
                    "{} serving at {:.2} MB/s vs best {:.2} MB/s — a replacement is worth probing for",
                    slow.addr,
                    slow.rate as f64 / 1e6,
                    slow.best as f64 / 1e6,
                );
                peer_wake.notify_one();
            }
            last_underserving = underserving.map(|slow| slow.addr);
        }
    })
}

/// Sort key for a connected peer's handshake ping: lower is better, and an
/// unmeasured lag (0) sorts as worst.
fn lag_key(peer: &ConnectedPeer) -> u32 {
    match peer.lag_ms() {
        0 => u32::MAX,
        ms => ms,
    }
}

/// The peer supervisor: the single task that owns the connected-peer set, keeping it
/// filled toward `max_peers` with the lowest-latency peers it can find.
///
/// - Below cap it probes candidates in parallel and accepts those with handshake
///   ping under the bad-lag threshold ([`BAD_LAG_MULTIPLIER`]), announcing each so sync
///   starts on the first. A very
///   bad peer is taken only when the set would otherwise be empty.
/// - At cap it waits to be woken by a lost or underserving peer, then probes for a
///   replacement. No periodic improvement pass: each probe costs a full handshake.
/// - Probed-but-unused peers are closed and remembered in the discoverer so
///   later rounds reconnect the best without probing blindly.
struct Supervisor {
    state: Arc<NetworkState>,
    shutdown: CancellationToken,
    /// Lowest handshake ping seen, the reference for the bad-lag threshold.
    best_lag_ms: AtomicU32,
    /// When a slow peer was last swapped out, for [`SWAP_COOLDOWN`].
    last_swap: Mutex<Option<Instant>>,
}

impl Supervisor {
    async fn run(self) {
        loop {
            self.repair_round().await;

            let short = self.state.connected.read().await.len() < self.state.max_peers;

            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = self.state.peer_wake.notified() => {}
                _ = tokio::time::sleep(FILL_TICK), if short => {}
            }
        }
    }

    async fn next_candidates(&self, want: usize) -> Vec<DisconnectedPeer> {
        let mut out = self.state.discoverer.lock().await.get(want).await;
        let live: HashSet<SocketAddr> =
            self.state.connected.read().await.iter().map(|p| p.addr()).collect();
        let banned = self.state.bans.banned().await;
        let mut seen = HashSet::new();
        out.retain(|p| {
            !live.contains(&p.addr()) && !banned.contains(&p.addr()) && seen.insert(p.addr())
        });
        out
    }

    /// Closes probed-but-unused peers and remembers them for the next round.
    async fn stash_backups(&self, peers: impl IntoIterator<Item = ConnectedPeer>) {
        let mut discoverer = self.state.discoverer.lock().await;
        for peer in peers {
            peer.close();
            discoverer.probed(peer.addr(), peer.lag_ms());
        }
    }

    /// One pass at whatever the peer set needs: fill a deficit, replace a peer that is
    /// underserving the rest, or both.
    async fn repair_round(&self) {
        let (deficit, slow) = {
            let peers = self.state.connected.read().await;
            let deficit = self.state.max_peers.saturating_sub(peers.len());
            // Only look for a laggard once full: below cap every arrival is wanted anyway.
            // Each swap re-sends the work the old peer held, so at most one per cooldown.
            let cooled = self.last_swap.lock().await.is_none_or(|t| t.elapsed() >= SWAP_COOLDOWN);
            let stalled = self.state.link_stalled.load(Ordering::Relaxed);
            let slow = (deficit == 0 && cooled && !stalled)
                .then(|| underserving_peer(&peers))
                .flatten()
                .map(|slow| slow.addr);
            (deficit, slow)
        };
        if deficit == 0 && slow.is_none() {
            return;
        }

        // Scale the probe to the need: a few candidates to find one replacement, a
        // full chunk when several slots are open and sync is waiting on them.
        let want = (deficit.max(1) + DIAL_MARGIN).min(CONNECT_CHUNK);
        let batch = self.next_candidates(want).await;
        if batch.is_empty() {
            return;
        }

        // Take each peer as soon as ITS handshake lands rather than waiting for the batch,
        // so one unreachable address doesn't delay sync. Completion order is itself a
        // latency ranking; the rest of the batch is drained only to bank backups.
        let mut inflight: FuturesUnordered<_> = batch
            .into_iter()
            .map(|c| {
                let addr = c.addr();
                let connect = c.connect(self.state.clone(), self.shutdown.clone());
                async move {
                    let result = tokio::select! {
                        _ = self.shutdown.cancelled() => Err(NetworkError::Timeout),
                        result = tokio::time::timeout(CONNECT_DEADLINE, connect) => {
                            result.unwrap_or(Err(NetworkError::Timeout))
                        }
                    };
                    (addr, result)
                }
            })
            .collect();

        let mut accepted = 0usize;
        let mut replaced: Option<SocketAddr> = None;
        let mut leftover: Vec<ConnectedPeer> = Vec::new();
        while let Some((addr, result)) = inflight.next().await {
            let Ok(peer) = result else {
                self.state.bans.ban(addr, Ban::DialFailed).await;
                continue;
            };
            self.state.bans.dialed(addr).await;
            let handle = peer.handle();
            self.state.connected.raise_best_tip(peer.version().start_height.max(0) as u32);

            let lag = peer.lag_ms();
            if lag > 0 {
                self.best_lag_ms.fetch_min(lag, Ordering::Relaxed);
            }
            let bad_lag = self
                .best_lag_ms
                .load(Ordering::Relaxed)
                .saturating_mul(BAD_LAG_MULTIPLIER)
                .max(BAD_LAG_FLOOR_MS);
            if lag == 0 || lag >= bad_lag {
                leftover.push(peer);
                continue;
            }

            let new_addr = peer.addr();
            // Our link can stall while the candidates are dialed, and then `slow` is stale.
            let stalled = self.state.link_stalled.load(Ordering::Relaxed);
            let slow = slow.filter(|_| replaced.is_none() && !stalled);
            match self.state.connected.admit(peer, &self.shutdown, self.state.max_peers, slow).await
            {
                Admission::Joined => accepted += 1,
                Admission::Swapped(old) => {
                    replaced = Some(new_addr);
                    tracing::info!(
                        target: "dash_spv::network",
                        "peer supervisor: swapped out slow {} for {}",
                        old.addr(),
                        new_addr,
                    );
                    // Close it: the pump requeues every request routed to THIS connection, as for any
                    // lost peer. Safe because the departure names a connection, not an address, so a
                    // reconnection to the same peer is not disturbed.
                    old.close();
                    *self.last_swap.lock().await = Some(Instant::now());
                }
                Admission::Full(peer) => {
                    leftover.push(peer);
                    continue;
                }
                Admission::Stopped(peer) => {
                    peer.close();
                    continue;
                }
            }
            let _ = handle.send(&NetworkMessage::GetAddr).await;
        }

        // Last resort: never sit at zero peers. If nothing decent connected and the
        // set is empty, take the least-bad handshake we got so sync can start; a
        // later round upgrades it once a decent peer appears.
        if accepted == 0 && self.state.connected.read().await.is_empty() && !leftover.is_empty() {
            leftover.sort_by_key(lag_key);
            let peer = leftover.remove(0);
            let (addr, lag) = (peer.addr(), peer.lag_ms());
            let handle = peer.handle();
            match self.state.connected.admit(peer, &self.shutdown, self.state.max_peers, None).await
            {
                Admission::Joined => {
                    tracing::warn!(
                        target: "dash_spv::network",
                        "no decent peer available; accepting {} (ping {}ms) as last resort",
                        addr,
                        lag,
                    );
                    let _ = handle.send(&NetworkMessage::GetAddr).await;
                    accepted += 1;
                }
                Admission::Full(peer) => leftover.push(peer),
                // Nothing is swapped out without a slow peer to name.
                Admission::Swapped(peer) | Admission::Stopped(peer) => peer.close(),
            }
        }

        self.stash_backups(leftover).await;

        if accepted > 0 {
            tracing::info!(
                target: "dash_spv::network",
                "peer supervisor: +{} peers -> {}",
                accepted,
                self.state.connected.read().await.len(),
            );
        }
    }
}

/// A peer underserving the rest, with its serving rate and the best one in bytes/s.
#[derive(Clone, Copy)]
struct SlowPeer {
    addr: SocketAddr,
    rate: u64,
    best: u64,
}

/// The connected peer clearly underserving the rest, if any: serving bytes at a small
/// fraction of the best connected peer's rate while bandwidth bound. Relative, so a slow
/// client link (every peer slow alike) never condemns anyone.
fn underserving_peer(peers: &[ConnectedPeer]) -> Option<SlowPeer> {
    let measured: Vec<(SocketAddr, u64)> = peers
        .iter()
        .filter_map(|p| {
            let rate = p.serving_rate();
            (rate > 0).then_some((p.addr(), rate))
        })
        .collect();
    // Comparing needs a reference point: with fewer than two measured peers there
    // is no "the rest" to be slow against.
    if measured.len() < 2 {
        return None;
    }
    let best = measured.iter().map(|&(_, r)| r).max().expect("non-empty");
    let (addr, worst) = measured.iter().copied().min_by_key(|&(_, r)| r).expect("non-empty");
    ((worst as f64) < best as f64 * SLOW_RATE_FRACTION).then_some(SlowPeer {
        addr,
        rate: worst,
        best,
    })
}

fn spawn_peer_supervisor(state: Arc<NetworkState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(
        Supervisor {
            state,
            shutdown,
            best_lag_ms: AtomicU32::new(u32::MAX),
            last_swap: Mutex::new(None),
        }
        .run(),
    )
}

/// What the timeout monitor reads of a connected peer each tick.
struct Observed {
    id: PeerId,
    bytes: u64,
    /// Whether part of a message has arrived and the rest has not.
    partial: bool,
    in_flight: u64,
    timeout: Duration,
}

/// What the timeout monitor knows of a connected peer.
struct Liveness {
    bytes: u64,
    /// When the peer last sent bytes or was idle.
    owing_since: Instant,
}

/// Decides which peers [`spawn_timeout_monitor`] kicks. A peer silent with work is blamed once
/// our link worked for more than a timeout of its silence, or after more than
/// [`LINK_STALL_TIMEOUTS`] timeouts of downtime. At most one is kicked per timeout.
#[derive(Default)]
struct StallJudge {
    liveness: HashMap<PeerId, Liveness>,
    /// The last kick of a silent peer, which paces the next.
    last_kick: Option<Instant>,
    /// Whether our own link may be stalled: the last judgement left a culprit no peer
    /// witnessed, held or waiting to be kicked.
    link_stalled: bool,
    /// When [`Self::observe`] last ran.
    last_tick: Option<Instant>,
    /// How long our link has provably worked: each tick on which some peer's bytes grew adds
    /// the time since the tick before, at most [`TIMEOUT_CHECK`]. A new peer's first counter
    /// is not growth.
    link_up: Duration,
    /// `link_up` at each tick, back to the last tick at or before the oldest silence judged
    /// now or later.
    uptime: VecDeque<(Instant, Duration)>,
}

impl StallJudge {
    /// Records the peers' byte counters and returns the peers that received bytes of a
    /// message still arriving. Small unrelated messages arrive whole, so only these bytes
    /// are progress on a request.
    fn observe(&mut self, now: Instant, peers: &[Observed]) -> Vec<PeerId> {
        self.liveness.retain(|id, _| peers.iter().any(|p| p.id == *id));
        let mut any_grew = false;
        let mut streaming = Vec::new();
        for p in peers {
            let entry = self.liveness.entry(p.id).or_insert(Liveness {
                bytes: p.bytes,
                owing_since: now,
            });
            let grew = p.bytes > entry.bytes;
            if grew {
                any_grew = true;
                entry.bytes = p.bytes;
                if p.partial {
                    streaming.push(p.id);
                }
            }
            // An idle peer owes no bytes, so its silence before it gets work
            // must not count against its first request.
            if grew || p.in_flight == 0 {
                entry.owing_since = now;
            }
        }
        // The cap keeps ticks the monitor ran late from counting an outage as uptime.
        if let Some(last) = self.last_tick.filter(|_| any_grew) {
            self.link_up += now.duration_since(last).min(TIMEOUT_CHECK);
        }
        self.last_tick = Some(now);
        self.uptime.push_back((now, self.link_up));
        streaming
    }

    /// How long our link worked since `from`. It overcounts by up to one tick.
    fn uptime_since(&self, from: Instant) -> Duration {
        // The last sample at or before `from`, or the oldest kept if all are later.
        let last = self.uptime.partition_point(|&(at, _)| at <= from).saturating_sub(1);
        let before = self.uptime.get(last).map_or(Duration::ZERO, |&(_, up)| up);
        self.link_up.saturating_sub(before)
    }

    /// Returns the peers to kick, how many culprits are spared, and the kicked peer no peer
    /// witnessed, if any. `culprits` maps the peers of stalled requests to when their
    /// silence began.
    fn judge(
        &mut self,
        now: Instant,
        peers: &[Observed],
        mut culprits: HashMap<PeerId, Instant>,
    ) -> (HashSet<PeerId>, usize, Option<PeerId>) {
        self.link_stalled = false;
        // Judged on the peer's own counters, not just the registry: streaming in-flight
        // bytes are freed on the peer separately, so a wedged peer can sit at its cap
        // with no registry entries. Pending work plus a byte counter
        // frozen for REQUEST_TIMEOUT means stuck, whatever the registry thinks.
        for p in peers.iter().filter(|p| p.in_flight > 0) {
            let Some(owing_since) = self.liveness.get(&p.id).map(|l| l.owing_since) else {
                continue;
            };
            if now.duration_since(owing_since) > p.timeout {
                let since = culprits.entry(p.id).or_insert(owing_since);
                *since = (*since).min(owing_since);
            }
        }
        // Uptime is kept back to the oldest silence judged now or later: a peer's, a culprit's,
        // or a request's, which `Broker::expire` blames from at most `ANSWER_TIMEOUTS` back.
        let oldest = peers
            .iter()
            .filter_map(|p| now.checked_sub(p.timeout * ANSWER_TIMEOUTS))
            .chain(self.liveness.values().map(|l| l.owing_since))
            .chain(culprits.values().copied())
            .min();
        while self.uptime.get(1).is_some_and(|&(at, _)| oldest.is_none_or(|oldest| at <= oldest)) {
            self.uptime.pop_front();
        }
        if culprits.is_empty() {
            return (HashSet::new(), 0, None);
        }

        let mut held = 0;
        let mut silent: Vec<(Instant, &Observed, bool)> = Vec::new();
        for p in peers {
            let Some(&since) = culprits.get(&p.id) else {
                continue;
            };
            // Silence is blamed once our link worked for more than a timeout of it, so the peer
            // had that long to answer, however outages split the uptime.
            let up = self.uptime_since(since);
            let down = now.duration_since(since).saturating_sub(up);
            let witnessed = up > p.timeout;
            if witnessed || down > p.timeout * LINK_STALL_TIMEOUTS {
                silent.push((since, p, witnessed));
            } else {
                held += 1;
            }
        }
        // A silent peer may still be our link failing it, so the one silent the longest
        // goes, and one kick per timeout keeps a stall of our link from taking the whole set
        // at once.
        silent.sort_by_key(|&(since, p, _)| (since, p.id.addr()));
        let due = silent.first().is_some_and(|(_, worst, _)| {
            self.last_kick.is_none_or(|at| now.duration_since(at) > worst.timeout)
        });
        if due {
            self.last_kick = Some(now);
        }
        // The culprits waiting behind kick pacing may be our link's victims too.
        let mut waiting = silent.iter().skip(usize::from(due));
        self.link_stalled = held > 0 || waiting.any(|&(_, _, witnessed)| !witnessed);
        // A culprit that already left is not spared, so its requests are still re-queued.
        let mut kicked: HashSet<PeerId> =
            culprits.into_keys().filter(|id| peers.iter().all(|p| p.id != *id)).collect();
        let kick = silent.first().filter(|_| due);
        kicked.extend(kick.map(|(_, p, _)| p.id));
        let unwitnessed = kick.filter(|(_, _, witnessed)| !witnessed).map(|(_, p, _)| p.id);
        (kicked, held + silent.len() - usize::from(due), unwitnessed)
    }
}

/// Every [`TIMEOUT_CHECK`], kicks the peers [`StallJudge`] finds stalled on requests with no
/// progress for a [`REQUEST_TIMEOUT`], bans every kicked peer except one kicked with no witness,
/// re-queues their on-wire requests for other peers and wakes the supervisor to refill the set.
fn spawn_timeout_monitor(state: Arc<NetworkState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let NetworkState {
            broker,
            connected,
            peer_wake,
            max_peers,
            bans,
            link_stalled,
            ..
        } = &*state;
        let mut ticker = tokio::time::interval(TIMEOUT_CHECK);
        let mut judge = StallJudge::default();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }

            let now = Instant::now();
            let peers: Vec<Observed> = connected
                .read()
                .await
                .iter()
                .map(|p| Observed {
                    id: p.id(),
                    bytes: p.bytes_read(),
                    partial: p.partial_message(),
                    in_flight: p.in_flight_bytes(),
                    timeout: request_timeout(p.lag_ms()),
                })
                .collect();
            broker.receiving(&judge.observe(now, &peers)).await;
            // A request with no progress for a timeout also condemns its peer: the
            // per-peer byte check sees unrelated traffic and judges it healthy.
            let timeout = |id: &PeerId| {
                peers.iter().find(|p| p.id == *id).map_or(REQUEST_TIMEOUT, |p| p.timeout)
            };
            let (culprits, spared, unwitnessed) =
                judge.judge(now, &peers, broker.expire(timeout).await);
            link_stalled.store(judge.link_stalled, Ordering::Relaxed);
            if culprits.is_empty() {
                if spared > 0 {
                    tracing::debug!(
                        target: "dash_spv::network",
                        "request timeout: kicked none, spared {}",
                        spared,
                    );
                }
                continue;
            }

            // Drop culprits still in the set (some may already be gone) before their work
            // is re-queued, so the router cannot hand it back to them.
            let (kicked, remaining) = connected.remove(&culprits).await;
            for peer in &kicked {
                peer.close();
            }
            // Re-queue every on-wire request of a culprit (fresh ones too: the connection is
            // going away), keeping keys as Queued so de-dup holds.
            let retried = broker.requeue_from(&culprits).await;
            let dropped = kicked.len();
            // A peer kicked only because its hold ran out is likely a victim of our own link.
            // If it is unreachable after all, redialing it fails and backs off.
            for peer in culprits.iter().filter(|&&peer| Some(peer) != unwitnessed) {
                bans.ban(peer.addr(), Ban::Kicked).await;
            }
            // The set is now short: wake the supervisor, which otherwise idles.
            if dropped > 0 && remaining < *max_peers {
                peer_wake.notify_one();
            }

            tracing::warn!(
                target: "dash_spv::network",
                "request timeout: kicked {} peer(s) {:?}, spared {}, retried {} request(s)",
                dropped,
                culprits,
                spared,
                retried,
            );
            broker.wake();
        }
    })
}

fn spawn_pump(
    state: Arc<NetworkState>,
    mut inbound: UnboundedReceiver<PeerEvent>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let NetworkState {
            subscribers,
            connected,
            broker,
            peer_wake,
            max_peers,
            discoverer,
            ..
        } = &*state;
        // Per-peer received-message counter to check load balance across peers.
        let mut recv_by_peer: HashMap<SocketAddr, u64> = HashMap::new();
        let mut total_recv: u64 = 0;
        let mut addr_answered: HashSet<PeerId> = HashSet::new();
        loop {
            let event = tokio::select! {
                _ = shutdown.cancelled() => break,
                ev = inbound.recv() => match ev {
                    Some(ev) => ev,
                    None => break,
                },
            };
            match event {
                PeerEvent::Message(peer, msg) => {
                    let addr = peer.addr();
                    *recv_by_peer.entry(addr).or_insert(0) += 1;
                    total_recv += 1;

                    if let NetworkMessage::NotFound(inv) = &*msg {
                        broker.not_found(peer, inv).await;
                    }

                    // A block is settled on arrival, not when the wallet gets to it: blocks
                    // are processed in height order, so one can wait long behind a gap, and
                    // charging that wait to the peer reads as a queue and shrinks its cap.
                    // The first copy of a hedged block settles it: the other is a cancel.
                    if let NetworkMessage::Block(block) = &*msg {
                        broker.block_arrived(peer, block.block_hash()).await;
                    }

                    // Peers answer in order, so any answer means the peer is working
                    // through its queue: refresh all its requests, or one waiting behind
                    // big answers on a slow link would be judged stalled.
                    if matches!(
                        *msg,
                        NetworkMessage::CFilter(_)
                            | NetworkMessage::CFHeaders(_)
                            | NetworkMessage::Block(_)
                            | NetworkMessage::Headers(_)
                            | NetworkMessage::Headers2(_)
                    ) {
                        broker.progress(peer).await;
                    }
                    if total_recv.is_multiple_of(250_000) {
                        let mut dist: Vec<(SocketAddr, u64)> =
                            recv_by_peer.iter().map(|(a, c)| (*a, *c)).collect();
                        dist.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
                        tracing::info!(
                            target: "filt_depth",
                            "recv balance ({} peers, {} total): {:?}",
                            dist.len(),
                            total_recv,
                            dist,
                        );
                        let lat: Vec<(SocketAddr, u64, String)> = connected
                            .read()
                            .await
                            .iter()
                            .map(|p| {
                                let (n, avg, max) = p.latency_stats();
                                (p.addr(), n, format!("avg={avg:.1}ms max={max:.1}ms"))
                            })
                            .collect();
                        tracing::info!(
                            target: "filt_depth",
                            "peer latency: {:?}",
                            lat,
                        );
                    }
                    // Addr gossip feeds the discovery pool, otherwise it stays frozen at the seeds and
                    // one DNS lookup. Both spellings: a peer that ignored `sendaddrv2` answers
                    // `getaddr` with legacy `addr`.
                    let gossiped: Option<Vec<(SocketAddr, u32)>> = match &*msg {
                        NetworkMessage::AddrV2(addrs) if addrs.len() <= MAX_ADDR_PER_MESSAGE => {
                            Some(
                                addrs
                                    .iter()
                                    .filter(|a| a.services.has(ServiceFlags::NETWORK))
                                    .filter_map(|a| Some((a.socket_addr().ok()?, a.time)))
                                    .collect(),
                            )
                        }
                        NetworkMessage::Addr(addrs) if addrs.len() <= MAX_ADDR_PER_MESSAGE => Some(
                            addrs
                                .iter()
                                .filter(|(_, a)| a.services.has(ServiceFlags::NETWORK))
                                .filter_map(|(time, a)| Some((a.socket_addr().ok()?, *time)))
                                .collect(),
                        ),
                        _ => None,
                    }
                    .filter(|_| addr_answered.insert(peer));
                    if let Some(gossiped) = gossiped {
                        let learned = discoverer.lock().await.learn(gossiped);
                        if learned > 0 {
                            tracing::debug!(
                                target: "dash_spv::network",
                                "learned {} new peer address(es) from {}",
                                learned,
                                addr
                            );
                            // Fresh candidates are what a short set is waiting for.
                            if connected.read().await.len() < *max_peers {
                                peer_wake.notify_one();
                            }
                        }
                    }

                    let mt = MessageType::from_cmd(msg.cmd());
                    // Early router wake on inbound traffic (`release_request` notifies again for the
                    // real capacity). `cfilter` is skipped: only the last of ~1000 frees anything.
                    if mt != Some(MessageType::CFilter) {
                        broker.wake();
                    }

                    {
                        let mut subscribers = subscribers.lock().await;
                        if let Some(list) = mt.and_then(|t| subscribers.get_mut(&t)) {
                            let last = list.len().saturating_sub(1);
                            let mut msg = Some(Arc::new(msg));
                            let mut idx = 0;

                            list.retain(|tx| {
                                // Give the *last* subscriber our reference instead of a clone. Heavy types have
                                // one subscriber, so the manager gets refcount 1 and can take the payload uncopied.
                                let shared = if idx == last {
                                    msg.take().expect("taken once, on the final subscriber")
                                } else {
                                    Arc::clone(
                                        msg.as_ref().expect("held until the final subscriber"),
                                    )
                                };
                                idx += 1;

                                tx.send((addr, shared)).is_ok()
                            });
                        }
                    }
                }
                PeerEvent::Disconnected(peer) => {
                    addr_answered.remove(&peer);
                    let addr = peer.addr();
                    // By CONNECTION: this event can arrive for one that already left the set while
                    // the supervisor reconnected to the same address; matching by address would
                    // evict the live one. One that already left was announced by whoever removed
                    // it, and a probed backup never joined.
                    let departed = HashSet::from([peer]);
                    let (removed, remaining) = connected.remove(&departed).await;

                    if remaining < *max_peers {
                        peer_wake.notify_one();
                    }

                    // Requeue the departed peer's in-flight requests; the timeout monitor only watches
                    // connected peers, so they would otherwise leak in the registry.
                    let retried = broker.requeue_from(&departed).await;

                    if removed.is_empty() {
                        tracing::debug!(
                            target: "dash_spv::network",
                            "connection to {} closed outside the peer set | {} request(s) re-queued",
                            addr,
                            retried,
                        );
                    } else {
                        tracing::info!(
                            target: "dash_spv::network",
                            "peer disconnected: {} | {} peers remaining | {} request(s) re-queued",
                            addr,
                            remaining,
                            retried,
                        );
                    }
                    broker.wake();
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use crate::test_utils::test_socket_address;
    use dashcore::consensus::encode::serialize;
    use dashcore::network::address::Address;
    use dashcore::network::message::{RawNetworkMessage, RawNetworkMessageCodec};
    use dashcore::network::message_blockdata::Inventory;
    use dashcore::network::message_filter::{CFilter, GetCFilters};
    use dashcore::network::message_network::VersionMessage;
    use dashcore::{BlockHash, Network};
    use std::sync::atomic::AtomicUsize;
    use test_case::test_case;
    use tokio::io::AsyncWriteExt;
    use tokio::net::tcp::OwnedWriteHalf;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task;
    use tokio::time;
    use tokio_util::codec::FramedRead;

    fn get_cfilters(start: u32) -> NetworkMessage {
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: start,
            stop_hash: BlockHash::dummy(9),
        })
    }

    fn block(n: u32) -> Inventory {
        Inventory::Block(BlockHash::dummy(n))
    }

    fn conn(addr: u8, n: u64) -> PeerId {
        PeerId::for_test(test_socket_address(addr), n)
    }

    /// `start()` is never called, so nothing touches the network.
    async fn broker() -> PeerNetworkManager {
        let config = ClientConfig::regtest().with_restrict_to_configured_peers(true);
        PeerNetworkManager::new(&config).await
    }

    /// Advances the clock `secs` seconds while peer `id` receives a whole `ping` each second
    /// through its far end `far`.
    async fn advance_receiving(
        net: &PeerNetworkManager,
        id: PeerId,
        far: &mut OwnedWriteHalf,
        secs: u64,
    ) {
        let ping = serialize(&RawNetworkMessage {
            magic: Network::Regtest.magic(),
            payload: NetworkMessage::Ping(1),
        });
        for _ in 0..secs {
            time::advance(TIMEOUT_CHECK).await;
            deliver(net, id, far, &ping).await;
            settle().await;
        }
    }

    /// Writes `bytes` to the far end `far` of peer `id` and waits until the peer's reader
    /// counted them. Socket readiness does not follow the paused clock, so a tick could
    /// otherwise miss bytes already written. A kicked peer's closed socket is skipped.
    async fn deliver(net: &PeerNetworkManager, id: PeerId, far: &mut OwnedWriteHalf, bytes: &[u8]) {
        let read = || async {
            net.state.connected.read().await.iter().find(|p| p.id() == id).map(|p| p.bytes_read())
        };
        let Some(before) = read().await else {
            return;
        };
        if far.write_all(bytes).await.is_err() {
            return;
        }
        let target = before + bytes.len() as u64;
        for _ in 0..100_000 {
            match read().await {
                Some(read) if read < target => task::yield_now().await,
                _ => return,
            }
        }
        panic!("the reader of {id:?} never counted {} bytes", bytes.len());
    }

    /// Advances the clock `secs` seconds in flow controller ticks, nobody receiving.
    async fn advance_silent(secs: u64) {
        for _ in 0..secs * 4 {
            time::advance(FLOW_TICK).await;
            settle().await;
        }
    }

    /// A framed `cfilter` for a peer to receive. Its block hash is not the stop hash of
    /// [`get_cfilters`], so it settles no charge and the peer's work stays in flight.
    fn unsettling_filter() -> Vec<u8> {
        serialize(&RawNetworkMessage {
            magic: Network::Regtest.magic(),
            payload: NetworkMessage::CFilter(CFilter {
                filter_type: 0,
                block_hash: BlockHash::dummy(1),
                filter: vec![0; 32 * 1024],
            }),
        })
    }

    /// A connected peer that receives a run of [`unsettling_filter`]s at its own rate.
    struct Feeder {
        id: PeerId,
        handle: PeerHandle,
        far: OwnedWriteHalf,
        rate: u64,
        sent: usize,
    }

    impl Feeder {
        /// Delivers what the peer receives in one [`FLOW_TICK`].
        async fn tick(&mut self, net: &PeerNetworkManager, frame: &[u8]) {
            let mut due = (self.rate as f64 * FLOW_TICK.as_secs_f64()) as usize;
            while due > 0 {
                let at = self.sent % frame.len();
                let piece = &frame[at..frame.len().min(at + due)];
                deliver(net, self.id, &mut self.far, piece).await;
                self.sent += piece.len();
                due -= piece.len();
            }
        }
    }

    /// Connects peer `n + 1` for each of `rates` and feeds it `rates[n]` bytes/s until the
    /// flow controller has measured how fast every peer serves.
    async fn measured_peers(net: &PeerNetworkManager, rates: &[u64]) -> Vec<Feeder> {
        let session = net.session.lock().await.clone();
        let mut feeders = Vec::new();
        for (n, &rate) in rates.iter().enumerate() {
            let id = conn(n as u8 + 1, 0);
            let (peer, far) = ConnectedPeer::for_test_reading(id, net.state.clone()).await;
            let handle = peer.handle();
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
            feeders.push(Feeder {
                id,
                handle,
                far,
                rate,
                sent: 0,
            });
        }
        feed(net, &mut feeders, SERVING_SAMPLE_TICKS * 2).await;
        let measured = net.state.connected.read().await.iter().all(|p| p.serving_rate() > 0);
        assert!(measured, "every peer has a serving rate");
        feeders
    }

    /// Feeds every peer at its rate for `ticks` flow controller ticks, with work up to its
    /// cap, as bulk download keeps it.
    async fn feed(net: &PeerNetworkManager, feeders: &mut [Feeder], ticks: u32) {
        let frame = unsettling_filter();
        for _ in 0..ticks {
            for feeder in feeders.iter() {
                while feeder.handle.in_flight_bytes() < feeder.handle.cap() {
                    let _ = feeder.handle.send(&get_cfilters(0)).await;
                }
            }
            time::advance(FLOW_TICK).await;
            for feeder in feeders.iter_mut() {
                feeder.tick(net, &frame).await;
            }
            settle().await;
        }
    }

    /// The peers' serving rates, by connection.
    async fn serving_rates(net: &PeerNetworkManager) -> Vec<u64> {
        net.state.connected.read().await.iter().map(ConnectedPeer::serving_rate).collect()
    }

    /// A peer on loopback that answers the version handshake once `go` is notified, then
    /// answers pings.
    struct HandshakingPeer {
        addr: SocketAddr,
        go: Arc<Notify>,
        accepted: Arc<AtomicUsize>,
        /// Whether a ping came after the handshake, which the client sends last.
        pinged: Arc<AtomicBool>,
        /// Whether the client closed the connection.
        closed: Arc<AtomicBool>,
    }

    impl HandshakingPeer {
        async fn listen() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
            let peer = HandshakingPeer {
                addr: listener.local_addr().expect("bound address"),
                go: Arc::new(Notify::new()),
                accepted: Arc::new(AtomicUsize::new(0)),
                pinged: Arc::new(AtomicBool::new(false)),
                closed: Arc::new(AtomicBool::new(false)),
            };
            let (addr, go) = (peer.addr, peer.go.clone());
            let (accepted, pinged, closed) =
                (peer.accepted.clone(), peer.pinged.clone(), peer.closed.clone());
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let (go, pinged, closed) = (go.clone(), pinged.clone(), closed.clone());
                    tokio::spawn(answer_handshake(stream, addr, go, pinged, closed));
                }
            });
            peer
        }
    }

    /// Answers the client's version handshake on `stream` once `go` is notified, then its
    /// pings, for [`HandshakingPeer`].
    async fn answer_handshake(
        stream: TcpStream,
        addr: SocketAddr,
        go: Arc<Notify>,
        pinged: Arc<AtomicBool>,
        closed: Arc<AtomicBool>,
    ) {
        stream.set_nodelay(true).expect("loopback nodelay");
        let (read, mut write) = stream.into_split();
        let mut frames = FramedRead::new(read, RawNetworkMessageCodec);
        let framed = |payload| {
            serialize(&RawNetworkMessage {
                magic: Network::Regtest.magic(),
                payload,
            })
        };
        while let Some(Ok(raw)) = frames.next().await {
            if matches!(raw.payload, NetworkMessage::Version(_)) {
                break;
            }
        }
        go.notified().await;
        let services = ServiceFlags::NETWORK | ServiceFlags::COMPACT_FILTERS | ServiceFlags::BLOOM;
        let version = VersionMessage::new(
            services,
            0,
            Address::new(&addr, ServiceFlags::NONE),
            Address::new(&addr, services),
            1,
            "/handshaking/".into(),
            0,
            false,
            [0; 32],
        );
        let mut hello = framed(NetworkMessage::Version(version));
        hello.extend(framed(NetworkMessage::Verack));
        let _ = write.write_all(&hello).await;
        while let Some(Ok(raw)) = frames.next().await {
            if let NetworkMessage::Ping(nonce) = raw.payload {
                pinged.store(true, Ordering::SeqCst);
                let _ = write.write_all(&framed(NetworkMessage::Pong(nonce))).await;
            }
        }
        closed.store(true, Ordering::SeqCst);
    }

    /// Lets the spawned tasks run what the last time advance made due.
    async fn settle() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    /// The events received until none arrives for a while.
    async fn drain(events: &mut broadcast::Receiver<NetworkEvent>) -> Vec<NetworkEvent> {
        let mut received = Vec::new();
        while let Ok(event) = tokio::time::timeout(Duration::from_millis(200), events.recv()).await
        {
            received.push(event.expect("channel open"));
        }
        received
    }

    /// A peer's flow, driven tick by tick as the flow controller would.
    struct Served {
        flow: PeerFlow,
        bytes: u64,
        cap: u64,
    }

    impl Served {
        fn new() -> Self {
            Self {
                flow: PeerFlow::new(0),
                bytes: 0,
                cap: MIN_CAP_BYTES,
            }
        }

        fn tick(&mut self, delivered: u64, in_flight: u64, link_full: bool) {
            self.bytes += delivered;
            self.cap = self.flow.tick(self.bytes, in_flight, link_full, false);
        }

        /// Bulk download at `rate` bytes/s. The router keeps the peer at its own cap, or
        /// at half of it when the client's link cap binds first.
        fn bulk(&mut self, rate: u64, link_full: bool, ticks: u32) {
            let delivered = (rate as f64 * FLOW_TICK.as_secs_f64()) as u64;
            for _ in 0..ticks {
                let in_flight = if link_full {
                    self.cap / 2
                } else {
                    self.cap
                };
                self.tick(delivered, in_flight, link_full);
            }
        }

        /// Small replies as at the chain tip, each answered `latency` ticks after its
        /// request and followed by ten quiet seconds.
        fn replies(&mut self, latency: u32, count: u32) {
            const REPLY_BYTES: u64 = 4 * 1024;
            for _ in 0..count {
                for _ in 1..latency {
                    self.tick(0, REPLY_BYTES, false);
                }
                self.tick(REPLY_BYTES, 0, false);
                for _ in 0..40 {
                    self.tick(0, 0, false);
                }
            }
        }
    }

    /// Only a peer serving all the work its caps allow is compared. Small replies at the
    /// tip measure the round trip, so a far peer must not look slow for them.
    #[test_case(1_000_000, false, true => None; "latency bound replies at the tip")]
    #[test_case(100_000, false, false => Some(1); "a slow peer at its own cap")]
    #[test_case(100_000, true, false => Some(1); "a slow peer held back by the link cap")]
    #[tokio::test]
    async fn only_bandwidth_bound_service_condemns_a_peer(
        second_rate: u64,
        link_full: bool,
        then_idle: bool,
    ) -> Option<usize> {
        let mut served = [Served::new(), Served::new()];
        for (s, rate) in served.iter_mut().zip([1_000_000, second_rate]) {
            s.bulk(rate, link_full, SERVING_SAMPLE_TICKS * 10);
            assert!(s.flow.serving_rate() > 0, "a bandwidth bound peer is measured");
        }
        if then_idle {
            served[0].replies(1, 50);
            served[1].replies(8, 50);
        }
        let mut peers = Vec::new();
        for (n, s) in served.iter().enumerate() {
            let peer = ConnectedPeer::for_test(conn(n as u8, 0)).await;
            peer.set_serving_rate(s.flow.serving_rate());
            peers.push(peer);
        }
        let slow = underserving_peer(&peers)?;
        peers.iter().position(|p| p.addr() == slow.addr)
    }

    #[test]
    fn headers_carry_the_hashes_computed_while_decompressing_them() {
        let header = Header::dummy(1);
        let hash = header.block_hash();
        let msg = InboundMessage::new_headers(vec![(header, hash)]);

        assert_eq!(msg.header_hashes(), Some([hash].as_slice()));
        assert_eq!(*msg, NetworkMessage::Headers(vec![header]));
        assert_eq!(InboundMessage::new(NetworkMessage::Verack).header_hashes(), None);
    }

    enum Departure {
        Drop,
        Kick,
        Stop,
    }

    /// Subscribers mirror the peer set from these events, so every departure is
    /// announced exactly once, every `PeersUpdated` lists the peers the other events
    /// left, and the last list is empty, which is what the sync layer acts on. A connection's own disconnect arriving after it left the set
    /// stays silent, and a handshake completing while `stop` runs never joins.
    #[test_case(Departure::Drop, 2; "the peers drop")]
    #[test_case(Departure::Kick, 2; "the timeout monitor kicks them")]
    #[test_case(Departure::Stop, 2; "the network stops")]
    #[test_case(Departure::Stop, 0; "the network stops while connecting its first peers")]
    #[tokio::test(start_paused = true)]
    async fn a_departed_peer_is_announced_once(departure: Departure, joined: u8) {
        let net = broker().await;
        let session = net.session.lock().await.clone();
        let mut events = net.events();
        let peers: Vec<PeerId> = (1..=joined).map(|n| conn(n, 0)).collect();
        for (start, id) in peers.iter().enumerate() {
            let peer = ConnectedPeer::for_test(*id).await;
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
            net.state.broker.mark_on_wire(&get_cfilters(start as u32), *id).await;
        }
        let disconnect_all = || {
            for id in &peers {
                net.state.inbound.send(PeerEvent::Disconnected(*id)).expect("the pump is running");
            }
        };

        let mut late = None;
        match departure {
            Departure::Drop => disconnect_all(),
            Departure::Kick => {
                // Silent past the bound, the peers go one per timeout.
                for _ in 0..2 {
                    time::advance(REQUEST_TIMEOUT * LINK_STALL_TIMEOUTS + TIMEOUT_CHECK).await;
                    settle().await;
                }
                // No peer witnessed the silence, so it may have been our link's.
                assert!(net.state.bans.banned().await.is_empty(), "a held peer was banned");
            }
            Departure::Stop => {
                net.stop().await;
                // A handshake that completed while `stop` ran.
                let peer = ConnectedPeer::for_test(conn(9, 0)).await;
                late = Some(
                    net.state.connected.admit(peer, &session, net.state.max_peers, None).await,
                );
            }
        }
        let received = drain(&mut events).await;
        let mut tracked = HashSet::new();
        for event in &received {
            match event {
                NetworkEvent::PeerConnected(addr) => {
                    tracked.insert(*addr);
                }
                NetworkEvent::PeerDisconnected(addr) => {
                    tracked.remove(addr);
                }
                NetworkEvent::PeersUpdated {
                    addresses,
                    ..
                } => {
                    let listed: HashSet<_> = addresses.iter().copied().collect();
                    assert_eq!(listed, tracked, "got {received:?}");
                }
            }
        }
        assert!(tracked.is_empty(), "connected peers never announced as gone: {received:?}");
        let mut departed: Vec<_> = received
            .iter()
            .filter_map(|event| match event {
                NetworkEvent::PeerDisconnected(addr) => Some(*addr),
                _ => None,
            })
            .collect();
        departed.sort();
        let expected: Vec<_> = peers.iter().map(|id| id.addr()).collect();
        assert_eq!(departed, expected, "got {received:?}");
        let last_listed = received.iter().rev().find_map(|event| match event {
            NetworkEvent::PeersUpdated {
                addresses,
                ..
            } => Some(addresses.clone()),
            _ => None,
        });
        assert_eq!(last_listed, (joined > 0).then(Vec::new), "got {received:?}");
        assert!(late.is_none_or(|admitted| matches!(admitted, Admission::Stopped(_))));

        disconnect_all();
        let late = drain(&mut events).await;
        assert!(late.is_empty(), "late disconnects were announced again: {late:?}");
        assert_eq!(net.connected_count().await, 0);
    }

    enum Feed {
        Nothing,
        /// A complete answer from this peer every second.
        Answers(u8),
        /// More bytes of one long message from this peer every second.
        Streams(u8),
        /// Small complete messages, such as pings, from this peer every second.
        Chatters(u8),
    }

    /// Peer 1 carries a request for `secs` seconds while idle peer 2 keeps receiving.
    #[test_case(Feed::Nothing, 12, true; "a silent request")]
    #[test_case(Feed::Answers(1), 20, false; "the carrier answering keeps it alive")]
    #[test_case(Feed::Answers(2), 12, true; "another peer answering is not progress")]
    #[test_case(Feed::Streams(1), 55, false; "the carrier streaming one long answer keeps it alive")]
    #[test_case(Feed::Streams(1), 61, true; "the carrier streaming one answer past the bound stalls")]
    #[test_case(Feed::Streams(2), 12, true; "another peer streaming is not progress")]
    #[test_case(Feed::Chatters(1), 12, true; "the carrier sending only small messages stalls")]
    #[tokio::test(start_paused = true)]
    async fn the_timeout_monitor_requeues_stalled_requests(feed: Feed, secs: u64, stalls: bool) {
        let net = broker().await;
        let session = net.session.lock().await.clone();
        let mut far_ends = Vec::new();
        for n in 1..=2 {
            let (peer, far) = ConnectedPeer::for_test_reading(conn(n, 0), net.state.clone()).await;
            far_ends.push(far);
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
        }
        net.state.broker.mark_on_wire(&get_cfilters(0), conn(1, 0)).await;
        let framed = |payload| {
            serialize(&RawNetworkMessage {
                magic: Network::Regtest.magic(),
                payload,
            })
        };
        let long_answer = framed(NetworkMessage::CFilter(CFilter {
            filter_type: 0,
            block_hash: BlockHash::dummy(1),
            filter: vec![0; 100_000],
        }));
        let ping = framed(NetworkMessage::Ping(1));

        for second in 0..secs as usize {
            tokio::time::advance(TIMEOUT_CHECK).await;
            // Peer 2 proves our link works, unless the feed already sends it bytes.
            if !matches!(feed, Feed::Streams(2) | Feed::Chatters(2)) {
                deliver(&net, conn(2, 0), &mut far_ends[1], &ping).await;
            }
            match feed {
                Feed::Nothing => {}
                Feed::Answers(peer) => {
                    let piece = NetworkMessage::CFilter(CFilter {
                        filter_type: 0,
                        block_hash: BlockHash::dummy(1),
                        filter: vec![0u8; 4],
                    });
                    net.state
                        .inbound
                        .send(PeerEvent::Message(conn(peer, 0), piece.into()))
                        .expect("the pump is running");
                }
                Feed::Streams(peer) => {
                    let piece = &long_answer[second * 1000..(second + 1) * 1000];
                    deliver(&net, conn(peer, 0), &mut far_ends[peer as usize - 1], piece).await;
                }
                Feed::Chatters(peer) => {
                    deliver(&net, conn(peer, 0), &mut far_ends[peer as usize - 1], &ping).await;
                }
            }
            settle().await;
        }

        // A stalled request is re-queued and may already be routed to peer 2.
        let carrier = net.state.broker.carrier_of(&RequestKey::CFilters(0)).await;
        assert_eq!(carrier == Some(conn(1, 0)), !stalls, "carrier {carrier:?}");
        let banned = net.state.bans.banned().await.contains(&conn(1, 0).addr());
        assert_eq!(banned, stalls, "a peer kicked beside a witness is banned");
    }

    /// A timeout kick re-queues the stalled peer's work only once that peer is closed and out
    /// of the set, so no router snapshot can hand the work back. Holding the filter queue
    /// stops the monitor at that point. The work then goes to the peer that stays.
    #[tokio::test(start_paused = true)]
    async fn a_kicked_peer_gets_none_of_its_requeued_work() {
        let net = broker().await;
        let session = net.session.lock().await.clone();
        let stalled = ConnectedPeer::for_test(conn(1, 0)).await;
        let (witness, mut witness_far) =
            ConnectedPeer::for_test_reading(conn(2, 0), net.state.clone()).await;
        let handles = [stalled.handle(), witness.handle()];
        for peer in [stalled, witness] {
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
        }
        net.state.broker.mark_on_wire(&get_cfilters(0), conn(1, 0)).await;

        let held = net.state.broker.hold_queue_of(&get_cfilters(0)).await;
        // The second peer keeps receiving, so the stall is not blamed on our link.
        advance_receiving(&net, conn(2, 0), &mut witness_far, REQUEST_TIMEOUT.as_secs() + 2).await;
        let key = RequestKey::CFilters(0);
        assert_eq!(
            net.state.broker.state_of(&key).await,
            Some("queued"),
            "the monitor reached the re-queue"
        );
        assert_eq!(net.connected_count().await, 1, "re-queued before the kick");
        assert!(handles[0].is_closed(), "re-queued before the stalled peer was closed");
        drop(held);
        for _ in 0..4 {
            task::yield_now().await;
        }

        assert_eq!(net.state.broker.state_of(&key).await, Some("on_wire"));
        assert_eq!(handles[0].in_flight_bytes(), 0, "work went back to the kicked peer");
        assert!(handles[1].in_flight_bytes() > 0, "the peer that stays carries the work");
    }

    /// A peer that was silent while idle is timed from the request it is given, and
    /// kicked only when it stays silent with that work for the full timeout.
    #[tokio::test(start_paused = true)]
    async fn the_timeout_monitor_times_an_idle_peer_from_its_first_request() {
        let net = broker().await;
        let session = net.session.lock().await.clone();
        let peer = ConnectedPeer::for_test(conn(1, 0)).await;
        let handle = peer.handle();
        let (witness, mut witness_far) =
            ConnectedPeer::for_test_reading(conn(2, 0), net.state.clone()).await;
        for peer in [peer, witness] {
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
        }

        // The second peer keeps receiving, so a stall is not blamed on our link.
        advance_receiving(&net, conn(2, 0), &mut witness_far, REQUEST_TIMEOUT.as_secs() * 3).await;
        // Only the charge matters here: the loopback has no reader to answer it.
        let _ = handle.send(&get_cfilters(0)).await;
        assert!(handle.in_flight_bytes() > 0);

        advance_receiving(&net, conn(2, 0), &mut witness_far, 2).await;
        assert_eq!(net.connected_count().await, 2, "kicked right after its first request");

        advance_receiving(&net, conn(2, 0), &mut witness_far, REQUEST_TIMEOUT.as_secs()).await;
        assert_eq!(net.connected_count().await, 1, "a peer silent with work stays connected");
    }

    /// What a peer of the set does, second by second.
    #[derive(Clone, Copy)]
    enum Role {
        /// Holds a request the registry tracks and receives bytes until this second.
        Registered(u64),
        /// Owes bytes the registry does not track and receives bytes until this second.
        Charged(u64),
        /// Idle, and receives bytes from this second on.
        Delivers(u64),
        /// Connects at this second, idle, and receives nothing.
        Joins(u64),
        /// Owes bytes. Receives until the time in the first field and again from the time
        /// in the second, both in seconds.
        Resumes(u64, u64),
        /// Idle, and receives bytes every this many seconds.
        Whispers(u64),
        /// Holds a request the registry tracks and receives small whole messages from
        /// this second on.
        Chatters(u64),
        /// Owes bytes. Repeats being silent for the first field's seconds and receiving for
        /// the second's.
        Flaps(u64, u64),
        /// Holds a request the registry tracks, sent this many milliseconds in, and receives
        /// nothing.
        Asks(u64),
        /// Holds a request the registry tracks and receives part of its answer every this many
        /// seconds, never all of it.
        Streams(u64),
    }

    /// Peer `n + 1` plays `roles[n]` for `secs` seconds. `link_stalled` is whether the
    /// judge then suspects our own link, `unbanned` the peers kicked with no witness.
    #[test_case(&[Role::Registered(0); 3], 11, &[1, 2, 3], true, &[]; "a stall of every peer at once is our link")]
    #[test_case(&[Role::Registered(0); 3], 41, &[1, 2, 3], true, &[]; "a 40 s silence of every peer kicks nobody")]
    #[test_case(&[Role::Registered(0); 3], 71, &[2, 3], true, &[1]; "every peer silent past the bound loses the one silent the longest")]
    #[test_case(&[Role::Registered(0); 3], 72, &[3], true, &[1, 2]; "every peer silent past the bound loses one per timeout")]
    #[test_case(&[Role::Charged(0); 3], 25, &[1, 2, 3], true, &[]; "a long stall of every peer is still our link")]
    #[test_case(&[Role::Registered(1), Role::Registered(2), Role::Registered(3)], 25, &[1, 2, 3], true, &[]; "peers going silent a second apart in an outage stay")]
    #[test_case(&[Role::Charged(1), Role::Charged(2), Role::Charged(3)], 25, &[1, 2, 3], true, &[]; "peers owing bytes and going silent a second apart stay")]
    #[test_case(&[Role::Delivers(0), Role::Registered(0), Role::Delivers(0)], 12, &[1, 3], false, &[]; "a lone silent request among delivering peers is kicked")]
    #[test_case(&[Role::Delivers(0), Role::Charged(0), Role::Delivers(0)], 12, &[1, 3], false, &[]; "a lone peer owing bytes among delivering peers is kicked")]
    #[test_case(&[Role::Delivers(0), Role::Asks(1500), Role::Delivers(0)], 12, &[1, 3], false, &[]; "a request sent between ticks is kicked on the first tick past its timeout")]
    #[test_case(&[Role::Streams(3)], 61, &[], false, &[]; "a sole peer streaming a never finished answer is kicked at the answer bound")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(0)], 12, &[2, 3], false, &[]; "two stalls beside a delivering peer kick one")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(0)], 23, &[2], false, &[]; "the second stall goes a timeout later")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(1)], 12, &[2, 3], false, &[]; "stalls a second apart beside a delivering peer go one per timeout")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(2)], 14, &[2, 3], false, &[]; "stalls two seconds apart beside a delivering peer go one per timeout")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(1), Role::Joins(11)], 12, &[2, 3, 4], false, &[]; "a replacement joining does not unpace the next stall")]
    #[test_case(&[Role::Registered(0), Role::Delivers(13), Role::Registered(1)], 24, &[2, 3], false, &[]; "a late witness kicks the peer silent the longest a timeout later")]
    #[test_case(&[Role::Resumes(5, 20), Role::Resumes(5, 20), Role::Charged(5)], 25, &[1, 2, 3], true, &[]; "a peer still silent when the link is back gets a timeout")]
    #[test_case(&[Role::Resumes(5, 20), Role::Resumes(5, 20), Role::Charged(5)], 31, &[1, 2], false, &[]; "a peer silent a timeout after the link is back is kicked")]
    #[test_case(&[Role::Charged(0), Role::Whispers(3)], 32, &[1, 2], true, &[]; "a lone peer owing bytes beside a pinging idle one is held while the pings add up")]
    #[test_case(&[Role::Charged(0), Role::Whispers(3)], 33, &[2], false, &[]; "a lone peer owing bytes beside a pinging idle one is kicked once they add up to a timeout")]
    #[test_case(&[Role::Registered(0)], 41, &[1], true, &[]; "a sole silent peer stays through a 40 s outage")]
    #[test_case(&[Role::Registered(0)], 61, &[], false, &[1]; "a sole silent peer is kicked past the bound")]
    #[test_case(&[Role::Registered(0), Role::Registered(0), Role::Joins(12)], 13, &[1, 2, 3], true, &[]; "a peer joining during an outage proves nothing")]
    #[test_case(&[Role::Charged(0), Role::Delivers(30)], 15, &[1, 2], true, &[]; "a lone peer owing bytes beside a quiet idle one is held")]
    #[test_case(&[Role::Registered(0), Role::Registered(0), Role::Delivers(25)], 34, &[1, 2, 3], true, &[]; "an idle peer receiving first after an outage gives the held peers a timeout")]
    #[test_case(&[Role::Registered(0), Role::Registered(0), Role::Delivers(25)], 36, &[2, 3], false, &[]; "held peers silent a timeout after an idle peer receives go")]
    #[test_case(&[Role::Registered(0), Role::Registered(0), Role::Delivers(25)], 47, &[3], false, &[]; "held peers silent after an idle peer receives go one per timeout")]
    #[test_case(&[Role::Charged(0), Role::Whispers(10)], 67, &[1, 2], true, &[]; "a lone peer owing bytes beside sparse traffic is held up to the bound")]
    #[test_case(&[Role::Charged(0), Role::Whispers(10)], 68, &[2], false, &[1]; "a lone peer owing bytes beside sparse traffic is kicked at the bound")]
    #[test_case(&[Role::Resumes(0, 55), Role::Charged(0)], 64, &[1, 2], true, &[]; "a peer silent through a 55 s outage gets a timeout after it")]
    #[test_case(&[Role::Resumes(0, 55), Role::Charged(0)], 65, &[1], false, &[]; "a peer silent a timeout after a 55 s outage is kicked")]
    #[test_case(&[Role::Chatters(0)], 12, &[], false, &[]; "a sole peer receiving only small messages is kicked")]
    #[test_case(&[Role::Chatters(25); 3], 36, &[2, 3], false, &[]; "peers receiving only small messages after an outage go one per timeout")]
    #[test_case(&[Role::Charged(0), Role::Flaps(12, 5)], 46, &[1, 2], true, &[]; "a dead peer beside a flapping link is held while its uptime adds up")]
    #[test_case(&[Role::Charged(0), Role::Flaps(12, 5)], 47, &[2], false, &[]; "a dead peer beside a flapping link is kicked once its uptime adds up to a timeout")]
    #[test_case(&[Role::Charged(0), Role::Flaps(3, 7), Role::Flaps(3, 7)], 16, &[1, 2, 3], true, &[]; "a dead peer beside peers pausing together is held while their uptime adds up")]
    #[test_case(&[Role::Charged(0), Role::Flaps(3, 7), Role::Flaps(3, 7)], 17, &[2, 3], false, &[]; "a dead peer beside peers pausing together is kicked once their uptime adds up")]
    #[test_case(&[Role::Charged(0), Role::Delivers(0), Role::Flaps(3, 1), Role::Flaps(3, 1)], 12, &[2, 3, 4], false, &[]; "a dead peer beside an idle stream and owing peers with gaps is kicked")]
    #[test_case(&[Role::Charged(0), Role::Resumes(0, 12)], 21, &[1, 2], true, &[]; "a peer silent with one resuming on the timeout tick gets a timeout")]
    #[test_case(&[Role::Charged(0), Role::Resumes(0, 12)], 22, &[2], false, &[]; "a peer silent with one resuming on the timeout tick is kicked a timeout later")]
    #[test_case(&[Role::Charged(0), Role::Resumes(3, 9)], 16, &[1, 2], true, &[]; "a peer silent across a 5 s outage gets a timeout of uptime")]
    #[test_case(&[Role::Charged(0), Role::Resumes(3, 9)], 17, &[2], false, &[]; "a peer silent across a 5 s outage is kicked after a timeout of uptime")]
    #[test_case(&[Role::Charged(0), Role::Resumes(0, 40)], 49, &[1, 2], true, &[]; "a peer silent through a 40 s outage gets a timeout after it")]
    #[test_case(&[Role::Charged(0), Role::Resumes(0, 40)], 50, &[2], false, &[]; "a peer silent a timeout after a 40 s outage is kicked")]
    #[test_case(&[Role::Registered(0), Role::Registered(0), Role::Registered(0), Role::Charged(20)], 34, &[4], true, &[]; "stalls paced past the link's last uptime keep their witness")]
    fn the_stall_judge_kicks_one_peer_per_shared_stall(
        roles: &[Role],
        secs: u64,
        kept: &[u8],
        link_stalled: bool,
        unbanned: &[u8],
    ) {
        // Every received byte but a chatter's is part of an answer still arriving.
        let peer = |n: u8, role: Role| Observed {
            id: conn(n, 0),
            bytes: 0,
            partial: !matches!(role, Role::Chatters(_)),
            in_flight: matches!(role, Role::Charged(_) | Role::Resumes(..) | Role::Flaps(..))
                .into(),
            timeout: REQUEST_TIMEOUT,
        };
        let start = Instant::now();
        let mut peers: Vec<Observed> = (1..)
            .zip(roles)
            .filter(|(_, role)| !matches!(role, Role::Joins(_)))
            .map(|(n, &role)| peer(n, role))
            .collect();
        // When each registered request was sent, and its last progress. None is answered.
        let mut requests: HashMap<PeerId, (Instant, Instant)> = (1..)
            .zip(roles)
            .filter_map(|(n, &role)| {
                let sent = match role {
                    Role::Registered(_) | Role::Chatters(_) | Role::Streams(_) => start,
                    Role::Asks(ms) => start + Duration::from_millis(ms),
                    _ => return None,
                };
                Some((conn(n, 0), (sent, sent)))
            })
            .collect();
        let mut judge = StallJudge::default();
        let mut kicked_unbanned = Vec::new();

        for second in 1..=secs {
            for (n, &role) in (1..).zip(roles) {
                let receives = match role {
                    Role::Registered(until) | Role::Charged(until) => second <= until,
                    Role::Delivers(from) | Role::Chatters(from) => second >= from,
                    Role::Resumes(until, from) => second <= until || second >= from,
                    Role::Whispers(period) | Role::Streams(period) => second.is_multiple_of(period),
                    Role::Asks(_) => false,
                    Role::Flaps(silent, receiving) => (second - 1) % (silent + receiving) >= silent,
                    Role::Joins(at) => {
                        if second == at {
                            peers.push(peer(n, role));
                        }
                        false
                    }
                };
                if let Some(p) = peers.iter_mut().find(|p| receives && p.id == conn(n, 0)) {
                    p.bytes += 100;
                }
            }
            let now = start + Duration::from_secs(second);
            for id in judge.observe(now, &peers) {
                if let Some((_, progress)) = requests.get_mut(&id) {
                    *progress = now;
                }
            }
            // As `Broker::expire` blames a request: from its progress, or from its answer.
            let stalled = requests
                .iter()
                .filter_map(|(&id, &(sent, progress))| {
                    if now.duration_since(progress) > REQUEST_TIMEOUT {
                        Some((id, progress))
                    } else {
                        (now.duration_since(sent) > REQUEST_TIMEOUT * ANSWER_TIMEOUTS)
                            .then_some((id, sent))
                    }
                })
                .collect();
            let (kicked, _, unwitnessed) = judge.judge(now, &peers, stalled);
            assert!(kicked.len() <= 1, "second {second} kicked {kicked:?}");
            kicked_unbanned.extend(unwitnessed);
            peers.retain(|p| !kicked.contains(&p.id));
            requests.retain(|id, _| !kicked.contains(id));
        }

        let left: Vec<PeerId> = peers.iter().map(|p| p.id).collect();
        let kept: Vec<PeerId> = kept.iter().map(|&n| conn(n, 0)).collect();
        assert_eq!(left, kept);
        assert_eq!(judge.link_stalled, link_stalled);
        let unbanned: Vec<PeerId> = unbanned.iter().map(|&n| conn(n, 0)).collect();
        assert_eq!(kicked_unbanned, unbanned, "kicked without a ban");
    }

    /// A peer's silence with work drags its serving rate. Once every peer is silent long
    /// enough for the judge to hold them as a possible stall of our own link, the flow
    /// controller leaves the rates alone, since such a stall says nothing about the peers.
    #[tokio::test(start_paused = true)]
    async fn a_stall_of_our_link_leaves_the_serving_rates_alone() {
        let net = broker().await;
        let _feeders = measured_peers(&net, &[1 << 20, 200 << 10]).await;
        let measured = serving_rates(&net).await;

        advance_silent(REQUEST_TIMEOUT.as_secs() + 2).await;
        let held = serving_rates(&net).await;
        assert!(held.iter().zip(&measured).all(|(h, m)| h < m), "{held:?} vs {measured:?}");

        advance_silent(REQUEST_TIMEOUT.as_secs() * 3).await;
        assert_eq!(serving_rates(&net).await, held);
        assert_eq!(net.connected_count().await, 2, "a held peer was kicked");
    }

    /// Peer 2 serves a fifth of peer 1's rate, then both go silent and the supervisor starts
    /// `start_at` seconds in. While the judge holds them it must not swap peer 2 out, nor dial
    /// once the hold began. When the peers deliver again, the held back swap goes ahead.
    #[test_case(REQUEST_TIMEOUT.as_secs() + 2, 0; "a round during the stall dials nobody")]
    #[test_case(REQUEST_TIMEOUT.as_secs() - 2, 1; "a stall during the dial keeps the slow peer")]
    #[tokio::test(start_paused = true)]
    async fn no_slow_peer_is_swapped_out_while_our_link_stalls(start_at: u64, dials: usize) {
        let replacement = HandshakingPeer::listen().await;
        let mut config = ClientConfig::regtest().with_restrict_to_configured_peers(true);
        config.add_peer(replacement.addr);
        config.max_peers = 2;
        config.transport_preference = TransportPreference::V1Only;
        let net = PeerNetworkManager::new(&config).await;
        let mut feeders = measured_peers(&net, &[1 << 20, 200 << 10]).await;
        let slow = feeders[1].handle.clone();

        advance_silent(start_at).await;
        net.start().await;
        settle().await;
        advance_silent((REQUEST_TIMEOUT.as_secs() + 2).saturating_sub(start_at)).await;
        replacement.go.notify_one();
        for _ in 0..100_000 {
            if replacement.closed.load(Ordering::SeqCst) || slow.is_closed() {
                break;
            }
            task::yield_now().await;
        }

        assert_eq!(replacement.accepted.load(Ordering::SeqCst), dials);
        assert_eq!(replacement.pinged.load(Ordering::SeqCst), dials > 0, "handshake finished");
        assert!(!slow.is_closed(), "the slow peer was swapped out");
        assert_eq!(net.connected_count().await, 2);

        // The peers deliver again, which proves our link works, and the held back swap goes
        // ahead. Nothing but the pick of a slow peer wakes a full supervisor.
        replacement.go.notify_one();
        for _ in 0..8 * 4 {
            feed(&net, &mut feeders, 1).await;
            if slow.is_closed() {
                break;
            }
        }
        assert!(slow.is_closed(), "the slow peer was kept once our link recovered");
        assert_eq!(replacement.accepted.load(Ordering::SeqCst), dials + 1);
        assert_eq!(net.connected_count().await, 2);
    }

    #[test_case(&[&[MessageType::Inv], &[MessageType::Inv]], 0, &[1, 1]; "every subscriber of the type")]
    #[test_case(&[&[MessageType::Inv; 3]], 0, &[1]; "a repeated type delivers once")]
    #[test_case(&[&[MessageType::Headers]], 0, &[0]; "other types are filtered out")]
    #[test_case(&[&[MessageType::Inv], &[MessageType::Inv]], 1, &[1]; "a dropped subscriber does not break the others")]
    #[tokio::test]
    async fn dispatch_local_delivers_to_subscribers(
        subscriptions: &[&[MessageType]],
        dropped: usize,
        expected: &[usize],
    ) {
        let net = broker().await;
        let mut receivers = Vec::new();
        for kinds in subscriptions {
            receivers.push(net.subscribe(kinds).await);
        }
        receivers.drain(..dropped);

        net.dispatch_local(NetworkMessage::Inv(vec![block(1)])).await;

        for (rx, &want) in receivers.iter_mut().zip(expected) {
            let mut got = 0;
            while let Ok(Some((peer, msg))) =
                tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
            {
                assert!(peer.ip().is_unspecified() && peer.port() == 0, "local sentinel address");
                assert!(matches!(**msg, NetworkMessage::Inv(_)));
                got += 1;
            }
            assert_eq!(got, want);
        }
    }

    #[tokio::test]
    async fn reports_no_peers_and_no_tip_before_start() {
        let net = broker().await;
        assert_eq!(net.connected_count().await, 0);
        assert_eq!(net.tip(), 0);
        assert!(net.broadcast(NetworkMessage::MemPool).await.is_err());
    }

    #[test_case("headers" => Some(MessageType::Headers))]
    #[test_case("clsig" => Some(MessageType::ChainLock))]
    #[test_case("ping" => None)]
    #[test_case("Headers" => None; "case sensitive")]
    fn message_type_from_cmd(cmd: &str) -> Option<MessageType> {
        MessageType::from_cmd(cmd)
    }
}
