use std::{
    cmp::Reverse,
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

/// Shortest time between two swaps of an underserving or crowded peer, and between two
/// probes for a network group the set lacks. The longest interval between rotations.
const SWAP_COOLDOWN: Duration = Duration::from_secs(60);

/// Shortest interval between two rotations. A newcomer needs [`SERVING_SAMPLE_TICKS`] to
/// be judged, and the rotated peer's work, [`TARGET_QUEUE_SECS`] of its served rate, has
/// to be served again by the others, so a faster rotation would mostly re-send work.
const EXPLORE_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// Consecutive rotations that found no faster peer before the interval starts doubling.
const EXPLORE_MISSES: u32 = 2;

/// A newcomer counts as faster only if it serves at least this multiple of the peer it
/// replaced. Slow peers vary within about twofold, so less is one slow peer for another.
const EXPLORE_HIT_MARGIN: u64 = 2;

/// A slowest peer serving below this fraction of the set's best is clearly worse and is
/// rotated at the fast pace. Otherwise the set is even and only explores once per
/// [`SWAP_COOLDOWN`]. Fast and slow peers differ more than tenfold on mainnet (1.4 to 2.9
/// MB/s against 0.01 to 0.15) and on testnet three to tenfold (0.3 to 0.5 against 0.02 to
/// 0.15), while slow peers among themselves vary within about twofold.
const EXPLORE_WORSE_FRACTION: f64 = 0.5;

/// A backed-off rotation turns fast again once the set's best rate has fallen below, or
/// risen above, this multiple of what it was when the back-off started.
const EXPLORE_RESET_FACTOR: u64 = 2;

/// A set whose slowest measured peer serves at least this many bytes/s is not rotated
/// for exploration. Healthy testnet peers serve several MB/s each, congested ones a
/// fraction of one, so at this rate a rotation costs more than it can find.
const EXPLORE_FLOOR_BYTES_PER_SEC: u64 = 1_000_000;

/// How often the supervisor re-checks a below-cap set and probes to keep filling.
const FILL_TICK: Duration = Duration::from_secs(2);

const DIAL_MARGIN: usize = 2;

/// A dial still pending after this long gets another candidate dialed beside it, so a
/// node that never answers does not hold a round until [`CONNECT_DEADLINE`]. A handshake
/// that falls back from V2 to V1 takes about 1.3 s here.
const DIAL_STAGGER: Duration = Duration::from_secs(2);
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);

/// How long the router sleeps on a full-capacity stall before re-evaluating. It
/// wakes early whenever a response frees a slot or the timeout monitor kicks a
/// peer; this is just a backstop so it never sleeps on a notify that never comes.
const STALL_CHECK: Duration = Duration::from_secs(5);

/// A request unanswered this long is treated as dead: the timeout monitor re-queues
/// it and kicks the peer holding it. Deliberately aggressive: replacing a peer that
/// stopped answering is faster than waiting for it; merely-slow peers are already
/// throttled by their per-peer cap.
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

/// Ticks in which no peer receives while two or more owe bytes, after which our own
/// link counts as stalled.
const LINK_QUIET_TICKS: u32 = 2;

/// A silent peer is held while our own link looks stalled, but only for this many
/// request timeouts of silence. Past it the whole set has been quiet that long, so the
/// peers are likely dead. 60 s lets the 40 s link outages seen on testnet pass.
const LINK_STALL_TIMEOUTS: u32 = 6;

use crate::error::{NetworkError, NetworkResult};
use crate::network::bans::{Ban, Bans};
use crate::network::broker::{Broker, RequestKey, HEDGE_AFTER};
use crate::network::peer_set::{Admission, PeerSet};
use crate::network::NetworkManager;
use crate::network::TransportPreference;
use crate::{
    network::{
        costs::ResponseCosts,
        discovery::{NetGroup, PeerDiscoverer, Pick},
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

impl NetworkState {
    /// Records what a peer that left the set served. A peer that held work for
    /// [`REQUEST_TIMEOUT`] without answering any of it is not dialed again this session.
    async fn departed(&self, peer: &ConnectedPeer) {
        self.discoverer.lock().await.served(peer.addr(), peer.serving_rate());
        if let Some(held) = peer.unanswered_for().await.filter(|held| *held >= REQUEST_TIMEOUT) {
            tracing::info!(
                target: "dash_spv::network",
                "{} held work for {:?} without answering any of it, not dialing it again",
                peer.addr(),
                held,
            );
            self.bans.ban(peer.addr(), Ban::Unusable).await;
        }
    }

    /// The state of a network with no task running yet, and the receiver of its
    /// peer events.
    fn new(config: &ClientConfig) -> (Self, UnboundedReceiver<PeerEvent>) {
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
        let state = NetworkState {
            connected: PeerSet::new(30),
            discoverer: Mutex::new(PeerDiscoverer::new(config)),
            bans: Bans::new(config.peers.iter().copied()),
            broker: Broker::new(),
            subscribers: Mutex::new(HashMap::new()),
            inbound,
            bytes: AtomicU64::new(0),
            peer_wake: Notify::new(),
            costs: Arc::new(ResponseCosts::new()),
            max_peers,
            required_services,
            user_agent: config.user_agent.clone(),
            transport_preference: config.transport_preference,
            link_stalled: AtomicBool::new(false),
        };
        (state, inbound_rx)
    }
}

impl PeerNetworkManager {
    pub async fn new(config: &ClientConfig) -> Self {
        let (state, inbound_rx) = NetworkState::new(config);
        let state = Arc::new(state);
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
            let sent = broker.route(&peers, costs).await;
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

/// Smallest cap of a peer: two header replies, so a new peer has one queued behind the
/// one it is serving.
const MIN_CAP_BYTES: u64 = INITIAL_CAP_BYTES;

/// Seconds of a peer's served rate its cap allows in flight. A request sent to the peer
/// waits this long behind the ones before it, so this stays small. It must still exceed
/// the round trip, or a peer limited by its cap cannot show it could serve more.
const TARGET_QUEUE_SECS: f64 = 2.0;

/// A peer owing replies that delivers less than this for [`HEDGE_AFTER`] is stalled. Pings
/// and announcements stay well below it, any reply streaming in rises above it.
const STALLED_BELOW_BYTES_PER_SEC: f64 = 8.0 * 1024.0;

/// Horizon of the served rate. A burst of `n` bytes raises the cap by about `n`.
const SERVED_RATE_SECS: f64 = 2.0;

/// Growth per second of a bound peer's cap, to find more than the served rate shows.
const CAP_PROBE_BYTES_PER_SEC: f64 = 32.0 * 1024.0;

/// Share per second of its excess over the target that a bound peer's cap gives back.
const CAP_DECAY_PER_SEC: f64 = 0.5;

/// Ticks a peer must have served all it can before its rate is compared (30 s), and
/// the span its serving rate is averaged over, so a momentary dip never condemns it. A
/// fast mainnet peer serves only 40 to 60% of its later rate in its first 15 s, and 70
/// to 100% by 30 s, so a newcomer judged sooner looks slow while it ramps.
const SERVING_SAMPLE_TICKS: u32 = 120;

/// A peer serving below this fraction of the best connected peer's rate is slow.
const SLOW_RATE_FRACTION: f64 = 0.25;

/// Sizes a peer's byte cap in seconds of its own served rate: a fast peer reaches
/// megabytes within a second or two and a slow one stays near [`MIN_CAP_BYTES`]. The cap
/// rises at once when the served rate supports it. It only falls while the peer is
/// [`ByteLimiter::serving_all`]. Otherwise a peer shows how much it was asked for, which
/// says nothing about what it can serve.
struct ByteLimiter {
    cap: f64,
    /// Bytes/s and bytes in flight, averaged over ticks.
    rate: f64,
    in_flight: f64,
    /// Bytes/s the peer serves, averaged over [`SERVED_RATE_SECS`] of ticks in which it
    /// served all it could.
    served: f64,
    last_bytes: u64,
}

impl ByteLimiter {
    fn new(last_bytes: u64) -> Self {
        Self {
            cap: MIN_CAP_BYTES as f64,
            rate: 0.0,
            in_flight: 0.0,
            served: 0.0,
            last_bytes,
        }
    }

    fn rtt(&self) -> f64 {
        self.in_flight / self.rate.max(1.0)
    }

    /// Whether the router has given the peer all its cap allows.
    fn bound(&self, in_flight: u64) -> bool {
        in_flight > 0 && in_flight >= self.cap as u64
    }

    /// Whether what the peer delivers is all it can serve: it is bound, or it holds more than
    /// [`TARGET_QUEUE_SECS`] of what it delivers. A cap raised by a burst leaves the peer below
    /// it, so without the second case the cap never comes down while the queue grows.
    /// Less than [`MIN_CAP_BYTES`] in flight is a reply or two in the making, not a backlog.
    fn serving_all(&self, in_flight: u64) -> bool {
        self.bound(in_flight)
            || (in_flight >= MIN_CAP_BYTES && in_flight as f64 > self.rate * TARGET_QUEUE_SECS)
    }

    /// One tick with the cumulative bytes received and the bytes in flight now. A stall
    /// of our own link says nothing about the peer, so it leaves the cap alone.
    fn tick(&mut self, bytes: u64, in_flight: u64, link_stalled: bool) -> u64 {
        let tick_s = FLOW_TICK.as_secs_f64();
        let got = bytes.saturating_sub(self.last_bytes) as f64 / tick_s;
        self.last_bytes = bytes;
        self.rate += FLOW_EMA_ALPHA * (got - self.rate);
        self.in_flight += FLOW_EMA_ALPHA * (in_flight as f64 - self.in_flight);
        if link_stalled {
            return self.cap as u64;
        }

        let serving_all = self.serving_all(in_flight);
        if serving_all || got > self.served {
            self.served += tick_s / SERVED_RATE_SECS * (got - self.served);
        }
        let target = self.served * TARGET_QUEUE_SECS;
        if target > self.cap {
            self.cap = target;
        } else if serving_all {
            // Only a bound peer can show it would serve more than its cap allows.
            if self.bound(in_flight) {
                self.cap += CAP_PROBE_BYTES_PER_SEC * tick_s;
            }
            self.cap -= (self.cap - target).max(0.0) * CAP_DECAY_PER_SEC * tick_s;
        }
        self.cap = self.cap.max(MIN_CAP_BYTES as f64);
        self.cap as u64
    }
}

/// A peer's limiter plus how fast it serves while serving all it can, for eviction.
struct PeerFlow {
    limiter: ByteLimiter,
    serving_rate: f64,
    serving_ticks: u32,
    /// Consecutive ticks in which the peer owed replies and delivered nearly nothing.
    stalled_ticks: u32,
}

impl PeerFlow {
    fn new(bytes: u64) -> Self {
        Self {
            limiter: ByteLimiter::new(bytes),
            serving_rate: 0.0,
            serving_ticks: 0,
            stalled_ticks: 0,
        }
    }

    /// One tick with the peer's cumulative bytes received, its bytes in flight now and
    /// whether our link is stalled. Returns its new cap.
    fn tick(&mut self, bytes: u64, in_flight: u64, link_stalled: bool) -> u64 {
        let serving_all = self.limiter.serving_all(in_flight);
        let got = bytes.saturating_sub(self.limiter.last_bytes);
        let cap = self.limiter.tick(bytes, in_flight, link_stalled);
        self.sample(self.limiter.rate, serving_all, link_stalled);
        let stalling = (got as f64) < STALLED_BELOW_BYTES_PER_SEC * FLOW_TICK.as_secs_f64();
        if in_flight == 0 || !stalling {
            self.stalled_ticks = 0;
        } else if !link_stalled {
            self.stalled_ticks += 1;
        }
        cap
    }

    /// Whether the peer owed replies and delivered nearly nothing for [`HEDGE_AFTER`].
    fn stalled(&self) -> bool {
        FLOW_TICK * self.stalled_ticks >= HEDGE_AFTER
    }

    /// Ticks the flow of `peer` with `in_flight` bytes owed and publishes its cap and rates.
    fn update(&mut self, peer: &ConnectedPeer, in_flight: u64, link_stalled: bool) {
        let (was_stalled, stalled_for) = (self.stalled(), FLOW_TICK * self.stalled_ticks);
        peer.set_cap(self.tick(peer.bytes_read(), in_flight, link_stalled));
        peer.set_serving_rate(self.serving_rate());
        peer.set_served(self.limiter.served as u64);
        let stalled = self.stalled();
        peer.set_stalled(stalled);
        if stalled && !was_stalled {
            tracing::debug!(
                target: "dash_spv::network",
                "{} stalled: owes {} KB and delivered under {} KB/s for {:.1}s",
                peer.addr(),
                in_flight >> 10,
                STALLED_BELOW_BYTES_PER_SEC as u64 >> 10,
                (FLOW_TICK * self.stalled_ticks).as_secs_f64(),
            );
        } else if was_stalled && !stalled {
            tracing::debug!(
                target: "dash_spv::network",
                "{} no longer stalled after {:.1}s, owes {} KB",
                peer.addr(),
                stalled_for.as_secs_f64(),
                in_flight >> 10,
            );
        }
    }

    /// Folds `rate` into the serving rate if the peer had work. A stall of our own link
    /// is skipped: it says nothing about the peer and would drag its average for 30 s.
    fn sample(&mut self, rate: f64, has_work: bool, link_stalled: bool) {
        if has_work && !link_stalled {
            self.serving_ticks += 1;
            let alpha = 1.0 / self.serving_ticks.min(SERVING_SAMPLE_TICKS) as f64;
            self.serving_rate += alpha * (rate - self.serving_rate);
        }
    }

    /// Returns the peer's serving rate in bytes/s, 0 until measured.
    fn serving_rate(&self) -> u64 {
        let measured = self.serving_ticks >= SERVING_SAMPLE_TICKS;
        if measured {
            self.serving_rate as u64
        } else {
            0
        }
    }
}

/// Sizes the byte cap of every peer with a [`ByteLimiter`] on its own throughput. Each cap
/// follows its peer's share of the client's link, so a full link needs no cap of its own.
/// Also reports how fast each peer serves while serving all it can, for [`underserving_peer`].
fn spawn_flow_controller(state: Arc<NetworkState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let NetworkState {
            bytes,
            connected,
            peer_wake,
            broker,
            costs,
            link_stalled,
            ..
        } = &*state;
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
            let stalled = link_stalled.load(Ordering::Relaxed);
            for (p, &in_flight) in g.iter().zip(&in_flights) {
                let flow = peers.entry(p.id()).or_insert_with(|| PeerFlow::new(p.bytes_read()));
                flow.update(p, in_flight, stalled);
            }

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
                        "peer {}: cap={} KB in_flight={} KB rate={:.2} MB/s served={:.2} MB/s rtt={:.0}ms lag={}ms total={:.1} MB",
                        p.addr(),
                        p.cap() >> 10,
                        p.in_flight_bytes() >> 10,
                        flow.limiter.rate / 1e6,
                        flow.limiter.served / 1e6,
                        flow.limiter.rtt() * 1e3,
                        p.lag_ms(),
                        p.bytes_read() as f64 / 1e6,
                    );
                }
                let bind = if total_in_flight >= caps {
                    "peers"
                } else {
                    "work"
                };
                let snapshot =
                    Some((bytes.load(Ordering::Relaxed), total_in_flight, caps, g.len()));
                if any_reported || reported_bandwidth != snapshot {
                    reported_bandwidth = snapshot;
                    let rate: f64 = peers.values().map(|flow| flow.limiter.rate).sum();
                    tracing::debug!(
                        target: "peer_speed",
                        "bandwidth: {:.1} MB/s bind={} | sum_peer_cap={} in_flight={} KB | rtt={:.0}ms | peers={} | resp KB {:?}",
                        rate / 1e6,
                        bind,
                        caps >> 10,
                        total_in_flight >> 10,
                        total_in_flight as f64 / rate.max(1.0) * 1e3,
                        g.len(),
                        costs.expected_kb(),
                    );
                }
            }

            // Only the transition wakes the supervisor, so a peer with no replacement
            // is not re-probed every tick.
            let underserving = underserving_peer(&g, link_stalled.load(Ordering::Relaxed));
            let handles: Vec<PeerHandle> = g.iter().map(|p| p.handle()).collect();
            drop(g);
            if broker.len() == 0 {
                if let Some(height) = broker.hedge(&handles).await {
                    tracing::debug!(target: "dash_spv::network", "endgame: hedged block {}", height);
                }
            }
            if let Some(height) = broker.hedge_filters(&handles).await {
                tracing::debug!(target: "dash_spv::network", "hedged filter batch {}", height);
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
/// - While two peers share a network group and the client has work, it also probes for
///   a group the set lacks, see [`crowded_peer`].
/// - While the client has work and every peer serves slowly, it rotates the slowest one
///   out for an untried address, see [`rotation_peer`] and [`Exploration`]. A newcomer
///   that turns out slower is the next to go, so the set keeps the fastest found.
/// - Probed-but-unused peers are closed. Their handshake ping gives them no priority
///   later: a low ping does not make a fast peer.
struct Supervisor {
    state: Arc<NetworkState>,
    shutdown: CancellationToken,
    /// Lowest handshake ping seen, the reference for the bad-lag threshold.
    best_lag_ms: AtomicU32,
    /// When a slow peer was last swapped out, for [`SWAP_COOLDOWN`].
    last_swap: Mutex<Option<Instant>>,
    /// When candidates were last probed for a network group the set lacks.
    last_probe: Mutex<Option<Instant>>,
    exploration: Mutex<Exploration>,
    /// Why the last round rotated no peer out, so each reason is logged once.
    rotation_held: Mutex<Option<&'static str>>,
}

/// How often the supervisor rotates a peer out to explore. Fast while rotations find
/// clearly faster peers, slower after [`EXPLORE_MISSES`] that did not, fast again once
/// the set's best rate moves far from where the back-off started.
struct Exploration {
    last: Option<Instant>,
    /// The newcomer of the last rotation and the serving rate of the peer it replaced,
    /// until the newcomer is measured.
    trial: Option<(SocketAddr, u64)>,
    misses: u32,
    /// The set's best serving rate at the last observation.
    best: u64,
    /// The set's best serving rate when the back-off started.
    backed_off_at: Option<u64>,
}

impl Exploration {
    fn new() -> Self {
        Exploration {
            last: None,
            trial: None,
            misses: 0,
            best: 0,
            backed_off_at: None,
        }
    }

    /// Updates from the connected peers' serving rates: judges the last newcomer once it
    /// is measured, and turns fast again when the set's best rate moved far.
    fn observe(&mut self, rates: &[(SocketAddr, u64)]) {
        let best = rates.iter().map(|&(_, rate)| rate).max().unwrap_or(0);
        self.best = best;
        if let Some((newcomer, replaced)) = self.trial {
            match rates.iter().find(|&&(addr, _)| addr == newcomer) {
                Some(&(_, 0)) => {}
                Some(&(_, rate)) => {
                    self.trial = None;
                    let beats = rate >= replaced * EXPLORE_HIT_MARGIN;
                    let worse = (rate as f64) < best as f64 * EXPLORE_WORSE_FRACTION;
                    self.judge(beats && !worse, best);
                }
                None => {
                    self.trial = None;
                    self.judge(false, best);
                }
            }
        }
        if let Some(reference) = self.backed_off_at {
            if best > 0
                && (best * EXPLORE_RESET_FACTOR < reference
                    || best > reference * EXPLORE_RESET_FACTOR)
            {
                self.misses = 0;
                self.backed_off_at = None;
            }
        }
    }

    fn judge(&mut self, faster: bool, best: u64) {
        if faster {
            self.misses = 0;
            self.backed_off_at = None;
        } else {
            self.misses += 1;
            if self.misses >= EXPLORE_MISSES && self.backed_off_at.is_none() {
                self.backed_off_at = Some(best);
            }
        }
    }

    /// The interval before the next rotation of a slowest peer serving `slowest` bytes/s.
    fn interval(&self, slowest: u64) -> Duration {
        if slowest as f64 >= self.best as f64 * EXPLORE_WORSE_FRACTION {
            return SWAP_COOLDOWN;
        }
        let doublings = (self.misses + 1).saturating_sub(EXPLORE_MISSES).min(8);
        (EXPLORE_MIN_INTERVAL * (1 << doublings)).min(SWAP_COOLDOWN)
    }

    /// Why a slowest peer serving `slowest` bytes/s may not be rotated now, or `None` if
    /// it may. Never while the last newcomer is still unjudged.
    fn hold(&self, slowest: u64) -> Option<&'static str> {
        if self.trial.is_some() {
            Some("the last newcomer is not measured yet")
        } else if self.last.is_some_and(|t| t.elapsed() < self.interval(slowest)) {
            Some("the rotation interval has not passed")
        } else {
            None
        }
    }

    /// Records a rotation: `newcomer` is the peer that replaced one serving `replaced`
    /// bytes/s. `None` means no candidate joined, which says nothing about the addresses
    /// still untried, so it changes nothing.
    fn rotated(&mut self, newcomer: Option<SocketAddr>, replaced: u64) {
        if let Some(addr) = newcomer {
            self.last = Some(Instant::now());
            self.trial = Some((addr, replaced));
        }
    }
}

/// Why a peer of a full set is to be replaced.
#[derive(Clone, Copy)]
enum Replace {
    /// A peer of a set where every peer refused a queued request.
    Refused(SocketAddr),
    Slow(SocketAddr),
    Crowded(SocketAddr),
    /// The slowest of a set that serves slowly as a whole, rotated out to explore, and
    /// its serving rate.
    Rotated(SocketAddr, u64),
}

impl Replace {
    fn addr(self) -> SocketAddr {
        match self {
            Replace::Refused(addr)
            | Replace::Slow(addr)
            | Replace::Crowded(addr)
            | Replace::Rotated(addr, _) => addr,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Replace::Refused(_) => "refusing",
            Replace::Slow(_) => "slow",
            Replace::Crowded(_) => "crowded",
            Replace::Rotated(..) => "rotated",
        }
    }

    /// Which candidates may replace the peer.
    fn pick(self) -> Pick {
        match self {
            Replace::Refused(_) | Replace::Slow(_) => Pick::Any,
            Replace::Crowded(_) => Pick::NewGroups,
            Replace::Rotated(..) => Pick::Faster,
        }
    }
}

impl Supervisor {
    fn new(state: Arc<NetworkState>, shutdown: CancellationToken) -> Self {
        Supervisor {
            state,
            shutdown,
            best_lag_ms: AtomicU32::new(u32::MAX),
            last_swap: Mutex::new(None),
            last_probe: Mutex::new(None),
            exploration: Mutex::new(Exploration::new()),
            rotation_held: Mutex::new(None),
        }
    }

    async fn run(self) {
        loop {
            self.repair_round().await;

            // Also re-checked on a timer: work starting, a newcomer getting measured or an
            // interval passing wakes nobody. A round with nothing to do probes nothing.
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = self.state.peer_wake.notified() => {}
                _ = tokio::time::sleep(FILL_TICK) => {}
            }
        }
    }

    async fn next_candidates(&self, want: usize, pick: Pick) -> Vec<DisconnectedPeer> {
        let live: HashMap<SocketAddr, u64> = self
            .state
            .connected
            .read()
            .await
            .iter()
            .map(|p| (p.addr(), p.serving_rate()))
            .collect();
        let banned = self.state.bans.banned().await;
        self.state.discoverer.lock().await.get(want, &live, &banned, pick).await
    }

    /// Closes probed-but-unused peers. Winning or losing a handshake race says nothing
    /// about how a node serves, so their addresses get no priority in the next round.
    async fn close_backups(&self, peers: impl IntoIterator<Item = ConnectedPeer>) {
        for peer in peers {
            peer.close();
        }
    }

    /// Logs why no peer was rotated out, once until the reason changes.
    async fn hold_rotation(&self, reason: &'static str) {
        let mut held = self.rotation_held.lock().await;
        if *held != Some(reason) {
            tracing::debug!(target: "dash_spv::network", "peer rotation held: {}", reason);
            *held = Some(reason);
        }
    }

    /// One pass at whatever the peer set needs: fill a deficit, replace a peer that is
    /// underserving the rest, crowding its network group or rotated out to explore, or
    /// both.
    async fn repair_round(&self) {
        let (deficit, replace) = {
            let peers = self.state.connected.read().await;
            let deficit = self.state.max_peers.saturating_sub(peers.len());
            // Only look for a laggard once full: below cap every arrival is wanted anyway.
            // Each swap re-sends the work the old peer held, so at most one per cooldown.
            let cooled = self.last_swap.lock().await.is_none_or(|t| t.elapsed() >= SWAP_COOLDOWN);
            let probe_cooled =
                self.last_probe.lock().await.is_none_or(|t| t.elapsed() >= SWAP_COOLDOWN);
            let stalled = self.state.link_stalled.load(Ordering::Relaxed);
            // Peers of one group slow down together, and a set of equally slow peers
            // never shows one as underserving. With work waiting on them, another group
            // or an untried address is worth a swap even when no peer looks slow.
            let has_work = self.state.broker.len() > 0;
            let explore = deficit == 0 && has_work && !stalled;
            // A request every peer refused is served by none of them, however long it waits.
            let addrs: Vec<SocketAddr> = peers.iter().map(|p| p.addr()).collect();
            let refused = self.state.broker.refused_by_all(&addrs).await;
            let replace = if deficit == 0 && cooled {
                refused
                    .then(|| slowest_peer(peers.iter()))
                    .flatten()
                    .map(Replace::Refused)
                    .or_else(|| {
                        underserving_peer(&peers, stalled).map(|slow| Replace::Slow(slow.addr))
                    })
                    .or_else(|| {
                        (explore && probe_cooled)
                            .then(|| crowded_peer(&peers))
                            .flatten()
                            .map(Replace::Crowded)
                    })
            } else {
                None
            };
            let rates: Vec<(SocketAddr, u64)> =
                peers.iter().map(|p| (p.addr(), p.serving_rate())).collect();
            let mut exploration = self.exploration.lock().await;
            exploration.observe(&rates);
            let rotation = if deficit > 0 {
                Err("the set is short")
            } else if !has_work {
                Err("no work is queued")
            } else if stalled {
                Err("the link is stalled")
            } else {
                rotation_peer(&peers).and_then(|(addr, rate)| {
                    exploration.hold(rate).map_or(Ok(Replace::Rotated(addr, rate)), Err)
                })
            };
            let replace = match (replace, rotation) {
                (Some(replace), _) => Ok(replace),
                (None, rotation) => rotation,
            };
            (deficit, replace)
        };
        let replace = match replace {
            Ok(replace) => Some(replace),
            Err(reason) => {
                self.hold_rotation(reason).await;
                None
            }
        };
        if deficit == 0 && replace.is_none() {
            return;
        }

        // Scale the probe to the need: a few candidates to find one replacement, a
        // full chunk when several slots are open and sync is waiting on them.
        let want = (deficit.max(1) + DIAL_MARGIN).min(CONNECT_CHUNK);
        let mut queue: VecDeque<DisconnectedPeer> = self
            .next_candidates(CONNECT_CHUNK, replace.map_or(Pick::Any, Replace::pick))
            .await
            .into();
        if queue.is_empty() {
            if matches!(replace, Some(Replace::Rotated(..))) {
                self.hold_rotation("no untried candidate").await;
            }
            return;
        }
        if matches!(replace, Some(Replace::Crowded(_))) {
            *self.last_probe.lock().await = Some(Instant::now());
        }
        let slow = replace.map(Replace::addr);

        // Take each peer as soon as ITS handshake lands rather than waiting for the batch,
        // so one unreachable address doesn't delay sync. Completion order is itself a
        // latency ranking. While a newcomer is still needed, `want` dials stay in flight and
        // a stuck one gets company after `DIAL_STAGGER`. Once none is needed, the dials
        // left are drained only to bank backups, or dropped after a swap.
        let dial = |c: DisconnectedPeer| {
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
        };
        let mut inflight = FuturesUnordered::new();

        let mut accepted = 0usize;
        let mut replaced: Option<SocketAddr> = None;
        let mut leftover: Vec<ConnectedPeer> = Vec::new();
        loop {
            if deficit == 0 && replaced.is_some() {
                break;
            }
            let needed = if deficit > 0 {
                accepted < deficit
            } else {
                replaced.is_none()
            };
            while needed && inflight.len() < want {
                let Some(candidate) = queue.pop_front() else {
                    break;
                };
                inflight.push(dial(candidate));
            }
            let stagger = needed && !queue.is_empty();
            let next = tokio::select! {
                next = inflight.next() => next,
                _ = tokio::time::sleep(DIAL_STAGGER), if stagger => {
                    if let Some(candidate) = queue.pop_front() {
                        inflight.push(dial(candidate));
                    }
                    continue;
                }
            };
            let Some((addr, result)) = next else {
                break;
            };
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
            let slow = slow.filter(|_| replaced.is_none());
            match self.state.connected.admit(peer, &self.shutdown, self.state.max_peers, slow).await
            {
                Admission::Joined => accepted += 1,
                Admission::Swapped(old) => {
                    replaced = Some(new_addr);
                    tracing::info!(
                        target: "dash_spv::network",
                        "peer supervisor: swapped out {} {} for {}",
                        replace.map_or("slow", Replace::reason),
                        old.addr(),
                        new_addr,
                    );
                    self.state.departed(&old).await;
                    // Close it: the pump requeues every request routed to THIS connection, as for any
                    // lost peer. Safe because the departure names a connection, not an address, so a
                    // reconnection to the same peer is not disturbed.
                    old.close();
                    if !matches!(replace, Some(Replace::Rotated(..))) {
                        *self.last_swap.lock().await = Some(Instant::now());
                    }
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

        if let Some(Replace::Rotated(_, rate)) = replace {
            self.exploration.lock().await.rotated(replaced, rate);
            if replaced.is_some() {
                *self.rotation_held.lock().await = None;
            } else {
                self.hold_rotation("no candidate joined").await;
            }
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

        self.close_backups(leftover).await;

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
/// fraction of the best connected peer's rate while serving all it can. Relative, so a slow
/// client link (every peer slow alike) never condemns anyone. None while our own link
/// is stalled, since the stall drags every rate down unevenly.
fn underserving_peer(peers: &[ConnectedPeer], link_stalled: bool) -> Option<SlowPeer> {
    if link_stalled {
        return None;
    }
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

/// The slowest peer and its serving rate, if it serves below
/// [`EXPLORE_FLOOR_BYTES_PER_SEC`], or why there is none. None while any peer is still
/// ramping, so one newcomer is judged before the next one joins.
fn rotation_peer(peers: &[ConnectedPeer]) -> Result<(SocketAddr, u64), &'static str> {
    if peers.iter().any(|p| p.serving_rate() == 0) {
        return Err("a peer is still being measured");
    }
    peers
        .iter()
        .map(|p| (p.addr(), p.serving_rate()))
        .min_by_key(|&(_, rate)| rate)
        .filter(|&(_, rate)| rate < EXPLORE_FLOOR_BYTES_PER_SEC)
        .ok_or("every peer serves above the floor")
}

/// The slowest peer of the most crowded network group, if any group holds more than one
/// peer.
fn crowded_peer(peers: &[ConnectedPeer]) -> Option<SocketAddr> {
    let mut groups: HashMap<NetGroup, Vec<&ConnectedPeer>> = HashMap::new();
    for peer in peers {
        groups.entry(NetGroup::of(peer.addr())).or_default().push(peer);
    }
    let crowded = groups.into_values().filter(|group| group.len() > 1).max_by_key(Vec::len)?;
    slowest_peer(crowded.into_iter())
}

/// The slowest of `peers`. An unmeasured peer counts as slowest, and a higher handshake
/// ping breaks ties.
fn slowest_peer<'a>(peers: impl Iterator<Item = &'a ConnectedPeer>) -> Option<SocketAddr> {
    peers.min_by_key(|p| (p.serving_rate(), Reverse(lag_key(p)))).map(|p| p.addr())
}

fn spawn_peer_supervisor(state: Arc<NetworkState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(Supervisor::new(state, shutdown).run())
}

/// What the timeout monitor knows of a connected peer.
struct Liveness {
    bytes: u64,
    /// When `bytes` last grew, `None` until they do. A new peer's handshake may predate
    /// a stall of our link, so it proves nothing about the link now.
    heard: Option<Instant>,
    /// When the peer last sent bytes or was idle.
    owing_since: Instant,
}

/// Time requests out and evict the peers that stalled on them.
///
/// A peer is a culprit when it has in-flight work and no bytes have arrived from it
/// for a full [`REQUEST_TIMEOUT`] since it was given that work, or when one of its
/// requests made no progress for that long. Bytes of an answer still arriving count
/// as progress, but a request also stalls once its peer has completed no answer for
/// [`ANSWER_DEADLINE_TIMEOUTS`](crate::network::broker::ANSWER_DEADLINE_TIMEOUTS)
/// timeouts. Liveness is per peer, not per request age: a healthy peer draining a
/// deep backlog keeps sending bytes even while its oldest request waits.
///
/// A culprit still receiving is kicked immediately. A kicked peer has ALL its on-wire
/// requests re-queued for other peers; leaving it connected would just route the
/// freed work back to it.
/// A silent culprit is held while no other peer received bytes a full timeout into
/// its silence, since then our own link stalled, but at most for
/// [`LINK_STALL_TIMEOUTS`] timeouts of silence. After a stall of our link its silence
/// counts only from when the link came back. Of the silent culprits only the one
/// silent the longest is kicked, and at most one per timeout while culprits remain.
/// The last peer is kicked only once it has stalled for another timeout. The
/// supervisor refills the set.
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
        let mut progress: HashMap<PeerId, Liveness> = HashMap::new();
        // The last connected peer kept through its stall, and since when.
        let mut held_last: Option<(PeerId, Instant)> = None;
        // The last kick of a silent peer, which paces the next.
        let mut last_kick: Option<Instant> = None;
        // Consecutive ticks in which no peer received while two or more owed bytes.
        let mut quiet_ticks = 0;
        // When some peer received again after such a stall.
        let mut link_back: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }

            let now = Instant::now();

            // Judged on the peer's own counters, not just the registry: streaming in-flight
            // bytes are freed on the peer separately, so a wedged peer can sit at its cap
            // with no registry entries. Pending work plus a byte counter
            // frozen for REQUEST_TIMEOUT means stuck, whatever the registry thinks.
            // Each culprit maps to when its silence began.
            let (mut culprits, receiving, owing) = {
                let peers = connected.read().await;
                let live: HashSet<PeerId> = peers.iter().map(|p| p.id()).collect();
                progress.retain(|addr, _| live.contains(addr));
                let mut culprits: HashMap<PeerId, Instant> = HashMap::new();
                let mut receiving = Vec::new();
                let mut owing = 0;
                for peer in peers.iter() {
                    let addr = peer.id();
                    let bytes = peer.bytes_read();
                    let in_flight = peer.in_flight_bytes();
                    let entry = progress.entry(addr).or_insert(Liveness {
                        bytes,
                        heard: None,
                        owing_since: now,
                    });
                    let grew = bytes > entry.bytes;
                    if grew {
                        receiving.push(addr);
                        entry.bytes = bytes;
                        entry.heard = Some(now);
                    }
                    // An idle peer owes no bytes, so its silence before it gets work
                    // must not count against its first request.
                    if grew || in_flight == 0 {
                        entry.owing_since = now;
                    }
                    if in_flight > 0 {
                        owing += 1;
                        if now.duration_since(entry.owing_since) > request_timeout(peer.lag_ms()) {
                            culprits.insert(addr, entry.owing_since);
                        }
                    }
                }
                (culprits, receiving, owing)
            };
            // One silent peer owing bytes looks the same as a dead one, so a stall of our
            // link needs two.
            if !receiving.is_empty() {
                if quiet_ticks >= LINK_QUIET_TICKS {
                    link_back = Some(now);
                }
                quiet_ticks = 0;
            } else if owing >= 2 {
                quiet_ticks += 1;
            }
            link_stalled.store(quiet_ticks >= LINK_QUIET_TICKS, Ordering::Relaxed);
            for peer in receiving {
                broker.receiving(peer).await;
            }
            // A request with no complete answer for long also condemns its peer: the
            // per-peer byte check above sees unrelated traffic and judges it healthy.
            let timeouts: HashMap<PeerId, Duration> = connected
                .read()
                .await
                .iter()
                .map(|p| (p.id(), request_timeout(p.lag_ms())))
                .collect();
            let expired =
                broker.expire(|peer| timeouts.get(peer).copied().unwrap_or(REQUEST_TIMEOUT)).await;
            for (peer, since) in expired {
                let silent_since = culprits.entry(peer).or_insert(since);
                *silent_since = (*silent_since).min(since);
            }

            if culprits.is_empty() {
                held_last = None;
                last_kick = None;
                continue;
            }

            let spared = {
                let peers = connected.read().await;
                match &*peers {
                    // Holding the last peer keeps a short outage from emptying the set.
                    [last] if culprits.contains_key(&last.id()) => {
                        let since = match held_last {
                            Some((id, since)) if id == last.id() => since,
                            _ => now,
                        };
                        if now.duration_since(since) <= request_timeout(last.lag_ms()) {
                            held_last = Some((last.id(), since));
                            vec![last.id()]
                        } else {
                            held_last = None;
                            Vec::new()
                        }
                    }
                    _ => {
                        held_last = None;
                        let mut spared = Vec::new();
                        let mut silent: Vec<(Instant, SocketAddr, PeerId)> = Vec::new();
                        for p in peers.iter() {
                            let Some(&since) = culprits.get(&p.id()) else {
                                continue;
                            };
                            let timeout = request_timeout(p.lag_ms());
                            // Still receiving, so its link works and only its answers stall.
                            if now.duration_since(since) <= timeout {
                                continue;
                            }
                            // Silence is blamed only while the link provably worked: another
                            // peer received a full timeout into it. Silence before the link
                            // came back does not count, so its own connection gets a timeout
                            // to resume. Past the bound the whole set has been quiet that long.
                            let blamed_from = link_back.map_or(since, |back| back.max(since));
                            let witnessed = peers.iter().any(|other| {
                                other.id() != p.id()
                                    && progress
                                        .get(&other.id())
                                        .and_then(|l| l.heard)
                                        .is_some_and(|heard| heard > blamed_from + timeout)
                            });
                            if witnessed
                                || now.duration_since(since) > timeout * LINK_STALL_TIMEOUTS
                            {
                                silent.push((since, p.addr(), p.id()));
                            } else {
                                spared.push(p.id());
                            }
                        }
                        // A silent peer may still be our link failing it, so the one silent
                        // the longest goes, and one kick per timeout lets such a stall cost a
                        // single peer, whatever share of the set it is.
                        silent.sort_by_key(|&(since, addr, _)| (since, addr));
                        let due = match (last_kick, silent.first()) {
                            (_, None) => false,
                            (Some(at), Some(&(_, _, worst))) => {
                                let timeout =
                                    timeouts.get(&worst).copied().unwrap_or(REQUEST_TIMEOUT);
                                now.duration_since(at) > timeout
                            }
                            (None, Some(_)) => true,
                        };
                        if due {
                            last_kick = Some(now);
                        }
                        spared.extend(silent.drain(usize::from(due)..).map(|(_, _, id)| id));
                        spared
                    }
                }
            };
            let culprits: HashSet<PeerId> =
                culprits.into_keys().filter(|id| !spared.contains(id)).collect();

            // Drop culprits still in the set (some may already be gone) before their work
            // is re-queued, so the router cannot hand it back to them.
            let (kicked, remaining) = connected.remove(&culprits).await;
            for peer in &kicked {
                peer.close();
                state.departed(peer).await;
            }
            // Re-queue every on-wire request of a culprit (fresh ones too: the connection is
            // going away), keeping keys as Queued so de-dup holds.
            let retried = broker.requeue_from(&culprits).await;
            let dropped = kicked.len();
            for peer in &culprits {
                bans.ban(peer.addr(), Ban::Kicked).await;
            }
            // The set is now short: wake the supervisor, which otherwise idles.
            if dropped > 0 && remaining < *max_peers {
                peer_wake.notify_one();
            }

            if dropped > 0 {
                tracing::warn!(
                    target: "dash_spv::network",
                    "request timeout: kicked {} peer(s) {:?}, spared {}, retried {} request(s)",
                    dropped,
                    culprits,
                    spared.len(),
                    retried,
                );
            } else {
                tracing::debug!(
                    target: "dash_spv::network",
                    "request timeout: kicked none, spared {}, retried {} request(s)",
                    spared.len(),
                    retried,
                );
            }
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
            required_services,
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

                    // A request is settled on arrival, not when its manager gets to it: blocks
                    // wait in height order behind a gap and filters in a long backlog, and
                    // charging that wait to the peer reads as a stall. The last `cfilter` of a
                    // reply is the one for the stop hash that keys the request.
                    let arrived = match &*msg {
                        NetworkMessage::Block(block) => Some(RequestKey::Block(block.block_hash())),
                        NetworkMessage::CFilter(filter) => {
                            Some(RequestKey::CFilters(filter.block_hash))
                        }
                        NetworkMessage::CFHeaders(headers) => {
                            Some(RequestKey::CfHeaders(headers.stop_hash))
                        }
                        _ => None,
                    };
                    if let Some(key) = arrived {
                        broker.arrived(peer, key).await;
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
                    // `getaddr` with legacy `addr`. An address whose services lack what we need
                    // would only be dropped after its handshake.
                    let gossiped: Option<Vec<(SocketAddr, u32)>> = match &*msg {
                        NetworkMessage::AddrV2(addrs) if addrs.len() <= MAX_ADDR_PER_MESSAGE => {
                            Some(
                                addrs
                                    .iter()
                                    .filter(|a| a.services.has(*required_services))
                                    .filter_map(|a| Some((a.socket_addr().ok()?, a.time)))
                                    .collect(),
                            )
                        }
                        NetworkMessage::Addr(addrs) if addrs.len() <= MAX_ADDR_PER_MESSAGE => Some(
                            addrs
                                .iter()
                                .filter(|(_, a)| a.services.has(*required_services))
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
                            // Fresh candidates are what a short or crowded set is waiting for.
                            peer_wake.notify_one();
                        }
                    }

                    let mt = MessageType::from_cmd(msg.cmd());
                    // Early router wake on inbound traffic. `cfilter` is skipped: only the last
                    // of ~1000 frees anything, and `arrived` wakes the router for it.
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
                    for peer in &removed {
                        state.departed(peer).await;
                    }

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
    use crate::network::broker::ANSWER_DEADLINE_TIMEOUTS;
    use crate::test_utils::test_socket_address;
    use dashcore::consensus::encode::serialize;
    use dashcore::network::address::Address;
    use dashcore::network::message::{RawNetworkMessage, RawNetworkMessageCodec};
    use dashcore::network::message_blockdata::{GetHeadersMessage, Inventory};
    use dashcore::network::message_filter::{CFilter, GetCFilters};
    use dashcore::network::message_network::VersionMessage;
    use dashcore::{BlockHash, Network};
    use std::fmt;
    use std::sync::atomic::AtomicUsize;
    use std::time::{SystemTime, UNIX_EPOCH};
    use test_case::test_case;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::codec::FramedRead;
    use tracing::field::{Field, Visit};
    use tracing::{span, Event, Level, Metadata, Subscriber};

    fn get_cfilters(start: u32) -> NetworkMessage {
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: start,
            stop_hash: BlockHash::dummy(start),
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

        fn tick(&mut self, delivered: u64, in_flight: u64) {
            self.bytes += delivered;
            self.cap = self.flow.tick(self.bytes, in_flight, false);
        }

        /// Bulk download at `rate` bytes/s, with the router keeping the peer at its cap.
        fn bulk(&mut self, rate: u64, ticks: u32) {
            let delivered = (rate as f64 * FLOW_TICK.as_secs_f64()) as u64;
            for _ in 0..ticks {
                self.tick(delivered, self.cap);
            }
        }

        /// Small replies as at the chain tip, each answered `latency` ticks after its
        /// request and followed by ten quiet seconds.
        fn replies(&mut self, latency: u32, count: u32) {
            const REPLY_BYTES: u64 = 4 * 1024;
            for _ in 0..count {
                for _ in 1..latency {
                    self.tick(0, REPLY_BYTES);
                }
                self.tick(REPLY_BYTES, 0);
                for _ in 0..40 {
                    self.tick(0, 0);
                }
            }
        }
    }

    /// Only a peer serving all the work its caps allow is compared. Small replies at the
    /// tip measure the round trip, so a far peer must not look slow for them.
    #[test_case(1_000_000, true => None; "latency bound replies at the tip")]
    #[test_case(100_000, false => Some(1); "a slow peer at its own cap")]
    #[tokio::test]
    async fn only_bandwidth_bound_service_condemns_a_peer(
        second_rate: u64,
        then_idle: bool,
    ) -> Option<usize> {
        let mut served = [Served::new(), Served::new()];
        for (s, rate) in served.iter_mut().zip([1_000_000, second_rate]) {
            s.bulk(rate, SERVING_SAMPLE_TICKS * 10);
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
        let slow = underserving_peer(&peers, false)?;
        peers.iter().position(|p| p.addr() == slow.addr)
    }

    /// A regtest node on loopback that completes the handshake and answers pings.
    async fn mock_node() -> SocketAddr {
        mock_node_serving(
            ServiceFlags::NETWORK | ServiceFlags::COMPACT_FILTERS | ServiceFlags::BLOOM,
        )
        .await
    }

    /// A mock node that advertises `services`.
    async fn mock_node_serving(services: ServiceFlags) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("bound address");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_handshake(stream, services));
            }
        });
        addr
    }

    async fn serve_handshake(stream: TcpStream, services: ServiceFlags) {
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = FramedRead::new(read_half, RawNetworkMessageCodec);
        let local: SocketAddr = "127.0.0.1:0".parse().expect("an address");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after epoch").as_secs();
        while let Some(Ok(raw)) = reader.next().await {
            let replies = match raw.payload {
                NetworkMessage::Version(_) => vec![
                    NetworkMessage::Version(VersionMessage::new(
                        services,
                        now as i64,
                        Address::new(&local, ServiceFlags::NONE),
                        Address::new(&local, services),
                        1,
                        "/mock/".to_owned(),
                        0,
                        false,
                        [0; 32],
                    )),
                    NetworkMessage::Verack,
                ],
                NetworkMessage::Ping(nonce) => vec![NetworkMessage::Pong(nonce)],
                _ => vec![],
            };
            for payload in replies {
                let raw = RawNetworkMessage {
                    magic: Network::Regtest.magic(),
                    payload,
                };
                if write_half.write_all(&serialize(&raw)).await.is_err() {
                    return;
                }
            }
        }
    }

    enum Spread {
        Work,
        /// A block every peer sent `notfound` for waits in the queue.
        Refused,
        NoWork,
        Stalled,
        Exclusive,
    }

    /// How the supervisor is driven over the set.
    enum Drive {
        /// This many rounds, back to back, with every peer measured from the start.
        Rounds(usize),
        /// Its own loop, with the peers measured only after its first round. Nothing
        /// wakes it, as nothing does when a peer's rate first becomes known.
        MeasuredWhileRunning,
        /// One round in which these candidates, more than one round dials at once, are
        /// dialed before the mock nodes. It must end well within `CONNECT_DEADLINE`.
        RoundPastDuds(Vec<SocketAddr>),
    }

    /// A node that accepts the connection but never answers the handshake.
    async fn silent_node() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("bound address");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr
    }

    /// Drives the supervisor over a full set of peers at `ips`, serving `rates`, with two
    /// untried mock nodes to dial. Returns the indices of the peers swapped out. No
    /// network task runs, so nothing but the supervisor changes the set.
    async fn swapped_out(
        ips: [[u8; 4]; 3],
        rates: [u64; 3],
        spread: Spread,
        drive: Drive,
    ) -> Vec<usize> {
        let nodes = [mock_node().await, mock_node().await];
        let mut config =
            ClientConfig::regtest().with_transport_preference(TransportPreference::V1Only);
        if matches!(spread, Spread::Exclusive) {
            config.peers = nodes.to_vec();
        }
        let (state, _inbound) = NetworkState::new(&config);
        let state = Arc::new(state);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after epoch").as_secs();
        state.discoverer.lock().await.learn(nodes.map(|node| (node, now as u32)));
        let session = CancellationToken::new();

        let peers: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::from((*ip, 19999))).collect();
        for (addr, rate) in peers.iter().zip(rates) {
            let peer = ConnectedPeer::for_test(PeerId::for_test(*addr, 0)).await;
            peer.set_serving_rate(rate);
            let admitted = state.connected.admit(peer, &session, state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
        }
        if matches!(spread, Spread::Refused) {
            state.broker.enqueue(0, NetworkMessage::GetData(vec![block(1)])).await;
            let handles: Vec<PeerHandle> =
                state.connected.read().await.iter().map(|p| p.handle()).collect();
            for one in handles.chunks(1) {
                assert_eq!(state.broker.route(one, &state.costs).await, 1);
                state.broker.not_found(one[0].id(), &[block(1)]).await;
            }
        } else if !matches!(spread, Spread::NoWork) {
            state.broker.enqueue(0, get_cfilters(0)).await;
        }
        if matches!(spread, Spread::Stalled) {
            state.link_stalled.store(true, Ordering::Relaxed);
        }

        let supervisor = Supervisor::new(state.clone(), session.clone());
        match drive {
            Drive::Rounds(rounds) => {
                for _ in 0..rounds {
                    supervisor.repair_round().await;
                }
            }
            Drive::RoundPastDuds(duds) => {
                let mut discoverer = state.discoverer.lock().await;
                discoverer.learn(duds.iter().map(|dud| (*dud, now as u32)));
                // Known to serve, so the untried duds are dialed first.
                for node in nodes {
                    discoverer.served(node, 500_000);
                }
                drop(discoverer);
                let started = Instant::now();
                supervisor.repair_round().await;
                assert!(started.elapsed() < CONNECT_DEADLINE / 2, "held {:?}", started.elapsed());
            }
            Drive::MeasuredWhileRunning => {
                for peer in state.connected.read().await.iter() {
                    peer.set_serving_rate(0);
                }
                let running = tokio::spawn(supervisor.run());
                tokio::time::sleep(Duration::from_millis(200)).await;
                for (peer, rate) in state.connected.read().await.iter().zip(rates) {
                    peer.set_serving_rate(rate);
                }
                let deadline = Instant::now() + FILL_TICK * 2;
                while Instant::now() < deadline
                    && state.connected.read().await.iter().all(|p| peers.contains(&p.addr()))
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                session.cancel();
                running.await.expect("the supervisor stops");
            }
        }

        let live: Vec<SocketAddr> = state.connected.read().await.iter().map(|p| p.addr()).collect();
        assert_eq!(live.len(), 3);
        let gone: Vec<usize> = (0..3).filter(|i| !live.contains(&peers[*i])).collect();
        let joined = nodes.iter().filter(|node| live.contains(node)).count();
        assert_eq!(gone.len(), joined, "got {live:?}");
        let banned = state.bans.banned().await;
        assert!(gone.iter().all(|i| !banned.contains(&peers[*i])), "a swapped out peer is banned");
        gone
    }

    const CROWDED: [[u8; 4]; 3] = [[68, 67, 122, 1], [68, 67, 122, 2], [68, 67, 122, 3]];
    const SPREAD: [[u8; 4]; 3] = [[68, 67, 122, 1], [206, 245, 167, 63], [85, 209, 243, 1]];

    /// A full set inside one network group swaps its slowest peer for a peer of a group
    /// it lacks. Only while work waits and the link flows, and never for configured peers.
    #[test_case(Spread::Work => vec![1]; "the slowest of the crowded group goes")]
    #[test_case(Spread::NoWork => Vec::<usize>::new(); "not at the tip with no work")]
    #[test_case(Spread::Stalled => Vec::<usize>::new(); "not while the link is stalled")]
    #[test_case(Spread::Exclusive => Vec::<usize>::new(); "configured peers are kept")]
    #[tokio::test]
    async fn a_crowded_set_swaps_toward_a_missing_group(spread: Spread) -> Vec<usize> {
        swapped_out(CROWDED, [1_000_000, 800_000, 900_000], spread, Drive::Rounds(1)).await
    }

    /// A set of peers equally slow, so none is underserving, rotates its slowest peer out
    /// for an untried address on the first round. The newcomer is judged before the next
    /// rotation. Only while work waits and the link flows, never while a peer is still
    /// ramping, never a configured peer or a set that serves well.
    #[test_case([120_000, 100_000, 110_000], Spread::Work, 1 => vec![1]; "equally slow peers rotate at once")]
    #[test_case([120_000, 100_000, 110_000], Spread::Work, 2 => vec![1]; "the newcomer is judged first")]
    #[test_case([0, 100_000, 110_000], Spread::Work, 1 => Vec::<usize>::new(); "not while a peer is ramping")]
    #[test_case([0, 0, 0], Spread::Work, 1 => Vec::<usize>::new(); "nothing measured yet")]
    #[test_case([120_000, 100_000, 110_000], Spread::NoWork, 1 => Vec::<usize>::new(); "not at the tip with no work")]
    #[test_case([120_000, 100_000, 110_000], Spread::Stalled, 1 => Vec::<usize>::new(); "not while the link is stalled")]
    #[test_case([120_000, 100_000, 110_000], Spread::Exclusive, 1 => Vec::<usize>::new(); "configured peers are kept")]
    #[test_case([3_000_000, 2_500_000, 2_800_000], Spread::Work, 1 => Vec::<usize>::new(); "a healthy set is not churned")]
    #[test_case([3_000_000, 2_500_000, 2_800_000], Spread::Refused, 1 => vec![1]; "a healthy set that refused a request swaps its slowest")]
    #[tokio::test]
    async fn a_slow_set_rotates_its_slowest_peer(
        rates: [u64; 3],
        spread: Spread,
        rounds: usize,
    ) -> Vec<usize> {
        swapped_out(SPREAD, rates, spread, Drive::Rounds(rounds)).await
    }

    /// The supervisor swaps out a slow peer from its own loop once the rates are known,
    /// without anything waking it. Each peer sits in its own network group, so only the
    /// timer re-checks the full set.
    #[tokio::test]
    async fn a_running_supervisor_swaps_a_slow_peer_once_it_is_measured() {
        let rates = [1_000_000, 100_000, 1_000_000];
        let gone = swapped_out(SPREAD, rates, Spread::NoWork, Drive::MeasuredWhileRunning).await;
        assert_eq!(gone, [1]);
    }

    /// A rotation round dials past candidates that fail or never answer, and one that
    /// admits no newcomer is no miss.
    #[tokio::test]
    async fn a_rotation_round_dials_past_dud_candidates() {
        let lacking = ServiceFlags::NETWORK | ServiceFlags::BLOOM;
        let mut duds = Vec::new();
        for _ in 0..3 {
            duds.push(mock_node_serving(lacking).await);
            duds.push(silent_node().await);
        }
        let gone = swapped_out(
            SPREAD,
            [120_000, 100_000, 110_000],
            Spread::Work,
            Drive::RoundPastDuds(duds),
        )
        .await;
        assert_eq!(gone, [1]);
    }

    /// The supervisor rotates a slow set out of its own loop once the peers are measured,
    /// without anything waking it.
    #[tokio::test]
    async fn a_running_supervisor_rotates_once_the_peers_are_measured() {
        let gone = swapped_out(
            SPREAD,
            [120_000, 100_000, 110_000],
            Spread::Work,
            Drive::MeasuredWhileRunning,
        )
        .await;
        assert_eq!(gone, [1]);
    }

    /// Only a group of two or more peers is crowded, and its slowest peer goes, even when
    /// a peer alone in its group is slower.
    #[test_case(&[[68, 67, 122, 1], [206, 245, 167, 63], [85, 209, 243, 1]] => None; "one peer per group")]
    #[test_case(&[[68, 67, 122, 1], [68, 67, 9, 2], [206, 245, 167, 63]] => Some(1); "the slower of a pair")]
    #[tokio::test]
    async fn crowded_peer_is_the_slowest_of_a_shared_group(ips: &[[u8; 4]]) -> Option<usize> {
        let mut peers = Vec::new();
        for (ip, rate) in ips.iter().zip([900_000, 800_000, 100_000]) {
            let peer = ConnectedPeer::for_test(PeerId::for_test((*ip, 19999).into(), 0)).await;
            peer.set_serving_rate(rate);
            peers.push(peer);
        }
        let crowded = crowded_peer(&peers)?;
        peers.iter().position(|p| p.addr() == crowded)
    }

    /// A newcomer has no rate to be judged by until it has been bound for 30 s, since a
    /// fast peer is still ramping before that. A dip of a few seconds barely moves the
    /// rate, so a proven peer is not judged by it either.
    #[test]
    fn a_newcomer_is_measured_after_30_s_bound() {
        let mut served = Served::new();
        served.bulk(400_000, SERVING_SAMPLE_TICKS - 1);
        assert_eq!(served.flow.serving_rate(), 0);

        served.bulk(400_000, 1);
        let rate = served.flow.serving_rate();
        assert!((300_000..=400_000).contains(&rate), "serving rate {rate}");

        served.bulk(40_000, 8);
        let rate = served.flow.serving_rate();
        assert!(rate >= 300_000, "a 2 s dip drags the rate to {rate}");
    }

    fn rates(rates: &[(u8, u64)]) -> Vec<(SocketAddr, u64)> {
        rates.iter().map(|&(n, rate)| (test_socket_address(n), rate)).collect()
    }

    /// Rotates out a peer at 100 KB/s for `newcomer`, which then serves `served`.
    fn trial(exploration: &mut Exploration, newcomer: u8, served: u64) {
        exploration.rotated(Some(test_socket_address(newcomer)), 100_000);
        exploration.observe(&rates(&[(1, 200_000), (newcomer, served)]));
    }

    /// The first rotation is due at once and the next after `EXPLORE_MIN_INTERVAL`, but
    /// only once the newcomer is measured.
    #[tokio::test(start_paused = true)]
    async fn exploration_rotates_fast_while_it_finds_faster_peers() {
        let mut exploration = Exploration::new();
        exploration.observe(&rates(&[(1, 200_000), (2, 50_000)]));
        assert!(exploration.hold(50_000).is_none());

        exploration.rotated(Some(test_socket_address(3)), 50_000);
        exploration.observe(&rates(&[(1, 200_000), (3, 0)]));
        tokio::time::advance(EXPLORE_MIN_INTERVAL).await;
        assert!(exploration.hold(50_000).is_some(), "the newcomer is still ramping");

        exploration.observe(&rates(&[(1, 200_000), (3, 150_000)]));
        assert_eq!(exploration.misses, 0);
        assert!(exploration.hold(50_000).is_none());
        assert_eq!(exploration.interval(50_000), EXPLORE_MIN_INTERVAL);
    }

    /// Newcomers no faster than the peer they replaced stretch the interval, doubling up
    /// to `SWAP_COOLDOWN`. A faster one makes it fast again.
    #[tokio::test(start_paused = true)]
    async fn exploration_backs_off_while_it_finds_nothing_faster() {
        let mut exploration = Exploration::new();
        let mut intervals = Vec::new();
        for n in 0..5 {
            trial(&mut exploration, 10 + n, 90_000);
            intervals.push(exploration.interval(50_000).as_secs());
        }
        assert_eq!(intervals, [10, 20, 40, 60, 60]);

        trial(&mut exploration, 20, 250_000);
        assert_eq!(exploration.interval(50_000), EXPLORE_MIN_INTERVAL);
    }

    /// A newcomer is a hit only if it serves at least twice what the peer it replaced did
    /// and is no longer clearly worse than the set's best. A little faster is a miss.
    #[test_case(200_000, 120_000 => 1; "a little faster")]
    #[test_case(200_000, 250_000 => 0; "clearly faster")]
    #[test_case(1_000_000, 250_000 => 1; "clearly faster but still far behind the best")]
    #[tokio::test(start_paused = true)]
    async fn a_newcomer_must_clearly_beat_the_peer_it_replaced(best: u64, served: u64) -> u32 {
        let mut exploration = Exploration::new();
        exploration.rotated(Some(test_socket_address(10)), 100_000);
        exploration.observe(&rates(&[(1, best), (10, served)]));
        exploration.misses
    }

    /// A rotation that admitted no newcomer is no miss and does not hold the next one.
    #[tokio::test(start_paused = true)]
    async fn a_rotation_without_a_newcomer_changes_nothing() {
        let mut exploration = Exploration::new();
        trial(&mut exploration, 10, 90_000);
        tokio::time::advance(EXPLORE_MIN_INTERVAL).await;

        exploration.rotated(None, 100_000);

        assert_eq!(exploration.misses, 1);
        assert_eq!(exploration.hold(50_000), None);
    }

    /// A backed-off rotation turns fast again once the set's best rate halves or doubles.
    #[test_case(200_000 => 20; "the best rate holds")]
    #[test_case(90_000 => 10; "a peer collapses")]
    #[test_case(450_000 => 10; "a slowdown passes")]
    #[tokio::test(start_paused = true)]
    async fn exploration_turns_fast_when_the_best_rate_moves(best: u64) -> u64 {
        let mut exploration = Exploration::new();
        trial(&mut exploration, 10, 90_000);
        trial(&mut exploration, 11, 90_000);
        exploration.observe(&rates(&[(1, best), (11, 60_000)]));
        exploration.interval(30_000).as_secs()
    }

    /// Only a slowest peer clearly worse than the set's best rotates at the fast pace. An
    /// even set explores once per `SWAP_COOLDOWN`, from its first rotation on.
    #[tokio::test(start_paused = true)]
    async fn exploration_is_slow_while_the_set_is_even() {
        let mut exploration = Exploration::new();
        exploration.observe(&rates(&[(1, 110_000), (2, 100_000)]));
        assert_eq!(exploration.interval(100_000), SWAP_COOLDOWN);
        assert_eq!(exploration.interval(50_000), EXPLORE_MIN_INTERVAL);
    }

    /// A node that cannot serve compact filters is banned on the spot, not only backed
    /// off like a failed dial, so it does not take a candidate slot round after round.
    #[tokio::test]
    async fn a_node_lacking_required_services_is_banned() {
        let node = mock_node_serving(ServiceFlags::NETWORK | ServiceFlags::BLOOM).await;
        let config = ClientConfig::regtest().with_transport_preference(TransportPreference::V1Only);
        let (state, _inbound) = NetworkState::new(&config);
        let state = Arc::new(state);

        let dialed = DisconnectedPeer::new(node, Network::Regtest)
            .connect(state.clone(), CancellationToken::new())
            .await;

        assert!(dialed.is_err());
        assert!(state.bans.banned().await.contains(&node));
    }

    /// Gossiped addresses whose service bits lack what the client needs are not learned.
    #[tokio::test]
    async fn gossip_without_required_services_is_not_learned() {
        let net = PeerNetworkManager::new(&ClientConfig::regtest()).await;
        let full = ServiceFlags::NETWORK | ServiceFlags::COMPACT_FILTERS | ServiceFlags::BLOOM;
        let serves = SocketAddr::from(([62, 60, 244, 174], 19999));
        let lacks = SocketAddr::from(([46, 224, 41, 173], 19999));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after epoch").as_secs();
        let addr = NetworkMessage::Addr(vec![
            (now as u32, Address::new(&serves, full)),
            (now as u32, Address::new(&lacks, ServiceFlags::NETWORK | ServiceFlags::BLOOM)),
        ]);
        net.state
            .inbound
            .send(PeerEvent::Message(conn(1, 0), addr.into()))
            .expect("the pump is running");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let known = net
            .state
            .discoverer
            .lock()
            .await
            .get(10, &HashMap::new(), &HashSet::new(), Pick::Any)
            .await;
        let known: Vec<SocketAddr> = known.iter().map(|p| p.addr()).collect();
        assert_eq!(known, [serves]);
    }

    /// A handshake that lost its round's race says nothing about how the node serves, so
    /// its address gets no priority over other untried ones in the next round.
    #[tokio::test]
    async fn a_backup_from_a_round_has_no_priority() {
        let config = ClientConfig::regtest();
        let (state, _inbound) = NetworkState::new(&config);
        let state = Arc::new(state);
        let addresses: Vec<SocketAddr> =
            (1..=5).map(|n| SocketAddr::from(([68, 67, 122, n], 19999))).collect();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after epoch").as_secs();
        state.discoverer.lock().await.learn(addresses.iter().map(|a| (*a, now as u32)));
        let supervisor = Supervisor::new(state.clone(), CancellationToken::new());

        let mut first = HashSet::new();
        for _ in 0..30 {
            supervisor
                .close_backups([ConnectedPeer::for_test(PeerId::for_test(addresses[0], 0)).await])
                .await;
            let picked = supervisor.next_candidates(1, Pick::Any).await;
            first.insert(picked[0].addr());
        }
        assert!(first.len() > 1, "the backup always leads: {first:?}");
    }

    /// A peer that leaves having held work for a request timeout without answering any
    /// is not dialed again this session. One asked for nothing, or for less long, is.
    #[test_case(Some(REQUEST_TIMEOUT) => true; "held work for a timeout")]
    #[test_case(Some(REQUEST_TIMEOUT / 2) => false; "left sooner")]
    #[test_case(None => false; "never asked")]
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_served_nothing_is_not_dialed_again(held: Option<Duration>) -> bool {
        let net = PeerNetworkManager::new(&ClientConfig::regtest()).await;
        let session = net.session.lock().await.clone();
        let id = conn(1, 0);
        let peer = ConnectedPeer::for_test(id).await;
        let handle = peer.handle();
        let admitted = net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
        assert!(matches!(admitted, Admission::Joined));
        if let Some(held) = held {
            handle.send(&get_cfilters(0)).await.expect("a loopback write");
            tokio::time::advance(held).await;
        }

        net.state.inbound.send(PeerEvent::Disconnected(id)).expect("the pump is running");
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::time::advance(Duration::from_secs(11 * 60)).await;

        net.state.bans.banned().await.contains(&id.addr())
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
                // The second peer keeps receiving until the first is kicked, then stalls
                // as the last peer, which is held for one more timeout before it goes too.
                for _ in 0..=REQUEST_TIMEOUT.as_secs() + 1 {
                    tokio::time::advance(TIMEOUT_CHECK).await;
                    receive(&net, 2, 100).await;
                    settle().await;
                }
                for _ in 0..2 {
                    tokio::time::advance(REQUEST_TIMEOUT + TIMEOUT_CHECK * 2).await;
                    settle().await;
                }
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

    /// Counts `n` bytes as read from connected peer `peer`.
    async fn receive(net: &PeerNetworkManager, peer: u8, n: u64) {
        for p in net.state.connected.read().await.iter() {
            if p.id() == conn(peer, 0) {
                p.receive_for_test(n);
            }
        }
    }

    enum Feed {
        Nothing,
        /// A complete answer from this peer every second.
        Answers(u8),
        /// Some bytes of an answer from this peer every second.
        Bytes(u8),
    }

    const ANSWER_DEADLINE_SECS: u64 = REQUEST_TIMEOUT.as_secs() * ANSWER_DEADLINE_TIMEOUTS as u64;

    /// Peer 1 carries a request for `secs` seconds while idle peer 2 keeps receiving.
    #[test_case(Feed::Nothing, 11, true; "a silent request")]
    #[test_case(Feed::Answers(1), 20, false; "the carrier answering keeps it alive")]
    #[test_case(Feed::Answers(2), 11, true; "another peer answering is not progress")]
    #[test_case(Feed::Bytes(1), ANSWER_DEADLINE_SECS - 2, false; "the carrier streaming one long answer keeps it alive")]
    #[test_case(Feed::Bytes(2), 11, true; "another peer streaming is not progress")]
    #[test_case(Feed::Bytes(1), ANSWER_DEADLINE_SECS + 2, true; "streaming that never completes an answer stalls")]
    #[tokio::test(start_paused = true)]
    async fn the_timeout_monitor_requeues_stalled_requests(feed: Feed, secs: u64, stalls: bool) {
        let net = broker().await;
        let session = net.session.lock().await.clone();
        for n in 1..=2 {
            let peer = ConnectedPeer::for_test(conn(n, 0)).await;
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
        }
        net.state.broker.mark_on_wire(&get_cfilters(0), conn(1, 0)).await;

        for _ in 0..secs {
            tokio::time::advance(TIMEOUT_CHECK).await;
            receive(&net, 2, 100).await;
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
                Feed::Bytes(peer) => receive(&net, peer, 1000).await,
            }
            settle().await;
        }

        // A stalled request is re-queued and may already be routed to peer 2.
        let carrier = net.state.broker.carrier_of(&RequestKey::CFilters(BlockHash::dummy(0))).await;
        assert_eq!(carrier == Some(conn(1, 0)), !stalls, "carrier {carrier:?}");
    }

    /// A kick re-sends what the peer still owes, not a batch that it delivered and that
    /// waits for the filters manager.
    #[tokio::test(start_paused = true)]
    async fn a_kick_requeues_no_delivered_filter_batch() {
        let net = broker().await;
        let session = net.session.lock().await.clone();
        for n in 1..=2 {
            let peer = ConnectedPeer::for_test(conn(n, 0)).await;
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
        }
        let (delivered, owed) = (get_cfilters(0), get_cfilters(1000));
        net.state.broker.mark_on_wire(&delivered, conn(1, 0)).await;
        net.state.broker.mark_on_wire(&owed, conn(1, 0)).await;
        let last = NetworkMessage::CFilter(CFilter {
            filter_type: 0,
            block_hash: BlockHash::dummy(0),
            filter: vec![0u8; 4],
        });
        net.state
            .inbound
            .send(PeerEvent::Message(conn(1, 0), last.into()))
            .expect("the pump is running");
        settle().await;

        for _ in 0..12 {
            tokio::time::advance(TIMEOUT_CHECK).await;
            receive(&net, 2, 100).await;
            settle().await;
        }

        let broker = &net.state.broker;
        let owed = RequestKey::CFilters(BlockHash::dummy(1000));
        assert_ne!(broker.carrier_of(&owed).await, Some(conn(1, 0)), "the peer must be kicked");
        let delivered = RequestKey::CFilters(BlockHash::dummy(0));
        assert_eq!(broker.state_of(&delivered).await, Some("arrived"));
    }

    /// A peer that was silent while idle is timed from the request it is given, and
    /// kicked only when it stays silent with that work for the full timeout.
    #[tokio::test(start_paused = true)]
    async fn the_timeout_monitor_times_an_idle_peer_from_its_first_request() {
        let net = broker().await;
        let session = net.session.lock().await.clone();
        let peer = ConnectedPeer::for_test(conn(1, 0)).await;
        let handle = peer.handle();
        // A second peer, so the stalled one is not the last peer.
        for peer in [peer, ConnectedPeer::for_test(conn(2, 0)).await] {
            let admitted =
                net.state.connected.admit(peer, &session, net.state.max_peers, None).await;
            assert!(matches!(admitted, Admission::Joined));
        }

        // The second peer keeps receiving, so a stall is not blamed on our link.
        let run = |secs: u64| {
            let net = &net;
            async move {
                for _ in 0..secs {
                    tokio::time::advance(TIMEOUT_CHECK).await;
                    receive(net, 2, 100).await;
                    settle().await;
                }
            }
        };
        run(REQUEST_TIMEOUT.as_secs() * 3).await;
        // Only the charge matters here: the loopback has no reader to answer it.
        let _ = handle.send(&get_cfilters(0)).await;
        assert!(handle.in_flight_bytes() > 0);

        run(2).await;
        assert_eq!(net.connected_count().await, 2, "kicked right after its first request");

        run(REQUEST_TIMEOUT.as_secs()).await;
        assert_eq!(net.connected_count().await, 1, "a peer silent with work stays connected");
    }

    /// Counts the request timeout warnings.
    struct TimeoutWarnings(Arc<AtomicUsize>);

    struct Message(String);

    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    impl Subscriber for TimeoutWarnings {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut message = Message(String::new());
            event.record(&mut message);
            if *event.metadata().level() == Level::WARN && message.0.starts_with("request timeout")
            {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn enter(&self, _: &span::Id) {}

        fn exit(&self, _: &span::Id) {}
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
        /// Owes bytes, receives until the first second and again from the second.
        Resumes(u64, u64),
        /// Idle, and receives bytes every this many seconds.
        Whispers(u64),
    }

    /// Peer `n + 1` plays `roles[n]` for `secs` seconds. Only a tick that kicks a peer
    /// warns, and each kicks one here.
    #[test_case(&[Role::Registered(0); 3], 11, &[1, 2, 3]; "a stall of every peer at once is our link")]
    #[test_case(&[Role::Registered(0); 3], 41, &[1, 2, 3]; "a 40 s silence of every peer kicks nobody")]
    #[test_case(&[Role::Registered(0); 3], 71, &[2, 3]; "every peer silent past the bound loses the one silent the longest")]
    #[test_case(&[Role::Registered(0); 3], 72, &[3]; "every peer silent past the bound loses one per timeout")]
    #[test_case(&[Role::Charged(0); 3], 25, &[1, 2, 3]; "a long stall of every peer is still our link")]
    #[test_case(&[Role::Registered(1), Role::Registered(2), Role::Registered(3)], 25, &[1, 2, 3]; "peers going silent a second apart in an outage stay")]
    #[test_case(&[Role::Charged(1), Role::Charged(2), Role::Charged(3)], 25, &[1, 2, 3]; "peers owing bytes and going silent a second apart stay")]
    #[test_case(&[Role::Delivers(0), Role::Registered(0), Role::Delivers(0)], 11, &[1, 3]; "a lone silent request among delivering peers is kicked")]
    #[test_case(&[Role::Delivers(0), Role::Charged(0), Role::Delivers(0)], 12, &[1, 3]; "a lone peer owing bytes among delivering peers is kicked")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(0)], 11, &[2, 3]; "two stalls beside a delivering peer kick one")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(0)], 22, &[2]; "the second stall goes a timeout later")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(1)], 12, &[2, 3]; "stalls a second apart beside a delivering peer go one per timeout")]
    #[test_case(&[Role::Registered(0), Role::Delivers(0), Role::Registered(1), Role::Joins(11)], 12, &[2, 3, 4]; "a replacement joining does not unpace the next stall")]
    #[test_case(&[Role::Registered(0), Role::Delivers(13), Role::Registered(1)], 13, &[2, 3]; "a late witness kicks the peer silent the longest")]
    #[test_case(&[Role::Resumes(5, 20), Role::Resumes(5, 20), Role::Charged(5)], 25, &[1, 2, 3]; "a peer still silent when the link is back gets a timeout")]
    #[test_case(&[Role::Resumes(5, 20), Role::Resumes(5, 20), Role::Charged(5)], 31, &[1, 2]; "a peer silent a timeout after the link is back is kicked")]
    #[test_case(&[Role::Charged(0), Role::Whispers(3)], 13, &[2]; "a lone peer owing bytes beside an idle one is no link stall")]
    #[test_case(&[Role::Registered(0)], 11, &[1]; "the last peer stays")]
    #[test_case(&[Role::Registered(0), Role::Registered(0), Role::Joins(12)], 13, &[1, 2, 3]; "a peer joining during an outage proves nothing")]
    #[tokio::test(start_paused = true)]
    async fn the_timeout_monitor_kicks_one_peer_per_shared_stall(
        roles: &[Role],
        secs: u64,
        kept: &[u8],
    ) {
        let warnings = Arc::new(AtomicUsize::new(0));
        let _logging = tracing::subscriber::set_default(TimeoutWarnings(warnings.clone()));
        let net = broker().await;
        let session = net.session.lock().await.clone();
        let join = |n: u8| {
            let (net, session) = (&net, &session);
            async move {
                let peer = ConnectedPeer::for_test(conn(n, 0)).await;
                if let Role::Charged(_) | Role::Resumes(..) = roles[usize::from(n) - 1] {
                    // Only the charge matters here: the loopback has no reader to answer it.
                    let _ = peer.handle().send(&get_cfilters(n.into())).await;
                }
                let admitted = net.state.connected.admit(peer, session, roles.len(), None).await;
                assert!(matches!(admitted, Admission::Joined));
            }
        };
        for (n, role) in (1..).zip(roles) {
            if !matches!(role, Role::Joins(_)) {
                join(n).await;
            }
        }
        // Registered after the sockets connect, so all requests start at the same instant.
        for (n, role) in (1..).zip(roles) {
            if let Role::Registered(_) = role {
                net.state.broker.mark_on_wire(&get_cfilters(n.into()), conn(n, 0)).await;
            }
        }

        for second in 1..=secs {
            tokio::time::advance(TIMEOUT_CHECK).await;
            for (n, role) in (1..).zip(roles) {
                let receives = match *role {
                    Role::Registered(until) | Role::Charged(until) => second <= until,
                    Role::Delivers(from) => second >= from,
                    Role::Resumes(until, from) => second <= until || second >= from,
                    Role::Whispers(period) => second.is_multiple_of(period),
                    Role::Joins(at) => {
                        if second == at {
                            join(n).await;
                        }
                        false
                    }
                };
                if receives {
                    receive(&net, n, 100).await;
                }
            }
            settle().await;
        }

        let left: Vec<SocketAddr> =
            net.state.connected.read().await.iter().map(|p| p.addr()).collect();
        let kept: Vec<SocketAddr> = kept.iter().map(|&n| test_socket_address(n)).collect();
        assert_eq!(left, kept);
        assert_eq!(warnings.load(Ordering::SeqCst), roles.len() - kept.len());
    }

    /// Peer 1 serves 1 MB/s and owes a `headers2` reply, peer 2 serves 50 KB/s and owes a
    /// block, so a new block goes to peer 1 unless it stalled. Then peer 1 delivers
    /// `per_tick` bytes for `ticks` ticks. Returns which peer the next block goes to.
    #[test_case(8, 64 => 2; "a peer owing replies that delivers only pings ranks last")]
    #[test_case(7, 64 => 1; "a reply in the making for less than the hedge delay keeps its rank")]
    #[test_case(40, 4096 => 1; "a reply streaming in slowly keeps its rank")]
    #[tokio::test]
    async fn a_stalled_peer_gets_no_new_blocks(ticks: u32, per_tick: u64) -> u8 {
        let peers =
            [ConnectedPeer::for_test(conn(1, 0)).await, ConnectedPeer::for_test(conn(2, 0)).await];
        let locator = GetHeadersMessage::new(vec![BlockHash::dummy(1)], BlockHash::dummy(0));
        peers[0].handle().send(&NetworkMessage::GetHeaders2(locator)).await.expect("loopback send");
        peers[1]
            .handle()
            .send(&NetworkMessage::GetData(vec![block(1)]))
            .await
            .expect("loopback send");
        let mut flows = peers.each_ref().map(|p| PeerFlow::new(p.bytes_read()));
        let tick_s = FLOW_TICK.as_secs_f64();
        let mut tick = |deliveries: [u64; 2]| {
            for ((peer, flow), bytes) in peers.iter().zip(&mut flows).zip(deliveries) {
                peer.receive_for_test(bytes);
                flow.update(peer, peer.in_flight_bytes(), false);
            }
        };
        for _ in 0..40 {
            tick([(1e6 * tick_s) as u64, (50e3 * tick_s) as u64]);
        }
        for _ in 0..ticks {
            tick([per_tick, (50e3 * tick_s) as u64]);
        }

        let broker = Broker::new();
        broker.enqueue(0, NetworkMessage::GetData(vec![block(2)])).await;
        let before = peers.each_ref().map(|p| p.in_flight_bytes());
        let handles = peers.each_ref().map(|p| p.handle());
        assert_eq!(broker.route(&handles, &ResponseCosts::new()).await, 1);
        let routed = peers.iter().zip(before).position(|(p, b)| p.in_flight_bytes() > b);
        routed.map_or(0, |i| i as u8 + 1)
    }

    /// A burst at 5 MB/s lifts the peer's cap, then it serves 100 KB/s of a 1 MB backlog
    /// below that cap. Its serving rate is measured while it is backlogged, not only once the
    /// cap has fallen enough to bind it.
    #[test]
    fn a_backlogged_peer_is_measured_below_its_cap() {
        let tick_s = FLOW_TICK.as_secs_f64();
        let mut flow = PeerFlow::new(0);
        let mut bytes = 0;
        for _ in 0..8 {
            bytes += (5e6 * tick_s) as u64;
            flow.tick(bytes, 64 * 1024, false);
        }
        // The cap falls below the backlog after about 34 ticks, so a peer sampled only while
        // bound misses those. The 1 s rate average needs about 9 to read the backlog.
        for _ in 0..SERVING_SAMPLE_TICKS + 20 {
            bytes += (100e3 * tick_s) as u64;
            flow.tick(bytes, 1 << 20, false);
        }

        let rate = flow.serving_rate();
        assert!(rate > 0 && rate < 300_000, "{rate} after {} samples", flow.serving_ticks);
    }

    /// A peer serves 1 MB/s with work for three ticks, then nothing for one.
    #[test_case(false, true => 750_000; "a stall of its own drags its serving rate")]
    #[test_case(true, true => 1_000_000; "a stall of our link does not")]
    #[test_case(false, false => 1_000_000; "idle ticks do not")]
    fn the_serving_rate_averages_ticks_with_work(link_stalled: bool, has_work: bool) -> u64 {
        let mut flow = PeerFlow {
            limiter: ByteLimiter::new(0),
            serving_rate: 0.0,
            serving_ticks: 0,
            stalled_ticks: 0,
        };
        for _ in 0..3 {
            flow.sample(1e6, true, false);
        }
        flow.sample(0.0, has_work, link_stalled);
        flow.serving_rate as u64
    }

    #[test_case(false => Some(test_socket_address(2)); "a slow peer is named")]
    #[test_case(true => None; "nobody is named while our link stalls")]
    #[tokio::test]
    async fn underserving_peer_names_the_slow_peer(link_stalled: bool) -> Option<SocketAddr> {
        let mut peers = Vec::new();
        for (n, rate) in [(1, 1_000_000), (2, 100_000)] {
            let peer = ConnectedPeer::for_test(conn(n, 0)).await;
            peer.set_serving_rate(rate);
            peers.push(peer);
        }
        underserving_peer(&peers, link_stalled).map(|slow| slow.addr)
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

    /// Returns the initial cap and the cap after every tick of `secs`, while the sender
    /// keeps the cap full and the path delivers `serve(second, in_flight)` bytes/s.
    fn caps_while_full(secs: u32, serve: impl Fn(f64, f64) -> f64) -> Vec<u64> {
        caps_with_work(secs, |_, cap| cap, serve)
    }

    /// Like [`caps_while_full`], with `work(second, cap)` bytes in flight.
    fn caps_with_work(
        secs: u32,
        work: impl Fn(f64, u64) -> u64,
        serve: impl Fn(f64, f64) -> f64,
    ) -> Vec<u64> {
        let tick_s = FLOW_TICK.as_secs_f64();
        let mut limiter = ByteLimiter::new(0);
        let mut bytes = 0.0;
        let mut caps = vec![MIN_CAP_BYTES];
        for tick in 0..(secs as f64 / tick_s) as usize {
            let second = tick as f64 * tick_s;
            let in_flight = work(second, caps[caps.len() - 1]);
            bytes += serve(second, in_flight as f64) * tick_s;
            caps.push(limiter.tick(bytes as u64, in_flight, false));
        }
        caps
    }

    fn cap_after(caps: &[u64], secs: u32) -> u64 {
        caps[(secs as f64 / FLOW_TICK.as_secs_f64()) as usize]
    }

    #[test_case(0.1, 2; "a near link")]
    #[test_case(0.8, 5; "a far link")]
    #[test_case(1.5, 30; "a link whose round trip nears the target queue")]
    fn a_byte_cap_ramps_to_fill_a_fast_link(round_trip: f64, within_secs: u32) {
        let link_rate = 10e6;
        let caps = caps_while_full(60, |_, in_flight| (in_flight / round_trip).min(link_rate));

        let bdp = (link_rate * round_trip) as u64;
        assert!(cap_after(&caps, within_secs) >= bdp, "{}", cap_after(&caps, within_secs));
    }

    #[test]
    fn a_slow_peer_keeps_a_small_cap() {
        let caps = caps_while_full(300, |_, _| 150_000.0);

        let peak = caps.iter().max().copied().unwrap_or_default();
        assert!(peak < MIN_CAP_BYTES + 128 * 1024, "peak cap {peak}");
    }

    /// After 10 s at 5 MB/s the peer serves 100 KB/s. With 4 MB to serve it stays below the
    /// cap that burst earned, yet holds a 40 s queue, so the cap must fall all the same.
    #[test_case(false; "kept full")]
    #[test_case(true; "below the cap with a backlog")]
    fn a_cap_falls_with_the_peer_that_slowed_down(backlog: bool) {
        let work = |second: f64, cap: u64| {
            if backlog && second >= 10.0 {
                4 << 20
            } else {
                cap
            }
        };
        let caps = caps_with_work(60, work, |second, _| {
            if second < 10.0 {
                5e6
            } else {
                100_000.0
            }
        });

        assert!(cap_after(&caps, 10) > 8_000_000, "{}", cap_after(&caps, 10));
        assert!(cap_after(&caps, 30) < MIN_CAP_BYTES + 128 * 1024, "{}", cap_after(&caps, 30));
    }

    /// The peer alternates a second at 4 MB/s with a silent second. Its cap follows that
    /// 2 MB/s average, not each burst, which alone would ask for 8 MB.
    #[test]
    fn a_bursty_peer_keeps_a_steady_cap() {
        let caps = caps_while_full(60, |second, _| {
            if (second as u32).is_multiple_of(2) {
                4e6
            } else {
                0.0
            }
        });

        let settled = &caps[caps.len() / 2..];
        let (low, high) = (settled.iter().min(), settled.iter().max());
        assert!(
            low.zip(high).is_some_and(|(&low, &high)| low > 2_500_000 && high < 6_000_000),
            "{low:?} to {high:?}"
        );
    }

    /// A peer that got less work than its cap shows what it was asked for, not what it can
    /// serve. Its cap neither falls nor grows then, and bulk work finds it where it was.
    #[test_case(4 * 1024, 4 * 1024, 1000; "a trickle of small replies")]
    #[test_case(0, 0, 1000; "no work")]
    #[test_case(MIN_CAP_BYTES / 2, 0, 40; "one reply in the making")]
    fn a_peer_below_its_cap_keeps_it(in_flight: u64, per_tick: u64, ticks: usize) {
        let delivered = (5e6 * FLOW_TICK.as_secs_f64()) as u64;
        let mut limiter = ByteLimiter::new(0);
        let mut bytes = 0;
        let mut cap = MIN_CAP_BYTES;
        for _ in 0..40 {
            bytes += delivered;
            cap = limiter.tick(bytes, cap, false);
        }
        let earned = cap;

        for _ in 0..ticks {
            bytes += per_tick;
            assert_eq!(limiter.tick(bytes, in_flight, false), earned);
        }
        for _ in 0..40 {
            bytes += delivered;
            cap = limiter.tick(bytes, cap, false);
            assert!(cap as f64 > earned as f64 * 0.9, "{cap} fell from {earned}");
        }
    }

    #[test]
    fn a_stall_of_our_link_leaves_the_cap_alone() {
        let delivered = (5e6 * FLOW_TICK.as_secs_f64()) as u64;
        let mut limiter = ByteLimiter::new(0);
        let mut bytes = 0;
        let mut cap = MIN_CAP_BYTES;
        for _ in 0..40 {
            bytes += delivered;
            cap = limiter.tick(bytes, cap, false);
        }
        let earned = cap;

        for _ in 0..40 {
            cap = limiter.tick(bytes, cap, true);
        }
        assert_eq!(cap, earned);
        assert!(
            limiter.tick(bytes + delivered, cap, false) > earned / 2,
            "the rate is still known"
        );
    }
}
