use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Bounded concurrent handshakes per probe round.
const CONNECT_CHUNK: usize = 16;

/// Handshake ping at/above which a peer is "very bad": taken only as a last resort,
/// when nothing better is connectable and the set would otherwise be empty.
const BAD_LAG_MS: u32 = 1000;

/// A connected peer is underserving when its mean service time exceeds the best
/// connected peer's by this multiple
const SLOW_SERVICE_MULTIPLIER: f64 = 4.0;

/// Absolute slack alongside [`SLOW_SERVICE_MULTIPLIER`], so that when every peer
/// is fast in absolute terms the multiple does not split hairs over jitter.
const SLOW_SERVICE_MARGIN_MS: f64 = 500.0;

/// Completed requests a peer needs before its mean is trusted for eviction. One
/// slow response early in a connection says nothing about how it serves.
const MIN_SERVICE_SAMPLES: u64 = 4;

/// How often the supervisor re-checks a below-cap set and probes to keep filling.
const FILL_TICK: Duration = Duration::from_secs(2);

/// Cap on remembered (ranked) backup addresses, as a multiple of `max_peers`.
const BACKUP_MULTIPLE: usize = 8;

/// How long the router sleeps on a full-capacity stall before re-evaluating. It
/// wakes early whenever a response frees a slot or the timeout monitor kicks a
/// peer; this is just a backstop so it never sleeps on a notify that never comes.
const STALL_CHECK: Duration = Duration::from_secs(5);

/// A request unanswered for this long is treated as dead: the timeout monitor
/// re-queues it to another peer and kicks the peer sitting on it.
///
/// Deliberately aggressive. A cfilter batch normally completes in well under a
/// second, so a peer holding a request for 10s is slow enough to be worth
/// dropping — the reconnector refills the slot with a fresh peer faster than a
/// laggard recovers, and we would rather churn a slow peer than let it drag its
/// in-flight slots. (The per-peer AIMED already throttles a merely-slow-but-
/// responding peer to the floor; this catches the ones that stop answering.)
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the timeout monitor scans the outstanding-request registry.
const TIMEOUT_CHECK: Duration = Duration::from_secs(1);

/// How long a retired peer (displaced during startup, see [`retire_drained`]) is
/// kept alive to drain its in-flight responses before being force-closed.
const RETIRE_DRAIN_CAP: Duration = Duration::from_secs(90);

/// Poll interval for draining a retired peer's in-flight requests (see
/// [`retire_drained`]). The drain is capped at [`RETIRE_DRAIN_CAP`].
const DRAIN_POLL: Duration = Duration::from_secs(1);
use crate::{
    network::{
        discovery::PeerDiscoverer,
        peer::{ConnectedPeer, DisconnectedPeer, PeerEvent},
    },
    ClientConfig,
};

/// An inbound message on its way to the managers that subscribed to its type.
///
/// Shared rather than cloned: a `block` or `cfilter` carries its whole payload, and the
/// pump would otherwise deep-copy it for every subscriber. See `spawn_pump`'s fan-out.
pub type Inbound = (SocketAddr, Arc<NetworkMessage>);
type Subscribers = Arc<Mutex<HashMap<MessageType, Vec<UnboundedSender<Inbound>>>>>;

/// Every pipeline request the broker is handling, keyed by its identity, from the
/// moment `send` accepts it until the owning manager reports it answered
/// (`request_answered`) or cancels it (`cancel`). This is the single home of
/// request state: the pipelines hold no download coordinator, they just declare
/// what they want and the broker de-duplicates, paces, times out and retries.
///
/// - Membership is the de-dup set: `send` ignores a key already present.
/// - `OnWire` entries carry the message so the timeout monitor can re-inject it
///   (retry) after dropping the peer that ignored it.
type Registry = Arc<Mutex<HashMap<RequestKey, ReqState>>>;

/// The kinds of peer message a sync manager can subscribe to. Replaces the
/// stringly-typed command names: managers declare interest with these variants
/// and the pump routes incoming messages by mapping `cmd()` back to one.
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
    /// The wire command string this type corresponds to.
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

    /// Map an incoming message's command back to a subscribed type, if any.
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

#[derive(Clone, Debug)]
pub enum NetworkEvent {
    /// The connected peer set changed.
    PeersUpdated {
        /// How many peers are currently connected.
        connected_count: u32,
        /// Best tip height advertised across those peers.
        best_height: u32,
    },
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
}

/// Identifies a pipeline request the network manager tracks from send to
/// response, so it can time the request out and re-queue it (and drop the peer
/// that ignored it). One variant per router-paced request type. Used as a map
/// key in the outstanding-request registry, hence `Hash`/`Eq`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RequestKey {
    /// `getheaders` — keyed by the locator's first hash (the segment tip).
    Headers(dashcore::BlockHash),
    /// `getcfheaders` — keyed by the stop hash.
    CfHeaders(dashcore::BlockHash),
    /// `getcfilters` — keyed by the start height.
    CFilters(u32),
    /// `getmnlistdiff` — keyed by the target block hash. Tracked for de-dup and
    /// retry only; unlike the others it is not counted against a peer's in-flight
    /// budget (masternode diffs are few and not throughput-paced).
    MnListDiff(dashcore::BlockHash),
    /// Block `getdata` — keyed by the requested block hash.
    Block(dashcore::BlockHash),
}

/// Where a broker-tracked request is in its lifecycle.
enum ReqState {
    /// Accepted by `send` and sitting in the `MsgQueue`, not yet on the wire.
    /// Held here only for de-dup; the message itself lives in the queue.
    Queued,
    /// Sent to a peer and awaiting a response. Carries the message so the timeout
    /// monitor can re-inject it (retry) after dropping the peer. Boxed: it holds a
    /// whole `NetworkMessage`, far larger than the `Queued` variant.
    OnWire(Box<OnWire>),
}

/// A request currently on the wire, awaiting a response or a timeout.
struct OnWire {
    /// The peer the request was routed to.
    peer: SocketAddr,
    /// When this request last made progress: set on send, refreshed by every piece of
    /// a streaming response, so a peer streaming steadily is not judged stalled.
    last_progress: Instant,
    /// The exact message, re-queued verbatim on timeout (requests are
    /// self-contained, so re-sending the same bytes is a valid retry).
    msg: NetworkMessage,
}

pub struct PeerNetworkManager {
    /// Wakes the peer supervisor when the peer set needs attention: a peer was
    /// lost, or one was measured to be underserving
    peer_wake: Arc<Notify>,
    connected_peers: Arc<Mutex<Vec<(ConnectedPeer, State)>>>,
    other_peers: Arc<Mutex<Vec<DisconnectedPeer>>>,
    discoverer: Arc<Mutex<PeerDiscoverer>>,
    msg_queue: Arc<MsgQueue>,
    inbound_tx: UnboundedSender<PeerEvent>,
    subscribers: Subscribers,
    /// Broker state for every request in play (queued or on the wire).
    requests: Registry,
    events_tx: broadcast::Sender<NetworkEvent>,
    /// Best tip advertised by the peers, learned in `start`. Shared with the
    /// reconnector so its `PeersUpdated` carries the real height.
    best_tip: Arc<AtomicU32>,
    max_peers: usize,
    /// Service flags a peer must advertise to be kept (e.g. COMPACT_FILTERS when
    /// filters are enabled). Checked at handshake; `NONE` keeps every peer.
    required_services: ServiceFlags,
    /// Total bytes read from all peers. Held so `start` can hand it to the peers it connects.
    bytes: Arc<AtomicU64>,
    // Cancelled by `stop()` to tear down the router, pump and every peer reader.
    shutdown: CancellationToken,
}

/// Scheduling class of a queued message, in strict-priority order (see
/// [`MsgQueue::pop_n`]). Splitting by type lets the router drain them by priority
/// rather than FIFO, so a big backlog of one type never blocks another behind it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MsgClass {
    /// Control traffic (mempool, tx, ping, chainlock/islock `getdata`,
    /// `filterload`…): always first, few, and usually something is blocked on it.
    Other,
    /// Block `getdata` — the wallet's matched blocks. Highest bulk priority: a
    /// matched block gates the gap-limit cascade and completes in a single reply,
    /// so getting it out first keeps the scan advancing instead of stalling behind
    /// the streaming filter backlog.
    Blocks,
    /// `getcfilters` — the bulk of the bytes.
    CFilters,
    /// `getcfheaders` — filter headers.
    CfHeaders,
    /// `getheaders` — block headers.
    Headers,
}

fn classify(msg: &NetworkMessage) -> MsgClass {
    match msg {
        NetworkMessage::GetData(inv)
            if !inv.is_empty() && inv.iter().all(|i| matches!(i, Inventory::Block(_))) =>
        {
            MsgClass::Blocks
        }
        NetworkMessage::GetCFilters(_) => MsgClass::CFilters,
        NetworkMessage::GetCFHeaders(_) => MsgClass::CfHeaders,
        NetworkMessage::GetHeaders(_) | NetworkMessage::GetHeaders2(_) => MsgClass::Headers,
        _ => MsgClass::Other,
    }
}

/// One queue per class, each behind its own lock: a pipeline enqueuing a burst
/// only contends with itself. The router drains them by strict priority, so no
/// class is ever starved behind another's backlog.
struct MsgQueue {
    other: Mutex<VecDeque<NetworkMessage>>,
    blocks: Mutex<VecDeque<NetworkMessage>>,
    cfilters: Mutex<VecDeque<NetworkMessage>>,
    cfheaders: Mutex<VecDeque<NetworkMessage>>,
    headers: Mutex<VecDeque<NetworkMessage>>,
    len: AtomicUsize,
    notify: Notify,
}

/// Strict drain priority: control traffic first, then blocks (they gate the scan
/// and complete fast), then filters (the bytes), then filter headers, then block
/// headers.
const DRAIN_PRIORITY: [MsgClass; 5] =
    [MsgClass::Other, MsgClass::Blocks, MsgClass::CFilters, MsgClass::CfHeaders, MsgClass::Headers];

struct State {}

impl PeerNetworkManager {
    pub async fn new(config: &ClientConfig) -> Self {
        let discoverer = Arc::new(Mutex::new(PeerDiscoverer::new(config)));
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

        let connected_peers = Arc::new(Mutex::new(Vec::with_capacity(30)));
        let other_peers = Arc::new(Mutex::new(Vec::with_capacity(30)));
        let msg_queue = Arc::new(MsgQueue::new());

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let subscribers: Subscribers = Arc::new(Mutex::new(HashMap::new()));
        let requests: Registry = Arc::new(Mutex::new(HashMap::new()));
        // Sized generously: peer-connect churn plus one `RequestTimedOut` per
        // dead request during a bad-peer storm.
        let (events_tx, _) = broadcast::channel(4096);
        let shutdown = CancellationToken::new();
        // Total bytes read from all peers (download-only) and the global in-flight
        // budget. The budget is NOT a fixed number: it starts at a tiny bootstrap
        // just large enough to begin measuring, then `spawn_bandwidth_controller`
        // sizes it from the measured download capacity (Little's Law).
        let bytes = Arc::new(AtomicU64::new(0));
        let global_cap = Arc::new(AtomicUsize::new(max_peers.saturating_mul(4).max(8)));
        let best_tip = Arc::new(AtomicU32::new(0));
        let peer_wake = Arc::new(Notify::new());

        // Detached like the bandwidth controller and reconnector below: torn down
        // via the shutdown token, not by holding their handles.
        spawn_pump(
            inbound_rx,
            subscribers.clone(),
            connected_peers.clone(),
            events_tx.clone(),
            msg_queue.clone(),
            requests.clone(),
            shutdown.clone(),
            peer_wake.clone(),
            max_peers,
            discoverer.clone(),
        );

        spawn_router(
            msg_queue.clone(),
            connected_peers.clone(),
            shutdown.clone(),
            global_cap.clone(),
            requests.clone(),
        );

        spawn_timeout_monitor(
            requests.clone(),
            connected_peers.clone(),
            msg_queue.clone(),
            shutdown.clone(),
            peer_wake.clone(),
            max_peers,
        );

        spawn_bandwidth_controller(
            bytes.clone(),
            global_cap.clone(),
            connected_peers.clone(),
            shutdown.clone(),
            peer_wake.clone(),
        );

        // The peer supervisor is spawned by `start()`, not here: it must not emit
        // `PeersUpdated` until the sync managers have subscribed (see `start`).

        PeerNetworkManager {
            peer_wake,
            connected_peers,
            other_peers,
            discoverer,
            msg_queue,
            inbound_tx,
            subscribers,
            requests,
            events_tx,
            best_tip,
            max_peers,
            required_services,
            bytes,
            shutdown,
        }
    }

    /// Connect to peers and announce them.
    ///
    /// Split out of `new` on purpose: connecting there meant the one-shot `PeersUpdated`
    /// (and every `PeerConnected`) fired before any sync manager had subscribed, so those
    /// events were simply lost. Managers that track the peer set — the mempool, which must
    /// send `filterload` to enable transaction relay — ended up with an empty set and never
    /// activated. Build the manager, let the coordinator spawn and subscribe its managers,
    /// then call this.
    pub fn start(&self) {
        // Non-blocking: spawn the supervisor and return. It probes peers, connects
        // the decent ones, and emits `PeerConnected`/`PeersUpdated` as they arrive —
        // so sync begins the moment the first decent peer is up, without `start`
        // waiting on peer discovery. Spawned here rather than in `new` so it runs
        // only after the coordinator has subscribed its managers; otherwise the first
        // `PeersUpdated` (and the mempool's `filterload` trigger) would fire into the
        // void.
        spawn_peer_supervisor(
            self.discoverer.clone(),
            self.connected_peers.clone(),
            self.other_peers.clone(),
            self.inbound_tx.clone(),
            self.shutdown.clone(),
            self.bytes.clone(),
            self.events_tx.clone(),
            self.best_tip.clone(),
            self.max_peers,
            self.required_services,
            self.peer_wake.clone(),
        );
    }

    /// Tear down the network layer: stop the router and pump, and cancel every
    /// peer reader so no more messages arrive. Called on client shutdown.
    pub fn stop(&self) {
        tracing::info!(target: "dash_spv::network", "network manager stopping: cancelling tasks and peers");
        self.shutdown.cancel();
    }

    /// Ask the broker to make a request. De-duplicated by request identity: if the
    /// same request is already queued or on the wire, this is a no-op. Pipelines
    /// exploit that to re-declare what they want each tick without tracking what
    /// they already sent — the broker paces it, times it out and retries it.
    ///
    /// Non-pipeline messages (tx, mempool, control `getdata`) carry no request key
    /// and are neither de-duplicated nor tracked; they just go on the queue.
    pub async fn send(&self, msg: NetworkMessage) {
        let keys = request_keys(&msg);
        if keys.is_empty() {
            self.msg_queue.push(msg).await;
            return;
        }
        {
            let mut reqs = self.requests.lock().await;
            if keys.iter().any(|k| reqs.contains_key(k)) {
                return; // already in play
            }
            for key in keys {
                reqs.insert(key, ReqState::Queued);
            }
        }
        self.msg_queue.push(msg).await;
    }

    /// Send a message to one specific peer, bypassing the router's round-robin.
    ///
    /// `send` hands a message to whichever peer has capacity, which is right for a request
    /// any peer can answer. It is wrong for a message that sets state ON the remote node:
    /// `filterload`/`filterclear` (and the `mempool` that follows) turn transaction relay
    /// on for THAT peer, so routing them to "whoever is free" leaves the intended peer
    /// silent — and, with several peers, can enable relay on the same one twice.
    ///
    /// Returns false if the peer is not connected (or the write failed).
    pub async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        let peers = self.connected_peers.lock().await;
        let Some((peer, _)) = peers.iter().find(|(p, _)| p.addr() == addr) else {
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

    /// Note that `n` streaming requests served by `peer` have fully completed
    /// (e.g. a `getcfilters` batch whose last `cfilter` just arrived), freeing
    /// that peer's in-flight units and waking the router. Single-response
    /// requests are freed in the peer's own reader instead.
    pub async fn request_completed(&self, peer: SocketAddr, n: usize) {
        if n == 0 {
            return;
        }
        if let Some((p, _)) =
            self.connected_peers.lock().await.iter().find(|(p, _)| p.addr() == peer)
        {
            p.response_completed(n).await;
        }
        self.msg_queue.notify.notify_one();
    }

    /// Report that a request's response arrived, so the broker stops tracking it
    /// (no timeout, no retry, and its key is free to be requested again). The
    /// owning manager calls this once it has correlated a response back to the
    /// request key — the broker can't do it generically, since some responses
    /// (e.g. an empty `headers`) carry nothing to match on. No-op if the key is
    /// already gone (timed out first).
    pub async fn request_answered(&self, key: RequestKey) {
        self.requests.lock().await.remove(&key);
    }

    pub fn broadcast(&self, msg: NetworkMessage) {
        let peers = self.connected_peers.clone();
        tokio::spawn(async move {
            let guard = peers.lock().await;
            for (peer, _) in guard.iter() {
                let _ = peer.send(&msg).await;
            }
        });
    }

    /// Inject a message into the local pump as if it arrived from a peer, so
    /// managers process it through the same path. Uses the `0.0.0.0:0` sentinel
    /// address that managers treat as locally-originated.
    pub async fn dispatch_local(&self, msg: NetworkMessage) {
        let local: SocketAddr = ([0, 0, 0, 0], 0).into();
        let _ = self.inbound_tx.send(PeerEvent::Message(local, msg));
    }

    pub async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut subscribers = self.subscribers.lock().await;
        for kind in kinds.iter().copied().collect::<HashSet<_>>() {
            subscribers.entry(kind).or_default().push(tx.clone());
        }
        rx
    }

    pub fn tip(&self) -> u32 {
        self.best_tip.load(Ordering::Relaxed)
    }

    /// How many peers are currently connected.
    pub async fn connected_count(&self) -> u32 {
        self.connected_peers.lock().await.len() as u32
    }

    pub fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.events_tx.subscribe()
    }
}

fn spawn_router(
    queue: Arc<MsgQueue>,
    connected: Arc<Mutex<Vec<(ConnectedPeer, State)>>>,
    shutdown: CancellationToken,
    global_cap: Arc<AtomicUsize>,
    requests: Registry,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            // Wait for work. `notify` fires both when a message is queued and
            // when a response frees a peer slot.
            if queue.len() == 0 {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = queue.notify.notified() => continue,
                }
            }

            let peers = connected.lock().await;
            let sent =
                route_tick(&queue, &peers, global_cap.load(Ordering::Relaxed), &requests).await;
            drop(peers);

            if sent == 0 {
                // Queue non-empty but every peer is at its in-flight cap: wait for
                // a response to free a slot (the pump notifies on each response) or
                // for the timeout monitor to kick a stalled peer (which notifies
                // too). The sleep is only a backstop against a missed wake — dead
                // in-flight slots are reclaimed by the monitor dropping the peer
                // that holds them, not here.
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = queue.notify.notified() => {},
                    _ = tokio::time::sleep(STALL_CHECK) => {},
                }
            }
        }
    })
}

/// Extract the pipeline keys of a router-paced request, so the router can record
/// it in the outstanding-request registry. Returns empty for non-pipeline
/// messages (mirrors `is_pipeline_request` in `peer`: only these count toward a
/// peer's in-flight and are timed out).
fn request_keys(msg: &NetworkMessage) -> Vec<RequestKey> {
    match msg {
        NetworkMessage::GetHeaders(m) | NetworkMessage::GetHeaders2(m) => {
            m.locator_hashes.first().map(|h| RequestKey::Headers(*h)).into_iter().collect()
        }
        NetworkMessage::GetCFHeaders(m) => vec![RequestKey::CfHeaders(m.stop_hash)],
        NetworkMessage::GetCFilters(m) => vec![RequestKey::CFilters(m.start_height)],
        NetworkMessage::GetMnListD(m) => vec![RequestKey::MnListDiff(m.block_hash)],
        // One `getdata` may name several blocks; each is its own tracked request.
        NetworkMessage::GetData(inv) => inv
            .iter()
            .filter_map(|i| match i {
                Inventory::Block(h) => Some(RequestKey::Block(*h)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

async fn route_tick(
    queue: &MsgQueue,
    peers: &[(ConnectedPeer, State)],
    global_cap: usize,
    requests: &Registry,
) -> usize {
    if peers.is_empty() {
        return 0;
    }

    // Free capacity this round = min(sum of per-peer room, global room). Each
    // peer's cap is its MEASURED serving capacity (its bandwidth-delay product),
    // sized by the controller from that peer's own completion rate and service
    // time — fast peers carry more, slow peers less, with no fixed constant. The
    // global cap is our measured download capacity. Whichever binds first limits
    // this round, so we ride each peer's real ceiling without over-committing.
    let total_in_flight: usize = peers.iter().map(|(p, _)| p.in_flight()).sum();
    let per_peer_room: usize =
        peers.iter().map(|(p, _)| p.cap().saturating_sub(p.in_flight())).sum();
    let global_room = global_cap.saturating_sub(total_in_flight);
    let capacity = per_peer_room.min(global_room);
    if capacity == 0 {
        return 0;
    }

    let msgs = queue.pop_n(capacity).await;
    let mut sent = 0;
    // Anything popped that we could not put on the wire goes BACK on the queue.
    // Dropping it would strand the owning pipeline forever: it has already marked
    // the request as handed to the network, and its response timeout only starts
    // when the router reports the request on the wire, so a dropped message is
    // never re-sent and never times out.
    let mut unsent: Vec<NetworkMessage> = Vec::new();
    // Messages that made it onto the wire this round, recorded in the broker in one
    // lock acquisition after the send loop.
    let mut on_wire: Vec<(NetworkMessage, SocketAddr)> = Vec::new();
    let mut msgs = msgs.into_iter();
    for msg in msgs.by_ref() {
        // Send to the peer with the most free measured capacity.
        let Some((peer, _)) = peers
            .iter()
            .filter(|(p, _)| p.in_flight() < p.cap())
            .max_by_key(|(p, _)| p.cap().saturating_sub(p.in_flight()))
        else {
            unsent.push(msg); // every peer is at its measured cap
            break;
        };
        if peer.send(&msg).await.is_ok() {
            sent += 1;
            // Record which peer got it, so the monitor can attribute a stall to it.
            on_wire.push((msg, peer.addr()));
        } else {
            tracing::warn!(target: "dash_spv::network", "router: send to {} failed", peer.addr());
            unsent.push(msg);
        }
    }
    unsent.extend(msgs); // whatever the loop never reached
    queue.push_front_all(unsent).await;

    if !on_wire.is_empty() {
        let mut reqs = requests.lock().await;
        for (msg, peer) in on_wire {
            for key in request_keys(&msg) {
                // Transition Queued -> OnWire, keeping the message for retry. Skip
                // keys no longer present (cancelled while queued): the request went
                // out but we don't track it, so its response is simply ignored.
                if let Some(slot) = reqs.get_mut(&key) {
                    *slot = ReqState::OnWire(Box::new(OnWire {
                        peer,
                        msg: msg.clone(),
                        last_progress: Instant::now(),
                    }));
                }
            }
        }
    }

    if sent > 0 {
        tracing::debug!(
            target: "dash_spv::network",
            "router: sent {} | peers={} queue={}",
            sent,
            peers.len(),
            queue.len(),
        );
    }
    sent
}

/// Per-peer state the bandwidth controller carries across windows to size each
/// connection's in-flight cap independently, by Little's Law over that peer's OWN
/// completion stream (rather than an even split of the global budget).
#[derive(Default, Clone, Copy)]
struct PeerCapState {
    /// Cumulative completions/service-ns at the last window, to diff against.
    last_count: u64,
    last_total_ns: u64,
    /// Cumulative bytes downloaded from this peer at the last window, for its
    /// per-window throughput.
    last_bytes: u64,
    /// Uncongested service-time baseline in seconds (the peer's min `W`), 0 until
    /// first measured. Little's Law targets `L = λ · min_W`.
    min_w: f64,
    /// Windows since `min_w` last took a new low (BBR-style min-filter age). Lets a
    /// stale baseline expire and re-track the current cost, instead of one cheap
    /// early sample pinning it forever.
    min_w_age: u32,
    /// Smoothed cap, so it doesn't jitter window to window.
    cap_ema: f64,
}

/// Sizes the host's GLOBAL in-flight budget from MEASURED download throughput and
/// each PEER's cap from its own completion stream — no fixed magic number, per the
/// design goal of estimating how many requests the current network can absorb
/// before it saturates.
///
/// Two levels, both measured:
/// - The GLOBAL budget (host downlink) hill-climbs on bytes/s read off the sockets
///   (see below). It is the ceiling the host can reach with all peers combined.
/// - Each PEER's cap is `L = λ · min_W` (Little's Law) from THAT peer's completion
///   rate `λ` and uncongested service time `min_W`, so a fast peer earns a high cap
///   and a slow one a low cap. `route_tick` binds `min(Σ per-peer room, global
///   room)`, so whichever is the real bottleneck — the peers or the host link —
///   limits each round.
///
/// The estimate is Little's Law applied to downloads: the number of requests in
/// flight that sustains a completion rate `λ` at an uncongested per-request
/// service time `W` is `L = λ · W`. We measure both from the peers' response
/// stream — `λ` = requests completed per second, `W` = average time from send to
/// the response that completes the request (for `getcfilters`, dominated by the
/// download time of its ~1000 `cfilter`s, i.e. our downlink). We track the
/// minimum `W` as the uncongested baseline (the pipe's true latency at the front
/// of the knee) and target `L = λ · min_W`, probing slightly past it.
///
/// Saturation is detected by `W` INFLATION, not by throughput: once in-flight
/// exceeds the bandwidth-delay product, extra requests just queue at the peers,
/// so `W` climbs while `λ` (and the download rate) plateaus. That inflation is
/// visible even though a raw throughput meter can't see the knee (a prior
/// throughput hill-climb ran away and regressed sync ~8x because the backlog
/// kept bytes flowing). When `W > min_W · INFLATE` we stop probing and shrink
/// back toward the sustaining level, so we ride just below saturation.
fn spawn_bandwidth_controller(
    bytes: Arc<AtomicU64>,
    cap: Arc<AtomicUsize>,
    connected: Arc<Mutex<Vec<(ConnectedPeer, State)>>>,
    shutdown: CancellationToken,
    peer_wake: Arc<Notify>,
) -> JoinHandle<()> {
    const WINDOW: Duration = Duration::from_millis(500);
    const FLOOR_PER_PEER: usize = 2; // global floor = peers · this
    const PEER_CEIL: usize = 32; // per-connection sanity bound on in-flight
    const RISE: f64 = 1.05; // throughput must climb 5% to justify a bigger cap
    const DROP: f64 = 0.85; // throughput below this·last => over-commit, back off
    const REPROBE: u32 = 8; // plateau windows to hold before nudging the cap up
    const IDLE_BPS: f64 = 1.0e6; // downlink under 1 MB/s = idle, hold the cap
    const EMA_ALPHA: f64 = 0.5; // smoothing for the noisy per-window rate
                                // Per-peer cap: AIMED driven purely by THIS peer's service-time (lag). There is
                                // NO hard per-peer request limit — a peer with headroom keeps growing, so we
                                // fill the peers we have instead of recruiting more. It only backs off when its
                                // own lag inflates past the uncongested baseline.
    const CAP_GROW: f64 = 1.0; // additive increase per window while lag is flat
    const CAP_BACKOFF: f64 = 0.8; // multiplicative decrease when lag inflates
    const W_INFLATE: f64 = 1.5; // W above min_W·this => this peer is backing up
    const MIN_W_WINDOW: u32 = 20; // windows before a stale min_W baseline is re-tracked
    let window_s = WINDOW.as_secs_f64();

    tokio::spawn(async move {
        let mut last_bytes = bytes.load(Ordering::Relaxed);
        let mut rate_ema = 0.0f64; // smoothed downlink bytes/s
        let mut last_rate = 0.0f64; // smoothed rate at the previous cap adjustment
        let mut hold = 0u32; // consecutive plateau windows
                             // Per-peer cap state across windows, keyed by peer address.
        let mut peer_caps: HashMap<SocketAddr, PeerCapState> = HashMap::new();
        // Last peer reported as underserving. The supervisor is woken on the
        // TRANSITION only: re-notifying every window would turn a peer that stays
        // slow into a probe every 500ms, which is exactly the churn the improve
        // timer used to cause.
        let mut last_underserving: Option<SocketAddr> = None;
        let mut ticker = tokio::time::interval(WINDOW);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }

            // Downlink throughput (bytes read off the sockets — our downlink only).
            // This is the saturation signal: unlike per-request service time — which
            // balloons with cfilter payload size and out-of-order batch completion,
            // reading "saturated" forever and pinning the cap at its floor — bytes/s
            // directly reflects whether we are using the pipe. We grow the in-flight
            // budget while throughput keeps climbing with it and stop at the plateau
            // (the bandwidth-delay product: past it, more in-flight only grows queues,
            // not bytes/s), backing off if it collapses (peers over-committed).
            let now_bytes = bytes.load(Ordering::Relaxed);
            let dl_rate = now_bytes.saturating_sub(last_bytes) as f64 / window_s;
            last_bytes = now_bytes;
            rate_ema = if rate_ema == 0.0 {
                dl_rate
            } else {
                EMA_ALPHA * dl_rate + (1.0 - EMA_ALPHA) * rate_ema
            };

            let npeers = connected.lock().await.len();
            if npeers == 0 {
                continue;
            }
            let floor = (npeers * FLOOR_PER_PEER).max(FLOOR_PER_PEER);
            let ceiling = (npeers * PEER_CEIL).max(floor + 1);
            let step = npeers.max(4); // ~one extra slot per peer per window
            let cur = cap.load(Ordering::Relaxed);

            // Gradient hill-climb on smoothed throughput.
            let (new, action) = if rate_ema < IDLE_BPS {
                // Nothing meaningful downloading (e.g. the commit tail): hold the
                // budget steady so it is ready when the download resumes.
                (cur, "idle")
            } else if cur <= floor || rate_ema >= last_rate * RISE {
                // Still gaining (or at the floor): push the budget up.
                hold = 0;
                ((cur + step).min(ceiling), "grow")
            } else if rate_ema < last_rate * DROP {
                // Throughput collapsed — the peers are over-committed. Back off.
                hold = 0;
                (((cur as f64 * 0.8) as usize).max(floor), "backoff")
            } else {
                // Plateau: we are at the knee. Hold, re-probing up occasionally to
                // catch a capacity increase (a faster peer, less congestion).
                hold += 1;
                if hold >= REPROBE {
                    hold = 0;
                    ((cur + step).min(ceiling), "reprobe")
                } else {
                    (cur, "hold")
                }
            };
            // Anchor RISE/DROP to the rate at each real adjustment (skip idle/hold
            // windows) so the next comparison is like-for-like.
            if matches!(action, "grow" | "backoff" | "reprobe") {
                last_rate = rate_ema;
            }
            cap.store(new, Ordering::Relaxed);

            // Size each peer's cap by AIMED on its OWN service time (lag): grow while
            // its lag stays at the uncongested baseline (it has headroom), back off
            // the moment its lag inflates (it is backing up). No hard per-peer
            // request limit — a fast peer keeps growing so we fill the peers we have
            // instead of forcing new connections while there is still room for work.
            // The global cap above stays the host ceiling (route_tick binds by it).
            let (mut cap_min, mut cap_max, mut cap_sum) = (usize::MAX, 0usize, 0usize);
            let mut inflight_sum = 0usize; // total requests on the wire right now
            {
                let g = connected.lock().await;
                let live: HashSet<SocketAddr> = g.iter().map(|(p, _)| p.addr()).collect();
                for (p, _) in g.iter() {
                    let addr = p.addr();
                    let (count, total_ns) = p.latency_totals();
                    let now_bytes = p.bytes_read();
                    let st = peer_caps.entry(addr).or_default();
                    let dc = count.saturating_sub(st.last_count);
                    let dt = total_ns.saturating_sub(st.last_total_ns);
                    let d_bytes = now_bytes.saturating_sub(st.last_bytes);
                    st.last_count = count;
                    st.last_total_ns = total_ns;
                    st.last_bytes = now_bytes;
                    let rate = d_bytes as f64 / window_s; // this peer's downlink (bytes/s)

                    let (lambda, w) = if dc == 0 {
                        // No completions this window: either idle (no work queued to
                        // it) or stalled — the timeout monitor kicks a stalled peer at
                        // REQUEST_TIMEOUT. Keep at least the floor so the router can
                        // hand it work to bootstrap/keep measuring, but don't grow blind.
                        st.cap_ema = st.cap_ema.max(FLOOR_PER_PEER as f64);
                        (0.0, 0.0)
                    } else {
                        let lambda = dc as f64 / window_s; // completions/sec
                        let w = (dt as f64 / dc as f64) / 1e9; // avg service time (s)
                                                               // Windowed min-W baseline (BBR-style min filter): take a new low
                                                               // immediately, otherwise let the baseline go stale and re-track
                                                               // the current cost after MIN_W_WINDOW windows. Without the reset,
                                                               // one low sample from a cheap phase (fast headers) pins the
                                                               // baseline forever and every later heavier request (cfilters)
                                                               // reads as inflated => the cap decays to the floor and never
                                                               // recovers, throttling the very phase we want parallel.
                        if st.min_w == 0.0 || w < st.min_w {
                            st.min_w = w;
                            st.min_w_age = 0;
                        } else {
                            st.min_w_age += 1;
                            if st.min_w_age >= MIN_W_WINDOW {
                                st.min_w = w;
                                st.min_w_age = 0;
                            }
                        }
                        // AIMED on this peer's own lag: additive-increase while its
                        // service time sits at the uncongested baseline (headroom),
                        // multiplicative-decrease the moment it inflates (backing up).
                        if st.cap_ema == 0.0 {
                            st.cap_ema = FLOOR_PER_PEER as f64;
                        } else if w > st.min_w * W_INFLATE {
                            st.cap_ema = (st.cap_ema * CAP_BACKOFF).max(FLOOR_PER_PEER as f64);
                        } else {
                            st.cap_ema = (st.cap_ema + CAP_GROW).min(PEER_CEIL as f64);
                        }
                        (lambda, w)
                    };

                    let cap_peer = (st.cap_ema.round() as usize).clamp(FLOOR_PER_PEER, PEER_CEIL);
                    p.set_cap(cap_peer);

                    tracing::debug!(
                        target: "peer_speed",
                        "peer {}: cap={} in_flight={} lag={}ms lambda={:.1}/s W={:.0}ms rate={:.2} MB/s total={:.1} MB",
                        addr,
                        cap_peer,
                        p.in_flight(),
                        p.lag_ms(),
                        lambda,
                        w * 1e3,
                        rate / 1e6,
                        p.bytes_read() as f64 / 1e6,
                    );

                    cap_min = cap_min.min(cap_peer);
                    cap_max = cap_max.max(cap_peer);
                    cap_sum += cap_peer;
                    inflight_sum += p.in_flight();
                }
                // Drop state for peers that have disconnected.
                peer_caps.retain(|addr, _| live.contains(addr));

                // The service times were just refreshed, so this is the cheapest
                // place to notice a peer falling behind the rest — no extra timer
                // and no extra lock. Only the transition wakes the supervisor;
                // while the same peer stays slow we stay quiet, so a peer with no
                // available replacement is not re-probed every window.
                let underserving = underserving_peer(&g);
                if underserving.is_some() && underserving != last_underserving {
                    peer_wake.notify_one();
                }
                last_underserving = underserving;
            }
            if cap_min == usize::MAX {
                cap_min = 0;
            }

            // `bind` names the constraint the router is hitting: `global` if the
            // host budget is the smaller room, `peers` if the summed per-peer caps
            // are, `work` if neither is full (queue-limited or peers just slow). If
            // the downlink is saturated the global cap should hold at the knee and
            // `bind=global`.
            let bind = if inflight_sum >= new.min(cap_sum) {
                if new <= cap_sum {
                    "global"
                } else {
                    "peers"
                }
            } else {
                "work"
            };
            tracing::debug!(
                target: "peer_speed",
                "bandwidth: {:.1} MB/s (ema {:.1}) | {} bind={} | global_cap={} sum_peer_cap={} in_flight={} | peers={} per-peer cap min/avg/max={}/{}/{}",
                dl_rate / 1e6,
                rate_ema / 1e6,
                action,
                bind,
                new,
                cap_sum,
                inflight_sum,
                npeers,
                cap_min,
                cap_sum / npeers.max(1),
                cap_max,
            );
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

/// The peer supervisor: the single task that owns the connected-peer set.
///
/// It keeps `connected` filled toward `max_peers` with the lowest-latency peers it
/// can find, without ever blocking the caller:
///
/// - Below cap it probes candidates in parallel and accepts the decent ones
///   (handshake ping under [`BAD_LAG_MS`]), emitting `PeersUpdated` as they connect
///   so sync starts on the first one. A "very bad" peer is taken only as a last
///   resort — when the set would otherwise be empty and nothing better connected.
/// - At cap it does nothing until woken. The wake-up comes from a peer being lost
///   or from one being measured as underserving the rest, at which point it probes
///   for a replacement. There is no periodic improvement pass: probing costs a
///   connect plus a full handshake per candidate, all closed again, so a set that
///   is serving evenly never pays for it. The displaced peer is handed to
///   [`retire_drained`] so its in-flight requests finish (or time out) before its
///   socket closes.
/// - A peer kicked by the timeout monitor just drops the set below cap, so the next
///   fill round refills it — the same path as any other deficit.
///
/// Probed-but-unused peers are closed and kept as ranked backups (`others`, carrying
/// their measured ping) so a later round reconnects the best of them without probing
/// blindly.
struct Supervisor {
    discoverer: Arc<Mutex<PeerDiscoverer>>,
    connected: Arc<Mutex<Vec<(ConnectedPeer, State)>>>,
    others: Arc<Mutex<Vec<DisconnectedPeer>>>,
    inbound: UnboundedSender<PeerEvent>,
    shutdown: CancellationToken,
    bytes: Arc<AtomicU64>,
    events: broadcast::Sender<NetworkEvent>,
    best_tip: Arc<AtomicU32>,
    max_peers: usize,
    required_services: ServiceFlags,
    /// Fired when something happened that may warrant changing the peer set: a
    /// peer was lost, or one was measured to be underserving. The supervisor
    /// does nothing until one of those occurs
    wake: Arc<Notify>,
}

impl Supervisor {
    async fn run(self) {
        loop {
            self.repair_round().await;

            let short = self.connected.lock().await.len() < self.max_peers;

            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(FILL_TICK), if short => {}
            }
        }
    }

    /// Up to `want` candidate addresses to probe: best-ranked backups first, then
    /// fresh discovery, de-duplicated against each other and the live set.
    async fn next_candidates(&self, want: usize) -> Vec<DisconnectedPeer> {
        let mut out: Vec<DisconnectedPeer> = {
            let mut o = self.others.lock().await;
            o.sort_by_key(|p| p.lag_ms().unwrap_or(u32::MAX));
            let take = want.min(o.len());
            o.drain(..take).collect()
        };
        if out.len() < want {
            out.extend(self.discoverer.lock().await.get(want - out.len()).await);
        }
        let live: HashSet<SocketAddr> =
            self.connected.lock().await.iter().map(|(p, _)| p.addr()).collect();
        let mut seen = HashSet::new();
        out.retain(|p| !live.contains(&p.addr()) && seen.insert(p.addr()));
        out
    }

    /// Close probed-but-unused peers and remember them as ranked backups, keeping the
    /// list de-duplicated (best ping per address) and bounded.
    async fn stash_backups(&self, peers: impl IntoIterator<Item = ConnectedPeer>) {
        let mut o = self.others.lock().await;
        for peer in peers {
            peer.close();
            o.push(peer.disconnect());
        }
        // Dedup by address keeping the lowest ping, then rank and cap the list.
        o.sort_by(|a, b| {
            a.addr()
                .cmp(&b.addr())
                .then(a.lag_ms().unwrap_or(u32::MAX).cmp(&b.lag_ms().unwrap_or(u32::MAX)))
        });
        o.dedup_by_key(|p| p.addr());
        o.sort_by_key(|p| p.lag_ms().unwrap_or(u32::MAX));
        o.truncate(self.max_peers * BACKUP_MULTIPLE);
    }

    async fn announce_update(&self) {
        let count = self.connected.lock().await.len() as u32;
        let _ = self.events.send(NetworkEvent::PeersUpdated {
            connected_count: count,
            best_height: self.best_tip.load(Ordering::Relaxed),
        });
    }

    /// One pass at whatever the peer set needs: fill a deficit, replace a peer that
    /// is underserving the rest, or both.
    ///
    /// Filling and replacing were separate rounds when the supervisor ran on a
    /// timer, because each had its own schedule. Now that it only runs for cause
    /// they are the same operation — probe candidates, then put each arrival where
    /// it does the most good — and keeping them apart only meant two probe sizes,
    /// two acceptance rules and two copies of the bookkeeping.
    async fn repair_round(&self) {
        let (deficit, slow) = {
            let peers = self.connected.lock().await;
            let deficit = self.max_peers.saturating_sub(peers.len());
            // Only look for a laggard once the set is full: below cap every arrival
            // is wanted anyway, and replacing while short would just churn.
            let slow = (deficit == 0).then(|| underserving_peer(&peers)).flatten();
            (deficit, slow)
        };
        if deficit == 0 && slow.is_none() {
            return;
        }

        // Scale the probe to the need: a few candidates to find one replacement, a
        // full chunk when several slots are open and sync is waiting on them.
        let want = (deficit.max(1) * 4).min(CONNECT_CHUNK);
        let batch = self.next_candidates(want).await;
        if batch.is_empty() {
            return;
        }

        // Take each peer the moment ITS OWN handshake lands rather than waiting for
        // the batch to settle. Sync can start on the first peer, so holding the
        // fastest hostage to the slowest delays the whole client for no gain — and
        // with a batch barrier one unreachable address sets that delay.
        //
        // Completion order is itself a latency ranking (the quickest handshake is
        // the nearest peer), so this keeps the "best first" preference a sort used
        // to provide. The batch is still drained to the end, but only to bank the
        // rest as backups — nothing waits on that.
        let mut inflight: FuturesUnordered<_> = batch
            .into_iter()
            .map(|c| {
                c.connect(
                    self.inbound.clone(),
                    self.shutdown.clone(),
                    self.bytes.clone(),
                    self.required_services,
                )
            })
            .collect();

        let mut accepted = 0usize;
        let mut replaced: Option<SocketAddr> = None;
        let mut leftover: Vec<ConnectedPeer> = Vec::new();
        while let Some(result) = inflight.next().await {
            let Ok(peer) = result else {
                continue;
            };
            self.best_tip.fetch_max(peer.version().start_height.max(0) as u32, Ordering::Relaxed);

            let lag = peer.lag_ms();
            if lag == 0 || lag >= BAD_LAG_MS {
                leftover.push(peer);
                continue;
            }

            let mut changed = true;
            let displaced = {
                let mut peers = self.connected.lock().await;
                if peers.len() < self.max_peers {
                    let addr = peer.addr();
                    peers.push((peer, State {}));
                    let _ = self.events.send(NetworkEvent::PeerConnected(addr));
                    accepted += 1;
                    None
                } else if let Some(pos) = slow
                    .filter(|_| replaced.is_none())
                    // Re-find by address under the lock: the set can change between
                    // measuring and acting, and the laggard may already be gone.
                    .and_then(|s| peers.iter().position(|(p, _)| p.addr() == s))
                {
                    let new_addr = peer.addr();
                    let (old, _) = peers.swap_remove(pos);
                    peers.push((peer, State {}));
                    replaced = Some(new_addr);
                    Some(old)
                } else {
                    leftover.push(peer);
                    changed = false;
                    None
                }
            };

            if let Some(old) = displaced {
                let old_addr = old.addr();
                tracing::info!(
                    target: "dash_spv::network",
                    "peer supervisor: swapped out slow {} for {}",
                    old_addr,
                    replaced.expect("set with the displacing peer"),
                );
                // Keep the displaced peer alive until its in-flight requests drain
                // or time out — don't strand work already routed to it.
                retire_drained(old, self.shutdown.clone());
                let _ = self.events.send(NetworkEvent::PeerDisconnected(old_addr));
            }

            // Announce only what actually changed this round-trip: the first
            // arrival is what takes the sync managers out of
            // `WaitingForConnections`, and a swap changes who is serving. A
            // candidate that went to the bench changed nothing.
            if changed {
                self.announce_update().await;
            }
        }

        // Last resort: never sit at zero peers. If nothing decent connected and the
        // set is empty, take the least-bad handshake we got so sync can start; a
        // later round upgrades it once a decent peer appears.
        if accepted == 0 && self.connected.lock().await.is_empty() && !leftover.is_empty() {
            leftover.sort_by_key(lag_key);
            let peer = leftover.remove(0);
            let addr = peer.addr();
            tracing::warn!(
                target: "dash_spv::network",
                "no decent peer available; accepting {} (ping {}ms) as last resort",
                addr,
                peer.lag_ms(),
            );
            self.connected.lock().await.push((peer, State {}));
            let _ = self.events.send(NetworkEvent::PeerConnected(addr));
            self.announce_update().await;
            accepted += 1;
        }

        self.stash_backups(leftover).await;

        if accepted > 0 {
            tracing::info!(
                target: "dash_spv::network",
                "peer supervisor: +{} peers -> {}",
                accepted,
                self.connected.lock().await.len(),
            );
        }
    }
}

/// The connected peer that is clearly underserving the rest, if any.
///
/// Judged on measured service time — how long a peer takes to answer the pipeline
/// requests routed to it — rather than the handshake ping, which is a single
/// sample taken at connect and says nothing about how a peer serves filters or
/// blocks. A peer with too few completed requests is not judged at all: absence
/// of evidence is not evidence of slowness.
///
/// `None` means every peer is serving within reach of the best, which is the
/// signal that there is nothing to improve and no reason to probe.
fn underserving_peer(peers: &[(ConnectedPeer, State)]) -> Option<SocketAddr> {
    let measured: Vec<(SocketAddr, f64)> = peers
        .iter()
        .filter_map(|(p, _)| {
            let (count, avg_ms, _) = p.latency_stats();
            (count >= MIN_SERVICE_SAMPLES).then_some((p.addr(), avg_ms))
        })
        .collect();
    // Comparing needs a reference point: with fewer than two measured peers there
    // is no "the rest" to be slow against.
    if measured.len() < 2 {
        return None;
    }
    let best = measured.iter().map(|&(_, ms)| ms).fold(f64::INFINITY, f64::min);
    let threshold = (best * SLOW_SERVICE_MULTIPLIER).max(best + SLOW_SERVICE_MARGIN_MS);
    let (addr, worst) =
        measured.iter().copied().max_by(|a, b| a.1.total_cmp(&b.1)).expect("non-empty");
    (worst > threshold).then(|| {
        tracing::debug!(
            target: "dash_spv::network",
            "{} serving at {:.0}ms vs best {:.0}ms — a replacement is worth probing for",
            addr, worst, best,
        );
        addr
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_peer_supervisor(
    discoverer: Arc<Mutex<PeerDiscoverer>>,
    connected: Arc<Mutex<Vec<(ConnectedPeer, State)>>>,
    others: Arc<Mutex<Vec<DisconnectedPeer>>>,
    inbound: UnboundedSender<PeerEvent>,
    shutdown: CancellationToken,
    bytes: Arc<AtomicU64>,
    events: broadcast::Sender<NetworkEvent>,
    best_tip: Arc<AtomicU32>,
    max_peers: usize,
    required_services: ServiceFlags,
    wake: Arc<Notify>,
) -> JoinHandle<()> {
    tokio::spawn(
        Supervisor {
            discoverer,
            connected,
            others,
            inbound,
            shutdown,
            bytes,
            events,
            best_tip,
            max_peers,
            required_services,
            wake,
        }
        .run(),
    )
}

/// Pull every on-wire request routed to one of `gone` back to `Queued`, returning
/// the messages to put back on the send queue.
///
/// Both ways of losing a peer must do this, and do it identically: the timeout
/// monitor kicking a stalled peer, and the pump seeing its socket close. A
/// request whose peer is gone is tracked by nobody — the monitor only watches
/// connected peers — so leaving it `OnWire` strands it in the registry forever
/// while the pipeline that owns it waits for a response that can never arrive.
///
/// The key stays registered, as `Queued`, rather than being removed: the request
/// is still wanted, so de-duplication must keep holding for it while the message
/// sits back on the queue, or a pipeline re-declaring it would queue a duplicate.
async fn requeue_requests_from(
    requests: &Registry,
    gone: &HashSet<SocketAddr>,
) -> Vec<NetworkMessage> {
    let mut reinject = Vec::new();
    let mut reqs = requests.lock().await;
    let keys: Vec<RequestKey> = reqs
        .iter()
        .filter_map(|(k, s)| match s {
            ReqState::OnWire(o) if gone.contains(&o.peer) => Some(k.clone()),
            _ => None,
        })
        .collect();
    for key in keys {
        if let Some(ReqState::OnWire(o)) = reqs.insert(key, ReqState::Queued) {
            reinject.push(o.msg);
        }
    }
    reinject
}

/// Time requests out and evict the peers that stalled on them.
///
/// A peer is a culprit when it has in-flight work (`in_flight > 0`) AND no bytes
/// have arrived from it for a full [`REQUEST_TIMEOUT`] — i.e. it has gone silent
/// while owing us responses. Kicking is on peer liveness, not on any single
/// request's age: a healthy peer draining a deep backlog (the per-peer cap grows
/// with headroom, so we may have many requests queued at it) keeps sending bytes,
/// so its liveness clock keeps resetting even while its OLDEST request sits waiting
/// its turn. Only a peer that has stopped sending anything is worth dropping.
///
/// Judging on the peer's own counters (not the broker registry) is deliberate: the
/// registry can desync from a peer's real `in_flight` — correlating a response
/// frees the registry key, while streaming in-flight units are freed on the peer
/// separately — so a wedged peer can pin `in_flight == cap` (starving the router,
/// which only sends to peers under cap) while showing zero registry entries. A
/// registry-based check would miss exactly that peer.
///
/// When one is found we kick it immediately: every request routed to it is now
/// dead, so we pull ALL its on-wire entries, re-inject their messages (retry to a
/// fresh peer), and drop the connection. Its in-flight slots die with it — no
/// separate reclaim — and the reconnector refills the peer set. Requests the
/// registry lost track of are re-driven by their pipeline's wanted set. Immediate
/// kick is deliberate: leaving a dead peer connected would just route the freed
/// work straight back to it (the router fills the emptiest peer first).
fn spawn_timeout_monitor(
    requests: Registry,
    connected: Arc<Mutex<Vec<(ConnectedPeer, State)>>>,
    queue: Arc<MsgQueue>,
    shutdown: CancellationToken,
    peer_wake: Arc<Notify>,
    max_peers: usize,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TIMEOUT_CHECK);
        // Per-peer liveness: (bytes read at last progress, when it last rose).
        let mut progress: HashMap<SocketAddr, (u64, Instant)> = HashMap::new();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }

            let now = Instant::now();

            // Liveness is judged on the peer itself, not on the broker registry.
            // The registry can desync from a peer's real in-flight count (a request
            // whose response we correlate frees the registry key, while streaming
            // in-flight units are freed on the peer separately), so a wedged peer can
            // hold `in_flight == cap` — blocking the router from sending it anything —
            // while showing zero registry entries. Watching `in_flight` (has pending
            // work) and `bytes_read` (is data still arriving — covers both completed
            // requests and mid-stream progress) catches that: a peer with work
            // outstanding whose byte counter is frozen for a full REQUEST_TIMEOUT is
            // stuck and must be dropped, whatever the registry thinks.
            let mut culprits: HashSet<SocketAddr> = {
                let peers = connected.lock().await;
                let live: HashSet<SocketAddr> = peers.iter().map(|(p, _)| p.addr()).collect();
                progress.retain(|addr, _| live.contains(addr));
                let mut culprits = HashSet::new();
                for (peer, _) in peers.iter() {
                    let addr = peer.addr();
                    let bytes = peer.bytes_read();
                    let entry = progress.entry(addr).or_insert((bytes, now));
                    if bytes > entry.0 {
                        *entry = (bytes, now);
                    }
                    if peer.in_flight() > 0 && now.duration_since(entry.1) > REQUEST_TIMEOUT {
                        culprits.insert(addr);
                    }
                }
                culprits
            };
            // A request that stopped making progress also condemns its peer: the
            // per-peer byte check above sees unrelated traffic and judges it healthy.
            {
                let reqs = requests.lock().await;
                for state in reqs.values() {
                    if let ReqState::OnWire(o) = state {
                        if now.duration_since(o.last_progress) > REQUEST_TIMEOUT {
                            culprits.insert(o.peer);
                        }
                    }
                }
            }

            if culprits.is_empty() {
                continue;
            }

            // Pull every on-wire request routed to a culprit (fresh ones included —
            // the connection is going away, so they are dead too) and re-inject its
            // message (key kept as Queued so de-dup still holds).
            let reinject = requeue_requests_from(&requests, &culprits).await;

            // Drop the culprits still in the active set (some may already be gone
            // — a retired-drained peer isn't here — which is fine).
            let (dropped, remaining) = {
                let mut peers = connected.lock().await;
                let before = peers.len();
                peers.retain(|(p, _)| {
                    if culprits.contains(&p.addr()) {
                        p.close();
                        false
                    } else {
                        true
                    }
                });
                (before - peers.len(), peers.len())
            };
            // Evicting a peer leaves the set short. Wake the supervisor now instead
            // of letting it find out on its next round: with the improve timer gone
            // there may not be a next round until something asks for one.
            if dropped > 0 && remaining < max_peers {
                peer_wake.notify_one();
            }

            tracing::warn!(
                target: "dash_spv::network",
                "request timeout: kicked {} peer(s) {:?}, retried {} request(s)",
                dropped,
                culprits,
                reinject.len(),
            );

            for msg in reinject {
                queue.push(msg).await;
            }
            // Freed capacity (dropped peers) — wake the router to re-evaluate.
            queue.notify.notify_one();
        }
    })
}

/// Retire a peer we are dropping from the active set WITHOUT stranding requests
/// already on the wire to it. During startup the reconnector connects peers and
/// the sync sends them pipeline requests before the probe has settled the final
/// peer set; replacing the set would then drop those peers mid-request, and the
/// stranded requests only recover on the pipelines' own (slow) timeout —
/// occasionally stalling whole header segments for a run. Instead keep the
/// connection alive in the background: its reader keeps delivering responses and
/// decrementing `in_flight`. Close it once it has drained, or after
/// `RETIRE_DRAIN_CAP` (a peer that never drains is dead), whichever comes first.
fn retire_drained(peer: ConnectedPeer, shutdown: CancellationToken) {
    if peer.in_flight() == 0 {
        peer.close();
        return;
    }
    tokio::spawn(async move {
        let mut waited = Duration::ZERO;
        while peer.in_flight() > 0 && waited < RETIRE_DRAIN_CAP {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(DRAIN_POLL) => waited += DRAIN_POLL,
            }
        }
        peer.close();
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_pump(
    mut inbound: UnboundedReceiver<PeerEvent>,
    subscribers: Subscribers,
    connected: Arc<Mutex<Vec<(ConnectedPeer, State)>>>,
    events: broadcast::Sender<NetworkEvent>,
    queue: Arc<MsgQueue>,
    requests: Registry,
    shutdown: CancellationToken,
    peer_wake: Arc<Notify>,
    max_peers: usize,
    discoverer: Arc<Mutex<PeerDiscoverer>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Per-peer received-message counter to check load balance across peers.
        let mut recv_by_peer: HashMap<SocketAddr, u64> = HashMap::new();
        let mut total_recv: u64 = 0;
        loop {
            let event = tokio::select! {
                _ = shutdown.cancelled() => break,
                ev = inbound.recv() => match ev {
                    Some(ev) => ev,
                    None => break,
                },
            };
            match event {
                PeerEvent::Message(addr, msg) => {
                    *recv_by_peer.entry(addr).or_insert(0) += 1;
                    total_recv += 1;

                    // A `cfilter` is one piece of a `getcfilters` batch, which is only
                    // marked answered once the whole batch lands. Refresh that request's
                    // deadline so the timeout means "the pieces stopped coming".
                    if matches!(msg, NetworkMessage::CFilter(_)) {
                        let mut reqs = requests.lock().await;
                        for state in reqs.values_mut() {
                            if let ReqState::OnWire(o) = state {
                                if o.peer == addr
                                    && matches!(
                                        request_keys(&o.msg).first(),
                                        Some(RequestKey::CFilters(_))
                                    )
                                {
                                    o.last_progress = Instant::now();
                                }
                            }
                        }
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
                        // Per-peer request->response latency (avg / worst).
                        let lat: Vec<(SocketAddr, u64, String)> = connected
                            .lock()
                            .await
                            .iter()
                            .map(|(p, _)| {
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
                    // Peer address gossip: fold it into the discovery pool instead
                    // of dropping it. We advertise `sendaddrv2` at handshake, so
                    // peers send these unprompted; ignoring them left the pool
                    // frozen at whatever the seeds and one DNS lookup returned, with
                    // no way to learn about the network as addresses went stale.
                    // Both spellings: we ask for `sendaddrv2` at handshake, but a
                    // peer that ignored it answers `getaddr` with legacy `addr`,
                    // and dropping that would waste the round trip.
                    let gossiped: Option<Vec<SocketAddr>> = match &msg {
                        NetworkMessage::AddrV2(addrs) => {
                            Some(addrs.iter().filter_map(|a| a.socket_addr().ok()).collect())
                        }
                        NetworkMessage::Addr(addrs) => {
                            Some(addrs.iter().filter_map(|(_, a)| a.socket_addr().ok()).collect())
                        }
                        _ => None,
                    };
                    if let Some(gossiped) = gossiped {
                        let learned = discoverer.lock().await.learn(gossiped);
                        if learned > 0 {
                            tracing::debug!(
                                target: "dash_spv::network",
                                "learned {} new peer address(es) from {}",
                                learned,
                                addr
                            );
                            // Fresh candidates are exactly what a short set was
                            // waiting for, so tell the supervisor rather than making
                            // it find out on its next tick.
                            if connected.lock().await.len() < max_peers {
                                peer_wake.notify_one();
                            }
                        }
                    }

                    let mt = MessageType::from_cmd(msg.cmd());
                    // Single-message responses free a slot in the peer's reader;
                    // wake the router so it can use the freed capacity. `cfilter`
                    // is skipped — its batch frees a slot via `request_completed`,
                    // which notifies once per ~1000 messages instead of each.
                    if mt != Some(MessageType::CFilter) {
                        queue.notify.notify_one();
                    }

                    {
                        let mut subscribers = subscribers.lock().await;
                        if let Some(list) = mt.and_then(|t| subscribers.get_mut(&t)) {
                            let last = list.len().saturating_sub(1);
                            let mut msg = Some(Arc::new(msg));
                            let mut idx = 0;

                            list.retain(|tx| {
                                // Hand the *last* subscriber our own reference instead of a
                                // clone. Every heavy message type (block, cfilter, cfheaders,
                                // headers) has exactly one subscriber, so it arrives with a
                                // refcount of 1 and the manager can take the payload without
                                // copying it. Only `inv`, which is tiny, is really shared.
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
                PeerEvent::Disconnected(addr) => {
                    let remaining = {
                        let mut guard = connected.lock().await;
                        guard.retain(|(peer, _)| peer.addr() != addr);
                        guard.len()
                    };

                    // Losing a peer is the main reason the set needs refilling
                    if remaining < max_peers {
                        peer_wake.notify_one();
                    }

                    // A peer vanishing takes its in-flight requests with it: every
                    // request routed to it is now dead and no one else is tracking it.
                    // Pull them back to Queued and re-inject the messages so the router
                    // retries them on a live peer — the timeout monitor only watches
                    // connected peers, so a request whose peer is already gone would
                    // otherwise leak in the registry forever.
                    let reinject = requeue_requests_from(&requests, &HashSet::from([addr])).await;

                    tracing::info!(
                        target: "dash_spv::network",
                        "peer disconnected: {} | {} peers remaining | {} request(s) re-queued",
                        addr,
                        remaining,
                        reinject.len(),
                    );

                    for msg in reinject {
                        queue.push(msg).await;
                    }
                    queue.notify.notify_one();

                    let _ = events.send(NetworkEvent::PeerDisconnected(addr));
                }
            }
        }
    })
}

impl MsgQueue {
    fn new() -> Self {
        Self {
            other: Mutex::new(VecDeque::with_capacity(30)),
            blocks: Mutex::new(VecDeque::with_capacity(30)),
            cfilters: Mutex::new(VecDeque::with_capacity(30)),
            cfheaders: Mutex::new(VecDeque::with_capacity(30)),
            headers: Mutex::new(VecDeque::with_capacity(30)),
            len: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    fn queue(&self, class: MsgClass) -> &Mutex<VecDeque<NetworkMessage>> {
        match class {
            MsgClass::Other => &self.other,
            MsgClass::Blocks => &self.blocks,
            MsgClass::CFilters => &self.cfilters,
            MsgClass::CfHeaders => &self.cfheaders,
            MsgClass::Headers => &self.headers,
        }
    }

    /// Take up to `n` messages in strict priority order ([`DRAIN_PRIORITY`]):
    /// control traffic, then blocks, filters, filter headers, block headers. A
    /// class is fully drained (up to the remaining budget) before the next is
    /// touched, so a large backlog of one type never blocks another behind it.
    async fn pop_n(&self, n: usize) -> Vec<NetworkMessage> {
        if n == 0 {
            return Vec::new();
        }
        let mut out: Vec<NetworkMessage> = Vec::with_capacity(n);
        for class in DRAIN_PRIORITY {
            if out.len() >= n {
                break;
            }
            let mut q = self.queue(class).lock().await;
            let take = (n - out.len()).min(q.len());
            out.extend(q.drain(..take));
        }
        self.len.fetch_sub(out.len(), Ordering::SeqCst);
        out
    }

    async fn push(&self, msg: NetworkMessage) {
        self.queue(classify(&msg)).lock().await.push_back(msg);
        self.len.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Return messages that were popped but could not be sent to the FRONT of
    /// their class queue, preserving order. A popped message must never be dropped:
    /// the owning pipeline has already recorded it as handed to the network and
    /// only starts its response timeout once the router reports it on the wire, so
    /// a dropped message is one the pipeline waits on forever — a permanent sync
    /// stall (observed as: queue backed up, 0 MB/s, no sends, no timeouts).
    async fn push_front_all(&self, msgs: Vec<NetworkMessage>) {
        if msgs.is_empty() {
            return;
        }
        let n = msgs.len();
        for msg in msgs.into_iter().rev() {
            self.queue(classify(&msg)).lock().await.push_front(msg);
        }
        self.len.fetch_add(n, Ordering::SeqCst);
        self.notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use dashcore::network::message_blockdata::GetHeadersMessage;
    use dashcore::network::message_filter::{GetCFHeaders, GetCFilters};
    use dashcore::network::message_sml::GetMnListDiff;
    use dashcore::{BlockHash, Txid};
    use dashcore_hashes::Hash;

    fn get_headers(locator: u32) -> NetworkMessage {
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![BlockHash::dummy(locator)],
            BlockHash::dummy(0),
        ))
    }

    fn get_cfilters(start: u32) -> NetworkMessage {
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: start,
            stop_hash: BlockHash::dummy(9),
        })
    }

    fn get_cfheaders(stop: u32) -> NetworkMessage {
        NetworkMessage::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 0,
            stop_hash: BlockHash::dummy(stop),
        })
    }

    /// A broker with no peers: `new` spawns the pump, router, timeout monitor and
    /// bandwidth controller but never touches the network — the peer supervisor is
    /// only started by `start()`, which these tests deliberately do not call.
    async fn broker() -> PeerNetworkManager {
        let config = ClientConfig::regtest().with_restrict_to_configured_peers(true);
        PeerNetworkManager::new(&config).await
    }

    // ---- request key derivation (the dedup identity) ----

    #[test]
    fn request_keys_derives_one_key_per_request_type() {
        assert_eq!(request_keys(&get_headers(1)), vec![RequestKey::Headers(BlockHash::dummy(1))]);
        assert_eq!(
            request_keys(&get_cfheaders(2)),
            vec![RequestKey::CfHeaders(BlockHash::dummy(2))]
        );
        assert_eq!(request_keys(&get_cfilters(100)), vec![RequestKey::CFilters(100)]);
        assert_eq!(
            request_keys(&NetworkMessage::GetMnListD(GetMnListDiff {
                base_block_hash: BlockHash::dummy(3),
                block_hash: BlockHash::dummy(4),
            })),
            vec![RequestKey::MnListDiff(BlockHash::dummy(4))]
        );
    }

    /// One `getdata` may name several blocks; each is tracked as its own request
    /// so a single missing block can time out and retry on its own.
    #[test]
    fn request_keys_splits_getdata_per_block_and_ignores_other_inventory() {
        let keys = request_keys(&NetworkMessage::GetData(vec![
            Inventory::Block(BlockHash::dummy(1)),
            Inventory::Transaction(Txid::from_byte_array([7; 32])),
            Inventory::Block(BlockHash::dummy(2)),
        ]));
        assert_eq!(
            keys,
            vec![RequestKey::Block(BlockHash::dummy(1)), RequestKey::Block(BlockHash::dummy(2))]
        );
    }

    /// Traffic the broker does not track for timeout/retry has no key, so it is
    /// never de-duplicated — two `mempool` messages must both go out.
    #[test]
    fn request_keys_is_empty_for_untracked_traffic() {
        assert!(request_keys(&NetworkMessage::MemPool).is_empty());
        assert!(request_keys(&NetworkMessage::Ping(1)).is_empty());
        assert!(request_keys(&NetworkMessage::GetData(vec![Inventory::Transaction(
            Txid::from_byte_array([1; 32])
        )]))
        .is_empty());
    }

    use crate::test_utils::test_socket_address;

    // ---- losing a peer requeues its work ----
    //
    // These cover centrally what dashpay/rust-dashcore#941, #943 and #953 each
    // fixed per sync manager before the network module was rewritten. The
    // per-manager `on_peer_disconnect` hooks are gone: the broker owns a
    // request from send to response, so it is the only thing that knows which
    // peer was carrying what. Three separate regressions landed in this area,
    // so it is worth pinning down.

    /// Mark `msg`'s request as on the wire to `peer`, the state the broker puts
    /// it in once the router hands it over.
    async fn mark_on_wire(net: &PeerNetworkManager, msg: &NetworkMessage, peer: SocketAddr) {
        let mut reqs = net.requests.lock().await;
        for key in request_keys(msg) {
            reqs.insert(
                key,
                ReqState::OnWire(Box::new(OnWire {
                    peer,
                    last_progress: Instant::now(),
                    msg: msg.clone(),
                })),
            );
        }
    }

    async fn state_of(net: &PeerNetworkManager, key: &RequestKey) -> Option<&'static str> {
        net.requests.lock().await.get(key).map(|s| match s {
            ReqState::Queued => "queued",
            ReqState::OnWire(_) => "on_wire",
        })
    }

    /// A peer that goes away takes its in-flight requests with it, and nothing
    /// else is tracking them: the timeout monitor only watches connected peers.
    /// They must go back on the queue for another peer to serve.
    #[tokio::test]
    async fn losing_a_peer_requeues_the_requests_it_was_carrying() {
        let net = broker().await;
        let (gone, kept) = (test_socket_address(1), test_socket_address(2));

        let doomed = get_cfilters(0);
        let survivor = get_cfilters(1000);
        mark_on_wire(&net, &doomed, gone).await;
        mark_on_wire(&net, &survivor, kept).await;

        let reinjected = requeue_requests_from(&net.requests, &HashSet::from([gone])).await;

        assert_eq!(reinjected.len(), 1, "only the departed peer's work comes back");
        assert!(matches!(reinjected[0], NetworkMessage::GetCFilters(ref g) if g.start_height == 0));
        assert_eq!(
            state_of(&net, &RequestKey::CFilters(1000)).await,
            Some("on_wire"),
            "a healthy peer's request must not be disturbed"
        );
    }

    /// The requeued request keeps its registry key. Dropping it would let a
    /// pipeline that re-declares the same request queue a second copy, so the
    /// peer's departure would cost duplicate traffic on top of the retry.
    #[tokio::test]
    async fn a_requeued_request_still_de_duplicates() {
        let net = broker().await;
        let peer = test_socket_address(1);

        let msg = get_cfilters(0);
        mark_on_wire(&net, &msg, peer).await;
        requeue_requests_from(&net.requests, &HashSet::from([peer])).await;

        assert_eq!(
            state_of(&net, &RequestKey::CFilters(0)).await,
            Some("queued"),
            "the request is wanted again, not forgotten"
        );

        net.send(get_cfilters(0)).await;
        assert_eq!(
            net.msg_queue.len(),
            0,
            "re-declaring a requeued request must not queue a duplicate"
        );
    }

    /// Requeuing is what makes the retry possible, but only the response
    /// clears the key — otherwise a request whose peer died would be dropped
    /// from tracking and never retried by anyone.
    #[tokio::test]
    async fn a_requeued_request_is_only_cleared_by_its_response() {
        let net = broker().await;
        let peer = test_socket_address(1);

        let msg = get_cfilters(0);
        mark_on_wire(&net, &msg, peer).await;
        requeue_requests_from(&net.requests, &HashSet::from([peer])).await;
        assert_eq!(state_of(&net, &RequestKey::CFilters(0)).await, Some("queued"));

        net.request_answered(RequestKey::CFilters(0)).await;
        assert_eq!(
            state_of(&net, &RequestKey::CFilters(0)).await,
            None,
            "the response, and only the response, retires the request"
        );
    }

    // ---- de-duplication ----

    #[tokio::test]
    async fn send_dedups_a_request_already_in_play() {
        let net = broker().await;

        net.send(get_cfilters(0)).await;
        assert_eq!(net.msg_queue.len(), 1);

        // Same key while the first is still tracked: dropped before the queue.
        net.send(get_cfilters(0)).await;
        assert_eq!(net.msg_queue.len(), 1, "a re-declared request must not be queued twice");

        // A different key is a different request.
        net.send(get_cfilters(1000)).await;
        assert_eq!(net.msg_queue.len(), 2);
    }

    /// The key is held for the whole lifecycle, so re-declaring is a no-op until
    /// the requester reports the response — that is what makes it safe for a
    /// pipeline to re-declare its whole wanted set on every tick.
    #[tokio::test]
    async fn request_answered_releases_the_key_for_re_declaration() {
        let net = broker().await;

        net.send(get_headers(1)).await;
        net.send(get_headers(1)).await;
        assert_eq!(net.msg_queue.len(), 1);

        net.request_answered(RequestKey::Headers(BlockHash::dummy(1))).await;
        assert!(net.requests.lock().await.is_empty(), "an answered request stops being tracked");

        // Now the same request is accepted again.
        net.send(get_headers(1)).await;
        assert_eq!(net.msg_queue.len(), 2);
    }

    #[tokio::test]
    async fn keyless_messages_are_never_deduplicated() {
        let net = broker().await;

        net.send(NetworkMessage::MemPool).await;
        net.send(NetworkMessage::MemPool).await;

        assert_eq!(net.msg_queue.len(), 2);
        assert!(
            net.requests.lock().await.is_empty(),
            "untracked traffic must not enter the registry"
        );
    }

    // ---- strict-priority scheduling ----

    #[test]
    fn classify_maps_each_request_to_its_scheduling_class() {
        assert_eq!(classify(&get_headers(1)), MsgClass::Headers);
        assert_eq!(classify(&get_cfheaders(1)), MsgClass::CfHeaders);
        assert_eq!(classify(&get_cfilters(0)), MsgClass::CFilters);
        assert_eq!(
            classify(&NetworkMessage::GetData(vec![Inventory::Block(BlockHash::dummy(1))])),
            MsgClass::Blocks
        );
        assert_eq!(classify(&NetworkMessage::MemPool), MsgClass::Other);
        // A `getdata` that is not purely blocks is control traffic, not a block download.
        assert_eq!(
            classify(&NetworkMessage::GetData(vec![Inventory::Transaction(
                Txid::from_byte_array([1; 32])
            )])),
            MsgClass::Other
        );
    }

    /// A backlog of one class must never block another behind it: the router
    /// drains control first, then blocks, filters, filter headers, block headers.
    #[tokio::test]
    async fn queue_drains_in_strict_priority_order() {
        let q = MsgQueue::new();

        // Pushed in reverse priority on purpose.
        q.push(get_headers(1)).await;
        q.push(get_cfheaders(1)).await;
        q.push(get_cfilters(0)).await;
        q.push(NetworkMessage::GetData(vec![Inventory::Block(BlockHash::dummy(1))])).await;
        q.push(NetworkMessage::MemPool).await;
        assert_eq!(q.len(), 5);

        let drained: Vec<MsgClass> = q.pop_n(5).await.iter().map(classify).collect();
        assert_eq!(
            drained,
            vec![
                MsgClass::Other,
                MsgClass::Blocks,
                MsgClass::CFilters,
                MsgClass::CfHeaders,
                MsgClass::Headers
            ]
        );
        assert_eq!(q.len(), 0);
    }

    /// A message popped but not sent goes back to the FRONT of its class, so it
    /// keeps its place: dropping it would strand the pipeline waiting forever.
    #[tokio::test]
    async fn unsent_messages_go_back_to_the_front_of_their_class() {
        let q = MsgQueue::new();
        q.push(get_cfilters(0)).await;
        q.push(get_cfilters(1000)).await;

        let popped = q.pop_n(1).await;
        assert_eq!(q.len(), 1);

        q.push_front_all(popped).await;
        assert_eq!(q.len(), 2);

        // The returned message is handed out first again, ahead of the one behind it.
        let order: Vec<u32> = q
            .pop_n(2)
            .await
            .iter()
            .map(|m| match m {
                NetworkMessage::GetCFilters(g) => g.start_height,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(order, vec![0, 1000]);
    }

    #[tokio::test]
    async fn pop_n_respects_its_budget() {
        let q = MsgQueue::new();
        for start in [0, 1000, 2000] {
            q.push(get_cfilters(start)).await;
        }
        assert_eq!(q.pop_n(2).await.len(), 2);
        assert_eq!(q.len(), 1);
        assert!(q.pop_n(0).await.is_empty());
    }

    // ---- inbound routing ----

    /// `dispatch_local` feeds a message through the same pump as a real peer,
    /// tagged with the `0.0.0.0:0` sentinel that managers read as "self-originated".
    #[tokio::test]
    async fn dispatch_local_reaches_subscribers_with_the_local_sentinel() {
        let net = broker().await;
        let mut rx = net.subscribe(&[MessageType::Tx]).await;

        let tx = dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        net.dispatch_local(NetworkMessage::Tx(tx)).await;

        let (peer, msg) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the pump must deliver the injected message")
            .expect("channel open");
        assert!(peer.ip().is_unspecified(), "locally injected messages carry the sentinel address");
        assert_eq!(peer.port(), 0);
        assert!(matches!(*msg, NetworkMessage::Tx(_)));
    }

    /// Subscriptions are per message type: a manager only wakes for what it asked for.
    #[tokio::test]
    async fn subscribers_only_receive_the_types_they_asked_for() {
        let net = broker().await;
        let mut headers_rx = net.subscribe(&[MessageType::Headers]).await;

        net.dispatch_local(NetworkMessage::Tx(dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        }))
        .await;

        // Give the pump a chance to run before asserting nothing arrived.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(headers_rx.try_recv().is_err(), "a Headers subscriber must not see a Tx");
    }

    // ---- peer-set accessors with no peers ----

    #[tokio::test]
    async fn reports_no_peers_and_no_tip_before_start() {
        let net = broker().await;
        assert_eq!(net.connected_count().await, 0);
        assert_eq!(net.tip(), 0);
        // Broadcasting with no peers is a no-op, not a panic.
        net.broadcast(NetworkMessage::MemPool);
    }

    /// `inv` goes to several managers at once, so the pump must fan the same
    /// message out to every subscriber of that type.
    #[tokio::test]
    async fn multiple_subscribers_of_the_same_type_all_receive_it() {
        let net = broker().await;
        let mut first = net.subscribe(&[MessageType::Inv]).await;
        let mut second = net.subscribe(&[MessageType::Inv]).await;

        net.dispatch_local(NetworkMessage::Inv(vec![Inventory::Block(BlockHash::dummy(1))])).await;

        for rx in [&mut first, &mut second] {
            let (_, msg) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("both subscribers must be served")
                .expect("channel open");
            assert!(matches!(*msg, NetworkMessage::Inv(_)));
        }
    }

    /// Asking for the same type more than once must still deliver it once: a
    /// manager that repeats a type in `wanted_message_types` would otherwise
    /// process every message of that type as many times as it listed it.
    #[tokio::test]
    async fn duplicate_requested_types_deliver_once() {
        let net = broker().await;
        let mut rx = net.subscribe(&[MessageType::Inv, MessageType::Inv, MessageType::Inv]).await;

        net.dispatch_local(NetworkMessage::Inv(vec![Inventory::Block(BlockHash::dummy(1))])).await;

        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the message must arrive")
            .expect("channel open");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err(), "a repeated type must not duplicate delivery");
    }

    /// A manager task that ended drops its receiver; the pump prunes it and the
    /// surviving subscribers keep working.
    #[tokio::test]
    async fn a_dropped_subscriber_does_not_break_the_others() {
        let net = broker().await;
        let dead = net.subscribe(&[MessageType::Inv]).await;
        let mut alive = net.subscribe(&[MessageType::Inv]).await;
        drop(dead);

        net.dispatch_local(NetworkMessage::Inv(vec![Inventory::Block(BlockHash::dummy(1))])).await;

        let (_, msg) = tokio::time::timeout(Duration::from_secs(2), alive.recv())
            .await
            .expect("the live subscriber must still be served")
            .expect("channel open");
        assert!(matches!(*msg, NetworkMessage::Inv(_)));
    }

    /// Routing keys off the wire command: an unknown command has no type and is
    /// therefore delivered to nobody.
    #[test]
    fn message_type_from_cmd_maps_known_commands_and_rejects_the_rest() {
        assert_eq!(MessageType::from_cmd("headers"), Some(MessageType::Headers));
        assert_eq!(MessageType::from_cmd("inv"), Some(MessageType::Inv));
        assert_eq!(MessageType::from_cmd("cfilter"), Some(MessageType::CFilter));
        assert_eq!(MessageType::from_cmd("cfheaders"), Some(MessageType::CfHeaders));
        assert_eq!(MessageType::from_cmd("block"), Some(MessageType::Block));
        assert_eq!(MessageType::from_cmd("mnlistdiff"), Some(MessageType::MnListDiff));
        assert_eq!(MessageType::from_cmd("qrinfo"), Some(MessageType::QrInfo));
        assert_eq!(MessageType::from_cmd("tx"), Some(MessageType::Tx));
        assert_eq!(MessageType::from_cmd("isdlock"), Some(MessageType::IsDLock));
        assert_eq!(MessageType::from_cmd("clsig"), Some(MessageType::ChainLock));

        assert_eq!(MessageType::from_cmd("ping"), None);
        assert_eq!(MessageType::from_cmd(""), None);
        assert_eq!(MessageType::from_cmd("Headers"), None, "the match is case-sensitive");
    }
}
