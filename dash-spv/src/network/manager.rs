use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

// Tokio's clock, so tests can pause time to drive the request-timeout machinery.
use tokio::time::Instant;

use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::{BlockHash, Header};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Bounded concurrent handshakes per probe round.
const CONNECT_CHUNK: usize = 16;

/// Ceiling on concurrent `headers2` decompressions across all peers: CPU-bound work
/// on the shared blocking pool, so it gets a few cores but never all of them.
const MAX_CONCURRENT_HEADERS2_DECOMPRESSIONS: usize = 4;

fn headers2_decompression_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().min(MAX_CONCURRENT_HEADERS2_DECOMPRESSIONS))
        .unwrap_or(1)
}

/// Releases header messages in wire order because an announcement can depend on the preceding
/// message from the same peer.
pub struct OrderedHeaderResults<T> {
    next_sequence: u64,
    completed: BTreeMap<u64, T>,
}

impl<T> Default for OrderedHeaderResults<T> {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            completed: BTreeMap::new(),
        }
    }
}

impl<T> OrderedHeaderResults<T> {
    pub fn complete(&mut self, sequence: u64, result: T) -> Vec<T> {
        let replaced = self.completed.insert(sequence, result);
        debug_assert!(replaced.is_none(), "header sequence completed twice");

        let mut ready = Vec::new();
        while let Some(result) = self.completed.remove(&self.next_sequence) {
            ready.push(result);
            self.next_sequence += 1;
        }
        ready
    }
}

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
const MAX_DIAL_BACKOFF: Duration = Duration::from_secs(60);

/// Cap on remembered (ranked) backup addresses, as a multiple of `max_peers`.
const BACKUP_MULTIPLE: usize = 8;

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

use crate::error::{NetworkError, NetworkResult};
use crate::network::NetworkManager;
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
type Subscribers = Arc<Mutex<HashMap<MessageType, Vec<UnboundedSender<Inbound>>>>>;

/// Every pipeline request the broker is handling, from `send` until the owning
/// manager reports it answered (`request_answered`) or cancels it. The single home
/// of request state: pipelines just declare what they want and the broker
/// de-duplicates, paces, times out and retries.
///
/// - Membership is the de-dup set: `send` ignores a key already present.
/// - `OnWire` entries carry the message so the timeout monitor can re-inject it.
type Registry = Arc<Mutex<HashMap<RequestKey, ReqState>>>;

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

#[derive(Clone, Debug)]
pub enum NetworkEvent {
    PeersUpdated {
        connected_count: u32,
        /// Best tip height advertised across those peers.
        best_height: u32,
    },
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
}

/// Identity of a broker-tracked pipeline request: the de-dup, timeout and retry key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RequestKey {
    /// `getheaders` — keyed by the locator's first hash (the segment tip).
    Headers(dashcore::BlockHash),
    /// `getcfheaders` — keyed by the stop hash.
    CfHeaders(dashcore::BlockHash),
    /// `getcfilters` — keyed by the start height.
    CFilters(u32),
    /// `getmnlistdiff` — keyed by the target block hash.
    MnListDiff(dashcore::BlockHash),
    /// Block `getdata` — keyed by the requested block hash.
    Block(dashcore::BlockHash),
}

enum ReqState {
    /// In the `MsgQueue`, not yet sent; held here only for de-dup.
    Queued,
    /// Sent and awaiting a response. Carries the message so the timeout monitor can
    /// retry it; boxed because a `NetworkMessage` dwarfs `Queued`.
    OnWire(Box<OnWire>),
}

struct OnWire {
    /// The CONNECTION the request was routed to, not the address: a close event for an
    /// earlier connection to the same address must not pull back the new one's work.
    peer: PeerId,
    /// When this request last made progress: set on send, refreshed by every piece of
    /// a streaming response, so a peer streaming steadily is not judged stalled.
    last_progress: Instant,
    /// Re-queued verbatim on timeout; requests are self-contained, so resending is a valid retry.
    msg: NetworkMessage,
    /// Queue order of `msg`, kept so a retry goes back to its place.
    height: u32,
    /// When it was sent, for hedging a block stuck at a slow peer.
    sent: Instant,
    /// The peer a copy was also sent to (endgame).
    hedge: Option<PeerId>,
}

pub struct PeerNetworkManager {
    /// Wakes the peer supervisor when a peer was lost or measured as underserving.
    peer_wake: Arc<Notify>,
    connected_peers: Arc<Mutex<Vec<ConnectedPeer>>>,
    other_peers: Arc<Mutex<Vec<DisconnectedPeer>>>,
    discoverer: Arc<Mutex<PeerDiscoverer>>,
    msg_queue: Arc<MsgQueue>,
    inbound_tx: UnboundedSender<PeerEvent>,
    subscribers: Subscribers,
    requests: Registry,
    events_tx: broadcast::Sender<NetworkEvent>,
    /// Best tip advertised by the peers, shared with the supervisor so its
    /// `PeersUpdated` carries the real height.
    best_tip: Arc<AtomicU32>,
    max_peers: usize,
    /// Service flags a peer must advertise to be kept (e.g. COMPACT_FILTERS when
    /// filters are enabled). Checked at handshake; `NONE` keeps every peer.
    required_services: ServiceFlags,
    user_agent: Arc<str>,
    /// Total bytes read from all peers, handed to every peer `start` connects.
    bytes: Arc<AtomicU64>,
    /// Global bound for CPU-heavy headers2 decompression work.
    headers2_decompression_semaphore: Arc<Semaphore>,
    // Cancelled on drop to tear down the router, pump, timeout monitor and bandwidth controller.
    shutdown: CancellationToken,
    // Cancelled by `stop()` to tear down the supervisor and peer readers; `start()`
    // replaces a cancelled one so a stopped manager can start again.
    session: Mutex<CancellationToken>,
}

impl Drop for PeerNetworkManager {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Scheduling class of a queued message. The router drains classes by strict priority
/// ([`DRAIN_PRIORITY`]), so a backlog of one type never blocks another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MsgClass {
    /// Control traffic (mempool, tx, ping, chainlock/islock `getdata`,
    /// `filterload`…): always first, few, and usually something is blocked on it.
    Other,
    Blocks,
    CFilters,
    CfHeaders,
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

/// One queue per class, each behind its own lock, so a pipeline enqueuing a burst
/// only contends with itself.
/// `(height, seq)`: lowest height first, then FIFO. Front inserts take negative seqs so
/// they go before everything of the same height.
type QueueKey = (u32, i64);

struct MsgQueue {
    other: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    blocks: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    cfilters: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    cfheaders: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    headers: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    back_seq: AtomicI64,
    front_seq: AtomicI64,
    len: AtomicUsize,
    notify: Notify,
    costs: Arc<ResponseCosts>,
}

/// Downstream first: the stage closest to the wallet is the one waiting on the network,
/// while the head of the chain has a full backlog and only waits for room.
const MSG_CLASSES: usize = 5;

/// Requests per class kept on the wire ahead of [`DRAIN_PRIORITY`] while the class has work.
const MIN_IN_FLIGHT_PER_CLASS: usize = 4;

const DRAIN_PRIORITY: [MsgClass; MSG_CLASSES] =
    [MsgClass::Other, MsgClass::Blocks, MsgClass::CFilters, MsgClass::CfHeaders, MsgClass::Headers];

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
        // Download-only byte counter and the global in-flight budget. The budget starts at a
        // tiny bootstrap and `spawn_bandwidth_controller` sizes it from measured capacity.
        let bytes = Arc::new(AtomicU64::new(0));
        let global_cap = Arc::new(AtomicU64::new(MIN_CAP_BYTES * max_peers as u64));
        let best_tip = Arc::new(AtomicU32::new(0));
        let peer_wake = Arc::new(Notify::new());

        // Detached like the bandwidth controller and timeout monitor: torn down via the
        // shutdown token, not by holding their handles.
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
            best_tip.clone(),
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

        spawn_flow_controller(
            bytes.clone(),
            global_cap.clone(),
            connected_peers.clone(),
            shutdown.clone(),
            peer_wake.clone(),
            msg_queue.clone(),
            requests.clone(),
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
            user_agent: config.user_agent.as_str().into(),
            bytes,
            headers2_decompression_semaphore: Arc::new(Semaphore::new(
                headers2_decompression_parallelism(),
            )),
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
        spawn_peer_supervisor(
            self.discoverer.clone(),
            self.connected_peers.clone(),
            self.other_peers.clone(),
            self.inbound_tx.clone(),
            session,
            self.bytes.clone(),
            self.events_tx.clone(),
            self.best_tip.clone(),
            self.max_peers,
            self.required_services,
            self.peer_wake.clone(),
            self.headers2_decompression_semaphore.clone(),
            self.msg_queue.costs.clone(),
            self.user_agent.clone(),
        );
    }

    /// Disconnect every peer and forget the requests in play, so none of them
    /// reaches the peers of the next `start()`.
    async fn stop(&self) {
        tracing::info!(target: "dash_spv::network", "network manager stopping: cancelling peers");
        self.session.lock().await.cancel();
        self.connected_peers.lock().await.clear();
        self.requests.lock().await.clear();
        self.msg_queue.pop_n(self.msg_queue.len()).await;
    }

    /// Ask the broker to make a request. De-duplicated by [`RequestKey`]: a request already
    /// queued or on the wire is a no-op, so pipelines can re-declare their whole wanted
    /// set every tick. Keyless messages (tx, mempool, control `getdata`) are queued
    /// untracked.
    async fn enqueue(&self, height: u32, msg: NetworkMessage) {
        let keys = request_keys(&msg);
        if keys.is_empty() {
            self.msg_queue.push(height, msg).await;
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
        self.msg_queue.push(height, msg).await;
    }

    /// Send to one specific peer, bypassing the router. Needed for messages that set
    /// state on that remote node (`filterload`/`filterclear`/`mempool` enable relay for
    /// THAT peer). Returns false if the peer is not connected or the write failed.
    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        // Drop the peer-set lock before writing: holding it across a socket write blocks
        // the router, monitor, supervisor and bandwidth controller for up to `WRITE_TIMEOUT`.
        let handle = {
            let peers = self.connected_peers.lock().await;
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

    async fn request_answered(&self, key: RequestKey) {
        if !matches!(self.requests.lock().await.remove(&key), Some(ReqState::OnWire(_))) {
            return;
        }
        self.msg_queue.notify.notify_one();
    }

    /// Broadcast a message to all connected peers
    async fn broadcast(&self, msg: NetworkMessage) -> NetworkResult<()> {
        let handles: Vec<PeerHandle> =
            self.connected_peers.lock().await.iter().map(|p| p.handle()).collect();
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
        let _ = self.inbound_tx.send(PeerEvent::Message(PeerId::synthetic(local), msg.into()));
    }

    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut subscribers = self.subscribers.lock().await;
        for kind in kinds.iter().copied().collect::<HashSet<_>>() {
            subscribers.entry(kind).or_default().push(tx.clone());
        }
        rx
    }

    fn tip(&self) -> u32 {
        self.best_tip.load(Ordering::Relaxed)
    }

    async fn connected_count(&self) -> u32 {
        self.connected_peers.lock().await.len() as u32
    }

    fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.events_tx.subscribe()
    }
}

fn spawn_router(
    queue: Arc<MsgQueue>,
    connected: Arc<Mutex<Vec<ConnectedPeer>>>,
    shutdown: CancellationToken,
    global_cap: Arc<AtomicU64>,
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

            let peers: Vec<PeerHandle> =
                connected.lock().await.iter().map(|p| p.handle()).collect();
            let sent =
                route_tick(&queue, &peers, global_cap.load(Ordering::Relaxed), &requests).await;
            drop(peers);

            if sent == 0 {
                // Every peer is at its in-flight cap: wait for a response or a kicked peer to free
                // a slot (both notify). The sleep is only a backstop against a missed wake.
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = queue.notify.notified() => {},
                    _ = tokio::time::sleep(STALL_CHECK) => {},
                }
            }
        }
    })
}

/// Pipeline keys of a router-paced request, recorded in the registry. Empty for
/// non-pipeline messages.
pub fn request_keys(msg: &NetworkMessage) -> Vec<RequestKey> {
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
    peers: &[PeerHandle],
    global_cap: u64,
    requests: &Registry,
) -> usize {
    if peers.is_empty() {
        return 0;
    }

    // Free capacity this round = min(sum of per-peer room, global room). Each peer's
    // cap is its measured bandwidth-delay product; the global cap is our measured
    // download capacity. Whichever binds first limits the round.
    let total_in_flight: u64 = peers.iter().map(PeerHandle::in_flight_bytes).sum();
    let per_peer_room: u64 =
        peers.iter().map(|p| p.cap().saturating_sub(p.in_flight_bytes())).sum();
    let global_room = global_cap.saturating_sub(total_in_flight);
    let budget = per_peer_room.min(global_room);
    if budget == 0 {
        return 0;
    }

    // A class with work queued but almost nothing on the wire goes first, so strict
    // priority never parks a stage: headers are tiny yet head the whole chain.
    let mut guaranteed = [MIN_IN_FLIGHT_PER_CLASS; MSG_CLASSES];
    for state in requests.lock().await.values() {
        if let ReqState::OnWire(o) = state {
            let slot = &mut guaranteed[classify(&o.msg) as usize];
            *slot = slot.saturating_sub(1);
        }
    }
    let msgs = queue.pop_guaranteed(budget, &guaranteed, |m| queue.costs.cost(m)).await;
    let mut sent = 0;
    // Anything popped but not sent goes BACK on the queue: its key is registered, so a
    // dropped message would never be re-sent nor time out and its pipeline would stall.
    let mut unsent: Vec<(u32, NetworkMessage)> = Vec::new();
    // Recorded in the broker under one lock after the send loop.
    let mut on_wire: Vec<(u32, NetworkMessage, PeerHandle)> = Vec::new();
    let mut msgs = msgs.into_iter();
    for (height, msg) in msgs.by_ref() {
        // Pick the least-loaded peer RELATIVE TO ITS OWN cap. Absolute free room
        // concentrates load: the biggest cap wins every round and keeps growing while the
        // others stay idle and never grow (measured: three identical peers split into one
        // at cap 12 and two stuck at 2). Cross-multiplied to avoid floats; neither side
        // can be zero (`cap >= FLOOR_BYTES`, full peers filtered above).
        let Some(peer) = peers.iter().filter(|p| p.in_flight_bytes() < p.cap()).min_by(|a, b| {
            (a.in_flight_bytes() as u128 * b.cap() as u128)
                .cmp(&(b.in_flight_bytes() as u128 * a.cap() as u128))
        }) else {
            unsent.push((height, msg)); // every peer is at its measured cap
            break;
        };
        if peer.send(&msg).await.is_ok() {
            sent += 1;
            // Record the peer so the monitor can attribute a stall to it.
            on_wire.push((height, msg, peer.clone()));
        } else {
            tracing::warn!(target: "dash_spv::network", "router: send to {} failed", peer.addr());
            unsent.push((height, msg));
        }
    }
    unsent.extend(msgs); // whatever the loop never reached
    queue.push_front_all(unsent).await;

    if !on_wire.is_empty() {
        let mut reqs = requests.lock().await;
        for (height, msg, peer) in on_wire {
            for key in request_keys(&msg) {
                if let Some(slot) = reqs.get_mut(&key) {
                    *slot = ReqState::OnWire(Box::new(OnWire {
                        peer: peer.id(),
                        msg: msg.clone(),
                        height,
                        last_progress: Instant::now(),
                        sent: Instant::now(),
                        hedge: None,
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

/// How long a block request waits at its peer before an idle peer is also asked.
const HEDGE_AFTER: Duration = Duration::from_secs(2);

/// Endgame (as in BitTorrent): with nothing queued, blocks are processed in height
/// order, so one block stuck at a slow peer stalls everything after it while the other
/// peers sit idle. Ask an idle peer for the lowest such blocks too; the first copy to
/// arrive settles both.
async fn hedge_stalled_blocks(
    peers: &[PeerHandle],
    requests: &Registry,
    costs: &ResponseCosts,
) -> usize {
    let mut plan: Vec<(RequestKey, NetworkMessage, PeerHandle)> = Vec::new();
    {
        let reqs = requests.lock().await;
        let mut stalled: Vec<(u32, &RequestKey, &OnWire)> = reqs
            .iter()
            .filter_map(|(key, state)| match state {
                ReqState::OnWire(o)
                    if matches!(key, RequestKey::Block(_))
                        && o.hedge.is_none()
                        && o.sent.elapsed() >= HEDGE_AFTER =>
                {
                    Some((o.height, key, o.as_ref()))
                }
                _ => None,
            })
            .collect();
        stalled.sort_by_key(|(height, _, _)| *height);
        let mut room: Vec<(PeerHandle, u64)> = peers
            .iter()
            .map(|p| (p.clone(), p.cap().saturating_sub(p.in_flight_bytes())))
            .collect();
        for (_, key, o) in stalled {
            let Some((peer, left)) = room
                .iter_mut()
                .filter(|(p, left)| p.id() != o.peer && *left > 0)
                .max_by_key(|(_, left)| *left)
            else {
                break;
            };
            *left = left.saturating_sub(costs.cost(&o.msg));
            plan.push((key.clone(), o.msg.clone(), peer.clone()));
        }
    }
    let mut hedged = 0;
    for (key, msg, peer) in plan {
        if peer.send(&msg).await.is_err() {
            continue;
        }
        if let Some(ReqState::OnWire(o)) = requests.lock().await.get_mut(&key) {
            if o.hedge.is_none() {
                o.hedge = Some(peer.id());
                hedged += 1;
            }
        }
    }
    hedged
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

/// Ticks a peer must have had work in flight before its rate is compared, and the
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

/// A peer's limiter plus how fast it serves while it has work, for eviction.
struct PeerFlow {
    limiter: ByteLimiter,
    serving_rate: f64,
    serving_ticks: u32,
}

/// Sizes the byte caps of every peer and of the client's own link, each with a
/// [`ByteLimiter`] on its own throughput: the router sends while both have room.
/// Also reports how fast each peer serves while it has work, for [`underserving_peer`].
fn spawn_flow_controller(
    bytes: Arc<AtomicU64>,
    global_cap: Arc<AtomicU64>,
    connected: Arc<Mutex<Vec<ConnectedPeer>>>,
    shutdown: CancellationToken,
    peer_wake: Arc<Notify>,
    queue: Arc<MsgQueue>,
    requests: Registry,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut global = ByteLimiter::new(MIN_CAP_BYTES, bytes.load(Ordering::Relaxed));
        let mut peers: HashMap<PeerId, PeerFlow> = HashMap::new();
        let mut last_underserving: Option<SocketAddr> = None;
        let mut ticks = 0u64;
        let mut ticker = tokio::time::interval(FLOW_TICK);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }
            ticks += 1;

            let g = connected.lock().await;
            if g.is_empty() {
                continue;
            }
            let live: HashSet<PeerId> = g.iter().map(|p| p.id()).collect();
            peers.retain(|id, _| live.contains(id));

            let mut total_in_flight = 0u64;
            for p in g.iter() {
                let in_flight = p.in_flight_bytes();
                total_in_flight += in_flight;
                let flow = peers.entry(p.id()).or_insert_with(|| PeerFlow {
                    limiter: ByteLimiter::new(MIN_CAP_BYTES, p.bytes_read()),
                    serving_rate: 0.0,
                    serving_ticks: 0,
                });
                let cap = flow.limiter.tick(p.bytes_read(), in_flight, CAP_STEP_BYTES_PER_SEC);
                p.set_cap(cap);
                if in_flight > 0 {
                    flow.serving_ticks += 1;
                    let alpha = 1.0 / flow.serving_ticks.min(SERVING_SAMPLE_TICKS) as f64;
                    flow.serving_rate += alpha * (flow.limiter.rate - flow.serving_rate);
                }
                let measured =
                    flow.limiter.found_ceiling && flow.serving_ticks >= SERVING_SAMPLE_TICKS;
                p.set_serving_rate(if measured {
                    flow.serving_rate as u64
                } else {
                    0
                });
            }

            global.min_cap = (MIN_CAP_BYTES * g.len() as u64) as f64;
            global.cap = global.cap.max(global.min_cap);
            let step = CAP_STEP_BYTES_PER_SEC * g.len() as f64;
            let cap = global.tick(bytes.load(Ordering::Relaxed), total_in_flight, step);
            global_cap.store(cap, Ordering::Relaxed);

            if ticks.is_multiple_of(2) {
                let caps: u64 = g.iter().map(|p| p.cap()).sum();
                for p in g.iter() {
                    let flow = &peers[&p.id()];
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
                    queue.costs.expected_kb(),
                );
            }

            // Only the transition wakes the supervisor, so a peer with no replacement
            // is not re-probed every tick.
            let underserving = underserving_peer(&g);
            let handles: Vec<PeerHandle> = g.iter().map(|p| p.handle()).collect();
            drop(g);
            if queue.len() == 0 {
                let hedged = hedge_stalled_blocks(&handles, &requests, &queue.costs).await;
                if hedged > 0 {
                    tracing::debug!(target: "dash_spv::network", "endgame: hedged {} block request(s)", hedged);
                }
            }
            if underserving.is_some() && underserving != last_underserving {
                peer_wake.notify_one();
            }
            last_underserving = underserving;
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
/// - Probed-but-unused peers are closed and kept as ranked backups (`others`) so
///   later rounds reconnect the best without probing blindly.
struct Supervisor {
    discoverer: Arc<Mutex<PeerDiscoverer>>,
    connected: Arc<Mutex<Vec<ConnectedPeer>>>,
    others: Arc<Mutex<Vec<DisconnectedPeer>>>,
    inbound: UnboundedSender<PeerEvent>,
    shutdown: CancellationToken,
    bytes: Arc<AtomicU64>,
    events: broadcast::Sender<NetworkEvent>,
    best_tip: Arc<AtomicU32>,
    max_peers: usize,
    required_services: ServiceFlags,
    /// Fired when a peer was lost or measured as underserving; the supervisor idles otherwise.
    wake: Arc<Notify>,
    /// Handed to every peer it connects, so the bound is global.
    headers2_decompression_semaphore: Arc<Semaphore>,
    costs: Arc<ResponseCosts>,
    user_agent: Arc<str>,
    /// Lowest handshake ping seen, the reference for the bad-lag threshold.
    best_lag_ms: AtomicU32,
    /// When a slow peer was last swapped out, for [`SWAP_COOLDOWN`].
    last_swap: Mutex<Option<Instant>>,
    failed_dials: Mutex<HashMap<SocketAddr, (u32, Instant)>>,
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
            self.connected.lock().await.iter().map(|p| p.addr()).collect();
        let now = Instant::now();
        let failed = self.failed_dials.lock().await;
        let mut seen = HashSet::new();
        out.retain(|p| {
            !live.contains(&p.addr())
                && failed.get(&p.addr()).is_none_or(|(_, retry)| *retry <= now)
                && seen.insert(p.addr())
        });
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

    /// One pass at whatever the peer set needs: fill a deficit, replace a peer that is
    /// underserving the rest, or both.
    async fn repair_round(&self) {
        let (deficit, slow) = {
            let peers = self.connected.lock().await;
            let deficit = self.max_peers.saturating_sub(peers.len());
            // Only look for a laggard once full: below cap every arrival is wanted anyway.
            // Each swap re-sends the work the old peer held, so at most one per cooldown.
            let cooled = self.last_swap.lock().await.is_none_or(|t| t.elapsed() >= SWAP_COOLDOWN);
            let slow = (deficit == 0 && cooled).then(|| underserving_peer(&peers)).flatten();
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
                let connect = c.connect(
                    self.inbound.clone(),
                    self.shutdown.clone(),
                    self.bytes.clone(),
                    self.required_services,
                    self.headers2_decompression_semaphore.clone(),
                    self.costs.clone(),
                    &self.user_agent,
                );
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
                let mut failed = self.failed_dials.lock().await;
                let fails = failed.get(&addr).map_or(0, |(fails, _)| *fails) + 1;
                let backoff = MAX_DIAL_BACKOFF.min(Duration::from_secs(1 << fails.min(6)));
                failed.insert(addr, (fails, Instant::now() + backoff));
                continue;
            };
            self.failed_dials.lock().await.remove(&addr);
            let handle = peer.handle();
            self.best_tip.fetch_max(peer.version().start_height.max(0) as u32, Ordering::Relaxed);

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

            let mut changed = true;
            let displaced = {
                let mut peers = self.connected.lock().await;
                if peers.len() < self.max_peers {
                    let addr = peer.addr();
                    peers.push(peer);
                    let _ = self.events.send(NetworkEvent::PeerConnected(addr));
                    accepted += 1;
                    None
                } else if let Some(pos) = slow
                    .filter(|_| replaced.is_none())
                    // Re-find by address under the lock: the set can change between
                    // measuring and acting, and the laggard may already be gone.
                    .and_then(|s| peers.iter().position(|p| p.addr() == s))
                {
                    let new_addr = peer.addr();
                    let old = peers.swap_remove(pos);
                    peers.push(peer);
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
                let new_addr = replaced.expect("set with the displacing peer");
                tracing::info!(
                    target: "dash_spv::network",
                    "peer supervisor: swapped out slow {} for {}",
                    old_addr,
                    new_addr,
                );
                // Close it: the pump requeues every request routed to THIS connection, as for any
                // lost peer. Safe because the departure names a connection, not an address, so a
                // reconnection to the same peer is not disturbed.
                old.close();
                *self.last_swap.lock().await = Some(Instant::now());
                let _ = self.events.send(NetworkEvent::PeerDisconnected(old_addr));
                let _ = self.events.send(NetworkEvent::PeerConnected(new_addr));
            }

            // Announce only real changes: an arrival or a swap. A candidate benched as a
            // backup changed nothing.
            if changed {
                let _ = handle.send(&NetworkMessage::GetAddr).await;
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
            let handle = peer.handle();
            self.connected.lock().await.push(peer);
            let _ = self.events.send(NetworkEvent::PeerConnected(addr));
            let _ = handle.send(&NetworkMessage::GetAddr).await;
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

/// The connected peer clearly underserving the rest, if any: serving bytes at a small
/// fraction of the best connected peer's rate while it had work. Relative, so a slow
/// client link (every peer slow alike) never condemns anyone.
fn underserving_peer(peers: &[ConnectedPeer]) -> Option<SocketAddr> {
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
    ((worst as f64) < best as f64 * SLOW_RATE_FRACTION).then(|| {
        tracing::debug!(
            target: "dash_spv::network",
            "{} serving at {:.2} MB/s vs best {:.2} MB/s — a replacement is worth probing for",
            addr,
            worst as f64 / 1e6,
            best as f64 / 1e6,
        );
        addr
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_peer_supervisor(
    discoverer: Arc<Mutex<PeerDiscoverer>>,
    connected: Arc<Mutex<Vec<ConnectedPeer>>>,
    others: Arc<Mutex<Vec<DisconnectedPeer>>>,
    inbound: UnboundedSender<PeerEvent>,
    shutdown: CancellationToken,
    bytes: Arc<AtomicU64>,
    events: broadcast::Sender<NetworkEvent>,
    best_tip: Arc<AtomicU32>,
    max_peers: usize,
    required_services: ServiceFlags,
    wake: Arc<Notify>,
    headers2_decompression_semaphore: Arc<Semaphore>,
    costs: Arc<ResponseCosts>,
    user_agent: Arc<str>,
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
            headers2_decompression_semaphore,
            costs,
            user_agent,
            best_lag_ms: AtomicU32::new(u32::MAX),
            last_swap: Mutex::new(None),
            failed_dials: Mutex::new(HashMap::new()),
        }
        .run(),
    )
}

/// Pull every on-wire request routed to one of `gone` back to `Queued`, returning
/// the messages to re-queue. Shared by both ways of losing a peer (monitor kick,
/// socket close); otherwise the request is stranded since the monitor only watches
/// connected peers. The key stays registered so de-dup still holds while queued.
async fn requeue_requests_from(
    requests: &Registry,
    gone: &HashSet<PeerId>,
) -> Vec<(u32, NetworkMessage)> {
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
            reinject.push((o.height, o.msg));
        }
    }
    reinject
}

/// Time requests out and evict the peers that stalled on them.
///
/// A peer is a culprit when it has in-flight work and no bytes have arrived from it
/// for a full [`REQUEST_TIMEOUT`], or when one of its requests made no progress
/// for that long. Liveness is per peer, not per request age: a healthy peer
/// draining a deep backlog keeps sending bytes even while its oldest request waits.
///
/// A culprit is kicked immediately and ALL its on-wire requests are re-queued for
/// other peers; leaving it connected would just route the freed work back to it.
/// The supervisor refills the set.
fn spawn_timeout_monitor(
    requests: Registry,
    connected: Arc<Mutex<Vec<ConnectedPeer>>>,
    queue: Arc<MsgQueue>,
    shutdown: CancellationToken,
    peer_wake: Arc<Notify>,
    max_peers: usize,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TIMEOUT_CHECK);
        // Per-peer liveness: (bytes read at last progress, when it last rose).
        let mut progress: HashMap<PeerId, (u64, Instant)> = HashMap::new();
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
            let mut culprits: HashSet<PeerId> = {
                let peers = connected.lock().await;
                let live: HashSet<PeerId> = peers.iter().map(|p| p.id()).collect();
                progress.retain(|addr, _| live.contains(addr));
                let mut culprits = HashSet::new();
                for peer in peers.iter() {
                    let addr = peer.id();
                    let bytes = peer.bytes_read();
                    let entry = progress.entry(addr).or_insert((bytes, now));
                    if bytes > entry.0 {
                        *entry = (bytes, now);
                    }
                    if peer.in_flight_bytes() > 0
                        && now.duration_since(entry.1) > request_timeout(peer.lag_ms())
                    {
                        culprits.insert(addr);
                    }
                }
                culprits
            };
            // A request that stopped making progress also condemns its peer: the
            // per-peer byte check above sees unrelated traffic and judges it healthy.
            {
                let timeouts: HashMap<PeerId, Duration> = connected
                    .lock()
                    .await
                    .iter()
                    .map(|p| (p.id(), request_timeout(p.lag_ms())))
                    .collect();
                let reqs = requests.lock().await;
                for state in reqs.values() {
                    if let ReqState::OnWire(o) = state {
                        let timeout = timeouts.get(&o.peer).copied().unwrap_or(REQUEST_TIMEOUT);
                        if now.duration_since(o.last_progress) > timeout {
                            culprits.insert(o.peer);
                        }
                    }
                }
            }

            if culprits.is_empty() {
                continue;
            }

            // Re-queue every on-wire request of a culprit (fresh ones too: the connection is
            // going away), keeping keys as Queued so de-dup holds.
            let reinject = requeue_requests_from(&requests, &culprits).await;

            // Drop culprits still in the set (some may already be gone).
            let (dropped, remaining) = {
                let mut peers = connected.lock().await;
                let before = peers.len();
                peers.retain(|p| {
                    if culprits.contains(&p.id()) {
                        p.close();
                        false
                    } else {
                        true
                    }
                });
                (before - peers.len(), peers.len())
            };
            // The set is now short: wake the supervisor, which otherwise idles.
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

            queue.push_front_all(reinject).await;
            // Freed capacity (dropped peers) — wake the router to re-evaluate.
            queue.notify.notify_one();
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_pump(
    mut inbound: UnboundedReceiver<PeerEvent>,
    subscribers: Subscribers,
    connected: Arc<Mutex<Vec<ConnectedPeer>>>,
    events: broadcast::Sender<NetworkEvent>,
    queue: Arc<MsgQueue>,
    requests: Registry,
    shutdown: CancellationToken,
    peer_wake: Arc<Notify>,
    max_peers: usize,
    discoverer: Arc<Mutex<PeerDiscoverer>>,
    best_tip: Arc<AtomicU32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
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

                    // A block is settled on arrival, not when the wallet gets to it: blocks
                    // are processed in height order, so one can wait long behind a gap, and
                    // charging that wait to the peer reads as a queue and shrinks its cap.
                    // The first copy of a hedged block settles it: the other is a cancel.
                    if let NetworkMessage::Block(block) = &*msg {
                        let key = RequestKey::Block(block.block_hash());
                        let mut reqs = requests.lock().await;
                        if matches!(reqs.get(&key), Some(ReqState::OnWire(o)) if o.peer == peer || o.hedge == Some(peer))
                        {
                            reqs.remove(&key);
                            drop(reqs);
                            queue.notify.notify_one();
                        }
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
                        let now = Instant::now();
                        let mut reqs = requests.lock().await;
                        for state in reqs.values_mut() {
                            if let ReqState::OnWire(o) = state {
                                if o.peer == peer {
                                    o.last_progress = now;
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
                        let lat: Vec<(SocketAddr, u64, String)> = connected
                            .lock()
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
                            if connected.lock().await.len() < max_peers {
                                peer_wake.notify_one();
                            }
                        }
                    }

                    let mt = MessageType::from_cmd(msg.cmd());
                    // Early router wake on inbound traffic (`request_answered` notifies again for the
                    // real capacity). `cfilter` is skipped: only the last of ~1000 frees anything.
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
                    // evict the live one.
                    let remaining = {
                        let mut guard = connected.lock().await;
                        guard.retain(|p| p.id() != peer);
                        guard.len()
                    };

                    if remaining < max_peers {
                        peer_wake.notify_one();
                    }

                    // Requeue the departed peer's in-flight requests; the timeout monitor only watches
                    // connected peers, so they would otherwise leak in the registry.
                    let reinject = requeue_requests_from(&requests, &HashSet::from([peer])).await;

                    tracing::info!(
                        target: "dash_spv::network",
                        "peer disconnected: {} | {} peers remaining | {} request(s) re-queued",
                        addr,
                        remaining,
                        reinject.len(),
                    );

                    queue.push_front_all(reinject).await;
                    queue.notify.notify_one();

                    let _ = events.send(NetworkEvent::PeerDisconnected(addr));

                    let _ = events.send(NetworkEvent::PeersUpdated {
                        connected_count: remaining as u32,
                        best_height: best_tip.load(Ordering::Relaxed),
                    });
                }
            }
        }
    })
}

impl MsgQueue {
    fn new() -> Self {
        Self {
            other: Mutex::new(BTreeMap::new()),
            blocks: Mutex::new(BTreeMap::new()),
            cfilters: Mutex::new(BTreeMap::new()),
            cfheaders: Mutex::new(BTreeMap::new()),
            headers: Mutex::new(BTreeMap::new()),
            back_seq: AtomicI64::new(0),
            front_seq: AtomicI64::new(-1),
            len: AtomicUsize::new(0),
            notify: Notify::new(),
            costs: Arc::new(ResponseCosts::new()),
        }
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    fn queue(&self, class: MsgClass) -> &Mutex<BTreeMap<QueueKey, NetworkMessage>> {
        match class {
            MsgClass::Other => &self.other,
            MsgClass::Blocks => &self.blocks,
            MsgClass::CFilters => &self.cfilters,
            MsgClass::CfHeaders => &self.cfheaders,
            MsgClass::Headers => &self.headers,
        }
    }

    /// Take up to `n` messages in strict [`DRAIN_PRIORITY`] order, fully draining a
    /// class (up to the budget) before touching the next.
    async fn pop_n(&self, n: usize) -> Vec<(u32, NetworkMessage)> {
        self.pop_guaranteed(n as u64, &[0; MSG_CLASSES], |_| 1).await
    }

    /// [`pop_n`](Self::pop_n) by `cost` until it reaches `budget` (the last one may
    /// overshoot), first taking up to `guaranteed[class]` from each class.
    async fn pop_guaranteed(
        &self,
        budget: u64,
        guaranteed: &[usize; MSG_CLASSES],
        cost: impl Fn(&NetworkMessage) -> u64,
    ) -> Vec<(u32, NetworkMessage)> {
        let mut out: Vec<(u32, NetworkMessage)> = Vec::new();
        let mut spent = 0u64;
        for class in DRAIN_PRIORITY {
            let mut q = self.queue(class).lock().await;
            let mut take = guaranteed[class as usize];
            while take > 0 && spent < budget {
                let Some(((height, _), msg)) = q.pop_first() else {
                    break;
                };
                spent += cost(&msg);
                out.push((height, msg));
                take -= 1;
            }
        }
        for class in DRAIN_PRIORITY {
            let mut q = self.queue(class).lock().await;
            while spent < budget {
                let Some(((height, _), msg)) = q.pop_first() else {
                    break;
                };
                spent += cost(&msg);
                out.push((height, msg));
            }
        }
        self.len.fetch_sub(out.len(), Ordering::SeqCst);
        out
    }

    async fn push(&self, height: u32, msg: NetworkMessage) {
        let key = (height, self.back_seq.fetch_add(1, Ordering::SeqCst));
        self.queue(classify(&msg)).lock().await.insert(key, msg);
        self.len.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Put messages first among their height, preserving order: popped-but-unsent ones
    /// (dropping one would stall its pipeline forever, see `route_tick`) and retries.
    async fn push_front_all(&self, msgs: Vec<(u32, NetworkMessage)>) {
        if msgs.is_empty() {
            return;
        }
        let n = msgs.len();
        for (height, msg) in msgs.into_iter().rev() {
            let key = (height, self.front_seq.fetch_sub(1, Ordering::SeqCst));
            self.queue(classify(&msg)).lock().await.insert(key, msg);
        }
        self.len.fetch_add(n, Ordering::SeqCst);
        self.notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use crate::network::SendRequest;
    use crate::test_utils::test_socket_address;
    use dashcore::network::message_blockdata::GetHeadersMessage;
    use dashcore::network::message_filter::{CFilter, GetCFHeaders, GetCFilters};
    use dashcore::network::message_sml::GetMnListDiff;
    use dashcore::{BlockHash, Txid};
    use dashcore_hashes::Hash;
    use test_case::test_case;

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

    fn block(n: u32) -> Inventory {
        Inventory::Block(BlockHash::dummy(n))
    }

    fn tx(n: u8) -> Inventory {
        Inventory::Transaction(Txid::from_byte_array([n; 32]))
    }

    fn conn(addr: u8, n: u64) -> PeerId {
        PeerId::for_test(test_socket_address(addr), n)
    }

    /// `start()` is never called, so nothing touches the network.
    async fn broker() -> PeerNetworkManager {
        let config = ClientConfig::regtest().with_restrict_to_configured_peers(true);
        PeerNetworkManager::new(&config).await
    }

    async fn mark_on_wire(net: &PeerNetworkManager, msg: &NetworkMessage, peer: PeerId) {
        let mut reqs = net.requests.lock().await;
        for key in request_keys(msg) {
            let on_wire = OnWire {
                peer,
                last_progress: Instant::now(),
                msg: msg.clone(),
                height: 0,
                sent: Instant::now(),
                hedge: None,
            };
            reqs.insert(key, ReqState::OnWire(Box::new(on_wire)));
        }
    }

    async fn state_of(net: &PeerNetworkManager, key: &RequestKey) -> Option<&'static str> {
        net.requests.lock().await.get(key).map(|s| match s {
            ReqState::Queued => "queued",
            ReqState::OnWire(_) => "on_wire",
        })
    }

    fn start_heights(msgs: &[(u32, NetworkMessage)]) -> Vec<u32> {
        msgs.iter()
            .map(|(_, m)| match m {
                NetworkMessage::GetCFilters(g) => g.start_height,
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    #[test]
    fn completed_decompressions_are_released_in_receive_order() {
        let mut results = OrderedHeaderResults::default();

        assert!(results.complete(2, "third").is_empty());
        assert_eq!(results.complete(0, "first"), ["first"]);
        assert_eq!(results.complete(1, "second"), ["second", "third"]);
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

    #[test_case(get_headers(1) => vec![RequestKey::Headers(BlockHash::dummy(1))]; "getheaders")]
    #[test_case(get_cfheaders(2) => vec![RequestKey::CfHeaders(BlockHash::dummy(2))]; "getcfheaders")]
    #[test_case(get_cfilters(100) => vec![RequestKey::CFilters(100)]; "getcfilters")]
    #[test_case(NetworkMessage::GetMnListD(GetMnListDiff {
        base_block_hash: BlockHash::dummy(3),
        block_hash: BlockHash::dummy(4),
    }) => vec![RequestKey::MnListDiff(BlockHash::dummy(4))]; "getmnlistd")]
    #[test_case(NetworkMessage::GetData(vec![block(1), tx(7), block(2)])
        => vec![RequestKey::Block(BlockHash::dummy(1)), RequestKey::Block(BlockHash::dummy(2))];
        "getdata splits per block and ignores other inventory")]
    #[test_case(NetworkMessage::GetData(vec![tx(1)]) => Vec::<RequestKey>::new(); "getdata tx")]
    #[test_case(NetworkMessage::MemPool => Vec::<RequestKey>::new(); "mempool")]
    fn request_keys_identify_tracked_requests(msg: NetworkMessage) -> Vec<RequestKey> {
        request_keys(&msg)
    }

    #[test_case(conn(1, 0), conn(2, 0), conn(1, 0), &[0]; "another peer's work is untouched")]
    #[test_case(conn(1, 0), conn(1, 1), conn(1, 0), &[0]; "the closed connection gives its work back")]
    #[test_case(conn(1, 1), conn(2, 0), conn(1, 0), &[]; "a late close leaves the replacement's work")]
    #[tokio::test]
    async fn losing_a_connection_requeues_only_its_requests(
        carrier_of_0: PeerId,
        carrier_of_1000: PeerId,
        gone: PeerId,
        expected: &[u32],
    ) {
        let net = broker().await;
        mark_on_wire(&net, &get_cfilters(0), carrier_of_0).await;
        mark_on_wire(&net, &get_cfilters(1000), carrier_of_1000).await;

        let requeued = requeue_requests_from(&net.requests, &HashSet::from([gone])).await;

        assert_eq!(start_heights(&requeued), expected);
        for height in [0, 1000] {
            let want = if expected.contains(&height) {
                "queued"
            } else {
                "on_wire"
            };
            assert_eq!(state_of(&net, &RequestKey::CFilters(height)).await, Some(want));
        }
    }

    #[tokio::test]
    async fn a_requeued_request_dedups_until_its_response_arrives() {
        let net = broker().await;
        let peer = conn(1, 0);
        mark_on_wire(&net, &get_cfilters(0), peer).await;
        requeue_requests_from(&net.requests, &HashSet::from([peer])).await;
        assert_eq!(state_of(&net, &RequestKey::CFilters(0)).await, Some("queued"));

        net.send(get_cfilters(0)).await;
        assert_eq!(net.msg_queue.len(), 0);

        net.request_answered(RequestKey::CFilters(0)).await;
        assert_eq!(state_of(&net, &RequestKey::CFilters(0)).await, None);
        net.send(get_cfilters(0)).await;
        assert_eq!(net.msg_queue.len(), 1);
    }

    #[test_case(vec![get_cfilters(0), get_cfilters(0), get_cfilters(1000)], 2, 2; "a request in play is dropped")]
    #[test_case(vec![NetworkMessage::MemPool, NetworkMessage::MemPool], 2, 0; "untracked traffic is never deduplicated")]
    #[tokio::test]
    async fn send_dedups_by_request_key(msgs: Vec<NetworkMessage>, queued: usize, tracked: usize) {
        let net = broker().await;
        for msg in msgs {
            net.send(msg).await;
        }
        assert_eq!(net.msg_queue.len(), queued);
        assert_eq!(net.requests.lock().await.len(), tracked);
    }

    /// Zero is what the sync layer acts on, so the count must fall as well as rise.
    #[tokio::test]
    async fn losing_a_peer_announces_the_new_count() {
        let net = broker().await;
        let mut events = net.events();

        net.inbound_tx.send(PeerEvent::Disconnected(conn(1, 0))).expect("the pump is running");

        let mut next = async || {
            tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .expect("the pump must report the departure")
                .expect("channel open")
        };
        let event = next().await;
        assert!(matches!(event, NetworkEvent::PeerDisconnected(_)), "got {event:?}");
        let event = next().await;
        assert!(
            matches!(
                event,
                NetworkEvent::PeersUpdated {
                    connected_count: 0,
                    ..
                }
            ),
            "got {event:?}"
        );
    }

    #[test_case(None, true; "a silent request")]
    #[test_case(Some(1), false; "the carrier streaming keeps it alive")]
    #[test_case(Some(2), true; "another peer streaming is not progress")]
    #[tokio::test(start_paused = true)]
    async fn the_timeout_monitor_requeues_stalled_requests(streamer: Option<u8>, stalls: bool) {
        let net = broker().await;
        mark_on_wire(&net, &get_cfilters(0), conn(1, 0)).await;

        // Two gaps that each stay under the deadline but together exceed it.
        for _ in 0..2 {
            tokio::time::advance(REQUEST_TIMEOUT - TIMEOUT_CHECK).await;
            tokio::task::yield_now().await;
            if let Some(peer) = streamer {
                let piece = NetworkMessage::CFilter(CFilter {
                    filter_type: 0,
                    block_hash: BlockHash::dummy(1),
                    filter: vec![0u8; 4],
                });
                net.inbound_tx
                    .send(PeerEvent::Message(conn(peer, 0), piece.into()))
                    .expect("the pump is running");
            }
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }

        let want = if stalls {
            "queued"
        } else {
            "on_wire"
        };
        assert_eq!(state_of(&net, &RequestKey::CFilters(0)).await, Some(want));
        assert_eq!(net.msg_queue.len(), stalls as usize);
    }

    #[test_case(get_headers(1) => MsgClass::Headers)]
    #[test_case(get_cfheaders(1) => MsgClass::CfHeaders)]
    #[test_case(get_cfilters(0) => MsgClass::CFilters)]
    #[test_case(NetworkMessage::GetData(vec![block(1)]) => MsgClass::Blocks; "getdata blocks")]
    #[test_case(NetworkMessage::GetData(vec![tx(1)]) => MsgClass::Other; "getdata tx is control traffic")]
    #[test_case(NetworkMessage::MemPool => MsgClass::Other)]
    fn classify_cases(msg: NetworkMessage) -> MsgClass {
        classify(&msg)
    }

    #[tokio::test]
    async fn queue_drains_in_strict_priority_order() {
        let q = MsgQueue::new();
        q.push(0, get_cfilters(0)).await;
        q.push(0, NetworkMessage::GetData(vec![block(1)])).await;
        q.push(0, get_cfheaders(1)).await;
        q.push(0, get_headers(1)).await;
        q.push(0, NetworkMessage::MemPool).await;

        let drained: Vec<MsgClass> = q.pop_n(5).await.iter().map(|(_, m)| classify(m)).collect();
        assert_eq!(
            drained,
            [
                MsgClass::Other,
                MsgClass::Blocks,
                MsgClass::CFilters,
                MsgClass::CfHeaders,
                MsgClass::Headers
            ]
        );
        assert_eq!(q.len(), 0);
    }

    #[tokio::test]
    async fn pop_n_respects_its_budget_and_unsent_messages_go_back_to_the_front() {
        let q = MsgQueue::new();
        for start in [0, 1000, 2000] {
            q.push(start, get_cfilters(start)).await;
        }

        let popped = q.pop_n(1).await;
        assert_eq!(start_heights(&popped), [0]);
        assert!(q.pop_n(0).await.is_empty());
        assert_eq!(q.len(), 2);

        q.push_front_all(popped).await;
        assert_eq!(start_heights(&q.pop_n(3).await), [0, 1000, 2000]);
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
