use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
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
pub(super) struct OrderedHeaderResults<T> {
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
    pub(super) fn complete(&mut self, sequence: u64, result: T) -> Vec<T> {
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

/// Handshake ping at/above which a peer is "very bad": taken only as a last resort,
/// when nothing better is connectable and the set would otherwise be empty.
const BAD_LAG_MS: u32 = 1000;

/// A connected peer is underserving when its mean service time exceeds the best
/// connected peer's by this multiple.
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

/// A request unanswered this long is treated as dead: the timeout monitor re-queues
/// it and kicks the peer holding it. Deliberately aggressive: replacing a peer that
/// stopped answering is faster than waiting for it; merely-slow peers are already
/// throttled by their per-peer cap.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the timeout monitor scans the outstanding-request registry.
const TIMEOUT_CHECK: Duration = Duration::from_secs(1);

use crate::error::{NetworkError, NetworkResult};
use crate::network::NetworkManager;
use crate::{
    network::{
        discovery::PeerDiscoverer,
        peer::{
            is_pipeline_request, ConnectedPeer, DisconnectedPeer, PeerEvent, PeerHandle, PeerId,
        },
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
    pub(crate) fn new(msg: NetworkMessage) -> Self {
        Self {
            msg,
            header_hashes: None,
        }
    }

    /// Headers message carrying the hashes computed during DIP-25 decompression (which
    /// must hash every header to rebuild `prev_blockhash`), so they are not hashed twice.
    pub(crate) fn new_headers(headers_with_hashes: Vec<(Header, BlockHash)>) -> Self {
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
    /// `getmnlistdiff` — keyed by the target block hash. Tracked for de-dup and retry
    /// only, not counted against a peer's in-flight budget.
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
struct MsgQueue {
    other: Mutex<VecDeque<NetworkMessage>>,
    blocks: Mutex<VecDeque<NetworkMessage>>,
    cfilters: Mutex<VecDeque<NetworkMessage>>,
    cfheaders: Mutex<VecDeque<NetworkMessage>>,
    headers: Mutex<VecDeque<NetworkMessage>>,
    len: AtomicUsize,
    notify: Notify,
}

/// Downstream first: the stage closest to the wallet is the one waiting on the network,
/// while the head of the chain has a full backlog and only waits for room.
const DRAIN_PRIORITY: [MsgClass; 5] =
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
        let global_cap = Arc::new(AtomicUsize::new(max_peers.saturating_mul(4).max(8)));
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

        spawn_bandwidth_controller(
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
    async fn send(&self, msg: NetworkMessage) {
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
        let Some(ReqState::OnWire(o)) = self.requests.lock().await.remove(&key) else {
            return;
        };
        if !is_pipeline_request(&o.msg) {
            return;
        }
        if let Some(p) = self.connected_peers.lock().await.iter().find(|p| p.id() == o.peer) {
            p.response_completed(1).await;
        }
        // A freed unit is capacity the router can use right now.
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
/// non-pipeline messages (mirrors `is_pipeline_request` in `peer`).
pub(crate) fn request_keys(msg: &NetworkMessage) -> Vec<RequestKey> {
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
    global_cap: usize,
    requests: &Registry,
) -> usize {
    if peers.is_empty() {
        return 0;
    }

    // Free capacity this round = min(sum of per-peer room, global room). Each peer's
    // cap is its measured bandwidth-delay product; the global cap is our measured
    // download capacity. Whichever binds first limits the round.
    let total_in_flight: usize = peers.iter().map(PeerHandle::in_flight).sum();
    let per_peer_room: usize = peers.iter().map(|p| p.cap().saturating_sub(p.in_flight())).sum();
    let global_room = global_cap.saturating_sub(total_in_flight);
    let capacity = per_peer_room.min(global_room);
    if capacity == 0 {
        return 0;
    }

    let msgs = queue.pop_n(capacity).await;
    let mut sent = 0;
    // Anything popped but not sent goes BACK on the queue: its key is registered, so a
    // dropped message would never be re-sent nor time out and its pipeline would stall.
    let mut unsent: Vec<NetworkMessage> = Vec::new();
    // Recorded in the broker under one lock after the send loop.
    let mut on_wire: Vec<(NetworkMessage, PeerHandle)> = Vec::new();
    let mut msgs = msgs.into_iter();
    for msg in msgs.by_ref() {
        // Pick the least-loaded peer RELATIVE TO ITS OWN cap. Absolute free room
        // concentrates load: the biggest cap wins every round and keeps growing while the
        // others stay idle and never grow (measured: three identical peers split into one
        // at cap 12 and two stuck at 2). Cross-multiplied to avoid floats; neither side
        // can be zero (`cap >= FLOOR_PER_PEER`, full peers filtered above).
        let Some(peer) = peers
            .iter()
            .filter(|p| p.in_flight() < p.cap())
            .min_by(|a, b| (a.in_flight() * b.cap()).cmp(&(b.in_flight() * a.cap())))
        else {
            unsent.push(msg); // every peer is at its measured cap
            break;
        };
        if peer.send(&msg).await.is_ok() {
            sent += 1;
            // Record the peer so the monitor can attribute a stall to it.
            on_wire.push((msg, peer.clone()));
        } else {
            tracing::warn!(target: "dash_spv::network", "router: send to {} failed", peer.addr());
            unsent.push(msg);
        }
    }
    unsent.extend(msgs); // whatever the loop never reached
    queue.push_front_all(unsent).await;

    if !on_wire.is_empty() {
        // Peers owed back a unit `send` charged for a request nobody tracks.
        let mut refund: Vec<PeerHandle> = Vec::new();
        {
            let mut reqs = requests.lock().await;
            for (msg, peer) in on_wire {
                let mut tracked = false;
                for key in request_keys(&msg) {
                    // Queued -> OnWire, keeping the message for retry. A key settled while queued is
                    // gone, so nothing would release the in-flight unit `send` charged: refund it.
                    if let Some(slot) = reqs.get_mut(&key) {
                        *slot = ReqState::OnWire(Box::new(OnWire {
                            peer: peer.id(),
                            msg: msg.clone(),
                            last_progress: Instant::now(),
                        }));
                        tracked = true;
                    }
                }
                if !tracked && is_pipeline_request(&msg) {
                    refund.push(peer);
                }
            }
        }
        for peer in refund {
            peer.response_completed(1).await;
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
/// connection's cap by Little's Law over its OWN completion stream.
#[derive(Default, Clone, Copy)]
struct PeerCapState {
    /// Cumulative completions/service-ns at the last window, to diff against.
    last_count: u64,
    last_total_ns: u64,
    /// Cumulative bytes from this peer at the last window, for per-window throughput.
    last_bytes: u64,
    /// Uncongested service-time baseline in seconds (min `W`), 0 until measured.
    min_w: f64,
    /// Windows since `min_w` took a new low (BBR-style min-filter age), so a stale
    /// baseline expires instead of one cheap early sample pinning it forever.
    min_w_age: u32,
    /// Smoothed service time in seconds, carried ACROSS windows: completions are sparse
    /// (most windows see none), and without it the cap could not move on empty windows.
    w_ema: f64,
    /// Windows since this peer last completed anything. Distinguishes "nothing routed
    /// here" from "sitting on work it will never answer"; only the latter stops the probe.
    dry_windows: u32,
    /// Windows since `max_lambda` took a new high, so a stale peak expires.
    max_lambda_age: u32,
    /// Best completion rate seen (BBR's `max_bw`, requests/s). Times `min_w` it is the
    /// peer's bandwidth-delay product.
    max_lambda: f64,
    cap_ema: f64,
    /// Smoothed response size in bytes. Converts a cap (a request count) into what the
    /// link rations: a 1000-filter `getcfilters` and a one-block `getdata` are each one
    /// request but orders of magnitude apart on the wire.
    resp_bytes_ema: f64,
    /// Windows left before another soft-timeout cut may fire. A cut takes a service time
    /// to show effect, so one reduction per feedback delay (as in TCP).
    soft_cut_cooldown: u32,
}

/// One peer's requested capacity, collected for all peers first because the shared
/// link bounds what they may have in flight together.
struct PeerPlan {
    addr: PeerId,
    /// Cap this peer's own measurements justify, in requests.
    want: usize,
    /// Smoothed bytes per response, to price `want` on the wire.
    resp_bytes: f64,
    lambda: f64,
    w: f64,
    min_w: f64,
    rate: f64,
    total_bytes: u64,
    in_flight: usize,
    lag_ms: u32,
}

/// Factor to shrink every peer's cap by so their combined bytes in flight fit the
/// shared link's bandwidth-delay product. Only ever shrinks; 1.0 when they fit or
/// when nothing is measured (scaling by a guess is worse than not scaling).
fn link_share_scale(link_bytes: f64, priced_bytes: f64) -> f64 {
    if !link_bytes.is_finite() || link_bytes <= 0.0 || priced_bytes <= 0.0 {
        return 1.0;
    }
    (link_bytes / priced_bytes).min(1.0)
}

/// How long a request may sit without progress before it counts as evidence its peer
/// is over-committed: a multiple of that peer's own UNCONGESTED cost `min_w`.
///
/// Relative, because at 700ms RTT a 1000-filter `getcfilters` legitimately takes
/// seconds. Based on `min_w`, not `w_ema`: `w_ema` inflates because of the backlog we
/// created, so scaling by it raises the threshold exactly when we over-commit (on
/// mainnet it put the threshold past the hard timeout, so it never fired). Capped
/// at half the hard timeout so the soft signal fires before eviction. `None` while
/// the peer is unmeasured.
fn soft_timeout_threshold(min_w: f64) -> Option<Duration> {
    const SOFT_GAIN: f64 = 3.0;
    if min_w <= 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(SOFT_GAIN * min_w).min(REQUEST_TIMEOUT / 2))
}

/// Sizes the GLOBAL in-flight budget and each PEER's cap from measurements, with no
/// fixed magic number.
///
/// - The global budget (host downlink) hill-climbs on bytes/s read off the sockets.
/// - Each peer's cap is `L = λ · min_W` (Little's Law): `λ` = its completion rate,
///   `min_W` = its minimum (uncongested) send-to-completion time; i.e. its
///   bandwidth-delay product, probed slightly past it.
///
/// `route_tick` binds `min(Σ per-peer room, global room)`. Saturation is detected by
/// `W` INFLATION, not throughput: past the BDP extra requests just queue at the
/// peers, so `W` climbs while `λ` plateaus (a pure throughput hill-climb can't see
/// the knee because the backlog keeps bytes flowing). When `W > min_W · W_INFLATE`
/// we stop probing and back off.
fn spawn_bandwidth_controller(
    bytes: Arc<AtomicU64>,
    cap: Arc<AtomicUsize>,
    connected: Arc<Mutex<Vec<ConnectedPeer>>>,
    shutdown: CancellationToken,
    peer_wake: Arc<Notify>,
    queue: Arc<MsgQueue>,

    requests: Registry,
) -> JoinHandle<()> {
    const WINDOW: Duration = Duration::from_millis(500);
    const FLOOR_PER_PEER: usize = 2; // global floor = peers · this
                                     // Bootstrap ceiling until the peer is measured; then its own BDP sets it (a
                                     // 700ms peer needs 14x the in-flight of a 50ms one for the same throughput).
    const BOOTSTRAP_CEIL: usize = 32;
    // Absolute backstop, not a tuning knob: only catches a peer whose service time
    // never inflates no matter what we send it.
    const HARD_CEIL: usize = 512;
    // Probe headroom above the `CAP_GAIN` target, letting us discover the pipe is
    // bigger than measured. Not a second multiplier: too large walks a fast peer to
    // the hard ceiling before a stale rate peak expires.
    const PROBE_GAIN: f64 = 2.5;
    const RISE: f64 = 1.05; // throughput must climb 5% to justify a bigger cap
    const DROP: f64 = 0.85; // throughput below this·last => over-commit, back off
    const REPROBE: u32 = 8; // plateau windows to hold before nudging the cap up

    // Idle means NOTHING QUEUED, not low byte rate: a budget backed off to its floor
    // produces little throughput, which would read as idle and hold it there with the
    // send queue backed up. The queue is the honest demand signal.
    const EMA_ALPHA: f64 = 0.5; // smoothing for the noisy per-window rate

    // Per-peer cap: increase/decrease on THIS peer's service time, no hard per-peer limit;
    // it grows while lag stays at baseline and backs off when lag inflates.
    const CAP_GROW: f64 = 1.25; // multiplicative probe per window while W is flat
    const CAP_BACKOFF: f64 = 0.8; // multiplicative decrease when lag inflates

    // Soft-timeout cut, harder than CAP_BACKOFF: a request untouched for several
    // service times is stronger evidence than an inflated average.
    const SOFT_BACKOFF: f64 = 0.7;
    const W_INFLATE: f64 = 1.5; // W above min_W·this => this peer is backing up
    const MIN_W_WINDOW: u32 = 20; // windows before a stale min_W baseline is re-tracked
    const MAX_LAMBDA_WINDOW: u32 = 20; // windows before a stale rate peak is re-tracked
    const W_EMA_ALPHA: f64 = 0.3; // weight of a new service-time sample
    const DRY_LIMIT: u32 = 20; // windows sitting on work with no completion => stop probing
                               // In-flight target as a multiple of the peer's BDP. Two, like BBR's cwnd: one
                               // BDP fills the pipe with no margin for jitter.
    const CAP_GAIN: f64 = 2.0;
    let window_s = WINDOW.as_secs_f64();

    tokio::spawn(async move {
        let mut last_bytes = bytes.load(Ordering::Relaxed);
        let mut rate_ema = 0.0f64; // smoothed downlink bytes/s
                                   // Best aggregate downlink seen: the shared bottleneck every peer queues behind.
                                   // Windowed like `max_lambda`, so an old peak expires.
        let mut max_rate = 0.0f64;
        let mut max_rate_age = 0u32;
        let mut last_rate = 0.0f64; // smoothed rate at the previous cap adjustment
        let mut hold = 0u32; // consecutive plateau windows
                             // Sum of per-peer caps from the previous window (they are computed after the host
                             // budget below).
        let mut last_sum_peer_cap = 0usize;
        let mut peer_caps: HashMap<PeerId, PeerCapState> = HashMap::new();
        // Last peer reported as underserving. The supervisor is woken on the TRANSITION
        // only, so a peer that stays slow does not trigger a probe every window.
        let mut last_underserving: Option<SocketAddr> = None;
        let mut ticker = tokio::time::interval(WINDOW);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }

            // Downlink throughput drives the host budget: grow while bytes/s climbs with it,
            // hold at the plateau (the BDP), back off if it collapses. Per-request service
            // time is a poor host signal: it balloons with payload size and batch completion.
            let now_bytes = bytes.load(Ordering::Relaxed);
            let dl_rate = now_bytes.saturating_sub(last_bytes) as f64 / window_s;
            last_bytes = now_bytes;
            rate_ema = if rate_ema == 0.0 {
                dl_rate
            } else {
                EMA_ALPHA * dl_rate + (1.0 - EMA_ALPHA) * rate_ema
            };

            if rate_ema > max_rate {
                max_rate = rate_ema;
                max_rate_age = 0;
            } else {
                max_rate_age += 1;
                if max_rate_age >= MAX_LAMBDA_WINDOW {
                    max_rate = rate_ema;
                    max_rate_age = 0;
                }
            }

            let npeers = connected.lock().await.len();
            if npeers == 0 {
                continue;
            }
            // Never bind below what the peers themselves justify (the sum of their BDPs).
            // At 700ms RTT the per-window byte rate swings between bursts and nothing, and the
            // hill-climb reads each trough as over-commitment; without this floor the budget
            // sat at 17 while the peers were sized for 49 and work sat queued.
            let floor = (npeers * FLOOR_PER_PEER).max(FLOOR_PER_PEER).max(last_sum_peer_cap);
            // Backstop only: the host budget is driven by the throughput hill-climb
            // below, which backs off on its own when the peers are over-committed.
            let ceiling = (npeers * HARD_CEIL).max(floor + 1);
            let step = npeers.max(4); // ~one extra slot per peer per window
            let cur = cap.load(Ordering::Relaxed);

            // Gradient hill-climb on smoothed throughput.
            let idle = queue.len() == 0;
            let (new, action) = if idle {
                // Genuinely nothing queued (e.g. the commit tail): hold the budget
                // steady so it is ready when the download resumes.
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
                // Plateau: at the knee. Hold, re-probing occasionally to catch more capacity.
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

            // Longest any on-wire request has gone without progress, per peer. Completion-
            // driven signals (`w_ema`, degradation) only move on windows where something
            // completes (~6% of them), so this is what reveals a peer sitting on work.
            let stalled_for: HashMap<PeerId, Duration> = {
                let now = Instant::now();
                let reqs = requests.lock().await;
                let mut worst: HashMap<PeerId, Duration> = HashMap::new();
                for state in reqs.values() {
                    if let ReqState::OnWire(o) = state {
                        let idle = now.duration_since(o.last_progress);
                        let e = worst.entry(o.peer).or_default();
                        if idle > *e {
                            *e = idle;
                        }
                    }
                }
                worst
            };

            let mut plans: Vec<PeerPlan> = Vec::new();
            let (mut cap_min, mut cap_max, mut cap_sum) = (usize::MAX, 0usize, 0usize);
            let mut inflight_sum = 0usize; // total requests on the wire right now
            {
                let g = connected.lock().await;
                let live: HashSet<PeerId> = g.iter().map(|p| p.id()).collect();
                for p in g.iter() {
                    let addr = p.id();
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
                        // No completions this window: the NORMAL case (one request covers up to
                        // thousands of items; ~94% of windows are empty). Carry the smoothed values and
                        // let the decision below run on them, or the cap could barely ever grow.
                        st.dry_windows += 1;
                        (0.0, st.w_ema)
                    } else {
                        st.dry_windows = 0;
                        let lambda = dc as f64 / window_s; // completions/sec
                        let w = (dt as f64 / dc as f64) / 1e9; // avg service time (s)
                        let resp = d_bytes as f64 / dc as f64; // avg bytes per response
                        st.resp_bytes_ema = if st.resp_bytes_ema == 0.0 {
                            resp
                        } else {
                            W_EMA_ALPHA * resp + (1.0 - W_EMA_ALPHA) * st.resp_bytes_ema
                        };
                        st.w_ema = if st.w_ema == 0.0 {
                            w
                        } else {
                            W_EMA_ALPHA * w + (1.0 - W_EMA_ALPHA) * st.w_ema
                        };
                        // Windowed max, mirroring the min-W filter: a running max never forgets one
                        // burst window, which would keep the BDP target and ceiling inflated.
                        if lambda > st.max_lambda {
                            st.max_lambda = lambda;
                            st.max_lambda_age = 0;
                        } else {
                            st.max_lambda_age += 1;
                            if st.max_lambda_age >= MAX_LAMBDA_WINDOW {
                                st.max_lambda = lambda;
                                st.max_lambda_age = 0;
                            }
                        }
                        // Windowed min-W baseline (BBR-style): take a new low immediately, else re-track
                        // after MIN_W_WINDOW windows. Otherwise one cheap-phase sample (fast headers)
                        // makes every later cfilter request read as inflated and pins the cap at the floor.
                        if st.min_w == 0.0 || w < st.min_w {
                            st.min_w = w;
                            st.min_w_age = 0;
                        } else {
                            st.min_w_age += 1;
                            // Re-track only when the queue is not ours: above the BDP the extra service time
                            // IS our backlog, and adopting it as baseline disables the degradation check and
                            // licenses more growth (a feedback loop that hit the 512 hard ceiling on mainnet).
                            let queue_is_ours = p.in_flight() as f64 > st.max_lambda * st.min_w;
                            if st.min_w_age >= MIN_W_WINDOW && !queue_is_ours {
                                st.min_w = w;
                                st.min_w_age = 0;
                            }
                        }
                        (lambda, w)
                    };

                    // Size this peer by its bandwidth-delay product `λ · min_W`, like BBR's cwnd.
                    // `min_W` measures distance, not queueing, so a peer 700ms away gets 14x the
                    // in-flight of a 50ms one at the same rate instead of a fourteenth the throughput.
                    let bdp_raw = if st.min_w > 0.0 {
                        st.max_lambda * st.min_w
                    } else {
                        0.0
                    };
                    let bdp = bdp_raw * CAP_GAIN;
                    // Ceiling from this peer's own BDP; the bootstrap value only until measured.
                    let peer_ceil =
                        ((bdp_raw * PROBE_GAIN) as usize).clamp(BOOTSTRAP_CEIL, HARD_CEIL);

                    // λ is only measured under the cap we granted, so the BDP can't discover unused
                    // capacity: probe past it while the peer shows no strain (BBR's ProbeBW) and back
                    // off when its service time inflates. Growth is per window, not per completion.
                    let degraded = st.w_ema > 0.0 && st.w_ema > st.min_w * W_INFLATE;
                    let saturated = p.in_flight() + 1 >= st.cap_ema.round() as usize;
                    // A peer holding work it never answers is not probed further; the timeout monitor
                    // removes it.
                    let stuck = st.dry_windows >= DRY_LIMIT && p.in_flight() > 0;

                    // Soft timeout: a request untouched for several service times means the peer is
                    // given more than it can turn around. Take future work away but leave in-flight
                    // alone: re-queueing would re-send bytes still on their way.
                    st.soft_cut_cooldown = st.soft_cut_cooldown.saturating_sub(1);
                    let burning = match (soft_timeout_threshold(st.min_w), stalled_for.get(&addr)) {
                        (Some(limit), Some(idle)) => *idle > limit,
                        _ => false,
                    };

                    if st.cap_ema == 0.0 {
                        st.cap_ema = FLOOR_PER_PEER as f64;
                    } else if burning && st.soft_cut_cooldown == 0 {
                        st.cap_ema = (st.cap_ema * SOFT_BACKOFF).max(FLOOR_PER_PEER as f64);
                        // Let the smaller cap take effect for a service time before cutting again.
                        st.soft_cut_cooldown =
                            ((st.w_ema / window_s).ceil() as u32).clamp(2, MIN_W_WINDOW);
                        tracing::debug!(
                            target: "peer_speed",
                            "{} soft timeout: idle {:?} > {:?}, cap -> {:.1}",
                            addr,
                            stalled_for.get(&addr).copied().unwrap_or_default(),
                            soft_timeout_threshold(st.min_w).unwrap_or_default(),
                            st.cap_ema,
                        );
                    } else if degraded {
                        st.cap_ema = (st.cap_ema * CAP_BACKOFF).max(FLOOR_PER_PEER as f64);
                    } else if saturated && !stuck {
                        st.cap_ema = (st.cap_ema * CAP_GROW).min(peer_ceil as f64);
                    }
                    // Never sit below what measurements justify, unless a request is stalled now: then
                    // the BDP (from a not-yet-expired rate peak) overstates capacity, and restoring it
                    // would undo the cut.
                    if !burning {
                        st.cap_ema = st.cap_ema.max(bdp.min(peer_ceil as f64));
                    }

                    let want = (st.cap_ema.round() as usize).clamp(FLOOR_PER_PEER, peer_ceil);
                    plans.push(PeerPlan {
                        addr,
                        want,
                        resp_bytes: st.resp_bytes_ema,
                        lambda,
                        w,
                        min_w: st.min_w,
                        rate,
                        total_bytes: p.bytes_read(),
                        in_flight: p.in_flight(),
                        lag_ms: p.lag_ms(),
                    });
                    inflight_sum += p.in_flight();
                }
                peer_caps.retain(|addr, _| live.contains(addr));

                // ---- phase two: ration the ONE link they all share ----
                //
                // Each cap above assumes its peer owns the pipe, so N peers over-commit the shared
                // downlink N-fold (seen: sum_peer_cap=121 vs global_cap=71, the floor pulling the
                // budget up). Bounded in bytes, because bytes are what the link rations.
                let link_rate = max_rate.max(rate_ema); // measured ceiling, bytes/s
                let w_ref = plans
                    .iter()
                    .map(|pl| pl.min_w)
                    .filter(|m| *m > 0.0)
                    .fold(f64::INFINITY, f64::min);
                let priced: f64 = plans.iter().map(|pl| pl.want as f64 * pl.resp_bytes).sum();
                // Only bind once there is something to bind with: an unpriced or
                // unmeasured window leaves the per-peer answers untouched rather
                // than scaling them by a guess.
                let link_bytes = if w_ref.is_finite() {
                    link_rate * w_ref * CAP_GAIN
                } else {
                    0.0
                };
                let scale = 1.0f64.min(link_share_scale(link_bytes, priced)).max(1.0);

                for (p, pl) in g.iter().zip(plans.iter()) {
                    let cap_peer = if scale < 1.0 {
                        ((pl.want as f64 * scale).round() as usize).max(FLOOR_PER_PEER)
                    } else {
                        pl.want
                    };
                    p.set_cap(cap_peer);

                    tracing::debug!(
                        target: "peer_speed",
                        "peer {}: cap={} (want {}) in_flight={} lag={}ms lambda={:.1}/s W={:.0}ms minW={:.0}ms resp={:.0} KB rate={:.2} MB/s total={:.1} MB",
                        pl.addr,
                        cap_peer,
                        pl.want,
                        pl.in_flight,
                        pl.lag_ms,
                        pl.lambda,
                        pl.w * 1e3,
                        pl.min_w * 1e3,
                        pl.resp_bytes / 1e3,
                        pl.rate / 1e6,
                        pl.total_bytes as f64 / 1e6,
                    );

                    cap_min = cap_min.min(cap_peer);
                    cap_max = cap_max.max(cap_peer);
                    cap_sum += cap_peer;
                }
                if scale < 1.0 {
                    tracing::debug!(
                        target: "peer_speed",
                        "link budget: {:.1} MB/s x {:.0}ms x{} = {:.1} MB vs {:.1} MB asked => scale {:.2}",
                        link_rate / 1e6,
                        w_ref * 1e3,
                        CAP_GAIN,
                        link_rate * w_ref * CAP_GAIN / 1e6,
                        priced / 1e6,
                        scale,
                    );
                }

                // Service times were just refreshed, so detect a laggard here. Only the transition
                // wakes the supervisor, so a peer with no replacement is not re-probed every window.
                let underserving = underserving_peer(&g);
                if underserving.is_some() && underserving != last_underserving {
                    peer_wake.notify_one();
                }
                last_underserving = underserving;
            }
            if cap_min == usize::MAX {
                cap_min = 0;
            }
            last_sum_peer_cap = cap_sum;

            // `bind` names the router's limiting constraint: `global` (host budget), `peers`
            // (summed per-peer caps) or `work` (neither full: queue-limited or peers slow).
            // With a saturated downlink the global cap should hold at the knee with `bind=global`.
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

/// The peer supervisor: the single task that owns the connected-peer set, keeping it
/// filled toward `max_peers` with the lowest-latency peers it can find.
///
/// - Below cap it probes candidates in parallel and accepts those with handshake
///   ping under [`BAD_LAG_MS`], announcing each so sync starts on the first. A very
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

        // Take each peer as soon as ITS handshake lands rather than waiting for the batch,
        // so one unreachable address doesn't delay sync. Completion order is itself a
        // latency ranking; the rest of the batch is drained only to bank backups.
        let mut inflight: FuturesUnordered<_> = batch
            .into_iter()
            .map(|c| {
                c.connect(
                    self.inbound.clone(),
                    self.shutdown.clone(),
                    self.bytes.clone(),
                    self.required_services,
                    self.headers2_decompression_semaphore.clone(),
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
                tracing::info!(
                    target: "dash_spv::network",
                    "peer supervisor: swapped out slow {} for {}",
                    old_addr,
                    replaced.expect("set with the displacing peer"),
                );
                // Close it: the pump requeues every request routed to THIS connection, as for any
                // lost peer. Safe because the departure names a connection, not an address, so a
                // reconnection to the same peer is not disturbed.
                old.close();
                let _ = self.events.send(NetworkEvent::PeerDisconnected(old_addr));
            }

            // Announce only real changes: an arrival or a swap. A candidate benched as a
            // backup changed nothing.
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
            self.connected.lock().await.push(peer);
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

/// The connected peer clearly underserving the rest, if any. Judged on measured
/// service time (not handshake ping) and only for peers with enough completions;
/// `None` means nothing to improve and no reason to probe.
fn underserving_peer(peers: &[ConnectedPeer]) -> Option<SocketAddr> {
    let measured: Vec<(SocketAddr, f64)> = peers
        .iter()
        .filter_map(|p| {
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
        }
        .run(),
    )
}

/// Pull every on-wire request routed to one of `gone` back to `Queued`, returning
/// the messages to re-queue. Shared by both ways of losing a peer (monitor kick,
/// socket close); otherwise the request is stranded since the monitor only watches
/// connected peers. The key stays registered so de-dup still holds while queued.
async fn requeue_requests_from(requests: &Registry, gone: &HashSet<PeerId>) -> Vec<NetworkMessage> {
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
            // units are freed on the peer separately, so a wedged peer can sit at
            // `in_flight == cap` with no registry entries. Pending work plus a byte counter
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

                    // A `cfilter` is one piece of a `getcfilters` batch, which is only
                    // marked answered once the whole batch lands. Refresh that request's
                    // deadline so the timeout means "the pieces stopped coming".
                    if matches!(*msg, NetworkMessage::CFilter(_)) {
                        let mut reqs = requests.lock().await;
                        for state in reqs.values_mut() {
                            if let ReqState::OnWire(o) = state {
                                if o.peer == peer
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
                    let gossiped: Option<Vec<SocketAddr>> = match &*msg {
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

    /// Take up to `n` messages in strict [`DRAIN_PRIORITY`] order, fully draining a
    /// class (up to the budget) before touching the next.
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

    /// Put messages at the FRONT of their class, preserving order: popped-but-unsent ones
    /// (dropping one would stall its pipeline forever, see `route_tick`) and retries, which
    /// would otherwise wait behind the whole backlog while the pipeline blocks on them.
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

    fn start_heights(msgs: &[NetworkMessage]) -> Vec<u32> {
        msgs.iter()
            .map(|m| match m {
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

    // rate x uncongested W x BBR gain, against what three peers asked for.
    #[test_case(5.0e6 * 0.95 * 2.0, 121.0 * 138.0e3 => 0.57; "peers sized for the whole pipe shrink")]
    #[test_case(9.5e6, 4.0e6 => 1.0; "peers that fit")]
    #[test_case(9.5e6, 9.5e6 => 1.0; "peers that exactly fit")]
    #[test_case(0.0, 4.0e6 => 1.0; "unmeasured link")]
    #[test_case(f64::INFINITY, 4.0e6 => 1.0; "infinite link")]
    #[test_case(9.5e6, 0.0 => 1.0; "nothing priced")]
    fn link_share_scale_cases(link_bytes: f64, priced_bytes: f64) -> f64 {
        (link_share_scale(link_bytes, priced_bytes) * 100.0).round() / 100.0
    }

    #[test_case(0.0 => None; "unmeasured peer")]
    #[test_case(0.05 => Some(Duration::from_secs_f64(0.15)); "near peer")]
    #[test_case(0.7 => Some(Duration::from_secs_f64(2.1)); "far peer")]
    #[test_case(60.0 => Some(REQUEST_TIMEOUT / 2); "capped before the hard timeout")]
    fn soft_timeout_threshold_cases(min_w: f64) -> Option<Duration> {
        soft_timeout_threshold(min_w)
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
        q.push(get_cfilters(0)).await;
        q.push(NetworkMessage::GetData(vec![block(1)])).await;
        q.push(get_cfheaders(1)).await;
        q.push(get_headers(1)).await;
        q.push(NetworkMessage::MemPool).await;

        let drained: Vec<MsgClass> = q.pop_n(5).await.iter().map(classify).collect();
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
            q.push(get_cfilters(start)).await;
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
