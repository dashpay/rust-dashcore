//! Peer network manager for SPV client

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time;

use crate::client::ClientConfig;
use crate::error::{NetworkError, NetworkResult, SpvError as Error};
use crate::network::addrv2::AddrV2Handler;
use crate::network::constants::*;
use crate::network::discovery::DnsDiscovery;
use crate::network::latency::PeerLatency;
use crate::network::pool::PeerPool;
use crate::network::reputation::{ChangeReason, PeerReputationManager, ReputationAware};
use crate::network::{
    HandshakeManager, Message, MessageDispatcher, MessageType, NetworkEvent, NetworkManager,
    NetworkRequest, Peer, RequestSender,
};
use crate::storage::{PeerStorage, PersistentPeerStorage, PersistentStorage};
use async_trait::async_trait;
use dashcore::network::address::{AddrV2, AddrV2Message};
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::network::message_headers2::CompressionState;
use dashcore::{BlockHash, Header, Network};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const DEFAULT_NETWORK_EVENT_CAPACITY: usize = 10000;
const MAX_CONCURRENT_HEADERS2_DECOMPRESSIONS: usize = 4;

fn headers2_decompression_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().min(MAX_CONCURRENT_HEADERS2_DECOMPRESSIONS))
        .unwrap_or(1)
}

enum Headers2DecompressionOutcome {
    Headers(Vec<(Header, BlockHash)>),
    Invalid(String),
    TaskFailed(String),
}

/// Releases parallel decompression results in wire order because a header announcement can
/// depend on the preceding message from the same peer.
struct OrderedHeaders2Results<T> {
    next_sequence: u64,
    completed: BTreeMap<u64, T>,
}

impl<T> Default for OrderedHeaders2Results<T> {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            completed: BTreeMap::new(),
        }
    }
}

impl<T> OrderedHeaders2Results<T> {
    fn complete(&mut self, sequence: u64, result: T) -> Vec<T> {
        let replaced = self.completed.insert(sequence, result);
        debug_assert!(replaced.is_none(), "headers2 sequence completed twice");

        let mut ready = Vec::new();
        while let Some(result) = self.completed.remove(&self.next_sequence) {
            ready.push(result);
            self.next_sequence += 1;
        }
        ready
    }
}

/// Peer network manager
pub struct PeerNetworkManager {
    /// Peer pool
    pool: Arc<PeerPool>,
    max_peers: usize,
    /// DNS discovery
    discovery: Arc<DnsDiscovery>,
    /// AddrV2 handler
    addrv2_handler: Arc<AddrV2Handler>,
    /// Peer persistence
    peer_store: Arc<PersistentPeerStorage>,
    /// Peer reputation manager
    reputation_manager: Arc<PeerReputationManager>,
    /// Network type
    network: Network,
    /// Shutdown token
    shutdown_token: CancellationToken,
    /// Background tasks
    tasks: Arc<Mutex<JoinSet<()>>>,
    /// Initial peer addresses
    initial_peers: Vec<SocketAddr>,
    /// Data directory for storage
    data_dir: PathBuf,
    /// Optional user agent to advertise
    user_agent: Option<String>,
    /// Exclusive mode: restrict to configured peers only (no DNS or peer store)
    exclusive_mode: bool,
    /// Service flags connected peers must advertise. NONE disables capability churn.
    required_services: ServiceFlags,
    /// Addresses evicted for lacking required services. Excluded from top-up candidates.
    /// TODO: remove once peer session outcomes track why sessions ended and drive reconnect policy.
    capability_rejected: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
    /// Cached count of currently connected peers for fast, non-blocking queries
    connected_peer_count: Arc<AtomicUsize>,
    /// Disable headers2 after decompression failure
    headers2_disabled: Arc<Mutex<HashSet<SocketAddr>>>,
    /// Global bound for CPU-heavy headers2 decompression work.
    headers2_decompression_semaphore: Arc<Semaphore>,
    /// Dispatcher for unbounded and message-type filtered message distribution.
    message_dispatcher: Arc<Mutex<MessageDispatcher>>,
    /// Request queue sender, cloneable handle for sending requests to the network manager.
    request_tx: UnboundedSender<NetworkRequest>,
    /// Request queue receiver (consumed by send loop).
    request_rx: Arc<Mutex<Option<UnboundedReceiver<NetworkRequest>>>>,
    /// Round-robin counter for distributing requests across peers.
    round_robin_counter: Arc<AtomicUsize>,
    /// Network event bus for notifying about network/peer related changes.
    network_event_sender: broadcast::Sender<NetworkEvent>,
    /// Instant each peer's oldest unanswered request of a given kind was sent.
    /// The answering response clears the entry, a stale one marks a stalling peer.
    outstanding_requests: Arc<Mutex<HashMap<(SocketAddr, RequestKind), Instant>>>,
    /// Rolling response times per peer, used to route requests to the peers that
    /// are actually answering fastest.
    latency: Arc<Mutex<PeerLatency>>,
    /// Instant of the previous stall sweep, used to detect a suspend/resume gap so
    /// a burst of stale requests on resume does not penalize every peer at once.
    last_maintenance_at: Arc<Mutex<Instant>>,
    /// Instant of the last reputation-driven eviction, enforcing a cooldown so a
    /// replacement can prove itself before another peer is dropped.
    last_eviction_at: Arc<Mutex<Option<Instant>>>,
}

const CAPABILITY_REJECTED_TTL: Duration = Duration::from_secs(30 * 60);

/// A connected peer whose oldest sync request stays unanswered this long is
/// treated as stalling and penalized. Any response resets its timer, so a peer
/// streaming a large block is not punished for the download taking a while.
///
/// Only kinds whose response time is a fair measure of the peer are judged here
/// (see `RequestKind::response_time_is_fair`), so this is generous: a filter,
/// filter-header or header response is at most a few tens of KB and arrives in
/// well under a second on any usable link. Large payloads are excluded, since
/// their transfer can legitimately exceed this on a slow mobile link.
pub(super) const REQUEST_STALL_TIMEOUT: Duration = Duration::from_secs(10);

/// A peer whose request of some kind has gone unanswered this long stops being
/// picked for further requests of that same kind, until it answers.
///
/// This is routing only, never a penalty, so it can be far stricter than
/// `REQUEST_STALL_TIMEOUT` without risking an honest peer: the cost of skipping
/// one wrongly is that another peer serves the request instead. It must stay
/// below the sync layer's own retry timeouts, so that a peer which dropped a
/// request is already out of the rotation by the time that request is reissued.
pub(super) const REQUEST_OWED_TIMEOUT: Duration = Duration::from_secs(5);

/// If a maintenance sweep runs at least this long after the previous one, the
/// process was likely suspended (e.g. an iOS app backgrounded). Every
/// outstanding request would look stale at once, so the sweep refreshes their
/// timers and skips penalties for that round instead of blaming every peer.
const SUSPEND_GAP: Duration = Duration::from_secs(90);

/// A connected peer scoring at least this becomes an eviction candidate: two
/// consecutive stalls, or equivalent misbehavior. Well below the +100 ban line,
/// so a peer is dropped and replaced long before it would be banned outright, and
/// eviction stays a soft demotion (the peer keeps its address-book entry and
/// decays back).
///
/// Reachable only because a stalling peer's timer is re-armed rather than
/// dropped: one stall already records a mean response time that freezes the peer
/// out of routing, so it receives no new request to re-arm from and could
/// otherwise never earn a second strike.
const STUCK_PEER_EVICTION_SCORE: i32 = 20;

/// Never evict a peer for reputation while at or below this many connections, so
/// a small pool is never churned down toward zero usable peers.
const MIN_CONNECTED_FLOOR: usize = 2;

/// Minimum spacing between reputation-driven evictions, so a fresh replacement
/// has time to connect and prove itself before another peer is dropped.
const EVICTION_COOLDOWN: Duration = Duration::from_secs(30);

fn required_services_from_config(config: &ClientConfig, exclusive_mode: bool) -> ServiceFlags {
    if exclusive_mode {
        return ServiceFlags::NONE;
    }
    let mut flags = ServiceFlags::NONE;
    if config.enable_filters {
        flags |= ServiceFlags::COMPACT_FILTERS;
    }
    flags
}

impl PeerNetworkManager {
    /// Create a new peer network manager
    pub async fn new(config: &ClientConfig) -> Result<Self, Error> {
        let discovery = DnsDiscovery::new();
        let data_dir = config.storage_path.clone();

        let peer_store = PersistentPeerStorage::open(data_dir.clone()).await?;

        let reputation_manager = Arc::new(PeerReputationManager::new());

        if let Err(e) = reputation_manager.load_from_storage(&peer_store).await {
            tracing::warn!("Failed to load peer reputation data: {}", e);
        }

        // Determine exclusive mode: either explicitly requested or peers were provided
        let exclusive_mode = config.restrict_to_configured_peers || !config.peers.is_empty();
        let required_services = required_services_from_config(config, exclusive_mode);

        // Create request queue for outgoing messages
        let (request_tx, request_rx) = unbounded_channel();

        let max_peers = config.max_peers.max(1) as usize;

        Ok(Self {
            pool: Arc::new(PeerPool::new(max_peers)),
            max_peers,
            discovery: Arc::new(discovery),
            addrv2_handler: Arc::new(AddrV2Handler::new()),
            peer_store: Arc::new(peer_store),
            reputation_manager,
            network: config.network,
            shutdown_token: CancellationToken::new(),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            initial_peers: config.peers.clone(),
            data_dir,
            user_agent: config.user_agent.clone(),
            exclusive_mode,
            required_services,
            capability_rejected: Arc::new(RwLock::new(HashMap::new())),
            connected_peer_count: Arc::new(AtomicUsize::new(0)),
            headers2_disabled: Arc::new(Mutex::new(HashSet::new())),
            headers2_decompression_semaphore: Arc::new(Semaphore::new(
                headers2_decompression_parallelism(),
            )),
            message_dispatcher: Arc::new(Mutex::new(MessageDispatcher::default())),
            request_tx,
            request_rx: Arc::new(Mutex::new(Some(request_rx))),
            round_robin_counter: Arc::new(AtomicUsize::new(0)),
            network_event_sender: broadcast::Sender::new(DEFAULT_NETWORK_EVENT_CAPACITY),
            outstanding_requests: Arc::new(Mutex::new(HashMap::new())),
            latency: Arc::new(Mutex::new(PeerLatency::default())),
            last_maintenance_at: Arc::new(Mutex::new(Instant::now())),
            last_eviction_at: Arc::new(Mutex::new(None)),
        })
    }

    /// Creates and returns a receiver that yields only messages of the matching the provided message types.
    pub async fn message_receiver(
        &mut self,
        message_types: &[MessageType],
    ) -> UnboundedReceiver<Message> {
        self.message_dispatcher.lock().await.message_receiver(message_types)
    }

    /// Get a RequestSender for queueing outgoing network requests.
    pub fn request_sender(&self) -> RequestSender {
        RequestSender::new(self.request_tx.clone())
    }

    /// Get the network event bus for sharing with other components.
    pub fn network_event_sender(&self) -> &broadcast::Sender<NetworkEvent> {
        &self.network_event_sender
    }

    /// Start the network manager
    pub async fn start(&self) -> Result<(), Error> {
        tracing::info!("Starting peer network manager for {:?}", self.network);

        let mut peer_addresses: Vec<AddrV2Message> = self
            .initial_peers
            .iter()
            .map(|addr| AddrV2Message::new(*addr, ServiceFlags::NETWORK))
            .collect();

        if self.exclusive_mode {
            tracing::info!(
                "Exclusive peer mode: connecting ONLY to {} specified peer(s)",
                self.initial_peers.len()
            );
        } else {
            // Load saved peers from disk
            let saved_peers = self.peer_store.load_peers().await.unwrap_or_else(|e| {
                tracing::warn!("Failed to load peers: {}", e);
                Vec::new()
            });
            peer_addresses.extend(saved_peers);

            // If we still have no peers, immediately discover via DNS
            if peer_addresses.is_empty() {
                tracing::info!(
                    "No peers configured, performing immediate DNS discovery for {:?}",
                    self.network
                );
                let dns_peers = self.discovery.discover_peers(self.network).await;
                let dns_peers_found = dns_peers.len();
                peer_addresses.extend(
                    dns_peers
                        .into_iter()
                        .take(self.max_peers)
                        .map(|addr| AddrV2Message::new(addr, ServiceFlags::NETWORK)),
                );
                tracing::info!(
                    "DNS discovery found {} peers, using {} for startup",
                    dns_peers_found,
                    peer_addresses.len()
                );
            } else {
                tracing::info!(
                    "Starting with {} peers from disk (DNS discovery will be used later if needed)",
                    peer_addresses.len()
                );
            }
        }

        self.addrv2_handler.handle_addrv2(peer_addresses.clone()).await;

        // Start maintenance loop
        self.start_maintenance_loop().await;

        // Start request processing task for managers to queue outgoing messages
        self.start_request_processor().await;

        Ok(())
    }

    /// Connect to a specific peer
    async fn connect_to_peer(&self, addr: SocketAddr) {
        // Check reputation first
        if !self.reputation_manager.should_connect_to_peer(&addr).await {
            tracing::warn!("Not connecting to {} due to bad reputation", addr);
            return;
        }

        // Check if already connected or connecting
        if self.pool.is_connected(&addr).await || self.pool.is_connecting(&addr).await {
            return;
        }

        // Mark as connecting
        if !self.pool.mark_connecting(addr).await {
            return; // Already being connected to
        }

        // Record connection attempt
        self.reputation_manager.record_connection_attempt(addr).await;

        let pool = self.pool.clone();
        let network = self.network;
        let addrv2_handler = self.addrv2_handler.clone();
        let shutdown_token = self.shutdown_token.clone();
        let reputation_manager = self.reputation_manager.clone();
        let outstanding_requests = self.outstanding_requests.clone();
        let latency = self.latency.clone();
        let user_agent = self.user_agent.clone();
        let required_services = self.required_services;
        let capability_rejected = self.capability_rejected.clone();
        let connected_peer_count = self.connected_peer_count.clone();
        let headers2_disabled = self.headers2_disabled.clone();
        let headers2_decompression_semaphore = self.headers2_decompression_semaphore.clone();
        let message_dispatcher = self.message_dispatcher.clone();
        let network_event_sender = self.network_event_sender.clone();

        // Spawn connection task — use select to avoid blocking on the lock during shutdown
        let mut tasks = tokio::select! {
            guard = self.tasks.lock() => guard,
            _ = self.shutdown_token.cancelled() => {
                self.pool.remove_peer(&addr).await;
                return;
            }
        };
        tasks.spawn(async move {
            tracing::debug!("Attempting to connect to {}", addr);

            let connect_result = tokio::select! {
                result = Peer::connect(addr, CONNECTION_TIMEOUT.as_secs(), network) => result,
                _ = shutdown_token.cancelled() => {
                    tracing::debug!("Connection to {} cancelled by shutdown", addr);
                    pool.remove_peer(&addr).await;
                    return;
                }
            };

            match connect_result {
                Ok(mut peer) => {
                    // Perform handshake
                    let mut handshake_manager = HandshakeManager::new(network, user_agent);
                    match handshake_manager.perform_handshake(&mut peer).await {
                        Ok(_) => {
                            if PeerNetworkManager::should_reject_after_handshake(
                                &pool,
                                &peer,
                                required_services,
                            )
                            .await
                            {
                                tracing::info!(
                                    "Rejecting peer {} during handshake - missing required services ({}) while a capable peer is connected",
                                    addr,
                                    required_services
                                );
                                PeerNetworkManager::record_capability_rejection_in(
                                    &capability_rejected,
                                    addr,
                                )
                                .await;
                                pool.remove_peer(&addr).await;
                                return;
                            }
                            tracing::info!("Successfully connected to {}", addr);

                            // Request addresses from the peer for discovery
                            if let Err(e) = peer.send_message(NetworkMessage::GetAddr).await {
                                tracing::warn!("Failed to send GetAddr to {}: {}", addr, e);
                            }

                            // Record successful connection
                            reputation_manager.record_successful_connection(addr).await;

                            // Both ways this can fail, a full pool and an address
                            // already connected, are ordinary outcomes of dialling
                            // several candidates for the same slot: one wins and the
                            // rest arrive to find it taken. Topping up after an
                            // eviction does exactly that, so logging it as an error
                            // reports routine contention as a fault.
                            if let Err(e) = pool.add_peer(addr, peer).await {
                                tracing::debug!("Not adding peer {} to pool: {}", addr, e);
                                return;
                            }

                            // Increment connected peer counter on successful add
                            connected_peer_count.fetch_add(1, Ordering::Relaxed);

                            // Emit peer connected event
                            let count = connected_peer_count.load(Ordering::Relaxed);
                            let addresses = pool.get_connected_addresses().await;
                            let best_height = pool.get_best_height().await;
                            let _ = network_event_sender.send(NetworkEvent::PeerConnected {
                                address: addr,
                            });
                            let _ = network_event_sender.send(NetworkEvent::PeersUpdated {
                                connected_count: count,
                                addresses,
                                best_height,
                            });

                            // Add to known addresses
                            addrv2_handler.add_known_address(addr, ServiceFlags::NETWORK).await;

                            // // Start message reader for this peer
                            Self::start_peer_reader(
                                addr,
                                pool.clone(),
                                addrv2_handler,
                                shutdown_token,
                                reputation_manager.clone(),
                                outstanding_requests,
                                latency,
                                connected_peer_count.clone(),
                                headers2_disabled.clone(),
                                headers2_decompression_semaphore.clone(),
                                message_dispatcher,
                                network_event_sender.clone(),
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!("Handshake failed with {}: {}", addr, e);
                            // Only clears connecting set. Peer was never added, so no count/event needed.
                            pool.remove_peer(&addr).await;
                            // Update reputation for handshake failure
                            reputation_manager
                                .update_reputation(addr, ChangeReason::HandshakeFailed)
                                .await;
                            // For handshake failures, try again later
                            tokio::time::sleep(RECONNECT_DELAY).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to connect to {}: {}", addr, e);
                    // Only clears connecting set. Peer was never added, so no count/event needed.
                    pool.remove_peer(&addr).await;
                    // Minor reputation penalty for connection failure
                    reputation_manager
                        .update_reputation(addr, ChangeReason::ConnectionFailed)
                        .await;
                }
            }
        });
    }

    /// Decrement the connected count and emit PeerDisconnected / PeersUpdated events.
    async fn notify_peer_removed(
        pool: &PeerPool,
        addr: &SocketAddr,
        connected_peer_count: &AtomicUsize,
        network_event_sender: &broadcast::Sender<NetworkEvent>,
    ) {
        let sub_result =
            connected_peer_count
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_sub(1));
        if sub_result.is_err() {
            tracing::warn!("Peer count already zero when removing {}", addr);
        }
        let count = connected_peer_count.load(Ordering::Relaxed);
        let addresses = pool.get_connected_addresses().await;
        let best_height = pool.get_best_height().await;
        let _ = network_event_sender.send(NetworkEvent::PeerDisconnected {
            address: *addr,
        });
        let _ = network_event_sender.send(NetworkEvent::PeersUpdated {
            connected_count: count,
            addresses,
            best_height,
        });
    }

    /// Remove a peer from the pool, decrement the connected count, and emit
    /// PeerDisconnected / PeersUpdated events.
    async fn remove_peer_and_notify(
        pool: &PeerPool,
        addr: &SocketAddr,
        connected_peer_count: &AtomicUsize,
        network_event_sender: &broadcast::Sender<NetworkEvent>,
    ) {
        if pool.remove_peer(addr).await.is_some() {
            Self::notify_peer_removed(pool, addr, connected_peer_count, network_event_sender).await;
        }
    }

    /// Start reading messages from a peer
    #[allow(clippy::too_many_arguments)] // TODO: refactor to reduce arguments
    async fn start_peer_reader(
        addr: SocketAddr,
        pool: Arc<PeerPool>,
        addrv2_handler: Arc<AddrV2Handler>,
        shutdown_token: CancellationToken,
        reputation_manager: Arc<PeerReputationManager>,
        outstanding_requests: Arc<Mutex<HashMap<(SocketAddr, RequestKind), Instant>>>,
        latency: Arc<Mutex<PeerLatency>>,
        connected_peer_count: Arc<AtomicUsize>,
        headers2_disabled: Arc<Mutex<HashSet<SocketAddr>>>,
        headers2_decompression_semaphore: Arc<Semaphore>,
        message_dispatcher: Arc<Mutex<MessageDispatcher>>,
        network_event_sender: broadcast::Sender<NetworkEvent>,
    ) {
        tokio::spawn(async move {
            tracing::debug!("Starting peer reader loop for {}", addr);
            let mut loop_iteration = 0;
            let mut headers2_sequence = 0_u64;
            let ordered_headers2_results = Arc::new(Mutex::new(OrderedHeaders2Results::default()));
            loop {
                loop_iteration += 1;

                // Check shutdown signal first with detailed logging
                if shutdown_token.is_cancelled() {
                    tracing::info!("Breaking peer reader loop for {} - shutdown signal received (iteration {})", addr, loop_iteration);
                    break;
                }

                // Get peer
                let peer = match pool.get_peer(&addr).await {
                    Some(peer) => peer,
                    None => {
                        tracing::warn!("Breaking peer reader loop for {} - peer no longer in pool (iteration {})", addr, loop_iteration);
                        break;
                    }
                };

                // Read message with minimal lock time
                let msg_result = {
                    // Try to get a read lock first to check if peer is available
                    let peer_guard = peer.read().await;
                    if !peer_guard.is_connected() {
                        tracing::warn!("Breaking peer reader loop for {} - peer no longer connected (iteration {})", addr, loop_iteration);
                        drop(peer_guard);
                        break;
                    }
                    drop(peer_guard);

                    // Now get write lock only for the duration of the read
                    let mut peer_guard = peer.write().await;
                    tokio::select! {
                        message = peer_guard.receive_message() => {
                            message
                        },
                        _ = tokio::time::sleep(MESSAGE_POLL_INTERVAL) => {
                            Ok(None)
                        },
                        _ = shutdown_token.cancelled() => {
                            tracing::info!("Breaking peer reader loop for {} - shutdown signal received while reading (iteration {})", addr, loop_iteration);
                            break;
                        }
                    }
                };

                match msg_result {
                    Ok(Some(msg)) => {
                        // Log all received messages at debug level to help troubleshoot
                        tracing::trace!("Received {:?} from {}", msg.cmd(), addr);

                        // A substantive response clearing a tracked request is the one
                        // point where a peer's speed is observable, so time it here.
                        // The elapsed time runs from the oldest request still
                        // unanswered, so it counts queueing behind that peer's own
                        // backlog as well as its service time. That is deliberate:
                        // both delay us equally, and it lets a peer we are
                        // over-feeding report itself as congested.
                        if let Some(kind) = timed_response_kind(msg.inner()) {
                            let sent = outstanding_requests.lock().await.remove(&(addr, kind));
                            if let Some(sent) = sent {
                                if kind.response_time_is_fair() {
                                    latency.lock().await.record(addr, sent.elapsed());
                                }
                            }
                        }

                        let inner = msg.into_inner();
                        if let NetworkMessage::Headers2(headers2) = inner {
                            tracing::info!(
                                "Received Headers2 from {} with {} compressed headers - decompressing",
                                addr,
                                headers2.headers.len()
                            );

                            let permit = tokio::select! {
                                permit = headers2_decompression_semaphore.clone().acquire_owned() => {
                                    match permit {
                                        Ok(permit) => permit,
                                        Err(_) => break,
                                    }
                                }
                                _ = shutdown_token.cancelled() => break,
                            };
                            let message_dispatcher = message_dispatcher.clone();
                            let headers2_disabled = headers2_disabled.clone();
                            let reputation_manager = reputation_manager.clone();
                            let shutdown_token = shutdown_token.clone();
                            let ordered_headers2_results = ordered_headers2_results.clone();
                            let sequence = headers2_sequence;
                            headers2_sequence += 1;
                            tokio::spawn(async move {
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut state = CompressionState::default();
                                    state.process_headers_with_hashes(&headers2.headers)
                                })
                                .await;
                                if shutdown_token.is_cancelled() {
                                    return;
                                }

                                let outcome = match result {
                                    Ok(Ok(headers_with_hashes)) => {
                                        Headers2DecompressionOutcome::Headers(headers_with_hashes)
                                    }
                                    Ok(Err(e)) => {
                                        Headers2DecompressionOutcome::Invalid(e.to_string())
                                    }
                                    Err(e) => {
                                        Headers2DecompressionOutcome::TaskFailed(e.to_string())
                                    }
                                };
                                let ready = ordered_headers2_results
                                    .lock()
                                    .await
                                    // Retain the permit while this result waits for earlier messages,
                                    // keeping the reorder buffer within the worker limit.
                                    .complete(sequence, (outcome, permit));

                                for (outcome, _permit) in ready {
                                    match outcome {
                                        Headers2DecompressionOutcome::Headers(
                                            headers_with_hashes,
                                        ) => {
                                            tracing::info!(
                                                "Decompressed {} headers from {} - forwarding as regular Headers",
                                                headers_with_hashes.len(),
                                                addr
                                            );
                                            let message =
                                                Message::new_headers(addr, headers_with_hashes);
                                            message_dispatcher.lock().await.dispatch(&message);
                                        }
                                        Headers2DecompressionOutcome::Invalid(e) => {
                                            tracing::error!(
                                                "Headers2 decompression failed from {}: {} - disabling headers2",
                                                addr,
                                                e
                                            );
                                            headers2_disabled.lock().await.insert(addr);
                                            reputation_manager
                                                .update_reputation(
                                                    addr,
                                                    ChangeReason::Headers2DecompressionFailed,
                                                )
                                                .await;
                                        }
                                        Headers2DecompressionOutcome::TaskFailed(e) => {
                                            tracing::error!(
                                                "Headers2 decompression task failed for {}: {}",
                                                addr,
                                                e
                                            );
                                        }
                                    }
                                }
                            });
                            continue;
                        }
                        let msg = Message::new(addr, inner);

                        // Handle some messages directly
                        match &msg.inner() {
                            NetworkMessage::SendAddrV2 => {
                                addrv2_handler.handle_sendaddrv2(addr).await;
                                continue; // Don't forward to client
                            }
                            NetworkMessage::SendHeaders2 => {
                                // Peer is indicating they will send us compressed headers
                                tracing::info!(
                                    "Peer {} sent SendHeaders2 - they will send compressed headers",
                                    addr
                                );
                                let mut peer_guard = peer.write().await;
                                peer_guard.set_peer_sent_sendheaders2(true);
                                drop(peer_guard);
                                continue; // Don't forward to client
                            }
                            NetworkMessage::AddrV2(addresses) => {
                                addrv2_handler.handle_addrv2(addresses.clone()).await;
                                continue; // Don't forward to client
                            }
                            NetworkMessage::GetAddr => {
                                tracing::trace!(
                                    "Received GetAddr from {}, sending known addresses",
                                    addr
                                );
                                // Send our known addresses
                                let response = addrv2_handler.build_addr_response().await;
                                let mut peer_guard = peer.write().await;
                                if let Err(e) = peer_guard.send_message(response).await {
                                    tracing::error!(
                                        "Failed to send addr response to {}: {}",
                                        addr,
                                        e
                                    );
                                }
                                continue; // Don't forward GetAddr to client
                            }
                            NetworkMessage::Ping(nonce) => {
                                // Handle ping directly
                                let mut peer_guard = peer.write().await;
                                if let Err(e) = peer_guard.handle_ping(*nonce).await {
                                    tracing::error!("Failed to handle ping from {}: {}", addr, e);
                                    // If we can't send pong, connection is likely broken
                                    if matches!(e, NetworkError::ConnectionFailed(_)) {
                                        tracing::warn!("Breaking peer reader loop for {} - failed to send pong response (iteration {})", addr, loop_iteration);
                                        break;
                                    }
                                }
                                continue; // Don't forward ping to client
                            }
                            NetworkMessage::Pong(nonce) => {
                                // Handle pong directly
                                let mut peer_guard = peer.write().await;
                                if let Err(e) = peer_guard.handle_pong(*nonce) {
                                    tracing::error!("Failed to handle pong from {}: {}", addr, e);
                                }
                                continue; // Don't forward pong to client
                            }
                            NetworkMessage::Version(_) | NetworkMessage::Verack => {
                                // These are handled during handshake, ignore here
                                tracing::trace!(
                                    "Ignoring handshake message {:?} from {}",
                                    msg.cmd(),
                                    addr
                                );
                                continue;
                            }
                            NetworkMessage::Addr(addresses) => {
                                // Convert legacy addr messages to AddrV2 format
                                let converted: Vec<AddrV2Message> = addresses
                                    .iter()
                                    .filter_map(|(time, a)| {
                                        let socket = a.socket_addr().ok()?;
                                        let addr_v2 = match socket.ip() {
                                            std::net::IpAddr::V4(v4) => AddrV2::Ipv4(v4),
                                            std::net::IpAddr::V6(v6) => AddrV2::Ipv6(v6),
                                        };
                                        Some(AddrV2Message {
                                            time: *time,
                                            services: a.services,
                                            addr: addr_v2,
                                            port: socket.port(),
                                        })
                                    })
                                    .collect();
                                if !converted.is_empty() {
                                    tracing::debug!(
                                        "Converted {} legacy addr entries from {}",
                                        converted.len(),
                                        addr
                                    );
                                    addrv2_handler.handle_addrv2(converted).await;
                                }
                                continue;
                            }
                            NetworkMessage::Headers(headers) => {
                                // Log headers messages specifically
                                tracing::info!(
                                    "📨 Received Headers message from {} with {} headers! (regular uncompressed)",
                                    addr,
                                    headers.len()
                                );
                                // Check if peer supports headers2
                                let peer_guard = peer.read().await;
                                if peer_guard.supports_headers2() {
                                    tracing::warn!("⚠️  Peer {} supports headers2 but sent regular headers - possible protocol issue", addr);
                                }
                                drop(peer_guard);
                                // Forward to client
                            }
                            NetworkMessage::Headers2(_) => unreachable!(),
                            NetworkMessage::GetHeaders(_) => {
                                // SPV clients don't serve headers to peers
                                tracing::debug!(
                                    "Received GetHeaders from {} - ignoring (SPV client)",
                                    addr
                                );
                                continue; // Don't forward to client
                            }
                            NetworkMessage::GetHeaders2(_) => {
                                // SPV clients don't serve compressed headers to peers
                                tracing::debug!(
                                    "Received GetHeaders2 from {} - ignoring (SPV client)",
                                    addr
                                );
                                continue; // Don't forward to client
                            }
                            NetworkMessage::Unknown {
                                command,
                                payload,
                            } => {
                                // Log unknown messages with more detail
                                tracing::warn!("Received unknown message from {}: command='{}', payload_len={}",
                                         addr, command, payload.len());
                                // Still forward to client
                            }
                            _ => {
                                // Forward other messages to client
                                tracing::trace!(
                                    "Forwarding {:?} from {} to client",
                                    msg.cmd(),
                                    addr
                                );
                            }
                        }

                        message_dispatcher.lock().await.dispatch(&msg);
                    }
                    Ok(None) => {
                        // No message available, continue immediately
                        // The socket read timeout already provides necessary delay
                        continue;
                    }
                    Err(e) => {
                        match e {
                            NetworkError::PeerDisconnected => {
                                tracing::info!("Peer {} disconnected", addr);
                                break;
                            }
                            NetworkError::Timeout => {
                                // Idle socket reads time out constantly on healthy
                                // connections, so this is not a quality signal.
                                tracing::debug!("Timeout reading from {}, continuing...", addr);
                                continue;
                            }
                            _ => {
                                tracing::error!("Fatal error reading from {}: {}", addr, e);

                                // Check if this is a serialization error that might have context
                                if let NetworkError::Serialization(ref decode_error) = e {
                                    let error_msg = decode_error.to_string();
                                    if error_msg.contains("unknown special transaction type") {
                                        tracing::warn!("Peer {} sent block with unsupported transaction type: {}", addr, decode_error);
                                        tracing::error!(
                                            "BLOCK DECODE FAILURE - Error details: {}",
                                            error_msg
                                        );
                                        // Reputation penalty for invalid data
                                        reputation_manager
                                            .update_reputation(
                                                addr,
                                                ChangeReason::InvalidTransactionInBlock,
                                            )
                                            .await;
                                    } else if error_msg
                                        .contains("Failed to decode transactions for block")
                                    {
                                        // The error now includes the block hash
                                        tracing::error!("Peer {} sent block that failed transaction decoding: {}", addr, decode_error);
                                        // Try to extract the block hash from the error message
                                        if let Some(hash_start) = error_msg.find("block ") {
                                            if let Some(hash_end) =
                                                error_msg[hash_start + 6..].find(':')
                                            {
                                                let block_hash = &error_msg
                                                    [hash_start + 6..hash_start + 6 + hash_end];
                                                tracing::error!(
                                                    "FAILING BLOCK HASH: {}",
                                                    block_hash
                                                );
                                            }
                                        }
                                    } else if error_msg.contains("IO error") {
                                        // This might be our wrapped error - log it prominently
                                        tracing::error!("BLOCK DECODE FAILURE - IO error (possibly unknown transaction type) from peer {}", addr);
                                        tracing::error!(
                                            "Serialization error from {}: {}",
                                            addr,
                                            decode_error
                                        );
                                    } else {
                                        tracing::error!(
                                            "Serialization error from {}: {}",
                                            addr,
                                            decode_error
                                        );
                                    }
                                }

                                break;
                            }
                        }
                    }
                }
            }

            // Remove from pool and notify consumers
            tracing::warn!("Disconnecting from {} (peer reader loop ended)", addr);
            Self::remove_peer_and_notify(
                &pool,
                &addr,
                &connected_peer_count,
                &network_event_sender,
            )
            .await;

            headers2_disabled.lock().await.remove(&addr);
        });
    }

    /// Start the request processing task for outgoing messages from managers via RequestSender.
    async fn start_request_processor(&self) {
        // Take the receiver (only one task can own it)
        let request_rx = {
            let mut rx_guard = self.request_rx.lock().await;
            rx_guard.take()
        };

        let Some(mut request_rx) = request_rx else {
            tracing::warn!("Request processor already started or receiver unavailable");
            return;
        };

        let this = self.clone();
        let shutdown_token = self.shutdown_token.clone();

        let mut tasks = self.tasks.lock().await;
        tasks.spawn(async move {
            tracing::info!("Starting request processor task");
            loop {
                tokio::select! {
                    request = request_rx.recv() => {
                        match request {
                            Some(NetworkRequest::SendMessage(msg)) => {
                                tracing::trace!("Request processor: sending {}", msg.cmd());
                                // Spawn each send concurrently to allow parallel requests across peers.
                                let this = this.clone();
                                tokio::spawn(async move {
                                    let result = match &msg {
                                        // Distribute across peers for parallel sync
                                        NetworkMessage::GetCFHeaders(_)
                                        | NetworkMessage::GetCFilters(_)
                                        | NetworkMessage::GetData(_)
                                        | NetworkMessage::GetMnListD(_)
                                        | NetworkMessage::GetQRInfo(_)
                                        | NetworkMessage::GetHeaders(_)
                                        | NetworkMessage::GetHeaders2(_) => {
                                            this.send_distributed(msg).await
                                        }
                                        _ => {
                                            this.send_to_single_peer(msg).await
                                        }
                                    };
                                    if let Err(e) = result {
                                        tracing::error!("Request processor: failed to send message: {}", e);
                                    }
                                });
                            }
                            Some(NetworkRequest::SendMessageToPeer(msg, peer_address)) => {
                                tracing::trace!("Request processor: sending {} to peer {}", msg.cmd(), peer_address);
                                let this = this.clone();
                                tokio::spawn(async move {
                                    let fallback_msg = msg.clone();
                                    let result = match this.pool.get_peer(&peer_address).await {
                                        Some(peer) => match this.send_message_to_peer(&peer_address, &peer, msg).await {
                                            Ok(()) => Ok(()),
                                            Err(err) => {
                                                tracing::warn!(
                                                    "Target peer {} send failed ({}), falling back to distributed send",
                                                    peer_address,
                                                    err
                                                );
                                                this.send_distributed(fallback_msg).await
                                            }
                                        },
                                        None => {
                                            tracing::warn!(
                                                "Target peer {} disconnected, falling back to distributed send",
                                                peer_address
                                            );
                                            this.send_distributed(fallback_msg).await
                                        }
                                    };
                                    if let Err(e) = result {
                                        tracing::error!("Request processor: failed to send message to peer {}: {}", peer_address, e);
                                    }
                                });
                            }
                            Some(NetworkRequest::BroadcastMessage(msg)) => {
                                tracing::debug!("Request processor: broadcasting {}", msg.cmd());
                                let this = this.clone();
                                tokio::spawn(async move {
                                    let results = this.broadcast(msg).await;
                                    let failures = results.iter().filter(|r| r.is_err()).count();
                                    if failures > 0 {
                                        tracing::warn!(
                                            "Request processor: broadcast had {} failures out of {} peers",
                                            failures,
                                            results.len()
                                        );
                                    }
                                });
                            }
                            None => {
                                tracing::info!("Request processor: channel closed");
                                break;
                            }
                        }
                    }
                    _ = shutdown_token.cancelled() => {
                        tracing::info!("Request processor: shutting down");
                        break;
                    }
                }
            }
        });
    }

    pub(crate) async fn evict_mismatched_peers(&self) {
        if self.required_services == ServiceFlags::NONE {
            return;
        }
        let all_peers = self.pool.get_all_peers().await;
        let connected_count = all_peers.len();
        if connected_count <= 1 {
            return;
        }
        let mut matched_count = 0;
        let mut mismatched = Vec::new();
        for (addr, peer) in &all_peers {
            let peer_guard = peer.read().await;
            if peer_guard.services_known() && peer_guard.has_service(self.required_services) {
                matched_count += 1;
            } else if peer_guard.services_known() {
                mismatched.push(*addr);
            }
        }
        if mismatched.is_empty() {
            return;
        }
        let drop_count = if matched_count > 0 {
            mismatched.len()
        } else {
            mismatched.len().min(connected_count - 1)
        };
        if drop_count == 0 {
            return;
        }
        tracing::info!(
            "Capability churn: dropping {} of {} peers lacking required services",
            drop_count,
            connected_count,
        );
        for addr in mismatched.into_iter().take(drop_count) {
            self.record_capability_rejection(addr).await;
            let _ = self
                .disconnect_peer(
                    &addr,
                    &format!("missing required services ({})", self.required_services),
                )
                .await;
        }
    }

    /// Penalize connected peers that have left a sync request unanswered past the
    /// stall timeout, so they fall out of routing and become eviction candidates.
    /// A long gap since the previous sweep is treated as a process suspend and the
    /// timers are refreshed instead, so a backgrounded client does not blame every
    /// peer at once on resume.
    /// Returns true if this tick was treated as a suspend/resume grace tick, so
    /// the caller can skip eviction rather than acting on stale pre-suspend state.
    async fn sweep_stalled_peers(&self) -> bool {
        let now = Instant::now();
        let gap = {
            let mut last = self.last_maintenance_at.lock().await;
            let gap = now.saturating_duration_since(*last);
            *last = now;
            gap
        };

        // Snapshot connected peers before taking the outstanding lock so this path
        // never holds the outstanding lock while touching the pool lock.
        let connected = self.pool.get_connected_addresses().await;
        self.latency.lock().await.retain_connected(&connected);

        let stalled = {
            let mut outstanding = self.outstanding_requests.lock().await;
            outstanding.retain(|(addr, _), _| connected.contains(addr));

            if gap > SUSPEND_GAP {
                for sent in outstanding.values_mut() {
                    *sent = now;
                }
                return true;
            }

            let aged: Vec<((SocketAddr, RequestKind), Duration)> = outstanding
                .iter()
                .filter(|((_, kind), _)| kind.response_time_is_fair())
                .filter_map(|(key, sent)| {
                    let waited = now.saturating_duration_since(*sent);
                    (waited > REQUEST_STALL_TIMEOUT).then_some((*key, waited))
                })
                .collect();
            // Re-arm rather than drop: one stall already freezes the peer out of
            // routing, so it gets no new request to re-arm the timer, and a still
            // unanswered request must keep counting for it to ever be evicted.
            for (key, _) in &aged {
                outstanding.insert(*key, now);
            }

            // Collapse to one entry per peer, keeping its worst wait. A peer
            // stalling on several kinds at once is one failing peer, not several,
            // and must not take several strikes from a single sweep.
            let mut stalled: HashMap<SocketAddr, Duration> = HashMap::new();
            for ((addr, _), waited) in aged {
                let worst = stalled.entry(addr).or_insert(waited);
                *worst = (*worst).max(waited);
            }
            stalled
        };

        // Recording how long the request has gone unanswered keeps the stalling
        // peer's measured mean fresh as well as bad, so it stays out of rotation
        // instead of ageing back into it while it is still failing to answer.
        {
            let mut latency = self.latency.lock().await;
            for (addr, waited) in &stalled {
                latency.record(*addr, *waited);
            }
        }

        // A peer already at the eviction threshold is condemned, so further strikes
        // add nothing and would only march it toward an outright ban.
        let scores = self.reputation_manager.scores_for(stalled.keys().copied()).await;
        for (addr, _) in stalled {
            if scores.get(&addr).copied().unwrap_or(0) >= STUCK_PEER_EVICTION_SCORE {
                continue;
            }
            tracing::debug!("Peer {} stalled on a sync request, penalizing", addr);
            self.reputation_manager.update_reputation(addr, ChangeReason::RequestTimeout).await;
        }
        false
    }

    /// Evict the single worst-scoring connected peer when it is clearly bad and a
    /// healthy replacement is available, so the client stops staying stuck on a
    /// peer that stalls. Heavily guarded so a small pool is never churned toward
    /// zero: it keeps a connection floor, only acts on a full pool with a
    /// replacement ready, skips when every peer is equally bad (a network or
    /// device problem, not a peer problem), never drops the sole peer providing a
    /// required service, and evicts at most one peer per cooldown.
    async fn evict_worst_stuck_peer(&self) {
        if let Some(t) = *self.last_eviction_at.lock().await {
            if Instant::now().saturating_duration_since(t) < EVICTION_COOLDOWN {
                return;
            }
        }

        let connected = self.pool.get_connected_addresses().await;
        let floor = self.max_peers.min(MIN_CONNECTED_FLOOR);
        if connected.len() < self.max_peers || connected.len() <= floor {
            return;
        }

        // A replacement must be ready, or eviction is pure loss.
        let mut has_replacement = false;
        for known in self.addrv2_handler.get_known_addresses().await {
            let Ok(sa) = known.socket_addr() else {
                continue;
            };
            if !connected.contains(&sa) && !self.is_capability_rejected(&sa).await {
                has_replacement = true;
                break;
            }
        }
        if !has_replacement {
            return;
        }

        let scores = self.reputation_manager.scores_for(connected.iter().copied()).await;
        let Some(min_score) = scores.values().copied().min() else {
            return;
        };
        let Some((worst_addr, worst_score)) = scores.into_iter().max_by_key(|(_, s)| *s) else {
            return;
        };

        // The worst must be clearly bad, and at least one peer clearly better,
        // otherwise the whole pool is bad and the problem is not this peer.
        if worst_score < STUCK_PEER_EVICTION_SCORE || min_score >= STUCK_PEER_EVICTION_SCORE {
            return;
        }

        if self.is_sole_service_provider(&worst_addr).await {
            return;
        }

        tracing::info!(
            "Evicting stalled peer {} (score {}) so a fresh peer can replace it",
            worst_addr,
            worst_score
        );
        let _ = self.disconnect_peer(&worst_addr, "poor reputation (stalled requests)").await;
        *self.last_eviction_at.lock().await = Some(Instant::now());
    }

    /// Whether `addr` is the only connected peer advertising the required service,
    /// so evicting it would strand a sync phase with no capable peer.
    async fn is_sole_service_provider(&self, addr: &SocketAddr) -> bool {
        if self.required_services == ServiceFlags::NONE {
            return false;
        }
        let providers = self.pool.peers_with_service(self.required_services).await;
        providers.len() == 1 && providers[0].0 == *addr
    }

    async fn maintenance_tick(&self) {
        // Remove peers that the reader loop failed to clean up.
        // This should not trigger under normal operation.
        let unhealthy = self.pool.remove_unhealthy().await;
        for addr in &unhealthy {
            tracing::warn!("Maintenance removed stale peer {} - reader loop missed cleanup", addr);
            Self::notify_peer_removed(
                &self.pool,
                addr,
                &self.connected_peer_count,
                &self.network_event_sender,
            )
            .await;
        }

        let count = self.pool.peer_count().await;
        tracing::debug!("Connected peers: {}", count);
        // Keep the cached counter in sync with actual pool count
        self.connected_peer_count.store(count, Ordering::Relaxed);
        if self.exclusive_mode {
            // In exclusive mode, only reconnect to originally specified peers
            for addr in self.initial_peers.iter() {
                if !self.pool.is_connected(addr).await && !self.pool.is_connecting(addr).await {
                    tracing::info!("Reconnecting to exclusive peer: {}", addr);
                    self.connect_to_peer(*addr).await;
                }
            }
        } else {
            // Penalize peers stalling on sync requests so they drop out of routing
            // and become eviction candidates before the top-up below.
            let grace_tick = self.sweep_stalled_peers().await;
            // Evict peers that lack required services before top-up so replacements
            // can be pulled in during the same tick.
            self.evict_mismatched_peers().await;
            // Drop one clearly-bad stalling peer, but never on a resume grace tick
            // where scores reflect stale pre-suspend state.
            if !grace_tick {
                self.evict_worst_stuck_peer().await;
            }
            // Re-read count after potential churn so top-up sees the current pool size.
            let count = self.pool.peer_count().await;
            if count < self.max_peers {
                // Try known addresses first, sorted by reputation
                let known = self.addrv2_handler.get_known_addresses().await;
                let needed = self.max_peers.saturating_sub(count);
                // Select best peers based on reputation
                let best_peers = self.reputation_manager.select_best_peers(known, needed * 2).await;
                let mut attempted = 0;

                for addr in best_peers {
                    if self.is_capability_rejected(&addr).await {
                        continue;
                    }
                    if !self.pool.is_connected(&addr).await && !self.pool.is_connecting(&addr).await
                    {
                        self.connect_to_peer(addr).await;
                        attempted += 1;
                        if attempted >= needed {
                            break;
                        }
                    }
                }
            }
        }

        if self.shutdown_token.is_cancelled() {
            return;
        }

        // Send ping to all peers if needed and disconnect unresponsive ones
        for (addr, peer) in self.pool.get_all_peers().await {
            let mut peer_guard = peer.write().await;
            if peer_guard.should_ping() {
                if let Err(e) = peer_guard.send_ping().await {
                    tracing::error!("Failed to ping {}: {}", addr, e);
                    // Update reputation for ping failure
                    self.reputation_manager.update_reputation(addr, ChangeReason::PingFailed).await;
                }
            }
            let has_expired = peer_guard.remove_expired_pings();
            drop(peer_guard);
            if has_expired {
                let _ = self.disconnect_peer(&addr, "ping timeout").await;
            }
        }

        // Only save known peers if not in exclusive mode
        if !self.exclusive_mode {
            let addresses = self.addrv2_handler.get_known_addresses().await;
            if !addresses.is_empty() {
                if let Err(e) = self.peer_store.save_peers(&addresses).await {
                    tracing::warn!("Failed to save peers: {}", e);
                }
            }

            // Save reputation data periodically
            if let Err(e) = self.reputation_manager.save_to_storage(&*self.peer_store).await {
                tracing::warn!("Failed to save reputation data: {}", e);
            }
        }
    }

    async fn dns_fallback_tick(&self) {
        let count = self.pool.peer_count().await;
        if count >= self.max_peers {
            return;
        }
        let dns_peers = tokio::select! {
            peers = self.discovery.discover_peers(self.network) => peers,
            _ = self.shutdown_token.cancelled() => {
                tracing::info!("Maintenance loop shutting down during DNS discovery");
                return
            }
        };
        let needed = self.max_peers.saturating_sub(count);
        tracing::debug!("DNS fallback tick found {} addresses. Needed {}", dns_peers.len(), needed);
        let mut dns_attempted = 0;
        for addr in dns_peers.iter() {
            if self.is_capability_rejected(addr).await {
                continue;
            }
            if !self.pool.is_connected(addr).await && !self.pool.is_connecting(addr).await {
                self.connect_to_peer(*addr).await;
                dns_attempted += 1;
                if dns_attempted >= needed {
                    break;
                }
            }
        }
    }

    /// Start peer connection maintenance loop
    async fn start_maintenance_loop(&self) {
        let this = self.clone();
        let mut tasks = self.tasks.lock().await;
        tasks.spawn(async move {
            // Periodic DNS discovery check (only active in non-exclusive mode)
            let mut dns_interval =
                time::interval_at(Instant::now() + DNS_DISCOVERY_DELAY, DNS_DISCOVERY_DELAY);
            // Periodic reconnection check (active in both modes)
            let mut maintenance_interval = time::interval(MAINTENANCE_INTERVAL);
            let mut network_events = this.network_event_sender.subscribe();
            while !this.shutdown_token.is_cancelled() {
                tokio::select! {
                    _ = maintenance_interval.tick() => {
                        tracing::trace!("Maintenance interval elapsed");
                        this.maintenance_tick().await;
                    }
                    _ = dns_interval.tick(), if !this.exclusive_mode => {
                        this.dns_fallback_tick().await;
                    }
                    event = network_events.recv() => {
                        match event {
                            Ok(event) => {
                                tracing::debug!("Network event in maintenance loop: {}", event);
                                dns_interval.reset();
                                this.maintenance_tick().await;
                            }
                            Err(error) => {
                                tracing::error!("Network event error: {}", error);
                                break;
                            }
                        }
                    }
                    _ = this.shutdown_token.cancelled() => {
                        tracing::info!("Maintenance loop shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Send a message to a single peer selected by message type requirements.
    async fn send_to_single_peer(&self, message: NetworkMessage) -> NetworkResult<()> {
        let peers = self.pool.get_all_peers().await;

        if peers.is_empty() {
            return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
        }

        let preferred_service = match &message {
            NetworkMessage::FilterLoad(_)
            | NetworkMessage::FilterClear
            | NetworkMessage::MemPool => Some((ServiceFlags::BLOOM, true)),
            NetworkMessage::GetCFHeaders(_) | NetworkMessage::GetCFilters(_) => {
                Some((ServiceFlags::COMPACT_FILTERS, true))
            }
            NetworkMessage::GetHeaders(_) | NetworkMessage::GetHeaders2(_) => {
                Some((ServiceFlags::NODE_HEADERS_COMPRESSED, false))
            }
            _ => None,
        };

        let (addr, peer) = if let Some((flags, required)) = preferred_service {
            match self.pool.peer_with_service(flags).await {
                Some((address, peer)) => {
                    tracing::debug!(
                        "Selected peer {} with {} for {}",
                        address,
                        flags,
                        message.cmd()
                    );
                    (address, peer)
                }
                None if required => {
                    tracing::warn!("No peers support {}, cannot send {}", flags, message.cmd());
                    return Err(NetworkError::ProtocolError(format!("No peers support {}", flags)));
                }
                None => self.next_peer(&peers).await,
            }
        } else {
            self.next_peer(&peers).await
        };

        self.send_message_to_peer(&addr, &peer, message).await
    }

    /// Send a message distributed across connected peers using round-robin selection.
    ///
    /// Peer selection and message handling based on message type:
    /// - Filters (GetCFHeaders/GetCFilters): requires peers that support compact filters
    /// - Headers (GetHeaders/GetHeaders2): prefers headers2 peers, upgrades GetHeaders if supported
    /// - Other (blocks, masternode data, etc.): uses all connected peers
    async fn send_distributed(&self, message: NetworkMessage) -> NetworkResult<()> {
        let peers = self.pool.get_all_peers().await;

        if peers.is_empty() {
            return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
        }

        // Select eligible peers based on message type
        let (selected_peers, require_capability) = match &message {
            NetworkMessage::GetCFHeaders(_) | NetworkMessage::GetCFilters(_) => {
                let filter_peers =
                    self.pool.peers_with_service(ServiceFlags::COMPACT_FILTERS).await;
                (filter_peers, true)
            }
            NetworkMessage::GetHeaders(_) | NetworkMessage::GetHeaders2(_) => {
                // Prefer headers2 peers (excluding disabled), fall back to all
                let disabled = self.headers2_disabled.lock().await;
                let mut headers2_peers =
                    self.pool.peers_with_service(ServiceFlags::NODE_HEADERS_COMPRESSED).await;
                headers2_peers.retain(|(addr, _)| !disabled.contains(addr));
                drop(disabled);
                if headers2_peers.is_empty() {
                    (peers.clone(), false)
                } else {
                    (headers2_peers, false)
                }
            }
            _ => {
                // All other messages use all connected peers
                (peers.clone(), false)
            }
        };

        if selected_peers.is_empty() {
            return if require_capability {
                Err(NetworkError::ProtocolError("No peers support required capability".to_string()))
            } else {
                Err(NetworkError::ConnectionFailed("No connected peers".to_string()))
            };
        }

        let selected_peers = match tracked_request_kind(&message) {
            Some(kind) => self.without_peers_owing(kind, selected_peers).await,
            None => selected_peers,
        };

        let (addr, peer) = self.next_peer(&selected_peers).await;

        tracing::trace!("Distributing {} request to peer {}", message.cmd(), addr);

        self.send_message_to_peer(&addr, &peer, message).await
    }

    /// Drop peers that already owe us a response of `kind` from the candidates.
    ///
    /// A peer that silently discards a request is invisible to latency-based
    /// routing: latency only ever records a response, so a peer that answers
    /// nothing is never measured and keeps its turn in the rotation. It then wins
    /// the retry of the very request it just dropped, which is how one such peer
    /// turned a 30s block timeout into 60s and 120s stalls, with filter sync
    /// halted behind it the whole time.
    ///
    /// The bar is what the peer owes rather than what it did wrong, so this needs
    /// no judgement about how slow is too slow and never accuses an honest peer on
    /// a slow link. It is also self-clearing: the peer becomes a candidate again
    /// the moment it answers, or the moment the request is satisfied elsewhere.
    ///
    /// Skipping is only ever a preference. If every candidate owes us something,
    /// the full set is kept, because refusing to send is worse than sending to a
    /// busy peer.
    async fn without_peers_owing(
        &self,
        kind: RequestKind,
        peers: Vec<(SocketAddr, Arc<RwLock<Peer>>)>,
    ) -> Vec<(SocketAddr, Arc<RwLock<Peer>>)> {
        let now = Instant::now();
        let owing: HashSet<SocketAddr> = {
            let outstanding = self.outstanding_requests.lock().await;
            outstanding
                .iter()
                .filter(|((_, k), sent)| {
                    *k == kind && now.saturating_duration_since(**sent) > REQUEST_OWED_TIMEOUT
                })
                .map(|((addr, _), _)| *addr)
                .collect()
        };

        if owing.is_empty() {
            return peers;
        }
        let free: Vec<(SocketAddr, Arc<RwLock<Peer>>)> =
            peers.iter().filter(|(addr, _)| !owing.contains(addr)).cloned().collect();
        if free.is_empty() {
            return peers;
        }
        free
    }

    /// Pick a peer from `peers`, rotating over those answering fastest.
    ///
    /// Selection reads measured response times rather than the misbehavior score.
    /// A score only ever accuses a peer, so a peer that is merely untried scores
    /// the same as a good one, and rewarding responses to break that tie makes the
    /// first peer to answer pull away and take the whole rotation: it earns more
    /// traffic, which earns it more reward, while the peers it starves get no
    /// traffic and so can never earn their way back. Latency has no such ratchet.
    /// It expires, so a starved peer becomes unmeasured and is retried, and it is
    /// bounded by what the peer actually did rather than by how often we picked it.
    ///
    /// The pool guard is already released by the caller (`get_all_peers` returns
    /// owned `Arc`s), so taking the latency lock here keeps a single lock order.
    async fn next_peer(
        &self,
        peers: &[(SocketAddr, Arc<RwLock<Peer>>)],
    ) -> (SocketAddr, Arc<RwLock<Peer>>) {
        let addrs: Vec<SocketAddr> = peers.iter().map(|(addr, _)| *addr).collect();
        let eligible_addrs = self.latency.lock().await.eligible(&addrs);
        let eligible: Vec<&(SocketAddr, Arc<RwLock<Peer>>)> =
            peers.iter().filter(|(addr, _)| eligible_addrs.contains(addr)).collect();

        // `eligible` only ever narrows `peers`, and never to nothing: a peer with
        // no fresh measurement always qualifies, so an empty result would mean
        // every peer was measured and none was within reach of the fastest, which
        // the fastest itself contradicts.
        let idx = self.round_robin_counter.fetch_add(1, Ordering::Relaxed) % eligible.len();
        let (addr, peer) = eligible[idx];
        (*addr, peer.clone())
    }

    /// Send a message to the given peer.
    /// For GetHeaders messages upgrade to GetHeaders2 if the peer supports it.
    async fn send_message_to_peer(
        &self,
        addr: &SocketAddr,
        peer: &Arc<RwLock<Peer>>,
        message: NetworkMessage,
    ) -> NetworkResult<()> {
        let message = match message {
            NetworkMessage::GetHeaders(get_headers) => {
                let supports_headers2 = peer.read().await.can_request_headers2();
                if supports_headers2 && !self.headers2_disabled.lock().await.contains(addr) {
                    tracing::debug!("Upgrading GetHeaders to GetHeaders2 for peer {}", addr);
                    NetworkMessage::GetHeaders2(get_headers)
                } else {
                    NetworkMessage::GetHeaders(get_headers)
                }
            }
            other => other,
        };

        let request_kind = tracked_request_kind(&message);
        let send_result = {
            let mut peer_guard = peer.write().await;
            peer_guard.send_message(message).await
        };
        let result = send_result
            .map_err(|e| NetworkError::ProtocolError(format!("Failed to send to {}: {}", addr, e)));

        // Arm the stall timer for request-type messages, keeping the oldest
        // unanswered timestamp so a peer that never replies is caught. The peer
        // lock is already released, so this only ever holds the outstanding lock.
        if result.is_ok() {
            if let Some(kind) = request_kind {
                self.outstanding_requests
                    .lock()
                    .await
                    .entry((*addr, kind))
                    .or_insert_with(Instant::now);
            }
        }
        result
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast(&self, message: NetworkMessage) -> Vec<Result<(), Error>> {
        let peers = self.pool.get_all_peers().await;
        let mut handles = Vec::new();

        // Spawn tasks for concurrent sending
        for (addr, peer) in peers {
            // Reduce verbosity for common sync messages
            match &message {
                NetworkMessage::GetHeaders(_) | NetworkMessage::GetCFilters(_) => {
                    tracing::debug!("Broadcasting {} to {}", message.cmd(), addr);
                }
                _ => {
                    tracing::trace!("Broadcasting {:?} to {}", message.cmd(), addr);
                }
            }
            let msg = message.clone();

            let handle = tokio::spawn(async move {
                let mut peer_guard = peer.write().await;
                peer_guard.send_message(msg).await.map_err(Error::Network)
            });
            handles.push(handle);
        }

        // Wait for all sends to complete
        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(_) => results.push(Err(Error::Network(NetworkError::ConnectionFailed(
                    "Task panicked during broadcast".to_string(),
                )))),
            }
        }

        results
    }

    /// Disconnect a specific peer
    pub async fn disconnect_peer(&self, addr: &SocketAddr, reason: &str) -> Result<(), Error> {
        tracing::info!("Disconnecting peer {} - reason: {}", addr, reason);

        Self::remove_peer_and_notify(
            &self.pool,
            addr,
            &self.connected_peer_count,
            &self.network_event_sender,
        )
        .await;

        Ok(())
    }

    /// Get reputation information for all peers
    pub async fn get_peer_reputations(&self) -> HashMap<SocketAddr, (i32, bool)> {
        let reputations = self.reputation_manager.get_all_reputations().await;
        reputations.into_iter().map(|(addr, rep)| (addr, (rep.score, rep.is_banned()))).collect()
    }

    /// Ban a specific peer manually
    pub async fn ban_peer(&self, addr: &SocketAddr, reason: &str) -> Result<(), Error> {
        tracing::info!("Manually banning peer {} - reason: {}", addr, reason);

        // Disconnect the peer first
        self.disconnect_peer(addr, reason).await?;

        // Update reputation to trigger ban
        self.reputation_manager.update_reputation(*addr, ChangeReason::ManuallyBanned).await;

        Ok(())
    }

    /// Unban a specific peer
    pub async fn unban_peer(&self, addr: &SocketAddr) {
        self.reputation_manager.unban_peer(addr).await;
    }

    /// Shutdown the network manager
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down peer network manager");
        self.shutdown_token.cancel();

        // Save known peers before shutdown
        let addresses = self.addrv2_handler.get_addresses_for_peer(MAX_ADDR_TO_STORE).await;
        if !addresses.is_empty() {
            if let Err(e) = self.peer_store.save_peers(&addresses).await {
                tracing::warn!("Failed to save peers on shutdown: {}", e);
            }
        }

        // Save reputation data before shutdown
        if let Err(e) = self.reputation_manager.save_to_storage(&*self.peer_store).await {
            tracing::warn!("Failed to save reputation data on shutdown: {}", e);
        }

        // Drain tasks while holding the lock.  connect_to_peer() already uses
        // `select!` with the cancellation token when acquiring this lock, so no
        // deadlock can occur once the shutdown token is cancelled above.
        let mut tasks = self.tasks.lock().await;
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                tracing::error!("Task join error: {}", e);
            }
        }

        // Disconnect all peers
        for addr in self.pool.get_connected_addresses().await {
            self.pool.remove_peer(&addr).await;
        }
    }

    async fn record_capability_rejection(&self, addr: SocketAddr) {
        Self::record_capability_rejection_in(&self.capability_rejected, addr).await;
    }

    async fn is_capability_rejected(&self, addr: &SocketAddr) -> bool {
        let mut rejected = self.capability_rejected.write().await;
        let now = Instant::now();
        rejected.retain(|_, rejected_at| {
            now.saturating_duration_since(*rejected_at) < CAPABILITY_REJECTED_TTL
        });
        rejected.contains_key(addr)
    }

    async fn record_capability_rejection_in(
        capability_rejected: &RwLock<HashMap<SocketAddr, Instant>>,
        addr: SocketAddr,
    ) {
        capability_rejected.write().await.insert(addr, Instant::now());
    }

    async fn should_reject_after_handshake(
        pool: &PeerPool,
        peer: &Peer,
        required_services: ServiceFlags,
    ) -> bool {
        required_services != ServiceFlags::NONE
            && pool.has_peers_with_service(required_services).await
            && peer.services_known()
            && !peer.has_service(required_services)
    }
}

// Implement Clone for use in async closures
impl Clone for PeerNetworkManager {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            max_peers: self.max_peers,
            discovery: self.discovery.clone(),
            addrv2_handler: self.addrv2_handler.clone(),
            peer_store: self.peer_store.clone(),
            reputation_manager: self.reputation_manager.clone(),
            network: self.network,
            shutdown_token: self.shutdown_token.clone(),
            tasks: self.tasks.clone(),
            initial_peers: self.initial_peers.clone(),
            data_dir: self.data_dir.clone(),
            user_agent: self.user_agent.clone(),
            exclusive_mode: self.exclusive_mode,
            required_services: self.required_services,
            capability_rejected: self.capability_rejected.clone(),
            connected_peer_count: self.connected_peer_count.clone(),
            headers2_disabled: self.headers2_disabled.clone(),
            headers2_decompression_semaphore: self.headers2_decompression_semaphore.clone(),
            message_dispatcher: self.message_dispatcher.clone(),
            request_tx: self.request_tx.clone(),
            request_rx: self.request_rx.clone(),
            round_robin_counter: self.round_robin_counter.clone(),
            network_event_sender: self.network_event_sender.clone(),
            outstanding_requests: self.outstanding_requests.clone(),
            latency: self.latency.clone(),
            last_maintenance_at: self.last_maintenance_at.clone(),
            last_eviction_at: self.last_eviction_at.clone(),
        }
    }
}

// Implement NetworkManager trait
#[async_trait]
impl NetworkManager for PeerNetworkManager {
    async fn message_receiver(&mut self, types: &[MessageType]) -> UnboundedReceiver<Message> {
        self.message_dispatcher.lock().await.message_receiver(types)
    }

    fn request_sender(&self) -> RequestSender {
        PeerNetworkManager::request_sender(self)
    }

    async fn connect(&mut self) -> NetworkResult<()> {
        self.start().await.map_err(|e| NetworkError::ConnectionFailed(e.to_string()))
    }

    async fn disconnect(&mut self) -> NetworkResult<()> {
        self.shutdown().await;
        Ok(())
    }

    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        // For sync messages that require consistent responses, send to only one peer
        match &message {
            NetworkMessage::GetHeaders(_)
            | NetworkMessage::GetHeaders2(_)
            | NetworkMessage::GetCFHeaders(_)
            | NetworkMessage::GetCFilters(_)
            | NetworkMessage::GetData(_)
            | NetworkMessage::GetMnListD(_) => self.send_to_single_peer(message).await,
            _ => {
                // For other messages, broadcast to all peers
                let results = self.broadcast(message).await;

                // Return error if all sends failed
                if results.is_empty() {
                    return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
                }

                let successes = results.iter().filter(|r| r.is_ok()).count();
                if successes == 0 {
                    return Err(NetworkError::ProtocolError(
                        "Failed to send to any peer".to_string(),
                    ));
                }

                Ok(())
            }
        } // end match
    } // end send_message

    fn peer_count(&self) -> usize {
        // Use cached counter to avoid blocking in async context
        self.connected_peer_count.load(Ordering::Relaxed)
    }

    async fn broadcast(&self, message: NetworkMessage) -> NetworkResult<()> {
        let results = PeerNetworkManager::broadcast(self, message).await;

        if results.is_empty() {
            return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
        }

        let successes = results.iter().filter(|r| r.is_ok()).count();
        if successes == 0 {
            return Err(NetworkError::ConnectionFailed("All broadcast sends failed".to_string()));
        }
        Ok(())
    }

    async fn dispatch_local(&self, message: NetworkMessage) {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let msg = Message::new(local_addr, message);
        self.message_dispatcher.lock().await.dispatch(&msg);
    }

    async fn disconnect_peer(&self, addr: &SocketAddr, reason: &str) -> NetworkResult<()> {
        PeerNetworkManager::disconnect_peer(self, addr, reason)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))
    }

    fn subscribe_network_events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.network_event_sender.subscribe()
    }
}

/// The sync request a timer belongs to.
///
/// Timers are kept per kind rather than per peer, so a response can only clear a
/// request it actually answers. Sharing one timer across kinds lets a peer that is
/// fast at one kind hide being slow at another: its quick responses clear the
/// timer the slow request armed, the slow response then finds nothing to clear and
/// is never measured, and the stall sweep never sees an aged entry to penalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RequestKind {
    Headers,
    FilterHeaders,
    Filters,
    Blocks,
}

impl RequestKind {
    /// Whether how long this kind took is a fair measure of the peer, and so may
    /// be scored against it: recorded as its response time, and penalized when it
    /// exceeds `REQUEST_STALL_TIMEOUT`.
    ///
    /// Only kinds with a small, fixed-size response qualify. A header, filter or
    /// filter-header reply is at most tens of KB and arrives in well under a
    /// second on any usable link, so a slow one really is a slow peer. A block
    /// body is megabytes and the peer sends nothing until the transfer finishes,
    /// so its elapsed time measures the payload rather than the peer: scoring it
    /// would both punish an honest peer on a slow link and, because response
    /// times feed one shared routing metric, push that peer out of serving
    /// filters and headers it was answering perfectly well.
    ///
    /// Blocks are still tracked, because an unanswered block request is exactly
    /// what should stop us handing that peer the next one. The judgement just
    /// stays at routing: the peer is skipped while it owes us, never scored.
    fn response_time_is_fair(self) -> bool {
        !matches!(self, RequestKind::Blocks)
    }
}

/// The kind of timer an outbound message arms, or `None` if it is not timed.
///
/// A `getdata` only arms the block timer when it actually asks for blocks. The
/// mempool sends `getdata` for transactions, which a `block` response would never
/// clear, so timing those would leave a timer armed forever against a peer that
/// answered everything it was asked.
///
/// Masternode-diff and quorum-info requests stay untimed: they are issued as a
/// single burst against one peer rather than as a rotation, so knowing the peer
/// owes us one changes nothing about where the next one goes.
fn tracked_request_kind(msg: &NetworkMessage) -> Option<RequestKind> {
    match msg {
        NetworkMessage::GetHeaders(_) | NetworkMessage::GetHeaders2(_) => {
            Some(RequestKind::Headers)
        }
        NetworkMessage::GetCFHeaders(_) => Some(RequestKind::FilterHeaders),
        NetworkMessage::GetCFilters(_) => Some(RequestKind::Filters),
        NetworkMessage::GetData(inv) => inv
            .iter()
            .any(|item| matches!(item, Inventory::Block(_)))
            .then_some(RequestKind::Blocks),
        _ => None,
    }
}

/// The kind of timer an inbound message clears, or `None` if it answers nothing we
/// timed. Unsolicited gossip (inv, tx, addr, ping) is excluded: it arrives
/// unprompted and would clear a timer the peer has not actually answered.
fn timed_response_kind(msg: &NetworkMessage) -> Option<RequestKind> {
    match msg {
        NetworkMessage::Headers(_) | NetworkMessage::Headers2(_) => Some(RequestKind::Headers),
        NetworkMessage::CFHeaders(_) => Some(RequestKind::FilterHeaders),
        NetworkMessage::CFilter(_) => Some(RequestKind::Filters),
        NetworkMessage::Block(_) => Some(RequestKind::Blocks),
        _ => None,
    }
}

#[cfg(test)]
impl PeerNetworkManager {
    pub(crate) async fn new_for_test(required_services: ServiceFlags) -> Self {
        let test_dir = tempfile::tempdir().expect("test dir creation failed").keep();
        let peer_store =
            PersistentPeerStorage::open(&test_dir).await.expect("test peer store init failed");
        let discovery = DnsDiscovery::new();
        let (request_tx, request_rx) = unbounded_channel();
        Self {
            pool: Arc::new(PeerPool::new(8)),
            max_peers: 8,
            discovery: Arc::new(discovery),
            addrv2_handler: Arc::new(AddrV2Handler::new()),
            peer_store: Arc::new(peer_store),
            reputation_manager: Arc::new(PeerReputationManager::new()),
            network: Network::Testnet,
            shutdown_token: CancellationToken::new(),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            initial_peers: vec![],
            data_dir: test_dir,
            user_agent: None,
            exclusive_mode: false,
            required_services,
            capability_rejected: Arc::new(RwLock::new(HashMap::new())),
            connected_peer_count: Arc::new(AtomicUsize::new(0)),
            headers2_disabled: Arc::new(Mutex::new(HashSet::new())),
            headers2_decompression_semaphore: Arc::new(Semaphore::new(
                headers2_decompression_parallelism(),
            )),
            message_dispatcher: Arc::new(Mutex::new(MessageDispatcher::default())),
            request_tx,
            request_rx: Arc::new(Mutex::new(Some(request_rx))),
            round_robin_counter: Arc::new(AtomicUsize::new(0)),
            network_event_sender: broadcast::Sender::new(DEFAULT_NETWORK_EVENT_CAPACITY),
            outstanding_requests: Arc::new(Mutex::new(HashMap::new())),
            latency: Arc::new(Mutex::new(PeerLatency::default())),
            last_maintenance_at: Arc::new(Mutex::new(Instant::now())),
            last_eviction_at: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) async fn insert_test_peer(&self, addr: SocketAddr, flags: ServiceFlags) {
        self.pool.insert_peer_with_services(addr, flags).await;
        self.connected_peer_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) async fn test_peer_count(&self) -> usize {
        self.pool.peer_count().await
    }

    pub(crate) async fn test_is_connected(&self, addr: &SocketAddr) -> bool {
        self.pool.is_connected(addr).await
    }

    pub(crate) async fn insert_test_capability_rejected(&self, addr: SocketAddr) {
        self.record_capability_rejection(addr).await;
    }

    pub(crate) async fn test_capability_rejected_count(&self) -> usize {
        self.capability_rejected.read().await.len()
    }

    pub(crate) async fn test_is_capability_rejected(&self, addr: &SocketAddr) -> bool {
        self.is_capability_rejected(addr).await
    }

    pub(crate) async fn test_has_capable_peer(&self) -> bool {
        self.required_services != ServiceFlags::NONE
            && self.pool.has_peers_with_service(self.required_services).await
    }

    pub(crate) async fn test_should_reject_after_handshake(&self, peer: &Peer) -> bool {
        Self::should_reject_after_handshake(&self.pool, peer, self.required_services).await
    }

    pub(crate) async fn test_update_reputation(&self, addr: SocketAddr, reason: ChangeReason) {
        self.reputation_manager.update_reputation(addr, reason).await;
    }

    pub(crate) async fn test_add_known_address(&self, addr: SocketAddr) {
        self.addrv2_handler.add_known_address(addr, ServiceFlags::NETWORK).await;
    }

    pub(crate) async fn test_next_peer(&self) -> SocketAddr {
        let peers = self.pool.get_all_peers().await;
        self.next_peer(&peers).await.0
    }

    /// Pick the peer `send_distributed` would route `msg` to, including the skip
    /// of peers that still owe a response of that kind.
    pub(crate) async fn test_route(&self, msg: &NetworkMessage) -> SocketAddr {
        let peers = self.pool.get_all_peers().await;
        let peers = match tracked_request_kind(msg) {
            Some(kind) => self.without_peers_owing(kind, peers).await,
            None => peers,
        };
        self.next_peer(&peers).await.0
    }

    pub(crate) async fn test_record_latency(&self, addr: SocketAddr, elapsed: Duration) {
        self.latency.lock().await.record(addr, elapsed);
    }

    /// Arm a stall timer exactly as a successful send does.
    pub(crate) async fn test_arm_request(&self, addr: SocketAddr, msg: &NetworkMessage) {
        if let Some(kind) = tracked_request_kind(msg) {
            self.outstanding_requests.lock().await.entry((addr, kind)).or_insert_with(Instant::now);
        }
    }

    /// Clear a stall timer exactly as the peer reader loop does on a response.
    pub(crate) async fn test_deliver_response(&self, addr: SocketAddr, msg: &NetworkMessage) {
        if let Some(kind) = timed_response_kind(msg) {
            let sent = self.outstanding_requests.lock().await.remove(&(addr, kind));
            if let Some(sent) = sent {
                self.latency.lock().await.record(addr, sent.elapsed());
            }
        }
    }

    pub(crate) async fn test_sweep_stalled_peers(&self) -> bool {
        self.sweep_stalled_peers().await
    }

    pub(crate) async fn test_score(&self, addr: SocketAddr) -> i32 {
        self.reputation_manager.scores_for([addr]).await.get(&addr).copied().unwrap_or(0)
    }

    pub(crate) async fn test_evict_worst_stuck_peer(&self) {
        self.evict_worst_stuck_peer().await;
    }
}

#[cfg(test)]
mod headers2_ordering_tests {
    use super::OrderedHeaders2Results;

    #[test]
    fn completed_decompressions_are_released_in_receive_order() {
        let mut results = OrderedHeaders2Results::default();

        assert!(results.complete(2, "third").is_empty());
        assert_eq!(results.complete(0, "first"), ["first"]);
        assert_eq!(results.complete(1, "second"), ["second", "third"]);
    }
}
