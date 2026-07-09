//! Peer network manager for SPV client

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::task::JoinSet;
use tokio::time;

use crate::client::ClientConfig;
use crate::error::{NetworkError, NetworkResult, SpvError as Error};
use crate::network::addrv2::AddrV2Handler;
use crate::network::constants::*;
use crate::network::discovery::DnsDiscovery;
use crate::network::pool::PeerPool;
use crate::network::reputation::{ChangeReason, PeerReputationManager};
use crate::network::{
    HandshakeManager, Message, MessageDispatcher, MessageType, NetworkEvent, NetworkManager,
    NetworkRequest, Peer, RequestSender,
};
use crate::storage::{PeerStorage, PersistentPeerStorage, PersistentStorage};
use async_trait::async_trait;
use dashcore::network::address::{AddrV2, AddrV2Message};
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_headers2::CompressionState;
use dashcore::Network;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const DEFAULT_NETWORK_EVENT_CAPACITY: usize = 10000;

/// Latency probes fired right after handshake to seed peer scoring.
const INITIAL_PROBE_PINGS: usize = 3;

/// How long to wait for the initial probe pongs before scoring the peer.
const INITIAL_PROBE_WAIT: Duration = Duration::from_millis(1200);

/// How often to probe known-but-unconnected peers looking for better ones.
const SCOUT_INTERVAL: Duration = Duration::from_secs(45);

/// Peers to probe per scout tick.
const SCOUT_BATCH: usize = 4;

/// Latency tier (lower is better): the band we rank and keep peers by. We only dial peers
/// in the best-known tier or one worse, and drop a connected peer more than one tier below
/// the best in the pool — so a genuinely slow peer never takes a slot. `<=50ms`=0,
/// `<=100ms`=1, `<=150ms`=2, else 3.
fn latency_tier(latency_ms: u32) -> u8 {
    match latency_ms {
        0..=50 => 0,
        51..=100 => 1,
        101..=150 => 2,
        _ => 3,
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
    /// Dispatcher for unbounded and message-type filtered message distribution.
    message_dispatcher: Arc<Mutex<MessageDispatcher>>,
    /// Request queue sender, cloneable handle for sending requests to the network manager.
    request_tx: UnboundedSender<NetworkRequest>,
    /// Request queue receiver (consumed by send loop).
    request_rx: Arc<Mutex<Option<UnboundedReceiver<NetworkRequest>>>>,
    /// Network event bus for notifying about network/peer related changes.
    network_event_sender: broadcast::Sender<NetworkEvent>,
}

const CAPABILITY_REJECTED_TTL: Duration = Duration::from_secs(30 * 60);

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
            message_dispatcher: Arc::new(Mutex::new(MessageDispatcher::default())),
            request_tx,
            request_rx: Arc::new(Mutex::new(Some(request_rx))),
            network_event_sender: broadcast::Sender::new(DEFAULT_NETWORK_EVENT_CAPACITY),
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
        // Skip peers whose multiplier has collapsed to zero (untrusted).
        if !self.reputation_manager.is_usable(&addr).await {
            tracing::warn!("Not connecting to {} - untrusted peer", addr);
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

        let pool = self.pool.clone();
        let network = self.network;
        let addrv2_handler = self.addrv2_handler.clone();
        let shutdown_token = self.shutdown_token.clone();
        let reputation_manager = self.reputation_manager.clone();
        let user_agent = self.user_agent.clone();
        let required_services = self.required_services;
        let capability_rejected = self.capability_rejected.clone();
        let connected_peer_count = self.connected_peer_count.clone();
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

                            // Seed behaviour and latency from persisted history, then measure
                            // latency inline so the peer enters the pool already scored and sync
                            // traffic avoids slow peers from the very first request.
                            if let Some((multiplier, median_ms)) =
                                reputation_manager.hint(&addr).await
                            {
                                peer.set_behavior_multiplier(multiplier);
                                if let Some(ms) = median_ms {
                                    peer.record_rtt(Duration::from_millis(ms as u64));
                                }
                            }
                            Self::probe_latency_inline(&mut peer).await;

                            // Record the freshly-measured latency to reputation (so its tier
                            // is known at once) and reject a clearly-slower peer BEFORE it
                            // joins the pool, so a bad peer never receives any sync traffic.
                            // Good peers connect faster, so they are already measured here.
                            if let Some(rtt) = peer.median_rtt() {
                                let ms = rtt.as_millis() as u32;
                                reputation_manager.record_latency(addr, ms).await;
                                let connected = pool.get_connected_addresses().await;
                                let best = reputation_manager
                                    .latencies(&connected)
                                    .await
                                    .values()
                                    .map(|m| latency_tier(*m))
                                    .min();
                                if let Some(best) = best {
                                    if latency_tier(ms) > best + 1 {
                                        tracing::info!(
                                            "Rejecting peer {} (tier {} > best {} + 1) before pool — worse than the set",
                                            addr,
                                            latency_tier(ms),
                                            best
                                        );
                                        pool.remove_peer(&addr).await;
                                        return;
                                    }
                                }
                            }

                            // Request addresses from the peer for discovery
                            if let Err(e) = peer.send_message(NetworkMessage::GetAddr).await {
                                tracing::warn!("Failed to send GetAddr to {}: {}", addr, e);
                            }

                            // Add to pool
                            if let Err(e) = pool.add_peer(addr, peer).await {
                                tracing::error!("Failed to add peer to pool: {}", e);
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
                                connected_peer_count.clone(),
                                message_dispatcher,
                                network_event_sender.clone(),
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!("Handshake failed with {}: {}", addr, e);
                            // Only clears connecting set. Peer was never added, so no count/event needed.
                            pool.remove_peer(&addr).await;
                            reputation_manager.penalize(addr, ChangeReason::HandshakeFailed).await;
                            // For handshake failures, try again later
                            tokio::time::sleep(RECONNECT_DELAY).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to connect to {}: {}", addr, e);
                    // Only clears connecting set. Peer was never added, so no count/event needed.
                    pool.remove_peer(&addr).await;
                    reputation_manager.penalize(addr, ChangeReason::ConnectionFailed).await;
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
        connected_peer_count: Arc<AtomicUsize>,
        message_dispatcher: Arc<Mutex<MessageDispatcher>>,
        network_event_sender: broadcast::Sender<NetworkEvent>,
    ) {
        tokio::spawn(async move {
            tracing::debug!("Starting peer reader loop for {}", addr);
            let mut loop_iteration = 0;
            let mut headers2_state = CompressionState::default();

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
                        tracing::debug!("Received {:?} from {}", msg.cmd(), addr);

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
                            NetworkMessage::Headers2(headers2) => {
                                // Decompress headers in network layer and forward as regular Headers
                                tracing::info!(
                                    "Received Headers2 from {} with {} compressed headers - decompressing",
                                    addr,
                                    headers2.headers.len()
                                );

                                match headers2_state.process_headers(&headers2.headers) {
                                    Ok(headers) => {
                                        tracing::info!(
                                            "Decompressed {} headers from {} - forwarding as regular Headers",
                                            headers.len(),
                                            addr
                                        );
                                        {
                                            let mut g = peer.write().await;
                                            g.note_response();
                                            g.apply_reason(ChangeReason::GoodResponse);
                                        }
                                        // Forward as regular Headers message
                                        let headers_msg = NetworkMessage::Headers(headers);
                                        let message = Message::new(msg.peer_address(), headers_msg);
                                        message_dispatcher.lock().await.dispatch(&message);
                                        continue; // Already sent, don't forward the original Headers2
                                    }
                                    Err(e) => {
                                        // A peer that opted into headers2 but sent data that fails
                                        // to decompress served us invalid data - distrust it.
                                        tracing::error!(
                                            "Headers2 decompression failed from {}: {} - distrusting peer",
                                            addr,
                                            e
                                        );
                                        peer.write().await.apply_reason(ChangeReason::InvalidData);
                                        break; // Disconnect the untrusted peer
                                    }
                                }
                            }
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

                        // A forwarded data message answers an outstanding request:
                        // clear the stall timer and reward the peer.
                        {
                            let mut peer_guard = peer.write().await;
                            peer_guard.note_response();
                            peer_guard.apply_reason(ChangeReason::GoodResponse);
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
                                tracing::debug!("Timeout reading from {}, continuing...", addr);
                                peer.write().await.apply_reason(ChangeReason::Timeout);
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
                                        peer.write().await.apply_reason(ChangeReason::BadResponse);
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

            // Persist the peer's final behaviour and latency before removing it.
            if let Some(peer) = pool.get_peer(&addr).await {
                let mut guard = peer.write().await;
                // Reward a long, healthy connection.
                if Duration::from_secs(60 * loop_iteration) > Duration::from_secs(3600) {
                    guard.apply_reason(ChangeReason::LongUptime);
                }
                let multiplier = guard.behavior_multiplier();
                let median = guard.median_rtt().map(|d| d.as_millis() as u32);
                drop(guard);
                reputation_manager.record(addr, multiplier, median).await;
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
                                tracing::debug!("Request processor: sending {}", msg.cmd());
                                let this = this.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = this.pool.send(msg).await {
                                        tracing::error!("Request processor: failed to send message: {}", e);
                                    }
                                });
                            }
                            Some(NetworkRequest::SendMessageToPeer(msg, peer_address)) => {
                                tracing::debug!("Request processor: sending {} to peer {}", msg.cmd(), peer_address);
                                let this = this.clone();
                                tokio::spawn(async move {
                                    let fallback_msg = msg.clone();
                                    let result = match this.pool.send_to(peer_address, msg).await {
                                        Ok(()) => Ok(()),
                                        Err(err) => {
                                            tracing::warn!(
                                                "Target peer {} send failed ({}), falling back to best peer",
                                                peer_address,
                                                err
                                            );
                                            this.pool.send(fallback_msg).await.map(|_| ())
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
            // Reconnect only to configured peers, and only those within the best tier band —
            // a configured peer that measured clearly worse than the others is not redialed
            // (max_peers is a ceiling). Unmeasured peers pass, so the first connect tries all.
            for addr in self.within_tier_band(self.initial_peers.clone()).await {
                if !self.pool.is_connected(&addr).await && !self.pool.is_connecting(&addr).await {
                    tracing::info!("Reconnecting to exclusive peer: {}", addr);
                    self.connect_to_peer(addr).await;
                }
            }
        } else {
            // Evict peers that lack required services before top-up so replacements
            // can be pulled in during the same tick.
            self.evict_mismatched_peers().await;
            // Re-read count after potential churn so top-up sees the current pool size.
            let count = self.pool.peer_count().await;
            if count < self.max_peers {
                let needed = self.max_peers.saturating_sub(count);
                // Dial known addresses best-first, restricted to the best tier band so we
                // never top up with a clearly-slower peer than the ones we could have.
                let known = self.known_socket_addrs().await;
                let best_peers =
                    self.within_tier_band(self.reputation_manager.rank(known).await).await;
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

        // Ping peers if needed, snapshot their measured quality for persistence,
        // and disconnect unresponsive ones.
        let mut low_quality: Vec<SocketAddr> = Vec::new();
        for (addr, peer) in self.pool.get_all_peers().await {
            let mut peer_guard = peer.write().await;
            if peer_guard.should_ping() {
                if let Err(e) = peer_guard.send_ping().await {
                    tracing::error!("Failed to ping {}: {}", addr, e);
                    peer_guard.apply_reason(ChangeReason::PingFailed);
                }
            }
            // We ONLY replace a peer when it STALLS (goes silent on a request). We do not
            // churn a merely-slow-but-responsive peer here: once syncing, every peer is
            // under our own request load, so a high latency is expected. (Genuinely-bad
            // peers are handled up front by measurement + `drop_worse_tier_peers`.)
            let stalling = peer_guard.is_stalling();
            if stalling {
                peer_guard.apply_reason(ChangeReason::Timeout);
                low_quality.push(addr);
            }
            if peer_guard.median_rtt().is_some() {
                let median = peer_guard.median_rtt().map(|d| d.as_millis() as u32);
                self.reputation_manager
                    .record(addr, peer_guard.behavior_multiplier(), median)
                    .await;
            }
            let has_expired = peer_guard.remove_expired_pings();
            drop(peer_guard);
            if has_expired {
                let _ = self.disconnect_peer(&addr, "ping timeout").await;
            }
        }

        // Drop any connected peer whose measured tier is clearly worse than the best in the
        // pool (the "bad peer" of a mixed set) — it should never hold a slot. Runs in every
        // mode (the mixed-set case is a local/exclusive scenario).
        self.drop_worse_tier_peers().await;

        // Replace peers that stalled, swapping in the best known unconnected peer and
        // probing more to find a permanent one.
        if !self.exclusive_mode {
            for addr in low_quality {
                self.replace_peer(addr).await;
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

    /// Send a burst of probe pings and wait briefly for the pongs, recording the
    /// RTTs. Unanswered probes are scored as the worst bucket so a silent or slow
    /// peer enters the pool already deprioritised.
    async fn probe_latency_inline(peer: &mut Peer) {
        let mut pending = Vec::new();
        for _ in 0..INITIAL_PROBE_PINGS {
            match peer.send_ping().await {
                Ok(nonce) => pending.push(nonce),
                Err(_) => break,
            }
        }
        if pending.is_empty() {
            return;
        }
        let deadline = Instant::now() + INITIAL_PROBE_WAIT;
        let mut answered = 0;
        while answered < pending.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, peer.receive_message()).await {
                Ok(Ok(Some(message))) => match message.inner() {
                    NetworkMessage::Pong(n) if pending.contains(n) => {
                        let _ = peer.handle_pong(*n);
                        answered += 1;
                    }
                    NetworkMessage::Ping(p) => {
                        let _ = peer.handle_ping(*p).await;
                    }
                    _ => {}
                },
                _ => break,
            }
        }
        for _ in answered..pending.len() {
            peer.record_rtt(INITIAL_PROBE_WAIT);
        }
    }

    /// Probe known-but-unconnected peers we have not measured yet, so the address
    /// pool has fresh latency data ready to swap in as replacements. Cycles until
    /// every known peer has been measured.
    async fn scout_once(&self) {
        if self.exclusive_mode {
            return;
        }
        let candidates = self.unmeasured_candidates().await;
        for addr in candidates.into_iter().take(SCOUT_BATCH) {
            match self.probe_peer(addr).await {
                Some(median_ms) => {
                    self.reputation_manager.record_latency(addr, median_ms).await;
                    tracing::debug!("Scout measured {} -> {}ms", addr, median_ms);
                }
                None => {
                    // Unreachable/failed probe: penalise so it ranks lower and, after
                    // enough failures, its multiplier hits zero and it drops out entirely.
                    self.reputation_manager.penalize(addr, ChangeReason::ConnectionFailed).await;
                }
            }
        }
    }

    /// Known addresses we are not connected to and have not measured yet.
    async fn unmeasured_candidates(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        for addr in self.known_socket_addrs().await {
            if self.pool.is_connected(&addr).await
                || self.pool.is_connecting(&addr).await
                || !self.reputation_manager.is_usable(&addr).await
                || self.reputation_manager.is_measured(&addr).await
                || self.is_capability_rejected(&addr).await
            {
                continue;
            }
            out.push(addr);
        }
        out
    }

    async fn known_socket_addrs(&self) -> Vec<SocketAddr> {
        self.addrv2_handler
            .get_known_addresses()
            .await
            .iter()
            .filter_map(|m| m.socket_addr().ok())
            .collect()
    }

    /// Keep only dial candidates within one latency tier of the best MEASURED candidate,
    /// so we never add a clearly-slower peer while good ones are known (connect only to
    /// the best tier or one worse). Unmeasured peers pass — they still need a probe.
    async fn within_tier_band(&self, ranked: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let latencies = self.reputation_manager.latencies(&ranked).await;
        let best_tier =
            ranked.iter().filter_map(|a| latencies.get(a)).map(|ms| latency_tier(*ms)).min();
        let Some(best_tier) = best_tier else {
            return ranked; // nothing measured yet — keep all to bootstrap
        };
        ranked
            .into_iter()
            .filter(|a| {
                latencies.get(a).map(|ms| latency_tier(*ms) <= best_tier + 1).unwrap_or(true)
            })
            .collect()
    }

    /// Drop connected peers whose latency tier is more than one worse than the best in the
    /// pool. `max_peers` is a ceiling, not a quota: a genuinely-slow peer is not worth a
    /// slot, so we run with fewer rather than keep it. Never drops below one peer, and if
    /// every peer is equally bad nothing is dropped (nothing better to prefer).
    async fn drop_worse_tier_peers(&self) {
        let mut tiers: Vec<(SocketAddr, u8)> = Vec::new();
        for (addr, _) in self.pool.get_all_peers().await {
            if let Some(ms) = self.reputation_manager.hint(&addr).await.and_then(|(_, l)| l) {
                tiers.push((addr, latency_tier(ms)));
            }
        }
        let Some(best) = tiers.iter().map(|(_, t)| *t).min() else {
            return;
        };
        for (addr, tier) in tiers {
            if tier > best + 1 && self.pool.peer_count().await > 1 {
                tracing::info!(
                    "Dropping peer {} (tier {} > best tier {} + 1) — worse than the pool",
                    addr,
                    tier,
                    best
                );
                let _ = self.disconnect_peer(&addr, "worse latency tier than the pool").await;
            }
        }
    }

    /// The best known peer we are not connected to (within the best tier band), for use
    /// as a replacement.
    async fn best_unconnected_peer(&self) -> Option<SocketAddr> {
        let ranked = self
            .within_tier_band(self.reputation_manager.rank(self.known_socket_addrs().await).await)
            .await;
        for addr in ranked {
            if !self.pool.is_connected(&addr).await
                && !self.pool.is_connecting(&addr).await
                && !self.is_capability_rejected(&addr).await
            {
                return Some(addr);
            }
        }
        None
    }

    /// Drop a peer whose quality fell below the threshold, swap in the best known
    /// unconnected peer as a temporary replacement, and probe more peers to find a
    /// permanent one. Keeps the peer if it is our only one and nothing can replace it.
    async fn replace_peer(&self, addr: SocketAddr) {
        let replacement = self.best_unconnected_peer().await;
        if replacement.is_none() && self.pool.peer_count().await <= 1 {
            return;
        }
        let _ = self.disconnect_peer(&addr, "quality below threshold").await;
        if let Some(candidate) = replacement {
            tracing::info!("Replacing low-quality peer {} with {}", addr, candidate);
            self.connect_to_peer(candidate).await;
        }
        let scout = self.clone();
        tokio::spawn(async move { scout.scout_once().await });
    }

    /// Connect, handshake and ping a peer once to measure its median latency, then
    /// disconnect. Returns the median RTT in ms on success.
    async fn probe_peer(&self, addr: SocketAddr) -> Option<u32> {
        const PROBE_TOTAL: Duration = Duration::from_secs(8);
        const PROBE_READ: Duration = Duration::from_millis(500);

        if !self.pool.mark_connecting(addr).await {
            return None;
        }
        let result = self.probe_peer_inner(addr, PROBE_TOTAL, PROBE_READ).await;
        // Clears the connecting flag; the probe peer was never added to the pool.
        self.pool.remove_peer(&addr).await;
        result
    }

    async fn probe_peer_inner(
        &self,
        addr: SocketAddr,
        total: Duration,
        read_timeout: Duration,
    ) -> Option<u32> {
        let mut peer = tokio::select! {
            r = Peer::connect(addr, CONNECTION_TIMEOUT.as_secs(), self.network) => r.ok()?,
            _ = self.shutdown_token.cancelled() => return None,
        };
        let mut handshake = HandshakeManager::new(self.network, self.user_agent.clone());
        tokio::select! {
            r = handshake.perform_handshake(&mut peer) => r.ok()?,
            _ = self.shutdown_token.cancelled() => return None,
        };

        let nonce = peer.send_ping().await.ok()?;
        let start = Instant::now();
        while start.elapsed() < total {
            match tokio::time::timeout(read_timeout, peer.receive_message()).await {
                Ok(Ok(Some(message))) => match message.inner() {
                    NetworkMessage::Pong(n) if *n == nonce => {
                        let _ = peer.handle_pong(*n);
                        break;
                    }
                    NetworkMessage::Ping(p) => {
                        let _ = peer.handle_ping(*p).await;
                    }
                    _ => {}
                },
                Ok(Ok(None)) | Err(_) => {}
                Ok(Err(_)) => return None,
            }
        }

        let median = peer.median_rtt()?;
        let _ = peer.disconnect().await;
        Some(median.as_millis() as u32)
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
            // Background probing of known-but-unconnected peers (non-exclusive mode).
            let mut scout_interval =
                time::interval_at(Instant::now() + SCOUT_INTERVAL, SCOUT_INTERVAL);
            let mut network_events = this.network_event_sender.subscribe();
            while !this.shutdown_token.is_cancelled() {
                tokio::select! {
                    _ = maintenance_interval.tick() => {
                        tracing::debug!("Maintenance interval elapsed");
                        this.maintenance_tick().await;
                    }
                    _ = dns_interval.tick(), if !this.exclusive_mode => {
                        this.dns_fallback_tick().await;
                    }
                    _ = scout_interval.tick(), if !this.exclusive_mode => {
                        let scout = this.clone();
                        tokio::spawn(async move { scout.scout_once().await });
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
            message_dispatcher: self.message_dispatcher.clone(),
            request_tx: self.request_tx.clone(),
            request_rx: self.request_rx.clone(),
            network_event_sender: self.network_event_sender.clone(),
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
        // For sync requests, route to the single best peer; broadcast everything else.
        match &message {
            NetworkMessage::GetHeaders(_)
            | NetworkMessage::GetHeaders2(_)
            | NetworkMessage::GetCFHeaders(_)
            | NetworkMessage::GetCFilters(_)
            | NetworkMessage::GetData(_)
            | NetworkMessage::GetMnListD(_) => self.pool.send(message).await.map(|_| ()),
            _ => {
                let results = self.broadcast(message).await;

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
            message_dispatcher: Arc::new(Mutex::new(MessageDispatcher::default())),
            request_tx,
            request_rx: Arc::new(Mutex::new(Some(request_rx))),
            network_event_sender: broadcast::Sender::new(DEFAULT_NETWORK_EVENT_CAPACITY),
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
}
