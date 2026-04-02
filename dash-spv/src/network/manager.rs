//! Peer network manager for SPV client

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
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
use crate::network::reputation::{
    misbehavior_scores, positive_scores, PeerReputationManager, ReputationAware,
};
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

/// Peer network manager
pub struct PeerNetworkManager {
    /// Peer pool
    pool: Arc<PeerPool>,
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
    /// Cached count of currently connected peers for fast, non-blocking queries
    connected_peer_count: Arc<AtomicUsize>,
    /// Disable headers2 after decompression failure
    headers2_disabled: Arc<Mutex<HashSet<SocketAddr>>>,
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
}

impl PeerNetworkManager {
    /// Create a new peer network manager
    pub async fn new(config: &ClientConfig) -> Result<Self, Error> {
        let discovery = DnsDiscovery::new().await?;
        let data_dir = config.storage_path.clone();

        let peer_store = PersistentPeerStorage::open(data_dir.clone()).await?;

        let reputation_manager = Arc::new(PeerReputationManager::new());

        if let Err(e) = reputation_manager.load_from_storage(&peer_store).await {
            log::warn!("Failed to load peer reputation data: {}", e);
        }

        // Determine exclusive mode: either explicitly requested or peers were provided
        let exclusive_mode = config.restrict_to_configured_peers || !config.peers.is_empty();

        // Create request queue for outgoing messages
        let (request_tx, request_rx) = unbounded_channel();

        Ok(Self {
            pool: Arc::new(PeerPool::new()),
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
            connected_peer_count: Arc::new(AtomicUsize::new(0)),
            headers2_disabled: Arc::new(Mutex::new(HashSet::new())),
            message_dispatcher: Arc::new(Mutex::new(MessageDispatcher::default())),
            request_tx,
            request_rx: Arc::new(Mutex::new(Some(request_rx))),
            round_robin_counter: Arc::new(AtomicUsize::new(0)),
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
        log::info!("Starting peer network manager for {:?}", self.network);

        let mut peer_addresses: Vec<AddrV2Message> = self
            .initial_peers
            .iter()
            .map(|addr| AddrV2Message::new(*addr, ServiceFlags::NETWORK))
            .collect();

        if self.exclusive_mode {
            log::info!(
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
                log::info!(
                    "No peers configured, performing immediate DNS discovery for {:?}",
                    self.network
                );
                let dns_peers = self.discovery.discover_peers(self.network).await;
                let dns_peers_found = dns_peers.len();
                peer_addresses.extend(
                    dns_peers
                        .into_iter()
                        .take(TARGET_PEERS)
                        .map(|addr| AddrV2Message::new(addr, ServiceFlags::NETWORK)),
                );
                log::info!(
                    "DNS discovery found {} peers, using {} for startup",
                    dns_peers_found,
                    peer_addresses.len()
                );
            } else {
                log::info!(
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
            log::warn!("Not connecting to {} due to bad reputation", addr);
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
        let user_agent = self.user_agent.clone();
        let connected_peer_count = self.connected_peer_count.clone();
        let headers2_disabled = self.headers2_disabled.clone();
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
            log::debug!("Attempting to connect to {}", addr);

            let connect_result = tokio::select! {
                result = Peer::connect(addr, CONNECTION_TIMEOUT.as_secs(), network) => result,
                _ = shutdown_token.cancelled() => {
                    log::debug!("Connection to {} cancelled by shutdown", addr);
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
                            log::info!("Successfully connected to {}", addr);

                            // Request addresses from the peer for discovery
                            if let Err(e) = peer.send_message(NetworkMessage::GetAddr).await {
                                log::warn!("Failed to send GetAddr to {}: {}", addr, e);
                            }

                            // Record successful connection
                            reputation_manager.record_successful_connection(addr).await;

                            // Add to pool
                            if let Err(e) = pool.add_peer(addr, peer).await {
                                log::error!("Failed to add peer to pool: {}", e);
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
                                headers2_disabled.clone(),
                                message_dispatcher,
                                network_event_sender.clone(),
                            )
                            .await;
                        }
                        Err(e) => {
                            log::warn!("Handshake failed with {}: {}", addr, e);
                            // Only clears connecting set. Peer was never added, so no count/event needed.
                            pool.remove_peer(&addr).await;
                            // Update reputation for handshake failure
                            reputation_manager
                                .update_reputation(
                                    addr,
                                    misbehavior_scores::INVALID_MESSAGE,
                                    "Handshake failed",
                                )
                                .await;
                            // For handshake failures, try again later
                            tokio::time::sleep(RECONNECT_DELAY).await;
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Failed to connect to {}: {}", addr, e);
                    // Only clears connecting set. Peer was never added, so no count/event needed.
                    pool.remove_peer(&addr).await;
                    // Minor reputation penalty for connection failure
                    reputation_manager
                        .update_reputation(
                            addr,
                            misbehavior_scores::TIMEOUT / 2,
                            "Connection failed",
                        )
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
            log::warn!("Peer count already zero when removing {}", addr);
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
        headers2_disabled: Arc<Mutex<HashSet<SocketAddr>>>,
        message_dispatcher: Arc<Mutex<MessageDispatcher>>,
        network_event_sender: broadcast::Sender<NetworkEvent>,
    ) {
        tokio::spawn(async move {
            log::debug!("Starting peer reader loop for {}", addr);
            let mut loop_iteration = 0;
            let mut headers2_state = CompressionState::default();

            loop {
                loop_iteration += 1;

                // Check shutdown signal first with detailed logging
                if shutdown_token.is_cancelled() {
                    log::info!("Breaking peer reader loop for {} - shutdown signal received (iteration {})", addr, loop_iteration);
                    break;
                }

                // Get peer
                let peer = match pool.get_peer(&addr).await {
                    Some(peer) => peer,
                    None => {
                        log::warn!("Breaking peer reader loop for {} - peer no longer in pool (iteration {})", addr, loop_iteration);
                        break;
                    }
                };

                // Read message with minimal lock time
                let msg_result = {
                    // Try to get a read lock first to check if peer is available
                    let peer_guard = peer.read().await;
                    if !peer_guard.is_connected() {
                        log::warn!("Breaking peer reader loop for {} - peer no longer connected (iteration {})", addr, loop_iteration);
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
                            log::info!("Breaking peer reader loop for {} - shutdown signal received while reading (iteration {})", addr, loop_iteration);
                            break;
                        }
                    }
                };

                match msg_result {
                    Ok(Some(msg)) => {
                        // Log all received messages at debug level to help troubleshoot
                        log::debug!("Received {:?} from {}", msg.cmd(), addr);

                        // Handle some messages directly
                        match &msg.inner() {
                            NetworkMessage::SendAddrV2 => {
                                addrv2_handler.handle_sendaddrv2(addr).await;
                                continue; // Don't forward to client
                            }
                            NetworkMessage::SendHeaders2 => {
                                // Peer is indicating they will send us compressed headers
                                log::info!(
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
                                log::trace!(
                                    "Received GetAddr from {}, sending known addresses",
                                    addr
                                );
                                // Send our known addresses
                                let response = addrv2_handler.build_addr_response().await;
                                let mut peer_guard = peer.write().await;
                                if let Err(e) = peer_guard.send_message(response).await {
                                    log::error!("Failed to send addr response to {}: {}", addr, e);
                                }
                                continue; // Don't forward GetAddr to client
                            }
                            NetworkMessage::Ping(nonce) => {
                                // Handle ping directly
                                let mut peer_guard = peer.write().await;
                                if let Err(e) = peer_guard.handle_ping(*nonce).await {
                                    log::error!("Failed to handle ping from {}: {}", addr, e);
                                    // If we can't send pong, connection is likely broken
                                    if matches!(e, NetworkError::ConnectionFailed(_)) {
                                        log::warn!("Breaking peer reader loop for {} - failed to send pong response (iteration {})", addr, loop_iteration);
                                        break;
                                    }
                                }
                                continue; // Don't forward ping to client
                            }
                            NetworkMessage::Pong(nonce) => {
                                // Handle pong directly
                                let mut peer_guard = peer.write().await;
                                if let Err(e) = peer_guard.handle_pong(*nonce) {
                                    log::error!("Failed to handle pong from {}: {}", addr, e);
                                }
                                continue; // Don't forward pong to client
                            }
                            NetworkMessage::Version(_) | NetworkMessage::Verack => {
                                // These are handled during handshake, ignore here
                                log::trace!(
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
                                    log::debug!(
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
                                log::info!(
                                    "📨 Received Headers message from {} with {} headers! (regular uncompressed)",
                                    addr,
                                    headers.len()
                                );
                                // Check if peer supports headers2
                                let peer_guard = peer.read().await;
                                if peer_guard.supports_headers2() {
                                    log::warn!("⚠️  Peer {} supports headers2 but sent regular headers - possible protocol issue", addr);
                                }
                                drop(peer_guard);
                                // Forward to client
                            }
                            NetworkMessage::Headers2(headers2) => {
                                // Decompress headers in network layer and forward as regular Headers
                                log::info!(
                                    "Received Headers2 from {} with {} compressed headers - decompressing",
                                    addr,
                                    headers2.headers.len()
                                );

                                match headers2_state.process_headers(&headers2.headers) {
                                    Ok(headers) => {
                                        log::info!(
                                            "Decompressed {} headers from {} - forwarding as regular Headers",
                                            headers.len(),
                                            addr
                                        );
                                        // Forward as regular Headers message
                                        let headers_msg = NetworkMessage::Headers(headers);
                                        let message = Message::new(msg.peer_address(), headers_msg);
                                        message_dispatcher.lock().await.dispatch(&message);
                                        continue; // Already sent, don't forward the original Headers2
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "Headers2 decompression failed from {}: {} - disabling headers2",
                                            addr,
                                            e
                                        );
                                        headers2_disabled.lock().await.insert(addr);
                                        // Apply reputation penalty
                                        reputation_manager
                                            .update_reputation(
                                                addr,
                                                misbehavior_scores::INVALID_MESSAGE,
                                                "Headers2 decompression failed",
                                            )
                                            .await;
                                        continue; // Don't forward corrupted message
                                    }
                                }
                            }
                            NetworkMessage::GetHeaders(_) => {
                                // SPV clients don't serve headers to peers
                                log::debug!(
                                    "Received GetHeaders from {} - ignoring (SPV client)",
                                    addr
                                );
                                continue; // Don't forward to client
                            }
                            NetworkMessage::GetHeaders2(_) => {
                                // SPV clients don't serve compressed headers to peers
                                log::debug!(
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
                                log::warn!("Received unknown message from {}: command='{}', payload_len={}",
                                         addr, command, payload.len());
                                // Still forward to client
                            }
                            _ => {
                                // Forward other messages to client
                                log::trace!("Forwarding {:?} from {} to client", msg.cmd(), addr);
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
                                log::info!("Peer {} disconnected", addr);
                                break;
                            }
                            NetworkError::Timeout => {
                                log::debug!("Timeout reading from {}, continuing...", addr);
                                // Minor reputation penalty for timeout
                                reputation_manager
                                    .update_reputation(
                                        addr,
                                        misbehavior_scores::TIMEOUT,
                                        "Read timeout",
                                    )
                                    .await;
                                continue;
                            }
                            _ => {
                                log::error!("Fatal error reading from {}: {}", addr, e);

                                // Check if this is a serialization error that might have context
                                if let NetworkError::Serialization(ref decode_error) = e {
                                    let error_msg = decode_error.to_string();
                                    if error_msg.contains("unknown special transaction type") {
                                        log::warn!("Peer {} sent block with unsupported transaction type: {}", addr, decode_error);
                                        log::error!(
                                            "BLOCK DECODE FAILURE - Error details: {}",
                                            error_msg
                                        );
                                        // Reputation penalty for invalid data
                                        reputation_manager
                                            .update_reputation(
                                                addr,
                                                misbehavior_scores::INVALID_TRANSACTION,
                                                "Invalid transaction type in block",
                                            )
                                            .await;
                                    } else if error_msg
                                        .contains("Failed to decode transactions for block")
                                    {
                                        // The error now includes the block hash
                                        log::error!("Peer {} sent block that failed transaction decoding: {}", addr, decode_error);
                                        // Try to extract the block hash from the error message
                                        if let Some(hash_start) = error_msg.find("block ") {
                                            if let Some(hash_end) =
                                                error_msg[hash_start + 6..].find(':')
                                            {
                                                let block_hash = &error_msg
                                                    [hash_start + 6..hash_start + 6 + hash_end];
                                                log::error!("FAILING BLOCK HASH: {}", block_hash);
                                            }
                                        }
                                    } else if error_msg.contains("IO error") {
                                        // This might be our wrapped error - log it prominently
                                        log::error!("BLOCK DECODE FAILURE - IO error (possibly unknown transaction type) from peer {}", addr);
                                        log::error!(
                                            "Serialization error from {}: {}",
                                            addr,
                                            decode_error
                                        );
                                    } else {
                                        log::error!(
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
            log::warn!("Disconnecting from {} (peer reader loop ended)", addr);
            Self::remove_peer_and_notify(
                &pool,
                &addr,
                &connected_peer_count,
                &network_event_sender,
            )
            .await;

            headers2_disabled.lock().await.remove(&addr);

            // Give small positive reputation if peer maintained long connection
            let conn_duration = Duration::from_secs(60 * loop_iteration); // Rough estimate
            if conn_duration > Duration::from_secs(3600) {
                // 1 hour
                reputation_manager
                    .update_reputation(addr, positive_scores::LONG_UPTIME, "Long connection uptime")
                    .await;
            }
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
            log::warn!("Request processor already started or receiver unavailable");
            return;
        };

        let this = self.clone();
        let shutdown_token = self.shutdown_token.clone();

        let mut tasks = self.tasks.lock().await;
        tasks.spawn(async move {
            log::info!("Starting request processor task");
            loop {
                tokio::select! {
                    request = request_rx.recv() => {
                        match request {
                            Some(NetworkRequest::SendMessage(msg)) => {
                                log::debug!("Request processor: sending {}", msg.cmd());
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
                                        log::error!("Request processor: failed to send message: {}", e);
                                    }
                                });
                            }
                            Some(NetworkRequest::SendMessageToPeer(msg, peer_address)) => {
                                log::debug!("Request processor: sending {} to peer {}", msg.cmd(), peer_address);
                                let this = this.clone();
                                tokio::spawn(async move {
                                    let fallback_msg = msg.clone();
                                    let result = match this.pool.get_peer(&peer_address).await {
                                        Some(peer) => match this.send_message_to_peer(&peer_address, &peer, msg).await {
                                            Ok(()) => Ok(()),
                                            Err(err) => {
                                                log::warn!(
                                                    "Target peer {} send failed ({}), falling back to distributed send",
                                                    peer_address,
                                                    err
                                                );
                                                this.send_distributed(fallback_msg).await
                                            }
                                        },
                                        None => {
                                            log::warn!(
                                                "Target peer {} disconnected, falling back to distributed send",
                                                peer_address
                                            );
                                            this.send_distributed(fallback_msg).await
                                        }
                                    };
                                    if let Err(e) = result {
                                        log::error!("Request processor: failed to send message to peer {}: {}", peer_address, e);
                                    }
                                });
                            }
                            None => {
                                log::info!("Request processor: channel closed");
                                break;
                            }
                        }
                    }
                    _ = shutdown_token.cancelled() => {
                        log::info!("Request processor: shutting down");
                        break;
                    }
                }
            }
        });
    }

    async fn maintenance_tick(&self) {
        // Remove peers that the reader loop failed to clean up.
        // This should not trigger under normal operation.
        let unhealthy = self.pool.remove_unhealthy().await;
        for addr in &unhealthy {
            log::warn!("Maintenance removed stale peer {} - reader loop missed cleanup", addr);
            Self::notify_peer_removed(
                &self.pool,
                addr,
                &self.connected_peer_count,
                &self.network_event_sender,
            )
            .await;
        }

        let count = self.pool.peer_count().await;
        log::debug!("Connected peers: {}", count);
        // Keep the cached counter in sync with actual pool count
        self.connected_peer_count.store(count, Ordering::Relaxed);
        if self.exclusive_mode {
            // In exclusive mode, only reconnect to originally specified peers
            for addr in self.initial_peers.iter() {
                if !self.pool.is_connected(addr).await && !self.pool.is_connecting(addr).await {
                    log::info!("Reconnecting to exclusive peer: {}", addr);
                    self.connect_to_peer(*addr).await;
                }
            }
        } else {
            // Normal mode: try to maintain minimum peer count with discovery
            if count < TARGET_PEERS {
                // Try known addresses first, sorted by reputation
                let known = self.addrv2_handler.get_known_addresses().await;
                let needed = TARGET_PEERS.saturating_sub(count);
                // Select best peers based on reputation
                let best_peers = self.reputation_manager.select_best_peers(known, needed * 2).await;
                let mut attempted = 0;

                for addr in best_peers {
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
                    log::error!("Failed to ping {}: {}", addr, e);
                    // Update reputation for ping failure
                    self.reputation_manager
                        .update_reputation(addr, misbehavior_scores::TIMEOUT, "Ping failed")
                        .await;
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
                    log::warn!("Failed to save peers: {}", e);
                }
            }

            // Save reputation data periodically
            if let Err(e) = self.reputation_manager.save_to_storage(&*self.peer_store).await {
                log::warn!("Failed to save reputation data: {}", e);
            }
        }
    }

    async fn dns_fallback_tick(&self) {
        let count = self.pool.peer_count().await;
        if count >= TARGET_PEERS {
            return;
        }
        let dns_peers = tokio::select! {
            peers = self.discovery.discover_peers(self.network) => peers,
            _ = self.shutdown_token.cancelled() => {
                log::info!("Maintenance loop shutting down during DNS discovery");
                return
            }
        };
        let needed = TARGET_PEERS.saturating_sub(count);
        log::debug!("DNS fallback tick found {} addresses. Needed {}", dns_peers.len(), needed);
        let mut dns_attempted = 0;
        for addr in dns_peers.iter() {
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
                        log::debug!("Maintenance interval elapsed");
                        this.maintenance_tick().await;
                    }
                    _ = dns_interval.tick(), if !this.exclusive_mode => {
                        this.dns_fallback_tick().await;
                    }
                    event = network_events.recv() => {
                        match event {
                            Ok(event) => {
                                log::debug!("Network event in maintenance loop: {}", event.description());
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
                        log::info!("Maintenance loop shutting down");
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
                    log::debug!("Selected peer {} with {} for {}", address, flags, message.cmd());
                    (address, peer)
                }
                None if required => {
                    log::warn!("No peers support {}, cannot send {}", flags, message.cmd());
                    return Err(NetworkError::ProtocolError(format!("No peers support {}", flags)));
                }
                None => self.next_peer(&peers),
            }
        } else {
            self.next_peer(&peers)
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

        let (addr, peer) = self.next_peer(&selected_peers);

        log::debug!("Distributing {} request to peer {}", message.cmd(), addr);

        self.send_message_to_peer(&addr, &peer, message).await
    }

    /// Pick the next peer from `peers` using round-robin rotation.
    fn next_peer(
        &self,
        peers: &[(SocketAddr, Arc<RwLock<Peer>>)],
    ) -> (SocketAddr, Arc<RwLock<Peer>>) {
        let idx = self.round_robin_counter.fetch_add(1, Ordering::Relaxed) % peers.len();
        (peers[idx].0, peers[idx].1.clone())
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
                    log::debug!("Upgrading GetHeaders to GetHeaders2 for peer {}", addr);
                    NetworkMessage::GetHeaders2(get_headers)
                } else {
                    NetworkMessage::GetHeaders(get_headers)
                }
            }
            other => other,
        };

        let mut peer_guard = peer.write().await;
        peer_guard
            .send_message(message)
            .await
            .map_err(|e| NetworkError::ProtocolError(format!("Failed to send to {}: {}", addr, e)))
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
                    log::debug!("Broadcasting {} to {}", message.cmd(), addr);
                }
                _ => {
                    log::trace!("Broadcasting {:?} to {}", message.cmd(), addr);
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
        log::info!("Disconnecting peer {} - reason: {}", addr, reason);

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
        log::info!("Manually banning peer {} - reason: {}", addr, reason);

        // Disconnect the peer first
        self.disconnect_peer(addr, reason).await?;

        // Update reputation to trigger ban
        self.reputation_manager
            .update_reputation(
                *addr,
                misbehavior_scores::INVALID_HEADER * 2, // Severe penalty
                reason,
            )
            .await;

        Ok(())
    }

    /// Unban a specific peer
    pub async fn unban_peer(&self, addr: &SocketAddr) {
        self.reputation_manager.unban_peer(addr).await;
    }

    /// Shutdown the network manager
    pub async fn shutdown(&self) {
        log::info!("Shutting down peer network manager");
        self.shutdown_token.cancel();

        // Save known peers before shutdown
        let addresses = self.addrv2_handler.get_addresses_for_peer(MAX_ADDR_TO_STORE).await;
        if !addresses.is_empty() {
            if let Err(e) = self.peer_store.save_peers(&addresses).await {
                log::warn!("Failed to save peers on shutdown: {}", e);
            }
        }

        // Save reputation data before shutdown
        if let Err(e) = self.reputation_manager.save_to_storage(&*self.peer_store).await {
            log::warn!("Failed to save reputation data on shutdown: {}", e);
        }

        // Drain tasks while holding the lock.  connect_to_peer() already uses
        // `select!` with the cancellation token when acquiring this lock, so no
        // deadlock can occur once the shutdown token is cancelled above.
        let mut tasks = self.tasks.lock().await;
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                log::error!("Task join error: {}", e);
            }
        }

        // Disconnect all peers
        for addr in self.pool.get_connected_addresses().await {
            self.pool.remove_peer(&addr).await;
        }
    }
}

// Implement Clone for use in async closures
impl Clone for PeerNetworkManager {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
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
            connected_peer_count: self.connected_peer_count.clone(),
            headers2_disabled: self.headers2_disabled.clone(),
            message_dispatcher: self.message_dispatcher.clone(),
            request_tx: self.request_tx.clone(),
            request_rx: self.request_rx.clone(),
            round_robin_counter: self.round_robin_counter.clone(),
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

    async fn disconnect_peer(&self, addr: &SocketAddr, reason: &str) -> NetworkResult<()> {
        PeerNetworkManager::disconnect_peer(self, addr, reason)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))
    }

    fn subscribe_network_events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.network_event_sender.subscribe()
    }
}
