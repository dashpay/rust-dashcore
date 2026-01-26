//! Peer network manager for SPV client

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time;

use crate::client::config::MempoolStrategy;
use crate::client::ClientConfig;
use crate::error::{NetworkError, NetworkResult, SpvError as Error};
use crate::network::addrv2::AddrV2Handler;
use crate::network::constants::*;
use crate::network::discovery::DnsDiscovery;
use crate::network::pool::PeerPool;
use crate::network::reputation::{ChangeReason, PeerReputationManager};
use crate::network::{
    HandshakeManager, Message, MessageDispatcher, MessageType, NetworkManager, Peer,
};
use crate::storage::{PeerStorage, PersistentPeerStorage, PersistentStorage};
use async_trait::async_trait;
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_headers2::CompressionState;
use dashcore::Network;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

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
    reputation_manager: Arc<Mutex<PeerReputationManager>>,
    /// Network type
    network: Network,
    /// Shutdown token
    shutdown_token: CancellationToken,
    /// Background tasks
    tasks: Arc<Mutex<JoinSet<()>>>,
    /// Initial peer addresses
    initial_peers: Vec<SocketAddr>,
    /// When we first started needing peers (for DNS delay)
    peer_search_started: Arc<Mutex<Option<SystemTime>>>,
    /// Current sync peer (sticky during sync operations)
    current_sync_peer: Arc<Mutex<Option<SocketAddr>>>,
    /// Data directory for storage
    data_dir: PathBuf,
    /// Mempool strategy from config
    mempool_strategy: MempoolStrategy,
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
}

impl PeerNetworkManager {
    /// Create a new peer network manager
    pub async fn new(config: &ClientConfig) -> Result<Self, Error> {
        let discovery = DnsDiscovery::new().await?;
        let data_dir = config.storage_path.clone().unwrap_or_else(|| PathBuf::from("."));

        let peer_store = PersistentPeerStorage::open(data_dir.clone()).await?;

        let reputation_manager = PeerReputationManager::load_or_new(&peer_store).await;

        // Determine exclusive mode: either explicitly requested or peers were provided
        let exclusive_mode = config.restrict_to_configured_peers || !config.peers.is_empty();

        Ok(Self {
            pool: Arc::new(PeerPool::new()),
            discovery: Arc::new(discovery),
            addrv2_handler: Arc::new(AddrV2Handler::new()),
            peer_store: Arc::new(peer_store),
            reputation_manager: Arc::new(Mutex::new(reputation_manager)),
            network: config.network,
            shutdown_token: CancellationToken::new(),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            initial_peers: config.peers.clone(),
            peer_search_started: Arc::new(Mutex::new(None)),
            current_sync_peer: Arc::new(Mutex::new(None)),
            data_dir,
            mempool_strategy: config.mempool_strategy,
            user_agent: config.user_agent.clone(),
            exclusive_mode,
            connected_peer_count: Arc::new(AtomicUsize::new(0)),
            headers2_disabled: Arc::new(Mutex::new(HashSet::new())),
            message_dispatcher: Arc::new(Mutex::new(MessageDispatcher::default())),
        })
    }

    /// Creates and returns a receiver that yields only messages of the matching the provided message types.
    pub async fn message_receiver(
        &mut self,
        message_types: &[MessageType],
    ) -> UnboundedReceiver<Message> {
        self.message_dispatcher.lock().await.message_receiver(message_types)
    }

    /// Start the network manager
    pub async fn start(&self) -> Result<(), Error> {
        log::info!("Starting peer network manager for {:?}", self.network);

        let mut peer_addresses = self.initial_peers.clone();

        if self.exclusive_mode {
            log::info!(
                "Exclusive peer mode: connecting ONLY to {} specified peer(s)",
                self.initial_peers.len()
            );
        } else {
            // Load saved peers from disk
            let saved_peers = self.peer_store.load_peers().await.unwrap_or_default();
            peer_addresses.extend(saved_peers);

            // If we still have no peers, immediately discover via DNS
            if peer_addresses.is_empty() {
                log::info!(
                    "No peers configured, performing immediate DNS discovery for {:?}",
                    self.network
                );
                let dns_peers = self.discovery.discover_peers(self.network).await;
                peer_addresses.extend(dns_peers.iter().take(TARGET_PEERS));
                log::info!(
                    "DNS discovery found {} peers, using {} for startup",
                    dns_peers.len(),
                    peer_addresses.len()
                );
            } else {
                log::info!(
                    "Starting with {} peers from disk (DNS discovery will be used later if needed)",
                    peer_addresses.len()
                );
            }
        }

        // Connect to peers (all in exclusive mode, or up to TARGET_PEERS in normal mode)
        let max_connections = if self.exclusive_mode {
            peer_addresses.len()
        } else {
            TARGET_PEERS
        };
        for addr in peer_addresses.iter().take(max_connections) {
            self.connect_to_peer(*addr).await;
        }

        // Start maintenance loop
        self.start_maintenance_loop().await;

        Ok(())
    }

    /// Connect to a specific peer
    async fn connect_to_peer(&self, addr: SocketAddr) {
        // Check reputation first
        if !self.reputation_manager.lock().await.should_connect_to_peer(&addr).await {
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
        self.reputation_manager.lock().await.record_connection_attempt(addr).await;

        let pool = self.pool.clone();
        let network = self.network;
        let addrv2_handler = self.addrv2_handler.clone();
        let shutdown_token = self.shutdown_token.clone();
        let reputation_manager = self.reputation_manager.clone();
        let mempool_strategy = self.mempool_strategy;
        let user_agent = self.user_agent.clone();
        let connected_peer_count = self.connected_peer_count.clone();
        let headers2_disabled = self.headers2_disabled.clone();
        let message_dispatcher = self.message_dispatcher.clone();

        // Spawn connection task
        let mut tasks = self.tasks.lock().await;
        tasks.spawn(async move {
            log::debug!("Attempting to connect to {}", addr);

            match Peer::connect(addr, CONNECTION_TIMEOUT.as_secs(), network).await {
                Ok(mut peer) => {
                    // Perform handshake
                    let mut handshake_manager =
                        HandshakeManager::new(network, mempool_strategy, user_agent);
                    match handshake_manager.perform_handshake(&mut peer).await {
                        Ok(_) => {
                            log::info!("Successfully connected to {}", addr);

                            // Add to pool
                            if let Err(e) = pool.add_peer(addr, peer).await {
                                log::error!("Failed to add peer to pool: {}", e);
                                return;
                            }

                            // Increment connected peer counter on successful add
                            connected_peer_count.fetch_add(1, Ordering::Relaxed);

                            // Add to known addresses
                            addrv2_handler.add_known_address(addr, ServiceFlags::from(1)).await;

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
                            )
                            .await;
                        }
                        Err(e) => {
                            log::warn!("Handshake failed with {}: {}", addr, e);
                            // Update reputation for handshake failure
                            reputation_manager
                                .lock()
                                .await
                                .update_reputation(addr, ChangeReason::HandshakeFailure)
                                .await;
                            // For handshake failures, try again later
                            tokio::time::sleep(RECONNECT_DELAY).await;
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Failed to connect to {}: {}", addr, e);
                    // Minor reputation penalty for connection failure
                    reputation_manager
                        .lock()
                        .await
                        .update_reputation(addr, ChangeReason::ConnectionFailure)
                        .await;
                }
            }
        });
    }

    /// Start reading messages from a peer
    #[allow(clippy::too_many_arguments)] // TODO: refactor to reduce arguments
    async fn start_peer_reader(
        addr: SocketAddr,
        pool: Arc<PeerPool>,
        addrv2_handler: Arc<AddrV2Handler>,
        shutdown_token: CancellationToken,
        reputation_manager: Arc<Mutex<PeerReputationManager>>,
        connected_peer_count: Arc<AtomicUsize>,
        headers2_disabled: Arc<Mutex<HashSet<SocketAddr>>>,
        message_dispatcher: Arc<Mutex<MessageDispatcher>>,
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
                            NetworkMessage::Addr(_) => {
                                // Handle legacy addr messages (convert to AddrV2 if needed)
                                log::trace!("Received legacy addr message from {}", addr);
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
                                            .lock()
                                            .await
                                            .update_reputation(addr, ChangeReason::InvalidHeaders2)
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
                                    .lock()
                                    .await
                                    .update_reputation(addr, ChangeReason::Timeout)
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
                                            .lock()
                                            .await
                                            .update_reputation(
                                                addr,
                                                ChangeReason::InvalidTransaction,
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

                                // For other errors, wait a bit then break
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                break;
                            }
                        }
                    }
                }
            }

            // Remove from pool
            log::warn!("Disconnecting from {} (peer reader loop ended)", addr);
            let removed = pool.remove_peer(&addr).await;
            if removed.is_some() {
                // Decrement connected peer counter when a peer is removed
                connected_peer_count.fetch_sub(1, Ordering::Relaxed);
            }

            headers2_disabled.lock().await.remove(&addr);

            // Give small positive reputation if peer maintained long connection
            let conn_duration = Duration::from_secs(60 * loop_iteration); // Rough estimate
            if conn_duration > Duration::from_secs(3600) {
                // 1 hour
                reputation_manager
                    .lock()
                    .await
                    .update_reputation(addr, ChangeReason::LongUptime)
                    .await;
            }
        });
    }

    /// Start peer connection maintenance loop
    async fn start_maintenance_loop(&self) {
        let pool = self.pool.clone();
        let discovery = self.discovery.clone();
        let network = self.network;
        let shutdown_token = self.shutdown_token.clone();
        let addrv2_handler = self.addrv2_handler.clone();
        let peer_store = self.peer_store.clone();
        let reputation_manager = self.reputation_manager.clone();
        let peer_search_started = self.peer_search_started.clone();
        let initial_peers = self.initial_peers.clone();
        let connected_peer_count = self.connected_peer_count.clone();

        // Check if we're in exclusive mode (explicit flag or peers configured)
        let exclusive_mode = self.exclusive_mode;

        // Clone self for peer callback
        let connect_fn = {
            let this = self.clone();
            move |addr| {
                let this = this.clone();
                async move { this.connect_to_peer(addr).await }
            }
        };

        let mut tasks = self.tasks.lock().await;
        tasks.spawn(async move {
            while !shutdown_token.is_cancelled() {
                // Clean up disconnected peers
                pool.cleanup_disconnected().await;

                let count = pool.peer_count().await;
                log::debug!("Connected peers: {}", count);
                // Keep the cached counter in sync with actual pool count
                connected_peer_count.store(count, Ordering::Relaxed);
                if exclusive_mode {
                    // In exclusive mode, only reconnect to originally specified peers
                    for addr in initial_peers.iter() {
                        if !pool.is_connected(addr).await && !pool.is_connecting(addr).await {
                            log::info!("Reconnecting to exclusive peer: {}", addr);
                            tokio::select! {
                                _= connect_fn(*addr) => {},
                                _ = shutdown_token.cancelled() => {
                                    log::info!("Maintenance loop shutting down during connection attempt (exclusive)");
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    // Normal mode: try to maintain minimum peer count with discovery
                    if count < MIN_PEERS {
                        // Track when we first started needing peers
                        let mut search_started = peer_search_started.lock().await;
                        if search_started.is_none() {
                            *search_started = Some(SystemTime::now());
                            log::info!("Below minimum peers ({}/{}), starting peer search (will try DNS after {}s)", count, MIN_PEERS, DNS_DISCOVERY_DELAY.as_secs());
                        }
                        let search_time = match *search_started {
                            Some(time) => time,
                            None => {
                                log::error!("Search time not set when expected");
                                continue;
                            }
                        };
                        drop(search_started);

                        // Try known addresses first, sorted by reputation
                        let known = addrv2_handler.get_known_addresses().await;
                        let needed = TARGET_PEERS.saturating_sub(count);
                        // Select best peers based on reputation
                        let best_peers = reputation_manager.lock().await.select_best_peers(known, needed * 2).await;
                        let mut attempted = 0;

                        for addr in best_peers {
                            if !pool.is_connected(&addr).await && !pool.is_connecting(&addr).await {
                                tokio::select! {
                                    _= connect_fn(addr) => {},
                                    _ = shutdown_token.cancelled() => {
                                        log::info!("Maintenance loop shutting down during connection attempt (min peers)");
                                        break;
                                    }
                                }
                                attempted += 1;
                                if attempted >= needed {
                                    break;
                                }
                            }
                        }

                        // If still need more, check if we can use DNS (after 10 second delay)
                        let count = pool.peer_count().await;
                        if count < MIN_PEERS {
                            let elapsed = SystemTime::now()
                                .duration_since(search_time)
                                .unwrap_or_else(|e| {
                                    log::warn!("System time error calculating elapsed time: {}", e);
                                    Duration::ZERO
                                });
                            if elapsed >= DNS_DISCOVERY_DELAY {
                                log::info!("Using DNS discovery after {}s delay", elapsed.as_secs());
                                let dns_peers = tokio::select! {
                                    peers = discovery.discover_peers(network) => peers,
                                    _ = shutdown_token.cancelled() => {
                                        log::info!("Maintenance loop shutting down during DNS discovery");
                                        break;
                                    }
                                };
                                let mut dns_attempted = 0;
                                for addr in dns_peers.into_iter() {
                                    if !pool.is_connected(&addr).await && !pool.is_connecting(&addr).await {
                                        tokio::select! {
                                            _= connect_fn(addr) => {},
                                            _ = shutdown_token.cancelled() => {
                                                log::info!("Maintenance loop shutting down during connection attempt (dns)");
                                                break;
                                            }
                                        }
                                        dns_attempted += 1;
                                        if dns_attempted >= needed {
                                            break;
                                        }
                                    }
                                }
                            } else {
                                log::debug!("Waiting for DNS delay: {}s elapsed, need {}s", elapsed.as_secs(), DNS_DISCOVERY_DELAY.as_secs());
                            }
                        }
                    } else {
                        // We have enough peers, reset the search timer
                        let mut search_started = peer_search_started.lock().await;
                        if search_started.is_some() {
                            log::trace!("Peer count restored, resetting DNS delay timer");
                            *search_started = None;
                        }
                    }
                }

                // Send ping to all peers if needed
                for (addr, peer) in pool.get_all_peers().await {
                    let mut peer_guard = peer.write().await;
                    if peer_guard.should_ping() {
                        if let Err(e) = peer_guard.send_ping().await {
                            log::error!("Failed to ping {}: {}", addr, e);
                            // Update reputation for ping failure
                            reputation_manager.lock().await.update_reputation(
                                addr,
                                ChangeReason::PingFailure,
                            ).await;
                        }
                    }
                    peer_guard.cleanup_old_pings();
                }

                // Only save known peers if not in exclusive mode
                if !exclusive_mode {
                    let addresses = addrv2_handler.get_addresses_for_peer(MAX_ADDR_TO_STORE).await;
                    if !addresses.is_empty() {
                        if let Err(e) = peer_store.save_peers(&addresses).await {
                            log::warn!("Failed to save peers: {}", e);
                        }
                    }

                    // Save reputation data periodically
                    if let Err(e) = reputation_manager.lock().await.save_to_storage(&*peer_store).await {
                        log::warn!("Failed to save reputation data: {}", e);
                    }
                }

                tokio::select! {
                    _ = time::sleep(MAINTENANCE_INTERVAL) => {
                        log::debug!("Maintenance interval elapsed");
                    }
                    _ = shutdown_token.cancelled() => {
                        log::info!("Maintenance loop shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Send a message to a single peer (using sticky peer selection for sync consistency)
    async fn send_to_single_peer(&self, message: NetworkMessage) -> NetworkResult<()> {
        let peers = self.pool.get_all_peers().await;

        if peers.is_empty() {
            return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
        }

        // For filter-related messages, we need a peer that supports compact filters
        let requires_compact_filters =
            matches!(&message, NetworkMessage::GetCFHeaders(_) | NetworkMessage::GetCFilters(_));
        let check_headers2 =
            matches!(&message, NetworkMessage::GetHeaders(_) | NetworkMessage::GetHeaders2(_));

        let selected_peer = if requires_compact_filters {
            // Find a peer that supports compact filters
            let mut filter_peer = None;
            for (addr, peer) in &peers {
                let peer_guard = peer.read().await;

                if peer_guard.supports_compact_filters() {
                    filter_peer = Some(*addr);
                    break;
                }
            }

            match filter_peer {
                Some(addr) => {
                    log::debug!("Selected peer {} for compact filter request", addr);
                    addr
                }
                None => {
                    log::warn!("No peers support compact filters, cannot send {}", message.cmd());
                    return Err(NetworkError::ProtocolError(
                        "No peers support compact filters".to_string(),
                    ));
                }
            }
        } else if check_headers2 {
            // Prefer a peer that advertises headers2 support
            let mut current_sync_peer = self.current_sync_peer.lock().await;
            let mut selected: Option<SocketAddr> = None;

            if let Some(current_addr) = *current_sync_peer {
                if let Some((_, peer)) = peers.iter().find(|(addr, _)| *addr == current_addr) {
                    let peer_guard = peer.read().await;
                    if peer_guard.supports_headers2() {
                        selected = Some(current_addr);
                    }
                }
            }

            if selected.is_none() {
                for (addr, peer) in &peers {
                    let peer_guard = peer.read().await;
                    if peer_guard.supports_headers2() {
                        selected = Some(*addr);
                        break;
                    }
                }
            }

            let chosen = selected.unwrap_or(peers[0].0);
            if Some(chosen) != *current_sync_peer {
                log::info!("Sync peer selected for Headers2: {}", chosen);
                *current_sync_peer = Some(chosen);
            }
            drop(current_sync_peer);
            chosen
        } else {
            // For non-filter messages, use the sticky sync peer
            let mut current_sync_peer = self.current_sync_peer.lock().await;
            let selected = if let Some(current_addr) = *current_sync_peer {
                // Check if current sync peer is still connected
                if peers.iter().any(|(addr, _)| *addr == current_addr) {
                    // Keep using the same peer for sync consistency
                    current_addr
                } else {
                    // Current sync peer disconnected, pick a new one
                    let new_addr = peers[0].0;
                    log::info!(
                        "Sync peer switched from {} to {} (previous peer disconnected)",
                        current_addr,
                        new_addr
                    );
                    *current_sync_peer = Some(new_addr);
                    new_addr
                }
            } else {
                // No current sync peer, pick the first available
                let new_addr = peers[0].0;
                log::info!("Sync peer selected: {}", new_addr);
                *current_sync_peer = Some(new_addr);
                new_addr
            };
            drop(current_sync_peer);
            selected
        };

        // Find the peer for the selected address
        let (addr, peer) = peers
            .iter()
            .find(|(a, _)| *a == selected_peer)
            .ok_or_else(|| NetworkError::ConnectionFailed("Selected peer not found".to_string()))?;

        // Upgrade GetHeaders to GetHeaders2 if this specific peer supports it and not disabled
        let peer_supports_headers2 = {
            let peer_guard = peer.read().await;
            peer_guard.can_request_headers2()
        };
        let message = match message {
            NetworkMessage::GetHeaders(get_headers)
                if !self.headers2_disabled.lock().await.contains(addr)
                    && peer_supports_headers2 =>
            {
                log::debug!(
                    "Upgrading GetHeaders to GetHeaders2 for peer {}: {:?}",
                    addr,
                    get_headers
                );
                NetworkMessage::GetHeaders2(get_headers)
            }
            other => other,
        };
        // Reduce verbosity for common sync messages
        match &message {
            NetworkMessage::GetHeaders(_)
            | NetworkMessage::GetCFilters(_)
            | NetworkMessage::GetCFHeaders(_) => {
                log::debug!("Sending {} to {}", message.cmd(), addr);
            }
            NetworkMessage::GetHeaders2(gh2) => {
                log::info!("📤 Sending GetHeaders2 to {} - version: {}, locator_count: {}, locator: {:?}, stop: {}",
                    addr,
                    gh2.version,
                    gh2.locator_hashes.len(),
                    gh2.locator_hashes.iter().take(2).collect::<Vec<_>>(),
                    gh2.stop_hash
                );
            }
            NetworkMessage::SendHeaders2 => {
                log::info!("🤝 Sending SendHeaders2 to {} - requesting compressed headers", addr);
            }
            _ => {
                log::trace!("Sending {:?} to {}", message.cmd(), addr);
            }
        }

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

        // Remove the peer
        self.pool.remove_peer(addr).await;

        Ok(())
    }

    /// Get reputation information for all peers
    pub async fn get_peer_reputations(&self) -> HashMap<SocketAddr, (i32, bool)> {
        let mut lock = self.reputation_manager.lock().await;
        let reputations = lock.get_all_reputations().await;
        reputations.iter().map(|(addr, rep)| (*addr, (rep.score(), rep.is_banned()))).collect()
    }

    /// Ban a specific peer manually
    pub async fn ban_peer(&self, addr: &SocketAddr, reason: &str) -> Result<(), Error> {
        log::info!("Manually banning peer {} - reason: {}", addr, reason);

        // Disconnect the peer first
        self.disconnect_peer(addr, reason).await?;

        // Update reputation to trigger ban
        self.reputation_manager
            .lock()
            .await
            .update_reputation(*addr, ChangeReason::ManuallyBanned)
            .await;

        Ok(())
    }

    /// Unban a specific peer
    pub async fn unban_peer(&self, addr: &SocketAddr) {
        self.reputation_manager.lock().await.unban_peer(addr).await;
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
        if let Err(e) =
            self.reputation_manager.lock().await.save_to_storage(&*self.peer_store).await
        {
            log::warn!("Failed to save reputation data on shutdown: {}", e);
        }

        // Wait for tasks to complete
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
            peer_search_started: self.peer_search_started.clone(),
            current_sync_peer: self.current_sync_peer.clone(),
            data_dir: self.data_dir.clone(),
            mempool_strategy: self.mempool_strategy,
            user_agent: self.user_agent.clone(),
            exclusive_mode: self.exclusive_mode,
            connected_peer_count: self.connected_peer_count.clone(),
            headers2_disabled: self.headers2_disabled.clone(),
            message_dispatcher: self.message_dispatcher.clone(),
        }
    }
}

// Implement NetworkManager trait
#[async_trait]
impl NetworkManager for PeerNetworkManager {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn message_receiver(&mut self, types: &[MessageType]) -> UnboundedReceiver<Message> {
        self.message_dispatcher.lock().await.message_receiver(types)
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

    async fn penalize_peer(&self, address: SocketAddr, reason: ChangeReason) {
        self.reputation_manager.lock().await.update_reputation(address, reason).await;
    }

    async fn penalize_peer_invalid_chainlock(&self, address: SocketAddr) {
        match self.disconnect_peer(&address, &ChangeReason::InvalidChainLock.to_string()).await {
            Ok(()) => {
                log::warn!("Peer {} disconnected for invalid ChainLock enforcement", address,);
            }
            Err(err) => {
                log::error!(
                    "Failed to disconnect peer {} after invalid ChainLock enforcement: {}",
                    address,
                    err
                );
            }
        }

        // Apply misbehavior score and a short temporary ban
        self.reputation_manager
            .lock()
            .await
            .update_reputation(address, ChangeReason::InvalidChainLock)
            .await;

        // Short ban: 10 minutes for relaying invalid ChainLock
        self.reputation_manager
            .lock()
            .await
            .temporary_ban_peer(address, Duration::from_secs(10 * 60))
            .await;
    }

    async fn penalize_peer_invalid_instantlock(&self, address: SocketAddr) {
        // Apply misbehavior score and a short temporary ban
        self.reputation_manager
            .lock()
            .await
            .update_reputation(address, ChangeReason::InvalidInstantLock)
            .await;

        // Short ban: 10 minutes for relaying invalid InstantLock
        self.reputation_manager
            .lock()
            .await
            .temporary_ban_peer(address, Duration::from_secs(10 * 60))
            .await;

        match self.disconnect_peer(&address, &ChangeReason::InvalidInstantLock.to_string()).await {
            Ok(()) => {
                log::warn!("Peer {} disconnected for invalid InstantLock enforcement", address,);
            }
            Err(err) => {
                log::error!(
                    "Failed to disconnect peer {} after invalid InstantLock enforcement: {}",
                    address,
                    err
                );
            }
        }
    }

    fn is_connected(&self) -> bool {
        // Use cached counter to avoid blocking in async context
        self.connected_peer_count.load(Ordering::Relaxed) > 0
    }

    fn peer_count(&self) -> usize {
        // Use cached counter to avoid blocking in async context
        self.connected_peer_count.load(Ordering::Relaxed)
    }

    async fn get_peer_best_height(&self) -> NetworkResult<Option<u32>> {
        let peers = self.pool.get_all_peers().await;

        if peers.is_empty() {
            log::debug!("get_peer_best_height: No peers available");
            return Ok(None);
        }

        let mut best_height = 0u32;
        let mut peer_count = 0;

        for (addr, peer) in peers.iter() {
            let peer_guard = peer.read().await;

            peer_count += 1;

            if let Some(peer_height) = peer_guard.best_height() {
                if peer_height > 0 {
                    best_height = best_height.max(peer_height);
                    log::debug!(
                        "get_peer_best_height: Updated best_height to {} from peer {}",
                        best_height,
                        addr
                    );
                }
            }
        }

        log::debug!(
            "get_peer_best_height: Checked {} peers, best_height: {}",
            peer_count,
            best_height
        );

        if best_height > 0 {
            Ok(Some(best_height))
        } else {
            Ok(None)
        }
    }

    async fn has_peer_with_service(&self, service_flags: ServiceFlags) -> bool {
        let peers = self.pool.get_all_peers().await;

        for (_, peer) in peers.iter() {
            let peer_guard = peer.read().await;
            if peer_guard.has_service(service_flags) {
                return true;
            }
        }

        false
    }
}
