//! Multi-peer network manager for SPV client

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time;

use dashcore::Network;
use dashcore::network::message::NetworkMessage;
use dashcore::network::constants::ServiceFlags;
use async_trait::async_trait;

use crate::error::{SpvError as Error, NetworkError, NetworkResult};
use crate::network::{NetworkManager, TcpConnection, HandshakeManager};
use crate::network::addrv2::AddrV2Handler;
use crate::network::constants::*;
use crate::network::discovery::DnsDiscovery;
use crate::network::persist::PeerStore;
use crate::network::pool::ConnectionPool;
use crate::client::ClientConfig;
use crate::types::PeerInfo;

/// Multi-peer network manager
pub struct MultiPeerNetworkManager {
    /// Connection pool
    pool: Arc<ConnectionPool>,
    /// DNS discovery
    discovery: Arc<DnsDiscovery>,
    /// AddrV2 handler
    addrv2_handler: Arc<AddrV2Handler>,
    /// Peer persistence
    peer_store: Arc<PeerStore>,
    /// Network type
    network: Network,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Channel for incoming messages
    message_tx: mpsc::Sender<(SocketAddr, NetworkMessage)>,
    message_rx: Arc<Mutex<mpsc::Receiver<(SocketAddr, NetworkMessage)>>>,
    /// Background tasks
    tasks: Arc<Mutex<JoinSet<()>>>,
    /// Initial peer addresses
    initial_peers: Vec<SocketAddr>,
    /// When we first started needing peers (for DNS delay)
    peer_search_started: Arc<Mutex<Option<SystemTime>>>,
    /// Current sync peer (sticky during sync operations)
    current_sync_peer: Arc<Mutex<Option<SocketAddr>>>,
}

impl MultiPeerNetworkManager {
    /// Create a new multi-peer network manager
    pub async fn new(config: &ClientConfig) -> Result<Self, Error> {
        let (message_tx, message_rx) = mpsc::channel(1000);
        
        let discovery = DnsDiscovery::new().await?;
        let data_dir = config.storage_path.clone().unwrap_or_else(|| PathBuf::from("."));
        let peer_store = PeerStore::new(config.network, data_dir);
        
        
        Ok(Self {
            pool: Arc::new(ConnectionPool::new()),
            discovery: Arc::new(discovery),
            addrv2_handler: Arc::new(AddrV2Handler::new()),
            peer_store: Arc::new(peer_store),
            network: config.network,
            shutdown: Arc::new(AtomicBool::new(false)),
            message_tx,
            message_rx: Arc::new(Mutex::new(message_rx)),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            initial_peers: config.peers.clone(),
            peer_search_started: Arc::new(Mutex::new(None)),
            current_sync_peer: Arc::new(Mutex::new(None)),
        })
    }
    
    /// Start the network manager
    pub async fn start(&self) -> Result<(), Error> {
        log::info!("Starting multi-peer network manager for {:?}", self.network);
        
        let mut peer_addresses = self.initial_peers.clone();
        
        // If specific peers were configured via -p flag, use ONLY those (exclusive mode)
        let exclusive_mode = !self.initial_peers.is_empty();
        
        if exclusive_mode {
            log::info!("Exclusive peer mode: connecting ONLY to {} specified peer(s)", self.initial_peers.len());
        } else {
            // Load saved peers only if no specific peers were configured
            let saved_peers = self.peer_store.load_peers().await.unwrap_or_default();
            peer_addresses.extend(saved_peers);
            log::info!("Starting with {} peers from config/disk (skipping DNS for now)", peer_addresses.len());
        }
        
        // Connect to peers (all in exclusive mode, or up to TARGET_PEERS in normal mode)
        let max_connections = if exclusive_mode { peer_addresses.len() } else { TARGET_PEERS };
        for addr in peer_addresses.iter().take(max_connections) {
            self.connect_to_peer(*addr).await;
        }
        
        // Start maintenance loop
        self.start_maintenance_loop().await;
        
        Ok(())
    }
    
    /// Connect to a specific peer
    async fn connect_to_peer(&self, addr: SocketAddr) {
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
        let message_tx = self.message_tx.clone();
        let addrv2_handler = self.addrv2_handler.clone();
        let shutdown = self.shutdown.clone();
        
        // Spawn connection task
        let mut tasks = self.tasks.lock().await;
        tasks.spawn(async move {
            log::debug!("Attempting to connect to {}", addr);
            
            match TcpConnection::connect(addr, CONNECTION_TIMEOUT.as_secs()).await {
                Ok(mut conn) => {
                    // Perform handshake
                    let mut handshake_manager = HandshakeManager::new(network);
                    match handshake_manager.perform_handshake(&mut conn).await {
                        Ok(_) => {
                            log::info!("Successfully connected to {}", addr);
                            
                            // Add to pool
                            if let Err(e) = pool.add_connection(addr, conn).await {
                                log::error!("Failed to add connection to pool: {}", e);
                                return;
                            }
                            
                            // Add to known addresses
                            addrv2_handler.add_known_address(addr, ServiceFlags::from(1)).await;
                            
                            // // Start message reader for this peer
                            Self::start_peer_reader(
                                addr,
                                pool.clone(),
                                message_tx,
                                addrv2_handler,
                                shutdown,
                            ).await;
                        }
                        Err(e) => {
                            log::warn!("Handshake failed with {}: {}", addr, e);
                            // For handshake failures, try again later
                            tokio::time::sleep(RECONNECT_DELAY).await;
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Failed to connect to {}: {}", addr, e);
                }
            }
        });
    }
    
    /// Start reading messages from a peer
    async fn start_peer_reader(
        addr: SocketAddr,
        pool: Arc<ConnectionPool>,
        message_tx: mpsc::Sender<(SocketAddr, NetworkMessage)>,
        addrv2_handler: Arc<AddrV2Handler>,
        shutdown: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            log::debug!("Starting peer reader loop for {}", addr);
            let mut loop_iteration = 0;
            
            while !shutdown.load(Ordering::Relaxed) {
                loop_iteration += 1;
                log::trace!("Peer reader loop iteration {} for {}", loop_iteration, addr);
                
                // Check shutdown signal first with detailed logging
                if shutdown.load(Ordering::Relaxed) {
                    log::info!("Breaking peer reader loop for {} - shutdown signal received (iteration {})", addr, loop_iteration);
                    break;
                }
                
                // Get connection
                let conn = match pool.get_connection(&addr).await {
                    Some(conn) => conn,
                    None => {
                        log::warn!("Breaking peer reader loop for {} - connection no longer in pool (iteration {})", addr, loop_iteration);
                        break;
                    }
                };
                
                // Read message with minimal lock time
                let msg_result = {
                    // Try to get a read lock first to check if connection is available
                    let conn_guard = conn.read().await;
                    if !conn_guard.is_connected() {
                        log::warn!("Breaking peer reader loop for {} - connection no longer connected (iteration {})", addr, loop_iteration);
                        drop(conn_guard);
                        break;
                    }
                    drop(conn_guard);
                    
                    // Now get write lock only for the duration of the read
                    let mut conn_guard = conn.write().await;
                    conn_guard.receive_message().await
                };
                
                match msg_result {
                    Ok(Some(msg)) => {
                        log::trace!("Received {:?} from {}", msg.cmd(), addr);
                        
                        // Handle some messages directly
                        match &msg {
                            NetworkMessage::SendAddrV2 => {
                                addrv2_handler.handle_sendaddrv2(addr).await;
                                continue; // Don't forward to client
                            }
                            NetworkMessage::AddrV2(addresses) => {
                                addrv2_handler.handle_addrv2(addresses.clone()).await;
                                continue; // Don't forward to client
                            }
                            NetworkMessage::GetAddr => {
                                log::trace!("Received GetAddr from {}, sending known addresses", addr);
                                // Send our known addresses
                                let response = addrv2_handler.build_addr_response().await;
                                let mut conn_guard = conn.write().await;
                                if let Err(e) = conn_guard.send_message(response).await {
                                    log::error!("Failed to send addr response to {}: {}", addr, e);
                                }
                                continue; // Don't forward GetAddr to client
                            }
                            NetworkMessage::Ping(nonce) => {
                                // Handle ping directly
                                let mut conn_guard = conn.write().await;
                                if let Err(e) = conn_guard.handle_ping(*nonce).await {
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
                                let mut conn_guard = conn.write().await;
                                if let Err(e) = conn_guard.handle_pong(*nonce) {
                                    log::error!("Failed to handle pong from {}: {}", addr, e);
                                }
                                continue; // Don't forward pong to client
                            }
                            NetworkMessage::Version(_) | NetworkMessage::Verack => {
                                // These are handled during handshake, ignore here
                                log::trace!("Ignoring handshake message {:?} from {}", msg.cmd(), addr);
                                continue;
                            }
                            NetworkMessage::Addr(_) => {
                                // Handle legacy addr messages (convert to AddrV2 if needed)
                                log::trace!("Received legacy addr message from {}", addr);
                                continue;
                            }
                            _ => {
                                // Forward other messages to client
                                log::trace!("Forwarding {:?} from {} to client", msg.cmd(), addr);
                            }
                        }
                        
                        
                        // Forward message to client
                        if message_tx.send((addr, msg)).await.is_err() {
                            log::warn!("Breaking peer reader loop for {} - failed to send message to client channel (iteration {})", addr, loop_iteration);
                            break;
                        }
                    }
                    Ok(None) => {
                        // No message available, brief pause to avoid aggressive polling but stay responsive
                        time::sleep(MESSAGE_POLL_INTERVAL).await;
                    }
                    Err(e) => {
                        match e {
                            NetworkError::PeerDisconnected => {
                                log::info!("Peer {} disconnected", addr);
                                break;
                            }
                            NetworkError::Timeout => {
                                log::debug!("Timeout reading from {}, continuing...", addr);
                                continue;
                            }
                            _ => {
                                log::error!("Fatal error reading from {}: {}", addr, e);
                                
                                // Check if this is a serialization error that might have context
                                if let NetworkError::Serialization(ref decode_error) = e {
                                    let error_msg = decode_error.to_string();
                                    if error_msg.contains("unknown special transaction type") {
                                        log::warn!("Peer {} sent block with unsupported transaction type: {}", addr, decode_error);
                                        log::error!("BLOCK DECODE FAILURE - Error details: {}", error_msg);
                                    } else if error_msg.contains("Failed to decode transactions for block") {
                                        // The error now includes the block hash
                                        log::error!("Peer {} sent block that failed transaction decoding: {}", addr, decode_error);
                                        // Try to extract the block hash from the error message
                                        if let Some(hash_start) = error_msg.find("block ") {
                                            if let Some(hash_end) = error_msg[hash_start + 6..].find(':') {
                                                let block_hash = &error_msg[hash_start + 6..hash_start + 6 + hash_end];
                                                log::error!("FAILING BLOCK HASH: {}", block_hash);
                                            }
                                        }
                                    } else if error_msg.contains("IO error") {
                                        // This might be our wrapped error - log it prominently
                                        log::error!("BLOCK DECODE FAILURE - IO error (possibly unknown transaction type) from peer {}", addr);
                                        log::error!("Serialization error from {}: {}", addr, decode_error);
                                    } else {
                                        log::error!("Serialization error from {}: {}", addr, decode_error);
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
            pool.remove_connection(&addr).await;
        });
    }
    
    /// Start connection maintenance loop
    async fn start_maintenance_loop(&self) {
        let pool = self.pool.clone();
        let discovery = self.discovery.clone();
        let network = self.network;
        let shutdown = self.shutdown.clone();
        let addrv2_handler = self.addrv2_handler.clone();
        let peer_store = self.peer_store.clone();
        let peer_search_started = self.peer_search_started.clone();
        let initial_peers = self.initial_peers.clone();
        
        // Check if we're in exclusive mode (specific peers configured via -p)
        let exclusive_mode = !initial_peers.is_empty();
        
        // Clone self for connection callback
        let connect_fn = {
            let this = self.clone();
            move |addr| {
                let this = this.clone();
                async move { this.connect_to_peer(addr).await }
            }
        };
        
        let mut tasks = self.tasks.lock().await;
        tasks.spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                // Clean up disconnected peers
                pool.cleanup_disconnected().await;
                
                let count = pool.connection_count().await;
                log::debug!("Connected peers: {}", count);
                
                if exclusive_mode {
                    // In exclusive mode, only reconnect to originally specified peers
                    for addr in initial_peers.iter() {
                        if !pool.is_connected(addr).await && !pool.is_connecting(addr).await {
                            log::info!("Reconnecting to exclusive peer: {}", addr);
                            connect_fn(*addr).await;
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
                        let search_time = search_started.unwrap();
                        drop(search_started);
                        
                        // Try known addresses first
                        let known = addrv2_handler.get_known_addresses().await;
                        let needed = TARGET_PEERS.saturating_sub(count);
                        let mut attempted = 0;
                        
                        for addr in known.into_iter().take(needed * 2) { // Try more to account for failures
                            if !pool.is_connected(&addr).await && !pool.is_connecting(&addr).await {
                                connect_fn(addr).await;
                                attempted += 1;
                                if attempted >= needed {
                                    break;
                                }
                            }
                        }
                        
                        // If still need more, check if we can use DNS (after 10 second delay)
                        let count = pool.connection_count().await;
                        if count < MIN_PEERS {
                            let elapsed = SystemTime::now().duration_since(search_time).unwrap_or(Duration::ZERO);
                            if elapsed >= DNS_DISCOVERY_DELAY {
                                log::info!("Using DNS discovery after {}s delay", elapsed.as_secs());
                                let dns_peers = discovery.discover_peers(network).await;
                                let mut dns_attempted = 0;
                                for addr in dns_peers.into_iter() {
                                    if !pool.is_connected(&addr).await && !pool.is_connecting(&addr).await {
                                        connect_fn(addr).await;
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
                for (addr, conn) in pool.get_all_connections().await {
                    let mut conn_guard = conn.write().await;
                    if conn_guard.should_ping() {
                        if let Err(e) = conn_guard.send_ping().await {
                            log::error!("Failed to ping {}: {}", addr, e);
                        }
                    }
                    conn_guard.cleanup_old_pings();
                }
                
                // Only save known peers if not in exclusive mode
                if !exclusive_mode {
                    let addresses = addrv2_handler.get_addresses_for_peer(MAX_ADDR_TO_STORE).await;
                    if !addresses.is_empty() {
                        if let Err(e) = peer_store.save_peers(&addresses).await {
                            log::warn!("Failed to save peers: {}", e);
                        }
                    }
                }
                
                time::sleep(MAINTENANCE_INTERVAL).await;
            }
        });
    }
    
    /// Send a message to a single peer (using sticky peer selection for sync consistency)
    async fn send_to_single_peer(&self, message: NetworkMessage) -> NetworkResult<()> {
        let connections = self.pool.get_all_connections().await;
        
        if connections.is_empty() {
            return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
        }
        
        // Try to use the current sync peer if it's still connected
        let mut current_sync_peer = self.current_sync_peer.lock().await;
        let selected_peer = if let Some(current_addr) = *current_sync_peer {
            // Check if current sync peer is still connected
            if connections.iter().any(|(addr, _)| *addr == current_addr) {
                // Keep using the same peer for sync consistency
                current_addr
            } else {
                // Current sync peer disconnected, pick a new one
                let new_addr = connections[0].0;
                log::info!("Sync peer switched from {} to {} (previous peer disconnected)", 
                          current_addr, new_addr);
                *current_sync_peer = Some(new_addr);
                new_addr
            }
        } else {
            // No current sync peer, pick the first available
            let new_addr = connections[0].0;
            log::info!("Sync peer selected: {}", new_addr);
            *current_sync_peer = Some(new_addr);
            new_addr
        };
        drop(current_sync_peer);
        
        // Find the connection for the selected peer
        let (addr, conn) = connections.iter()
            .find(|(a, _)| *a == selected_peer)
            .ok_or_else(|| NetworkError::ConnectionFailed("Selected peer not found".to_string()))?;
        
        // Reduce verbosity for common sync messages
        match &message {
            NetworkMessage::GetHeaders(_) | NetworkMessage::GetCFilters(_) | NetworkMessage::GetCFHeaders(_) => {
                log::debug!("Sending {} to {}", message.cmd(), addr);
            }
            _ => {
                log::trace!("Sending {:?} to {}", message.cmd(), addr);
            }
        }
        
        let mut conn_guard = conn.write().await;
        conn_guard.send_message(message).await
            .map_err(|e| NetworkError::ProtocolError(format!("Failed to send to {}: {}", addr, e)))
    }
    
    /// Broadcast a message to all connected peers
    pub async fn broadcast(&self, message: NetworkMessage) -> Vec<Result<(), Error>> {
        let connections = self.pool.get_all_connections().await;
        let mut handles = Vec::new();
        
        // Spawn tasks for concurrent sending
        for (addr, conn) in connections {
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
                let mut conn_guard = conn.write().await;
                conn_guard.send_message(msg).await
                    .map_err(|e| Error::Network(e))
            });
            handles.push(handle);
        }
        
        // Wait for all sends to complete
        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(_) => results.push(Err(Error::Network(NetworkError::ConnectionFailed(
                    "Task panicked during broadcast".to_string()
                )))),
            }
        }
        
        results
    }
    
    
    /// Select a peer for sending a message
    async fn select_peer(&self) -> Option<SocketAddr> {
        // Try to use current sync peer if available
        let current_sync_peer = self.current_sync_peer.lock().await;
        if let Some(peer) = *current_sync_peer {
            // Check if still connected
            if self.pool.is_connected(&peer).await {
                return Some(peer);
            }
        }
        drop(current_sync_peer);
        
        // Otherwise pick the first available peer
        let connections = self.pool.get_all_connections().await;
        connections.first().map(|(addr, _)| *addr)
    }
    
    /// Send a message to a specific peer
    async fn send_to_peer(&self, peer: SocketAddr, message: NetworkMessage) -> Result<(), Error> {
        let connections = self.pool.get_all_connections().await;
        let conn = connections.iter()
            .find(|(addr, _)| *addr == peer)
            .map(|(_, conn)| conn)
            .ok_or_else(|| Error::Network(NetworkError::ConnectionFailed(format!("Peer {} not connected", peer))))?;
        
        let mut conn_guard = conn.write().await;
        conn_guard.send_message(message).await
            .map_err(|e| Error::Network(e))
    }
    
    
    /// Disconnect a specific peer
    pub async fn disconnect_peer(&self, addr: &SocketAddr, reason: &str) -> Result<(), Error> {
        log::info!("Disconnecting peer {} - reason: {}", addr, reason);
        
        // Remove the connection
        self.pool.remove_connection(addr).await;
        
        Ok(())
    }
    
    /// Get the number of connected peers (async version).
    pub async fn peer_count_async(&self) -> usize {
        self.pool.connection_count().await
    }
    
    /// Shutdown the network manager
    pub async fn shutdown(&self) {
        log::info!("Shutting down multi-peer network manager");
        self.shutdown.store(true, Ordering::Relaxed);
        
        // Save known peers before shutdown
        let addresses = self.addrv2_handler.get_addresses_for_peer(MAX_ADDR_TO_STORE).await;
        if !addresses.is_empty() {
            if let Err(e) = self.peer_store.save_peers(&addresses).await {
                log::warn!("Failed to save peers on shutdown: {}", e);
            }
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
            self.pool.remove_connection(&addr).await;
        }
    }
}

// Implement Clone for use in async closures
impl Clone for MultiPeerNetworkManager {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            discovery: self.discovery.clone(),
            addrv2_handler: self.addrv2_handler.clone(),
            peer_store: self.peer_store.clone(),
            network: self.network,
            shutdown: self.shutdown.clone(),
            message_tx: self.message_tx.clone(),
            message_rx: self.message_rx.clone(),
            tasks: self.tasks.clone(),
            initial_peers: self.initial_peers.clone(),
            peer_search_started: self.peer_search_started.clone(),
            current_sync_peer: self.current_sync_peer.clone(),
        }
    }
}

// Implement NetworkManager trait
#[async_trait]
impl NetworkManager for MultiPeerNetworkManager {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    async fn connect(&mut self) -> NetworkResult<()> {
        self.start().await
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))
    }
    
    async fn disconnect(&mut self) -> NetworkResult<()> {
        self.shutdown().await;
        Ok(())
    }
    
    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        // For sync messages that require consistent responses, send to only one peer
        match &message {
            NetworkMessage::GetHeaders(_) | NetworkMessage::GetCFHeaders(_) | NetworkMessage::GetCFilters(_) => {
                self.send_to_single_peer(message).await
            }
            _ => {
                // For other messages, broadcast to all peers
                let results = self.broadcast(message).await;
                
                // Return error if all sends failed
                if results.is_empty() {
                    return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
                }
                
                let successes = results.iter().filter(|r| r.is_ok()).count();
                if successes == 0 {
                    return Err(NetworkError::ProtocolError("Failed to send to any peer".to_string()));
                }
                
                Ok(())
            }
        }
    }
    
    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        let mut rx = self.message_rx.lock().await;
        
        // Use a timeout to prevent indefinite blocking when peers disconnect
        match tokio::time::timeout(MESSAGE_RECEIVE_TIMEOUT, rx.recv()).await {
            Ok(Some((addr, msg))) => {
                // Reduce verbosity for common sync messages
                match &msg {
                    NetworkMessage::Headers(_) | NetworkMessage::CFilter(_) => {
                        // Headers and filters are logged by the sync managers - reduced verbosity
                        log::debug!("Delivering {} from {} to client", msg.cmd(), addr);
                    }
                    _ => {
                        log::trace!("Delivering {:?} from {} to client", msg.cmd(), addr);
                    }
                }
                Ok(Some(msg))
            }
            Ok(None) => Ok(None),
            Err(_) => {
                // Timeout - no message available
                Ok(None)
            }
        }
    }
    
    fn is_connected(&self) -> bool {
        // We're "connected" if we have at least one peer
        let pool = self.pool.clone();
        let count = tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(pool.connection_count())
        });
        count > 0
    }
    
    fn peer_count(&self) -> usize {
        let pool = self.pool.clone();
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(pool.connection_count())
        })
    }
    
    fn peer_info(&self) -> Vec<PeerInfo> {
        let pool = self.pool.clone();
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async {
                let connections = pool.get_all_connections().await;
                let mut infos = Vec::new();
                for (_, conn) in connections.iter() {
                    let conn_guard = conn.read().await;
                    infos.push(conn_guard.peer_info());
                }
                infos
            })
        })
    }
    
    async fn send_ping(&mut self) -> NetworkResult<u64> {
        // Send ping to all peers, return first nonce
        let connections = self.pool.get_all_connections().await;
        
        if connections.is_empty() {
            return Err(NetworkError::ConnectionFailed("No connected peers".to_string()));
        }
        
        let (_, conn) = &connections[0];
        let mut conn_guard = conn.write().await;
        conn_guard.send_ping().await
    }
    
    async fn handle_ping(&mut self, _nonce: u64) -> NetworkResult<()> {
        // This is handled in the peer reader
        Ok(())
    }
    
    fn handle_pong(&mut self, _nonce: u64) -> NetworkResult<()> {
        // This is handled in the peer reader
        Ok(())
    }
    
    fn should_ping(&self) -> bool {
        // Individual connections handle their own ping timing
        false
    }
    
    fn cleanup_old_pings(&mut self) {
        // Individual connections handle their own ping cleanup
    }
    
    fn get_message_sender(&self) -> mpsc::Sender<NetworkMessage> {
        // Create a sender that routes messages to our internal send_message logic
        let (tx, mut rx) = mpsc::channel(1000);
        let pool = Arc::clone(&self.pool);
        
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                // Route message through the multi-peer logic
                // For sync messages that require consistent responses, send to only one peer
                match &message {
                    NetworkMessage::GetHeaders(_) | NetworkMessage::GetCFHeaders(_) | NetworkMessage::GetCFilters(_) | NetworkMessage::GetData(_) => {
                        // Send to a single peer for sync messages including GetData for block downloads
                        let connections = pool.get_all_connections().await;
                        if let Some((_, conn)) = connections.first() {
                            let mut conn_guard = conn.write().await;
                            let _ = conn_guard.send_message(message).await;
                        }
                    }
                    _ => {
                        // Broadcast to all peers for other messages
                        let connections = pool.get_all_connections().await;
                        for (_, conn) in connections {
                            let mut conn_guard = conn.write().await;
                            let _ = conn_guard.send_message(message.clone()).await;
                        }
                    }
                }
            }
        });
        
        tx
    }
}
