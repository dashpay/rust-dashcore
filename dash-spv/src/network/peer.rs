//! Dash peer connection management.

use dashcore::network::constants::ServiceFlags;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use dashcore::consensus::{encode, Decodable};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::Network;

use crate::error::{NetworkError, NetworkResult};
use crate::network::constants::PING_INTERVAL;
use crate::network::Message;

/// Internal state for the TCP connection
struct ConnectionState {
    stream: TcpStream,
    // Stateful message framing buffer to ensure full frames before decoding
    framing_buffer: Vec<u8>,
}

/// Dash P2P peer
pub struct Peer {
    address: SocketAddr,
    // Use a single mutex to protect both the write stream and read buffer
    // This ensures no concurrent access to the underlying socket
    state: Option<Arc<Mutex<ConnectionState>>>,
    timeout: Duration,
    connected_at: Option<SystemTime>,
    bytes_sent: u64,
    network: Network,
    // Ping/pong state
    last_ping_sent: Option<SystemTime>,
    last_pong_received: Option<SystemTime>,
    pending_pings: HashMap<u64, SystemTime>, // nonce -> sent_time
    // Peer information from Version message
    version: Option<u32>,
    services: Option<u64>,
    user_agent: Option<String>,
    best_height: Option<u32>,
    relay: Option<bool>,
    prefers_headers2: bool,
    sent_sendheaders2: bool,
    // Basic telemetry for resync events
    consecutive_resyncs: u32,
}

impl Peer {
    /// Get the remote peer socket address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    /// Create a new peer.
    pub fn new(address: SocketAddr, timeout: Duration, network: Network) -> Self {
        Self {
            address,
            state: None,
            timeout,
            connected_at: None,
            bytes_sent: 0,
            network,
            last_ping_sent: None,
            last_pong_received: None,
            pending_pings: HashMap::new(),
            version: None,
            services: None,
            user_agent: None,
            best_height: None,
            relay: None,
            prefers_headers2: false,
            sent_sendheaders2: false,
            consecutive_resyncs: 0,
        }
    }

    /// Connect to a peer and return a connected instance.
    pub async fn connect(
        address: SocketAddr,
        timeout_secs: u64,
        network: Network,
    ) -> NetworkResult<Self> {
        let timeout = Duration::from_secs(timeout_secs);

        let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
            .await
            .map_err(|_| {
                NetworkError::ConnectionFailed(format!("Connection to {} timed out", address))
            })?
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("Failed to connect to {}: {}", address, e))
            })?;

        stream.set_nodelay(true).map_err(|e| {
            NetworkError::ConnectionFailed(format!("Failed to set TCP_NODELAY: {}", e))
        })?;

        let state = ConnectionState {
            stream,
            framing_buffer: Vec::new(),
        };

        Ok(Self {
            address,
            state: Some(Arc::new(Mutex::new(state))),
            timeout,
            connected_at: Some(SystemTime::now()),
            bytes_sent: 0,
            network,
            last_ping_sent: None,
            last_pong_received: None,
            pending_pings: HashMap::new(),
            version: None,
            services: None,
            user_agent: None,
            best_height: None,
            relay: None,
            prefers_headers2: false,
            sent_sendheaders2: false,
            consecutive_resyncs: 0,
        })
    }

    pub fn best_height(&self) -> Option<u32> {
        self.best_height
    }

    /// Check if peer supports compact filters (BIP 157/158).
    pub fn supports_compact_filters(&self) -> bool {
        self.has_service(ServiceFlags::COMPACT_FILTERS)
    }

    /// Check if peer supports headers2 compression (DIP-0025).
    pub fn supports_headers2(&self) -> bool {
        self.has_service(ServiceFlags::NODE_HEADERS_COMPRESSED)
    }

    pub fn has_service(&self, flags: ServiceFlags) -> bool {
        self.services.map(|s| ServiceFlags::from(s).has(flags)).unwrap_or(false)
    }

    /// Connect to the peer (instance method for compatibility).
    pub async fn connect_instance(&mut self) -> NetworkResult<()> {
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(self.address))
            .await
            .map_err(|_| {
                NetworkError::ConnectionFailed(format!("Connection to {} timed out", self.address))
            })?
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!(
                    "Failed to connect to {}: {}",
                    self.address, e
                ))
            })?;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true).map_err(|e| {
            NetworkError::ConnectionFailed(format!("Failed to set TCP_NODELAY: {}", e))
        })?;

        let state = ConnectionState {
            stream,
            framing_buffer: Vec::new(),
        };

        self.state = Some(Arc::new(Mutex::new(state)));
        self.connected_at = Some(SystemTime::now());

        tracing::info!("Connected to peer {}", self.address);

        Ok(())
    }

    /// Disconnect from the peer.
    pub async fn disconnect(&mut self) -> NetworkResult<()> {
        if let Some(state_arc) = self.state.take() {
            if let Ok(state_mutex) = Arc::try_unwrap(state_arc) {
                let mut state = state_mutex.into_inner();
                let _ = state.stream.shutdown().await;
            }
        }
        self.connected_at = None;

        tracing::info!("Disconnected from peer {}", self.address);

        Ok(())
    }

    /// Update peer information from a received Version message
    pub fn update_peer_info(
        &mut self,
        version_msg: &dashcore::network::message_network::VersionMessage,
    ) {
        // Define validation constants
        const MIN_PROTOCOL_VERSION: u32 = 60001; // Minimum version that supports ping/pong
        const MAX_PROTOCOL_VERSION: u32 = 100000; // Reasonable upper bound for protocol version
        const MAX_USER_AGENT_LENGTH: usize = 256; // Maximum reasonable user agent length
        const MAX_START_HEIGHT: i32 = 10_000_000; // Reasonable upper bound for block height

        // Validate protocol version
        if version_msg.version < MIN_PROTOCOL_VERSION {
            tracing::warn!(
                "Peer {} reported protocol version {} below minimum {}, skipping update",
                self.address,
                version_msg.version,
                MIN_PROTOCOL_VERSION
            );
            return;
        }

        if version_msg.version > MAX_PROTOCOL_VERSION {
            tracing::warn!(
                "Peer {} reported suspiciously high protocol version {}, skipping update",
                self.address,
                version_msg.version
            );
            return;
        }

        // Validate start height
        if version_msg.start_height < 0 {
            tracing::warn!(
                "Peer {} reported negative start height {}, skipping update",
                self.address,
                version_msg.start_height
            );
            return;
        }

        if version_msg.start_height > MAX_START_HEIGHT {
            tracing::warn!(
                "Peer {} reported suspiciously high start height {}, skipping update",
                self.address,
                version_msg.start_height
            );
            return;
        }

        // Validate user agent
        if version_msg.user_agent.is_empty() {
            tracing::warn!("Peer {} provided empty user agent, skipping update", self.address);
            return;
        }

        if version_msg.user_agent.len() > MAX_USER_AGENT_LENGTH {
            tracing::warn!(
                "Peer {} provided excessively long user agent ({} bytes), skipping update",
                self.address,
                version_msg.user_agent.len()
            );
            return;
        }

        // Validate services - ensure they contain expected flags
        let services = version_msg.services.as_u64();
        const KNOWN_SERVICE_FLAGS: u64 = 0x0000_0000_0000_1FFF; // All known service flags up to bit 12
        if services & !KNOWN_SERVICE_FLAGS != 0 {
            tracing::warn!(
                "Peer {} reported unknown service flags: 0x{:016x}, proceeding with caution",
                self.address,
                services
            );
            // Note: We don't return here as unknown flags might be from newer versions
        }

        // All validations passed, update peer info
        self.version = Some(version_msg.version);
        self.services = Some(version_msg.services.as_u64());
        self.user_agent = Some(version_msg.user_agent.clone());
        self.best_height = Some(version_msg.start_height as u32);
        self.relay = Some(version_msg.relay);

        tracing::info!(
            "Updated peer info for {}: height={}, version={}, services={:?}",
            self.address,
            version_msg.start_height,
            version_msg.version,
            version_msg.services
        );

        // Also log with standard logging for debugging
        log::info!(
            "PEER_INFO_DEBUG: Updated peer {} with height={}, version={}",
            self.address,
            version_msg.start_height,
            version_msg.version
        );
    }

    /// Helper function to read some bytes into the framing buffer.
    async fn read_some(state: &mut ConnectionState) -> std::io::Result<usize> {
        let mut tmp = [0u8; 8192];
        match state.stream.read(&mut tmp).await {
            Ok(0) => Ok(0),
            Ok(n) => {
                state.framing_buffer.extend_from_slice(&tmp[..n]);
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }

    /// Send a message to the peer.
    pub async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        let state_arc = self
            .state
            .as_ref()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        let raw_message = RawNetworkMessage {
            magic: self.network.magic(),
            payload: message,
        };

        let serialized = encode::serialize(&raw_message);

        // Log details for debugging headers2 issues
        if matches!(
            raw_message.payload,
            NetworkMessage::GetHeaders2(_) | NetworkMessage::GetHeaders(_)
        ) {
            let msg_type = match raw_message.payload {
                NetworkMessage::GetHeaders2(_) => "GetHeaders2",
                NetworkMessage::GetHeaders(_) => "GetHeaders",
                _ => "Unknown",
            };
            tracing::debug!(
                "Sending {} raw bytes (len={}): {:02x?}",
                msg_type,
                serialized.len(),
                &serialized[..std::cmp::min(100, serialized.len())]
            );
        }

        // Lock the state for the entire write operation
        let mut state = state_arc.lock().await;

        // Write with error handling
        match state.stream.write_all(&serialized).await {
            Ok(_) => {
                // Flush to ensure data is sent immediately
                if let Err(e) = state.stream.flush().await {
                    tracing::warn!("Failed to flush socket {}: {}", self.address, e);
                }
                self.bytes_sent += serialized.len() as u64;
                tracing::debug!("Sent message to {}: {:?}", self.address, raw_message.payload);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Disconnecting {} due to write error: {}", self.address, e);
                // Drop the lock before clearing connection state
                drop(state);
                // Clear connection state on write error
                self.state = None;
                self.connected_at = None;
                Err(NetworkError::ConnectionFailed(format!("Write failed: {}", e)))
            }
        }
    }

    /// Receive a message from the peer.
    pub async fn receive_message(&mut self) -> NetworkResult<Option<Message>> {
        // First check if we have a state
        let state_arc = self
            .state
            .as_ref()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        // Lock the state for the entire read operation
        // This ensures no concurrent access to the socket
        let mut state = state_arc.lock().await;

        // Buffered, stateful framing
        const HEADER_LEN: usize = 24; // magic[4] + cmd[12] + length[4] + checksum[4]
        const MAX_RESYNC_STEPS_PER_CALL: usize = 64;

        let result = async {
            let magic_bytes = self.network.magic().to_le_bytes();
            let mut resync_steps = 0usize;

            loop {
                // Ensure header availability
                if state.framing_buffer.len() < HEADER_LEN {
                    match Self::read_some(&mut state).await {
                        Ok(0) => {
                            tracing::info!("Peer {} closed connection (EOF)", self.address);
                            return Err(NetworkError::PeerDisconnected);
                        }
                        Ok(_) => {}
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(None);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            return Ok(None);
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::ConnectionAborted
                                || e.kind() == std::io::ErrorKind::ConnectionReset =>
                        {
                            tracing::info!("Peer {} connection reset/aborted", self.address);
                            return Err(NetworkError::PeerDisconnected);
                        }
                        Err(e) => {
                            return Err(NetworkError::ConnectionFailed(format!(
                                "Read failed: {}",
                                e
                            )));
                        }
                    }
                }

                // Align to magic
                if state.framing_buffer.len() >= 4 && state.framing_buffer[..4] != magic_bytes {
                    if let Some(pos) =
                        state.framing_buffer.windows(4).position(|w| w == magic_bytes)
                    {
                        if pos > 0 {
                            tracing::warn!(
                                "{}: stream desync: skipping {} stray bytes before magic",
                                self.address,
                                pos
                            );
                            self.consecutive_resyncs = self.consecutive_resyncs.saturating_add(1);
                            state.framing_buffer.drain(0..pos);
                            resync_steps += 1;
                            if resync_steps >= MAX_RESYNC_STEPS_PER_CALL {
                                return Ok(None);
                            }
                            continue;
                        }
                    } else {
                        // Keep last 3 bytes of potential magic prefix
                        if state.framing_buffer.len() > 3 {
                            let dropped = state.framing_buffer.len() - 3;
                            tracing::warn!(
                                "{}: stream desync: dropping {} bytes (no magic found)",
                                self.address,
                                dropped
                            );
                            self.consecutive_resyncs = self.consecutive_resyncs.saturating_add(1);
                            state.framing_buffer.drain(0..dropped);
                            resync_steps += 1;
                            if resync_steps >= MAX_RESYNC_STEPS_PER_CALL {
                                return Ok(None);
                            }
                        }
                        // Need more data
                        match Self::read_some(&mut state).await {
                            Ok(0) => {
                                tracing::info!("Peer {} closed connection (EOF)", self.address);
                                return Err(NetworkError::PeerDisconnected);
                            }
                            Ok(_) => {}
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                return Ok(None);
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                return Ok(None);
                            }
                            Err(e) => {
                                return Err(NetworkError::ConnectionFailed(format!(
                                    "Read failed: {}",
                                    e
                                )));
                            }
                        }
                        continue;
                    }
                }

                // Ensure full header
                if state.framing_buffer.len() < HEADER_LEN {
                    match Self::read_some(&mut state).await {
                        Ok(0) => {
                            tracing::info!("Peer {} closed connection (EOF)", self.address);
                            return Err(NetworkError::PeerDisconnected);
                        }
                        Ok(_) => {}
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(None);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            return Ok(None);
                        }
                        Err(e) => {
                            return Err(NetworkError::ConnectionFailed(format!(
                                "Read failed: {}",
                                e
                            )));
                        }
                    }
                    continue;
                }

                // Parse header fields
                let length_le = u32::from_le_bytes([
                    state.framing_buffer[16],
                    state.framing_buffer[17],
                    state.framing_buffer[18],
                    state.framing_buffer[19],
                ]) as usize;
                let header_checksum = [
                    state.framing_buffer[20],
                    state.framing_buffer[21],
                    state.framing_buffer[22],
                    state.framing_buffer[23],
                ];
                // Validate announced length to prevent unbounded accumulation or overflow
                if length_le > dashcore::network::message::MAX_MSG_SIZE {
                    return Err(NetworkError::ProtocolError(format!(
                        "Declared payload length {} exceeds MAX_MSG_SIZE {}",
                        length_le,
                        dashcore::network::message::MAX_MSG_SIZE
                    )));
                }
                let total_len = match HEADER_LEN.checked_add(length_le) {
                    Some(v) => v,
                    None => {
                        return Err(NetworkError::ProtocolError(
                            "Message length overflow".to_string(),
                        ));
                    }
                };

                // Ensure full frame available
                if state.framing_buffer.len() < total_len {
                    match Self::read_some(&mut state).await {
                        Ok(0) => {
                            tracing::info!("Peer {} closed connection (EOF)", self.address);
                            return Err(NetworkError::PeerDisconnected);
                        }
                        Ok(_) => {}
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(None);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            return Ok(None);
                        }
                        Err(e) => {
                            return Err(NetworkError::ConnectionFailed(format!(
                                "Read failed: {}",
                                e
                            )));
                        }
                    }
                    continue;
                }

                // Verify checksum
                let payload_slice = &state.framing_buffer[HEADER_LEN..total_len];
                let expected = {
                    let checksum = <dashcore_hashes::sha256d::Hash as dashcore_hashes::Hash>::hash(
                        payload_slice,
                    );
                    [checksum[0], checksum[1], checksum[2], checksum[3]]
                };
                if expected != header_checksum {
                    tracing::warn!(
                        "Skipping message with invalid checksum from {}: expected {:02x?}, actual {:02x?}",
                        self.address,
                        expected,
                        header_checksum
                    );
                    if header_checksum == [0, 0, 0, 0] {
                        tracing::warn!(
                            "All-zeros checksum detected from {}, likely corrupted stream - resyncing",
                            self.address
                        );
                    }
                    // Resync by dropping a byte and retrying
                    state.framing_buffer.drain(0..1);
                    self.consecutive_resyncs = self.consecutive_resyncs.saturating_add(1);
                    resync_steps += 1;
                    if resync_steps >= MAX_RESYNC_STEPS_PER_CALL {
                        return Ok(None);
                    }
                    continue;
                }

                // Decode full RawNetworkMessage from the frame using existing decoder
                let mut cursor = std::io::Cursor::new(&state.framing_buffer[..total_len]);
                match RawNetworkMessage::consensus_decode(&mut cursor) {
                    Ok(raw_message) => {
                        // Consume bytes
                        state.framing_buffer.drain(0..total_len);
                        self.consecutive_resyncs = 0;

                        // Validate magic matches our network
                        if raw_message.magic != self.network.magic() {
                            tracing::warn!(
                                "Received message with wrong magic bytes: expected {:#x}, got {:#x}",
                                self.network.magic(),
                                raw_message.magic
                            );
                            return Err(NetworkError::ProtocolError(format!(
                                "Wrong magic bytes: expected {:#x}, got {:#x}",
                                self.network.magic(),
                                raw_message.magic
                            )));
                        }

                        tracing::trace!(
                            "Successfully decoded message from {}: {:?}",
                            self.address,
                            raw_message.payload.cmd()
                        );

                        return Ok(Some(Message::new(self.address, raw_message.payload)));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "{}: decode error after framing ({}), attempting resync",
                            self.address,
                            e
                        );
                        state.framing_buffer.drain(0..1);
                        self.consecutive_resyncs = self.consecutive_resyncs.saturating_add(1);
                        resync_steps += 1;
                        if resync_steps >= MAX_RESYNC_STEPS_PER_CALL {
                            return Ok(None);
                        }
                        continue;
                    }
                }
            }
        }
        .await;

        // Drop the lock before disconnecting
        drop(state);

        // Handle disconnection if needed
        if let Err(NetworkError::PeerDisconnected) = &result {
            self.state = None;
            self.connected_at = None;
        }

        result
    }

    /// Check if the connection is active.
    pub fn is_connected(&self) -> bool {
        self.state.is_some()
    }

    /// Check if connection appears healthy (not just connected).
    pub fn is_healthy(&self) -> bool {
        if !self.is_connected() {
            tracing::debug!("Connection to {} marked unhealthy: not connected", self.address);
            return false;
        }

        let now = SystemTime::now();

        // If we have exchanged pings/pongs, check the last activity
        if let Some(last_pong) = self.last_pong_received {
            if let Ok(duration) = now.duration_since(last_pong) {
                // If no pong in 10 minutes, consider unhealthy
                if duration > Duration::from_secs(600) {
                    tracing::warn!("Connection to {} marked unhealthy: no pong received for {} seconds (limit: 600)",
                                  self.address, duration.as_secs());
                    return false;
                }
            }
        } else if let Some(connected_at) = self.connected_at {
            // If we haven't received any pongs yet, check how long we've been connected
            if let Ok(duration) = now.duration_since(connected_at) {
                // Give new connections 5 minutes before considering them unhealthy
                if duration > Duration::from_secs(300) {
                    tracing::warn!("Connection to {} marked unhealthy: no pong activity after {} seconds (limit: 300, last_ping_sent: {:?})",
                                  self.address, duration.as_secs(), self.last_ping_sent.is_some());
                    return false;
                }
            }
        }

        // Connection is healthy
        true
    }

    /// Get connection statistics.
    pub fn stats(&self) -> (u64, u64) {
        (self.bytes_sent, 0) // TODO: Track bytes received
    }

    /// Send a ping message with a random nonce.
    pub async fn send_ping(&mut self) -> NetworkResult<u64> {
        let nonce = rand::random::<u64>();
        let ping_message = NetworkMessage::Ping(nonce);

        self.send_message(ping_message).await?;

        let now = SystemTime::now();
        self.last_ping_sent = Some(now);
        self.pending_pings.insert(nonce, now);

        tracing::trace!("Sent ping to {} with nonce {}", self.address, nonce);

        Ok(nonce)
    }

    /// Handle a received ping message by sending a pong response.
    pub async fn handle_ping(&mut self, nonce: u64) -> NetworkResult<()> {
        let pong_message = NetworkMessage::Pong(nonce);
        self.send_message(pong_message).await?;

        tracing::debug!("Responded to ping from {} with pong nonce {}", self.address, nonce);

        Ok(())
    }

    /// Handle a received pong message by validating the nonce.
    pub fn handle_pong(&mut self, nonce: u64) -> NetworkResult<()> {
        if let Some(sent_time) = self.pending_pings.remove(&nonce) {
            let now = SystemTime::now();
            let rtt = now.duration_since(sent_time).unwrap_or(Duration::from_secs(0));

            self.last_pong_received = Some(now);

            tracing::debug!(
                "Received valid pong from {} with nonce {} (RTT: {:?})",
                self.address,
                nonce,
                rtt
            );

            Ok(())
        } else {
            tracing::warn!("Received unexpected pong from {} with nonce {}", self.address, nonce);
            Err(NetworkError::ProtocolError(format!(
                "Unexpected pong nonce {} from {}",
                nonce, self.address
            )))
        }
    }

    /// Check if we need to send a ping (no ping/pong activity for 2 minutes).
    pub fn should_ping(&self) -> bool {
        let now = SystemTime::now();

        // Check if we've sent a ping recently
        if let Some(last_ping) = self.last_ping_sent {
            if now.duration_since(last_ping).unwrap_or(Duration::MAX) < PING_INTERVAL {
                return false;
            }
        }

        // Check if we've received a pong recently
        if let Some(last_pong) = self.last_pong_received {
            if now.duration_since(last_pong).unwrap_or(Duration::MAX) < PING_INTERVAL {
                return false;
            }
        }

        // If we haven't sent a ping or received a pong in 2 minutes, we should ping
        true
    }

    /// Clean up old pending pings that haven't received responses.
    pub fn cleanup_old_pings(&mut self) {
        const PING_TIMEOUT: Duration = Duration::from_secs(60); // 1 minute timeout for pings

        let now = SystemTime::now();
        let mut expired_nonces = Vec::new();

        for (&nonce, &sent_time) in &self.pending_pings {
            if now.duration_since(sent_time).unwrap_or(Duration::ZERO) > PING_TIMEOUT {
                expired_nonces.push(nonce);
            }
        }

        for nonce in expired_nonces {
            self.pending_pings.remove(&nonce);
            tracing::warn!("Ping timeout for {} with nonce {}", self.address, nonce);
        }
    }

    /// Get ping/pong statistics.
    pub fn ping_stats(&self) -> (Option<SystemTime>, Option<SystemTime>, usize) {
        (self.last_ping_sent, self.last_pong_received, self.pending_pings.len())
    }

    /// Set that peer prefers headers2.
    pub fn set_prefers_headers2(&mut self, prefers: bool) {
        self.prefers_headers2 = prefers;
        if prefers {
            tracing::info!("Peer {} prefers headers2 compression", self.address);
        }
    }

    /// Check if peer prefers headers2.
    pub fn prefers_headers2(&self) -> bool {
        self.prefers_headers2
    }

    /// Set that peer sent us SendHeaders2.
    pub fn set_peer_sent_sendheaders2(&mut self, sent: bool) {
        self.sent_sendheaders2 = sent;
        if sent {
            tracing::info!(
                "Peer {} sent SendHeaders2 - they will send compressed headers",
                self.address
            );
        }
    }

    /// Check if peer sent us SendHeaders2.
    pub fn peer_sent_sendheaders2(&self) -> bool {
        self.sent_sendheaders2
    }

    /// Check if we can request headers2 from this peer.
    pub fn can_request_headers2(&self) -> bool {
        // We can request headers2 if peer has the service flag for headers2 support
        // Note: We don't wait for SendHeaders2 from peer as that creates a race condition
        // during initial sync. The service flag is sufficient to know they support headers2.
        if let Some(services) = self.services {
            dashcore::network::constants::ServiceFlags::from(services)
                .has(dashcore::network::constants::NODE_HEADERS_COMPRESSED)
        } else {
            false
        }
    }
}
