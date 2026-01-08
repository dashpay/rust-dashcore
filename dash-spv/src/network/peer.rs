//! Dash peer connection management.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;

use dashcore::network::message::NetworkMessage;
use dashcore::Network;

use crate::error::{NetworkError, NetworkResult};
use crate::network::constants::PING_INTERVAL;
use crate::network::transport::{
    Transport, TransportPreference, V1Transport, V2HandshakeManager, V2HandshakeResult, V2Transport,
};
use crate::types::PeerInfo;

/// Dash P2P peer
pub struct Peer {
    address: SocketAddr,
    /// The transport layer (V1 or V2)
    transport: Option<Box<dyn Transport>>,
    timeout: Duration,
    connected_at: Option<SystemTime>,
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
    // Transport protocol version used (1 or 2)
    transport_version: u8,
}

impl Peer {
    /// Get the remote peer socket address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Get the transport protocol version (1 = unencrypted, 2 = BIP324 encrypted).
    pub fn transport_version(&self) -> u8 {
        self.transport_version
    }

    /// Create a new peer (not connected).
    pub fn new(address: SocketAddr, timeout: Duration, network: Network) -> Self {
        Self {
            address,
            transport: None,
            timeout,
            connected_at: None,
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
            transport_version: 1,
        }
    }

    /// Connect to a peer with the specified transport preference.
    ///
    /// # Arguments
    /// * `address` - The peer's socket address
    /// * `timeout_secs` - Connection timeout in seconds
    /// * `network` - The Dash network (mainnet, testnet, etc.)
    /// * `transport_pref` - V1Only, V2Only, or V2Preferred (default)
    ///
    /// # Returns
    /// A connected Peer instance using the appropriate transport.
    pub async fn connect(
        address: SocketAddr,
        timeout_secs: u64,
        network: Network,
        transport_pref: TransportPreference,
    ) -> NetworkResult<Self> {
        let timeout = Duration::from_secs(timeout_secs);

        let (transport, transport_version): (Box<dyn Transport>, u8) = match transport_pref {
            TransportPreference::V1Only => {
                tracing::info!("Connecting to {} using V1 transport (unencrypted)", address);
                let transport = Self::establish_v1_transport(address, timeout, network).await?;
                (Box::new(transport), 1)
            }
            TransportPreference::V2Only => {
                tracing::info!(
                    "Connecting to {} using V2 transport (BIP324 encrypted, no fallback)",
                    address
                );
                let transport = Self::establish_v2_transport(address, timeout, network).await?;
                (Box::new(transport), 2)
            }
            TransportPreference::V2Preferred => {
                tracing::info!(
                    "Connecting to {} using V2 transport (BIP324 encrypted, with V1 fallback)",
                    address
                );
                Self::try_v2_with_fallback(address, timeout, network).await?
            }
        };

        tracing::info!(
            "Successfully connected to {} using V{} transport",
            address,
            transport_version
        );

        Ok(Self {
            address,
            transport: Some(transport),
            timeout,
            connected_at: Some(SystemTime::now()),
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
            transport_version,
        })
    }

    /// Establish a V1 (unencrypted) transport connection.
    async fn establish_v1_transport(
        address: SocketAddr,
        timeout: Duration,
        network: Network,
    ) -> NetworkResult<V1Transport> {
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

        Ok(V1Transport::new(stream, network, address))
    }

    /// Establish a V2 (BIP324 encrypted) transport connection.
    /// Fails if peer doesn't support V2.
    async fn establish_v2_transport(
        address: SocketAddr,
        timeout: Duration,
        network: Network,
    ) -> NetworkResult<V2Transport> {
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

        let handshake_manager = V2HandshakeManager::new_initiator(network, address);
        match handshake_manager.perform_handshake(stream).await? {
            V2HandshakeResult::Success(session) => {
                Ok(V2Transport::new(session.stream, session.cipher, session.session_id, address))
            }
            V2HandshakeResult::FallbackToV1 => Err(NetworkError::V2NotSupported),
        }
    }

    /// Try V2 transport first, fall back to V1 if peer doesn't support V2.
    async fn try_v2_with_fallback(
        address: SocketAddr,
        timeout: Duration,
        network: Network,
    ) -> NetworkResult<(Box<dyn Transport>, u8)> {
        // First, try to establish TCP connection
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

        // Try V2 handshake
        let handshake_manager = V2HandshakeManager::new_initiator(network, address);
        match handshake_manager.perform_handshake(stream).await {
            Ok(V2HandshakeResult::Success(session)) => {
                tracing::info!("V2 handshake succeeded with {}", address);
                let transport =
                    V2Transport::new(session.stream, session.cipher, session.session_id, address);
                Ok((Box::new(transport), 2))
            }
            Ok(V2HandshakeResult::FallbackToV1) => {
                tracing::info!(
                    "V2 handshake detected V1-only peer {}, reconnecting with V1 transport",
                    address
                );
                // Need to reconnect since the stream was consumed
                let transport = Self::establish_v1_transport(address, timeout, network).await?;
                Ok((Box::new(transport), 1))
            }
            Err(e) => {
                tracing::warn!("V2 handshake failed with {}: {}, falling back to V1", address, e);
                // Try V1 as fallback
                let transport = Self::establish_v1_transport(address, timeout, network).await?;
                Ok((Box::new(transport), 1))
            }
        }
    }

    /// Connect to the peer (instance method for compatibility).
    pub async fn connect_instance(
        &mut self,
        transport_pref: TransportPreference,
    ) -> NetworkResult<()> {
        let (transport, transport_version): (Box<dyn Transport>, u8) = match transport_pref {
            TransportPreference::V1Only => {
                let t =
                    Self::establish_v1_transport(self.address, self.timeout, self.network).await?;
                (Box::new(t), 1)
            }
            TransportPreference::V2Only => {
                let t =
                    Self::establish_v2_transport(self.address, self.timeout, self.network).await?;
                (Box::new(t), 2)
            }
            TransportPreference::V2Preferred => {
                Self::try_v2_with_fallback(self.address, self.timeout, self.network).await?
            }
        };

        self.transport = Some(transport);
        self.transport_version = transport_version;
        self.connected_at = Some(SystemTime::now());

        tracing::info!("Connected to peer {} using V{} transport", self.address, transport_version);

        Ok(())
    }

    /// Disconnect from the peer.
    pub async fn disconnect(&mut self) -> NetworkResult<()> {
        if let Some(mut transport) = self.transport.take() {
            transport.shutdown().await?;
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

    /// Send a message to the peer.
    pub async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        transport.send_message(message).await
    }

    /// Receive a message from the peer.
    pub async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        let result = transport.receive_message().await;

        // Handle disconnection
        if let Err(NetworkError::PeerDisconnected) = &result {
            self.transport = None;
            self.connected_at = None;
        }

        result
    }

    /// Check if the connection is active.
    pub fn is_connected(&self) -> bool {
        self.transport.as_ref().map(|t| t.is_connected()).unwrap_or(false)
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

    /// Get peer information.
    pub fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            address: self.address,
            connected: self.is_connected(),
            last_seen: self.connected_at.unwrap_or(SystemTime::UNIX_EPOCH),
            version: self.version,
            services: self.services,
            user_agent: self.user_agent.clone(),
            best_height: self.best_height,
            wants_dsq_messages: None, // We don't track this yet
            has_sent_headers2: false, // Will be tracked by the connection pool
        }
    }

    /// Get connection statistics.
    pub fn stats(&self) -> (u64, u64) {
        if let Some(transport) = &self.transport {
            (transport.bytes_sent(), transport.bytes_received())
        } else {
            (0, 0)
        }
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
