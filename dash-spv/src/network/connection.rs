//! TCP connection management.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};
use std::collections::HashMap;

use dashcore::consensus::{encode, Decodable};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::Network;

use crate::error::{NetworkError, NetworkResult};
use crate::types::PeerInfo;

/// TCP connection to a Dash peer
pub struct TcpConnection {
    address: SocketAddr,
    write_stream: Option<TcpStream>,
    read_stream: Option<BufReader<TcpStream>>,
    timeout: Duration,
    connected_at: Option<SystemTime>,
    bytes_sent: u64,
    network: Network,
    // Ping/pong state
    last_ping_sent: Option<SystemTime>,
    last_pong_received: Option<SystemTime>,
    pending_pings: HashMap<u64, SystemTime>, // nonce -> sent_time
}

impl TcpConnection {
    /// Create a new TCP connection to the given address.
    pub fn new(address: SocketAddr, timeout: Duration, network: Network) -> Self {
        Self {
            address,
            write_stream: None,
            read_stream: None,
            timeout,
            connected_at: None,
            bytes_sent: 0,
            network,
            last_ping_sent: None,
            last_pong_received: None,
            pending_pings: HashMap::new(),
        }
    }
    
    /// Connect to the peer.
    pub async fn connect(&mut self) -> NetworkResult<()> {
        let stream = TcpStream::connect_timeout(&self.address, self.timeout)
            .map_err(|e| NetworkError::ConnectionFailed(format!("Failed to connect to {}: {}", self.address, e)))?;
        
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        
        // Clone stream for reading
        let read_stream = stream.try_clone()
            .map_err(|e| NetworkError::ConnectionFailed(format!("Failed to clone stream: {}", e)))?;
        
        self.write_stream = Some(stream);
        self.read_stream = Some(BufReader::new(read_stream));
        self.connected_at = Some(SystemTime::now());
        
        tracing::info!("Connected to peer {}", self.address);
        
        Ok(())
    }
    
    /// Disconnect from the peer.
    pub async fn disconnect(&mut self) -> NetworkResult<()> {
        if let Some(stream) = self.write_stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        self.read_stream = None;
        self.connected_at = None;
        
        tracing::info!("Disconnected from peer {}", self.address);
        
        Ok(())
    }
    
    /// Send a message to the peer.
    pub async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        let stream = self.write_stream.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        let raw_message = RawNetworkMessage {
            magic: self.network.magic(),
            payload: message,
        };
        
        let serialized = encode::serialize(&raw_message);
        stream.write_all(&serialized)?;
        
        self.bytes_sent += serialized.len() as u64;
        
        tracing::debug!("Sent message to {}: {:?}", self.address, raw_message.payload);
        
        Ok(())
    }
    
    /// Receive a message from the peer.
    pub async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        let reader = self.read_stream.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        // Read message from the BufReader
        match RawNetworkMessage::consensus_decode(reader) {
            Ok(raw_message) => {
                // Validate magic bytes match our network
                if raw_message.magic != self.network.magic() {
                    tracing::warn!("Received message with wrong magic bytes: expected {:#x}, got {:#x}",
                                  self.network.magic(), raw_message.magic);
                    return Err(NetworkError::ProtocolError(format!(
                        "Wrong magic bytes: expected {:#x}, got {:#x}", 
                        self.network.magic(), raw_message.magic
                    )));
                }
                
                // Message received successfully
                Ok(Some(raw_message.payload))
            }
            Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(None)
            }
            Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::info!("Peer {} disconnected", self.address);
                self.write_stream = None;
                self.read_stream = None;
                self.connected_at = None;
                Err(NetworkError::PeerDisconnected)
            }
            Err(e) => {
                tracing::error!("Failed to decode message from {}: {}", self.address, e);
                Err(NetworkError::Serialization(e))
            }
        }
    }
    
    /// Check if the connection is active.
    pub fn is_connected(&self) -> bool {
        self.write_stream.is_some() && self.read_stream.is_some()
    }
    
    /// Get peer information.
    pub fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            address: self.address,
            connected: self.is_connected(),
            last_seen: self.connected_at.unwrap_or(SystemTime::UNIX_EPOCH),
            version: None, // TODO: Track from handshake
            services: None, // TODO: Track from handshake
            user_agent: None, // TODO: Track from handshake
            best_height: None, // TODO: Track from handshake
        }
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
            let rtt = now.duration_since(sent_time)
                .unwrap_or(Duration::from_secs(0));
            
            self.last_pong_received = Some(now);
            
            tracing::debug!("Received valid pong from {} with nonce {} (RTT: {:?})", 
                          self.address, nonce, rtt);
            
            Ok(())
        } else {
            tracing::warn!("Received unexpected pong from {} with nonce {}", self.address, nonce);
            Err(NetworkError::ProtocolError(format!(
                "Unexpected pong nonce {} from {}", nonce, self.address
            )))
        }
    }
    
    /// Check if we need to send a ping (no ping/pong activity for 2 minutes).
    pub fn should_ping(&self) -> bool {
        const PING_INTERVAL: Duration = Duration::from_secs(120); // 2 minutes
        
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
}