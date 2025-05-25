//! TCP connection management.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};

use dashcore::consensus::{encode, Decodable};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
use dashcore::Network;

use crate::error::{NetworkError, NetworkResult};
use crate::types::PeerInfo;

/// TCP connection to a Dash peer.
pub struct TcpConnection {
    address: SocketAddr,
    stream: Option<TcpStream>,
    timeout: Duration,
    connected_at: Option<SystemTime>,
    bytes_sent: u64,
    bytes_received: u64,
}

impl TcpConnection {
    /// Create a new TCP connection to the given address.
    pub fn new(address: SocketAddr, timeout: Duration) -> Self {
        Self {
            address,
            stream: None,
            timeout,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
    
    /// Connect to the peer.
    pub async fn connect(&mut self) -> NetworkResult<()> {
        // For now, we'll use blocking I/O since the original code uses it
        // In a full implementation, we'd use tokio::net::TcpStream
        let stream = std::net::TcpStream::connect_timeout(&self.address, self.timeout)
            .map_err(|e| NetworkError::ConnectionFailed(format!("Failed to connect to {}: {}", self.address, e)))?;
        
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        
        self.stream = Some(stream);
        self.connected_at = Some(SystemTime::now());
        
        tracing::info!("Connected to peer {}", self.address);
        
        Ok(())
    }
    
    /// Disconnect from the peer.
    pub async fn disconnect(&mut self) -> NetworkResult<()> {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        self.connected_at = None;
        
        tracing::info!("Disconnected from peer {}", self.address);
        
        Ok(())
    }
    
    /// Send a message to the peer.
    pub async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        let raw_message = RawNetworkMessage {
            magic: Network::Dash.magic(), // TODO: Make configurable
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
        let stream = self.stream.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        let mut reader = BufReader::new(stream);
        
        match RawNetworkMessage::consensus_decode(&mut reader) {
            Ok(raw_message) => {
                // Estimate bytes received (this is approximate)
                self.bytes_received += 100; // TODO: Calculate actual size
                
                tracing::debug!("Received message from {}: {:?}", self.address, raw_message.payload);
                
                Ok(Some(raw_message.payload))
            }
            Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No message available
                Ok(None)
            }
            Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Peer disconnected
                tracing::info!("Peer {} disconnected", self.address);
                self.stream = None;
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
        self.stream.is_some()
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
        (self.bytes_sent, self.bytes_received)
    }
}