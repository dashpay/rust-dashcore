//! TCP connection management.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};

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
}

impl TcpConnection {
    /// Create a new TCP connection to the given address.
    pub fn new(address: SocketAddr, timeout: Duration) -> Self {
        Self {
            address,
            write_stream: None,
            read_stream: None,
            timeout,
            connected_at: None,
            bytes_sent: 0,
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
            magic: Network::Dash.magic(),
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
}