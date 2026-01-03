//! V1 Transport - Unencrypted Dash P2P protocol transport.
//!
//! This implements the traditional Bitcoin/Dash P2P message framing:
//! - 4 bytes: Network magic
//! - 12 bytes: Command string
//! - 4 bytes: Payload length (little-endian)
//! - 4 bytes: Checksum (first 4 bytes of SHA256d of payload)
//! - Variable: Payload

use std::net::SocketAddr;

use async_trait::async_trait;
use dashcore::consensus::{encode, Decodable};
use dashcore::network::message::{NetworkMessage, RawNetworkMessage, MAX_MSG_SIZE};
use dashcore::Network;
use dashcore_hashes::Hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::Transport;
use crate::error::{NetworkError, NetworkResult};

/// Header length for V1 protocol: magic(4) + command(12) + length(4) + checksum(4)
const HEADER_LEN: usize = 24;

/// Maximum resync steps per receive call to prevent infinite loops.
const MAX_RESYNC_STEPS_PER_CALL: usize = 64;

/// Read buffer size for TCP reads.
const READ_BUFFER_SIZE: usize = 8192;

/// V1 Transport implementation for unencrypted P2P communication.
pub struct V1Transport {
    /// The underlying TCP stream.
    stream: TcpStream,
    /// Stateful message framing buffer.
    framing_buffer: Vec<u8>,
    /// Network for magic byte validation.
    network: Network,
    /// Remote peer address (for logging).
    peer_address: SocketAddr,
    /// Bytes sent counter.
    bytes_sent: u64,
    /// Bytes received counter.
    bytes_received: u64,
    /// Whether the connection is active.
    connected: bool,
    /// Consecutive resync counter (for telemetry).
    consecutive_resyncs: u32,
}

impl V1Transport {
    /// Create a new V1 transport from an established TCP stream.
    ///
    /// # Arguments
    /// * `stream` - An already-connected TCP stream
    /// * `network` - The Dash network (for magic byte validation)
    /// * `peer_address` - Remote peer address (for logging)
    pub fn new(stream: TcpStream, network: Network, peer_address: SocketAddr) -> Self {
        Self {
            stream,
            framing_buffer: Vec::with_capacity(READ_BUFFER_SIZE),
            network,
            peer_address,
            bytes_sent: 0,
            bytes_received: 0,
            connected: true,
            consecutive_resyncs: 0,
        }
    }

    /// Helper function to read some bytes into the framing buffer.
    async fn read_some(&mut self) -> std::io::Result<usize> {
        let mut tmp = [0u8; READ_BUFFER_SIZE];
        match self.stream.read(&mut tmp).await {
            Ok(0) => Ok(0),
            Ok(n) => {
                self.framing_buffer.extend_from_slice(&tmp[..n]);
                self.bytes_received += n as u64;
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }

    /// Get the consecutive resync count (for telemetry).
    pub fn consecutive_resyncs(&self) -> u32 {
        self.consecutive_resyncs
    }
}

#[async_trait]
impl Transport for V1Transport {
    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        if !self.connected {
            return Err(NetworkError::ConnectionFailed("Not connected".to_string()));
        }

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
                "V1Transport: Sending {} raw bytes (len={}): {:02x?}",
                msg_type,
                serialized.len(),
                &serialized[..std::cmp::min(100, serialized.len())]
            );
        }

        // Write with error handling
        match self.stream.write_all(&serialized).await {
            Ok(_) => {
                // Flush to ensure data is sent immediately
                if let Err(e) = self.stream.flush().await {
                    tracing::warn!(
                        "V1Transport: Failed to flush socket {}: {}",
                        self.peer_address,
                        e
                    );
                }
                self.bytes_sent += serialized.len() as u64;
                tracing::debug!(
                    "V1Transport: Sent message to {}: {:?}",
                    self.peer_address,
                    raw_message.payload
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "V1Transport: Disconnecting {} due to write error: {}",
                    self.peer_address,
                    e
                );
                self.connected = false;
                Err(NetworkError::ConnectionFailed(format!("Write failed: {}", e)))
            }
        }
    }

    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        if !self.connected {
            return Err(NetworkError::ConnectionFailed("Not connected".to_string()));
        }

        let magic_bytes = self.network.magic().to_le_bytes();
        let mut resync_steps = 0usize;

        loop {
            // Ensure header availability
            if self.framing_buffer.len() < HEADER_LEN {
                match self.read_some().await {
                    Ok(0) => {
                        tracing::info!(
                            "V1Transport: Peer {} closed connection (EOF)",
                            self.peer_address
                        );
                        self.connected = false;
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
                        tracing::info!(
                            "V1Transport: Peer {} connection reset/aborted",
                            self.peer_address
                        );
                        self.connected = false;
                        return Err(NetworkError::PeerDisconnected);
                    }
                    Err(e) => {
                        self.connected = false;
                        return Err(NetworkError::ConnectionFailed(format!("Read failed: {}", e)));
                    }
                }
            }

            // Align to magic
            if self.framing_buffer.len() >= 4 && self.framing_buffer[..4] != magic_bytes {
                if let Some(pos) = self.framing_buffer.windows(4).position(|w| w == magic_bytes) {
                    if pos > 0 {
                        tracing::warn!(
                            "V1Transport {}: stream desync: skipping {} stray bytes before magic",
                            self.peer_address,
                            pos
                        );
                        self.consecutive_resyncs = self.consecutive_resyncs.saturating_add(1);
                        self.framing_buffer.drain(0..pos);
                        resync_steps += 1;
                        if resync_steps >= MAX_RESYNC_STEPS_PER_CALL {
                            return Ok(None);
                        }
                        continue;
                    }
                } else {
                    // Keep last 3 bytes of potential magic prefix
                    if self.framing_buffer.len() > 3 {
                        let dropped = self.framing_buffer.len() - 3;
                        tracing::warn!(
                            "V1Transport {}: stream desync: dropping {} bytes (no magic found)",
                            self.peer_address,
                            dropped
                        );
                        self.consecutive_resyncs = self.consecutive_resyncs.saturating_add(1);
                        self.framing_buffer.drain(0..dropped);
                        resync_steps += 1;
                        if resync_steps >= MAX_RESYNC_STEPS_PER_CALL {
                            return Ok(None);
                        }
                    }
                    // Need more data
                    match self.read_some().await {
                        Ok(0) => {
                            tracing::info!(
                                "V1Transport: Peer {} closed connection (EOF)",
                                self.peer_address
                            );
                            self.connected = false;
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
                            self.connected = false;
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
            if self.framing_buffer.len() < HEADER_LEN {
                match self.read_some().await {
                    Ok(0) => {
                        tracing::info!(
                            "V1Transport: Peer {} closed connection (EOF)",
                            self.peer_address
                        );
                        self.connected = false;
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
                        self.connected = false;
                        return Err(NetworkError::ConnectionFailed(format!("Read failed: {}", e)));
                    }
                }
                continue;
            }

            // Parse header fields
            let length_le = u32::from_le_bytes([
                self.framing_buffer[16],
                self.framing_buffer[17],
                self.framing_buffer[18],
                self.framing_buffer[19],
            ]) as usize;
            let header_checksum = [
                self.framing_buffer[20],
                self.framing_buffer[21],
                self.framing_buffer[22],
                self.framing_buffer[23],
            ];

            // Validate announced length to prevent unbounded accumulation or overflow
            if length_le > MAX_MSG_SIZE {
                return Err(NetworkError::ProtocolError(format!(
                    "Declared payload length {} exceeds MAX_MSG_SIZE {}",
                    length_le, MAX_MSG_SIZE
                )));
            }
            let total_len = match HEADER_LEN.checked_add(length_le) {
                Some(v) => v,
                None => {
                    return Err(NetworkError::ProtocolError("Message length overflow".to_string()));
                }
            };

            // Ensure full frame available
            if self.framing_buffer.len() < total_len {
                match self.read_some().await {
                    Ok(0) => {
                        tracing::info!(
                            "V1Transport: Peer {} closed connection (EOF)",
                            self.peer_address
                        );
                        self.connected = false;
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
                        self.connected = false;
                        return Err(NetworkError::ConnectionFailed(format!("Read failed: {}", e)));
                    }
                }
                continue;
            }

            // Verify checksum
            let payload_slice = &self.framing_buffer[HEADER_LEN..total_len];
            let expected = {
                let checksum = dashcore_hashes::sha256d::Hash::hash(payload_slice);
                [checksum[0], checksum[1], checksum[2], checksum[3]]
            };
            if expected != header_checksum {
                tracing::warn!(
                    "V1Transport: Skipping message with invalid checksum from {}: expected {:02x?}, actual {:02x?}",
                    self.peer_address,
                    expected,
                    header_checksum
                );
                if header_checksum == [0, 0, 0, 0] {
                    tracing::warn!(
                        "V1Transport: All-zeros checksum detected from {}, likely corrupted stream - resyncing",
                        self.peer_address
                    );
                }
                // Resync by dropping a byte and retrying
                self.framing_buffer.drain(0..1);
                self.consecutive_resyncs = self.consecutive_resyncs.saturating_add(1);
                resync_steps += 1;
                if resync_steps >= MAX_RESYNC_STEPS_PER_CALL {
                    return Ok(None);
                }
                continue;
            }

            // Decode full RawNetworkMessage from the frame using existing decoder
            let mut cursor = std::io::Cursor::new(&self.framing_buffer[..total_len]);
            match RawNetworkMessage::consensus_decode(&mut cursor) {
                Ok(raw_message) => {
                    // Consume bytes
                    self.framing_buffer.drain(0..total_len);
                    self.consecutive_resyncs = 0;

                    // Validate magic matches our network
                    if raw_message.magic != self.network.magic() {
                        tracing::warn!(
                            "V1Transport: Received message with wrong magic bytes: expected {:#x}, got {:#x}",
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
                        "V1Transport: Successfully decoded message from {}: {:?}",
                        self.peer_address,
                        raw_message.payload.cmd()
                    );

                    if raw_message.payload.cmd() == "headers2" {
                        tracing::info!(
                            "V1Transport: Received Headers2 message from {}!",
                            self.peer_address
                        );
                    }

                    if let NetworkMessage::Block(ref block) = raw_message.payload {
                        let block_hash = block.block_hash();
                        tracing::info!(
                            "V1Transport: Successfully decoded block {} from {}",
                            block_hash,
                            self.peer_address
                        );
                    }

                    if let NetworkMessage::Headers2(ref headers2) = raw_message.payload {
                        tracing::info!(
                            "V1Transport: Successfully decoded Headers2 message from {} with {} compressed headers",
                            self.peer_address,
                            headers2.headers.len()
                        );
                    }

                    return Ok(Some(raw_message.payload));
                }
                Err(e) => {
                    tracing::warn!(
                        "V1Transport {}: decode error after framing ({}), attempting resync",
                        self.peer_address,
                        e
                    );
                    self.framing_buffer.drain(0..1);
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

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn protocol_version(&self) -> u8 {
        1
    }

    fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    async fn shutdown(&mut self) -> NetworkResult<()> {
        if self.connected {
            let _ = self.stream.shutdown().await;
            self.connected = false;
            tracing::info!("V1Transport: Shutdown connection to {}", self.peer_address);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_len() {
        // Verify our header length constant is correct
        assert_eq!(HEADER_LEN, 4 + 12 + 4 + 4); // magic + command + length + checksum
    }
}
