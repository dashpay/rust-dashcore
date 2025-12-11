//! V2 Transport - BIP324 encrypted Dash P2P protocol transport.
//!
//! This implements the BIP324 encrypted transport protocol:
//! - 3 bytes: Encrypted length
//! - 1 byte: Header (flags, short message ID or 0x00 for extended)
//! - Variable: Contents (for extended format: 12-byte command + payload)
//! - 16 bytes: Authentication tag (ChaCha20-Poly1305)

use std::net::SocketAddr;

use async_trait::async_trait;
use bip324::{CipherSession, PacketType, NUM_LENGTH_BYTES};
use dashcore::network::message::{NetworkMessage, MAX_MSG_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::message_ids::{network_message_to_short_id, short_id_to_command, MSG_ID_EXTENDED};
use super::Transport;
use crate::error::{NetworkError, NetworkResult};

/// Read buffer size for TCP reads.
const READ_BUFFER_SIZE: usize = 8192;

/// Extended command length in bytes.
const COMMAND_LEN: usize = 12;

/// V2 Transport implementation for BIP324 encrypted P2P communication.
pub struct V2Transport {
    /// The underlying TCP stream.
    stream: TcpStream,
    /// The cipher session for encryption/decryption.
    cipher: CipherSession,
    /// Session ID for optional MitM verification.
    session_id: [u8; 32],
    /// Stateful receive buffer for partial reads.
    receive_buffer: Vec<u8>,
    /// Remote peer address (for logging).
    peer_address: SocketAddr,
    /// Bytes sent counter.
    bytes_sent: u64,
    /// Bytes received counter.
    bytes_received: u64,
    /// Whether the connection is active.
    connected: bool,
    /// Cached decrypted packet length (to avoid re-decrypting on partial reads).
    /// This is needed because `decrypt_packet_len` advances the cipher state.
    pending_packet_len: Option<usize>,
}

impl V2Transport {
    /// Create a new V2 transport from a successful handshake.
    ///
    /// # Arguments
    /// * `stream` - The TCP stream (ownership transferred from handshake)
    /// * `cipher` - The cipher session for encryption/decryption
    /// * `session_id` - Session ID for optional MitM verification
    /// * `peer_address` - Remote peer address (for logging)
    pub fn new(
        stream: TcpStream,
        cipher: CipherSession,
        session_id: [u8; 32],
        peer_address: SocketAddr,
    ) -> Self {
        Self {
            stream,
            cipher,
            session_id,
            receive_buffer: Vec::with_capacity(READ_BUFFER_SIZE),
            peer_address,
            bytes_sent: 0,
            bytes_received: 0,
            connected: true,
            pending_packet_len: None,
        }
    }

    /// Get the session ID for optional out-of-band MitM verification.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Encode a NetworkMessage into V2 plaintext format.
    ///
    /// Format:
    /// - Short format (common messages): payload bytes (header byte added by cipher)
    /// - Extended format (Dash-specific): 12-byte command + payload bytes
    fn encode_message(&self, message: &NetworkMessage) -> NetworkResult<Vec<u8>> {
        // Serialize the message payload using dashcore's canonical serialization
        let payload = message.consensus_encode_payload();

        // Check for short message ID
        if let Some(short_id) = network_message_to_short_id(message) {
            // Short format: just the short ID byte followed by payload
            // The short ID will be put in the header byte by the cipher
            // So we return: [short_id] + payload
            let mut plaintext = Vec::with_capacity(1 + payload.len());
            plaintext.push(short_id);
            plaintext.extend_from_slice(&payload);
            Ok(plaintext)
        } else {
            // Extended format: 0x00 header + 12-byte command + payload
            let cmd = message.cmd();
            let cmd_bytes = cmd.as_bytes();

            // Create 12-byte null-padded command
            let mut command = [0u8; COMMAND_LEN];
            let copy_len = std::cmp::min(cmd_bytes.len(), COMMAND_LEN);
            command[..copy_len].copy_from_slice(&cmd_bytes[..copy_len]);

            let mut plaintext = Vec::with_capacity(1 + COMMAND_LEN + payload.len());
            plaintext.push(MSG_ID_EXTENDED); // 0x00 marker for extended format
            plaintext.extend_from_slice(&command);
            plaintext.extend_from_slice(&payload);
            Ok(plaintext)
        }
    }

    /// Decode a V2 plaintext into a NetworkMessage.
    ///
    /// # Arguments
    /// * `plaintext` - Decrypted plaintext (header byte + optional command + payload)
    fn decode_message(&self, plaintext: &[u8]) -> NetworkResult<NetworkMessage> {
        // The bip324 crate prepends a "packet type" byte (0 for Genuine, 128 for Decoy)
        // Our actual message ID/content starts at byte 1
        if plaintext.len() < 2 {
            return Err(NetworkError::ProtocolError("V2 message too short".to_string()));
        }

        // Byte 0 is the crate's packet type indicator (always 0 for genuine messages)
        // Byte 1 is our actual message ID (short ID or 0 for extended format)
        let _crate_header = plaintext[0]; // Should be 0 for genuine, 128 for decoy
        let message_id = plaintext[1];

        // Trace: log first bytes of decrypted plaintext (verbose, for debugging only)
        let preview_len = std::cmp::min(20, plaintext.len());
        tracing::trace!(
            "V2Transport: Decrypted message preview ({} bytes total): {:02x?}, message_id={}",
            plaintext.len(),
            &plaintext[..preview_len],
            message_id
        );

        let (cmd, payload) = if message_id == MSG_ID_EXTENDED {
            // Extended format: 12-byte command + payload (starting at byte 2)
            if plaintext.len() < 2 + COMMAND_LEN {
                return Err(NetworkError::ProtocolError(
                    "V2 extended message too short".to_string(),
                ));
            }

            let command_bytes = &plaintext[2..2 + COMMAND_LEN];
            let payload = &plaintext[2 + COMMAND_LEN..];

            // Find null terminator in command
            let cmd_end = command_bytes.iter().position(|&b| b == 0).unwrap_or(COMMAND_LEN);
            let cmd = std::str::from_utf8(&command_bytes[..cmd_end]).map_err(|_| {
                NetworkError::ProtocolError("Invalid UTF-8 in V2 command".to_string())
            })?;

            tracing::trace!(
                "V2Transport: Decoding extended format message '{}' ({} bytes payload) from {}",
                cmd,
                payload.len(),
                self.peer_address
            );

            (cmd, payload)
        } else {
            // Short format: message_id is the short message ID, payload starts at byte 2
            let payload = &plaintext[2..];

            let cmd = short_id_to_command(message_id).ok_or_else(|| {
                NetworkError::ProtocolError(format!("Unknown V2 short message ID: {}", message_id))
            })?;

            tracing::trace!(
                "V2Transport: Decoding short format message '{}' (ID={}, {} bytes payload) from {}",
                cmd,
                message_id,
                payload.len(),
                self.peer_address
            );

            (cmd, payload)
        };

        // Decode the NetworkMessage using dashcore's canonical decoder
        NetworkMessage::consensus_decode_payload(cmd, payload)
            .map_err(|e| NetworkError::ProtocolError(format!("Failed to decode '{}': {}", cmd, e)))
    }

    /// Helper function to read some bytes into the receive buffer.
    async fn read_some(&mut self) -> std::io::Result<usize> {
        let mut tmp = [0u8; READ_BUFFER_SIZE];
        match self.stream.read(&mut tmp).await {
            Ok(0) => Ok(0),
            Ok(n) => {
                self.receive_buffer.extend_from_slice(&tmp[..n]);
                self.bytes_received += n as u64;
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl Transport for V2Transport {
    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        if !self.connected {
            return Err(NetworkError::ConnectionFailed("Not connected".to_string()));
        }

        // Encode the message to V2 plaintext format
        let plaintext = self.encode_message(&message)?;

        tracing::debug!(
            "V2Transport: Encoding message {:?} ({} bytes plaintext) for {}",
            message.cmd(),
            plaintext.len(),
            self.peer_address
        );

        // Encrypt the message
        // Note: The bip324 crate handles the header byte internally, but we're
        // putting our message type in the plaintext, so we use Genuine packet type
        let encrypted =
            self.cipher.outbound().encrypt_to_vec(&plaintext, PacketType::Genuine, None);

        // Write the encrypted packet
        match self.stream.write_all(&encrypted).await {
            Ok(_) => {
                // Flush to ensure data is sent immediately
                if let Err(e) = self.stream.flush().await {
                    tracing::warn!(
                        "V2Transport: Failed to flush socket {}: {}",
                        self.peer_address,
                        e
                    );
                }
                self.bytes_sent += encrypted.len() as u64;
                tracing::debug!(
                    "V2Transport: Sent encrypted message to {}: {:?} ({} bytes)",
                    self.peer_address,
                    message.cmd(),
                    encrypted.len()
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "V2Transport: Disconnecting {} due to write error: {}",
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

        loop {
            // Step 1: Ensure we have at least 3 bytes for the length
            while self.receive_buffer.len() < NUM_LENGTH_BYTES {
                match self.read_some().await {
                    Ok(0) => {
                        tracing::info!(
                            "V2Transport: Peer {} closed connection (EOF)",
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
                            "V2Transport: Peer {} connection reset/aborted",
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

            // Step 2: Decrypt the length (only if we haven't already for this packet)
            // IMPORTANT: decrypt_packet_len advances the cipher state, so we must
            // cache the result if we don't have enough bytes for the full packet yet.
            let packet_len = if let Some(cached_len) = self.pending_packet_len {
                cached_len
            } else {
                let len_bytes: [u8; NUM_LENGTH_BYTES] =
                    self.receive_buffer[..NUM_LENGTH_BYTES].try_into().expect("3 bytes for length");

                // Note: decrypt_packet_len returns the length of remaining data to read
                // (header + contents + tag), NOT just the contents length
                let decrypted_len = self.cipher.inbound().decrypt_packet_len(len_bytes);

                // Validate packet length
                if decrypted_len > MAX_MSG_SIZE + 1 + 16 {
                    // MAX_MSG_SIZE + header + tag
                    return Err(NetworkError::ProtocolError(format!(
                        "V2 packet too large: {} bytes",
                        decrypted_len
                    )));
                }

                // Cache the length in case we need to return early
                self.pending_packet_len = Some(decrypted_len);
                decrypted_len
            };

            let total_len = NUM_LENGTH_BYTES + packet_len;

            // Step 3: Ensure we have the complete packet
            while self.receive_buffer.len() < total_len {
                match self.read_some().await {
                    Ok(0) => {
                        tracing::info!(
                            "V2Transport: Peer {} closed connection (EOF)",
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
            }

            // Step 4: Extract and decrypt the packet (excluding length bytes which are already consumed)
            let ciphertext = &self.receive_buffer[NUM_LENGTH_BYTES..total_len];

            let (packet_type, plaintext) =
                self.cipher.inbound().decrypt_to_vec(ciphertext, None).map_err(|e| {
                    NetworkError::V2DecryptionFailed(format!("Decryption failed: {}", e))
                })?;

            // Consume the packet from the buffer and clear cached length
            self.receive_buffer.drain(0..total_len);
            self.pending_packet_len = None;

            // Step 5: Handle decoy packets
            if packet_type == PacketType::Decoy {
                tracing::debug!(
                    "V2Transport: Received decoy packet from {}, ignoring",
                    self.peer_address
                );
                continue; // Read next packet
            }

            // Step 6: Decode the message
            // Note: plaintext includes the header byte at position 0
            let message = self.decode_message(&plaintext)?;

            tracing::trace!(
                "V2Transport: Successfully decoded message from {}: {:?}",
                self.peer_address,
                message.cmd()
            );

            return Ok(Some(message));
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn protocol_version(&self) -> u8 {
        2
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
            tracing::info!("V2Transport: Shutdown connection to {}", self.peer_address);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_len() {
        // Verify command length constant
        assert_eq!(COMMAND_LEN, 12);
    }

    #[test]
    fn test_short_id_encoding() {
        // Verify ping/pong use short IDs
        assert!(network_message_to_short_id(&NetworkMessage::Ping(0)).is_some());
        assert!(network_message_to_short_id(&NetworkMessage::Pong(0)).is_some());
    }
}
