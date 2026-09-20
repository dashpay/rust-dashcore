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
use super::v2_handshake::V2Session;
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
    /// Any ciphertext the handshake already read past the version packet is seeded
    /// into the receive buffer so the peer's first message is not lost.
    ///
    /// # Arguments
    /// * `session` - Session produced by [`super::V2HandshakeManager::perform_handshake`]
    /// * `peer_address` - Remote peer address (for logging)
    pub fn new(session: V2Session, peer_address: SocketAddr) -> Self {
        let V2Session {
            stream,
            cipher,
            session_id,
            pending,
        } = session;
        let bytes_received = pending.len() as u64;
        let mut receive_buffer = Vec::with_capacity(READ_BUFFER_SIZE.max(pending.len()));
        receive_buffer.extend_from_slice(&pending);
        Self {
            stream,
            cipher,
            session_id,
            receive_buffer,
            peer_address,
            bytes_sent: 0,
            bytes_received,
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
    /// - Short format (common messages): `[short_id] + payload`
    /// - Extended format: `[0x00] + 12-byte null-padded command + payload`
    ///
    /// The bip324 cipher prepends its own packet-type header byte on encryption, so
    /// this returns only the contents that follow it.
    fn encode_message(message: &NetworkMessage) -> Vec<u8> {
        // Serialize the message payload using dashcore's canonical serialization
        let payload = message.consensus_encode_payload();

        if let Some(short_id) = network_message_to_short_id(message) {
            let mut plaintext = Vec::with_capacity(1 + payload.len());
            plaintext.push(short_id);
            plaintext.extend_from_slice(&payload);
            plaintext
        } else {
            // Use `command()` rather than `cmd()`: the latter returns the static string
            // "unknown" for `NetworkMessage::Unknown`, which would discard the real command
            // name on the wire. `CommandString` is at most 12 bytes by construction.
            let command = message.command();
            let cmd_bytes = command.as_ref().as_bytes();
            let mut command_field = [0u8; COMMAND_LEN];
            let copy_len = std::cmp::min(cmd_bytes.len(), COMMAND_LEN);
            command_field[..copy_len].copy_from_slice(&cmd_bytes[..copy_len]);

            let mut plaintext = Vec::with_capacity(1 + COMMAND_LEN + payload.len());
            plaintext.push(MSG_ID_EXTENDED);
            plaintext.extend_from_slice(&command_field);
            plaintext.extend_from_slice(&payload);
            plaintext
        }
    }

    /// Decode a V2 plaintext into a NetworkMessage.
    ///
    /// # Arguments
    /// * `plaintext` - Decrypted plaintext as returned by the bip324 cipher: the crate's
    ///   packet-type header byte, followed by the short ID (or `0x00` + 12-byte command),
    ///   followed by the payload.
    fn decode_message(plaintext: &[u8]) -> NetworkResult<NetworkMessage> {
        // The bip324 crate prepends a "packet type" byte (0 for Genuine, 128 for Decoy)
        // Our actual message ID/content starts at byte 1
        if plaintext.len() < 2 {
            return Err(NetworkError::ProtocolError("V2 message too short".to_string()));
        }

        // Byte 0 is the crate's packet type indicator (always 0 for genuine messages)
        // Byte 1 is our actual message ID (short ID or 0 for extended format)
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
                "V2Transport: Decoding extended format message '{}' ({} bytes payload)",
                cmd,
                payload.len()
            );

            (cmd, payload)
        } else {
            // Short format: message_id is the short message ID, payload starts at byte 2
            let payload = &plaintext[2..];

            let cmd = short_id_to_command(message_id).ok_or_else(|| {
                NetworkError::ProtocolError(format!("Unknown V2 short message ID: {}", message_id))
            })?;

            tracing::trace!(
                "V2Transport: Decoding short format message '{}' (ID={}, {} bytes payload)",
                cmd,
                message_id,
                payload.len()
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
        let plaintext = Self::encode_message(&message);

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
            let message = Self::decode_message(&plaintext).map_err(|e| {
                tracing::warn!(
                    "V2Transport: Failed to decode message from {}: {}",
                    self.peer_address,
                    e
                );
                e
            })?;

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

    /// Helper: Encode a message with the real transport encoder.
    fn test_encode_v2_message(message: &NetworkMessage) -> Vec<u8> {
        V2Transport::encode_message(message)
    }

    /// Helper: Decode a V2 message with the real transport decoder, prepending the
    /// packet-type header byte (0 = genuine) exactly as the bip324 cipher does.
    fn test_decode_v2_message(plaintext: &[u8]) -> Result<NetworkMessage, NetworkError> {
        let mut with_header = vec![0u8];
        with_header.extend_from_slice(plaintext);
        V2Transport::decode_message(&with_header)
    }

    #[test]
    fn test_decode_rejects_truncated_input() {
        // Only the crate header byte, no message ID
        assert!(matches!(V2Transport::decode_message(&[0u8]), Err(NetworkError::ProtocolError(_))));
        // Extended marker without a full 12-byte command
        assert!(matches!(
            test_decode_v2_message(&[MSG_ID_EXTENDED, b'v', b'e', b'r']),
            Err(NetworkError::ProtocolError(_))
        ));
        // Reserved / unassigned short ID
        assert!(matches!(
            test_decode_v2_message(&[29u8, 0, 0]),
            Err(NetworkError::ProtocolError(_))
        ));
    }

    #[test]
    fn test_unknown_message_preserves_command_name() {
        use dashcore::network::message::CommandString;

        let original = NetworkMessage::Unknown {
            command: CommandString::try_from_static("custom").unwrap(),
            payload: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };

        let encoded = test_encode_v2_message(&original);

        // Unknown messages have no short ID, so they must use the extended format
        assert_eq!(encoded[0], MSG_ID_EXTENDED);

        // The real command name must be on the wire, not the static "unknown" from cmd()
        let cmd_bytes = &encoded[1..1 + COMMAND_LEN];
        let cmd = std::str::from_utf8(cmd_bytes).unwrap().trim_end_matches('\0');
        assert_eq!(cmd, "custom");

        // Payload is the raw bytes with no length prefix
        assert_eq!(&encoded[1 + COMMAND_LEN..], &[0xaa, 0xbb, 0xcc, 0xdd]);

        let decoded = test_decode_v2_message(&encoded).expect("Failed to decode unknown message");
        assert_eq!(original, decoded, "Unknown message round-trip failed");
    }

    #[test]
    fn test_short_id_round_trip_common_messages() {
        // Messages that should use short format (1 byte ID)
        let short_format_messages: Vec<NetworkMessage> = vec![
            NetworkMessage::Ping(0x1234567890abcdef),
            NetworkMessage::Pong(0xfedcba0987654321),
            NetworkMessage::Inv(vec![]),
            NetworkMessage::GetData(vec![]),
            NetworkMessage::NotFound(vec![]),
            NetworkMessage::MemPool,
            NetworkMessage::FilterClear,
            NetworkMessage::SendHeaders2,
            NetworkMessage::SendDsq(true),
        ];

        for original in &short_format_messages {
            // Verify it uses short format (first byte is the short ID, not 0x00)
            let encoded = test_encode_v2_message(original);
            assert_ne!(
                encoded[0],
                MSG_ID_EXTENDED,
                "{} should use short format, not extended",
                original.cmd()
            );

            // Verify round-trip
            let decoded = test_decode_v2_message(&encoded)
                .unwrap_or_else(|e| panic!("Failed to decode {}: {}", original.cmd(), e));
            assert_eq!(original, &decoded, "Round-trip failed for {} message", original.cmd());
        }
    }

    #[test]
    fn test_extended_format_round_trip() {
        use dashcore::network::address::Address;
        use dashcore::network::constants::ServiceFlags;
        use dashcore::network::message_network::VersionMessage;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333),
            ServiceFlags::NONE,
        );

        let version = VersionMessage {
            version: 70015,
            services: ServiceFlags::NONE,
            timestamp: 0,
            receiver: addr.clone(),
            sender: addr,
            nonce: 0,
            user_agent: "/test/".to_string(),
            start_height: 0,
            relay: false,
            mn_auth_challenge: [0u8; 32],
            masternode_connection: false,
        };

        // Version message should use extended format (no short ID)
        let original = NetworkMessage::Version(version);

        let encoded = test_encode_v2_message(&original);

        // Verify extended format: first byte should be 0x00
        assert_eq!(encoded[0], MSG_ID_EXTENDED, "Version message should use extended format");

        // Verify command is in bytes 1-12
        let cmd_bytes = &encoded[1..1 + COMMAND_LEN];
        let cmd = std::str::from_utf8(cmd_bytes).unwrap().trim_end_matches('\0');
        assert_eq!(cmd, "version", "Command should be 'version'");

        // Verify round-trip
        let decoded = test_decode_v2_message(&encoded).expect("Failed to decode version message");
        assert_eq!(original, decoded, "Version round-trip failed");
    }
}
