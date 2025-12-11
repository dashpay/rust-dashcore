//! V2 Handshake implementation for BIP324 encrypted transport.
//!
//! This module implements the BIP324 handshake protocol:
//! 1. Key Exchange: ElligatorSwift-encoded public keys + garbage data
//! 2. Version Negotiation: Encrypted version packets confirm mutual v2 support
//!
//! The handshake detects v1-only peers by checking if the first bytes
//! received match the network magic (indicating v1 protocol).

use std::net::SocketAddr;
use std::time::Duration;

use bip324::{CipherSession, GarbageResult, Handshake, Role, VersionResult};
use dashcore::Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{NetworkError, NetworkResult};

/// Maximum garbage data size per BIP324 spec.
const MAX_GARBAGE_LEN: usize = 4095;

/// Timeout for handshake operations.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Size of ElligatorSwift public key.
const ELLIGATOR_SWIFT_KEY_SIZE: usize = 64;

/// Size of garbage terminator.
const GARBAGE_TERMINATOR_SIZE: usize = 16;

/// Result of the V2 handshake attempt.
pub enum V2HandshakeResult {
    /// Successfully completed V2 handshake.
    Success(V2Session),
    /// Detected V1-only peer (first bytes matched network magic).
    FallbackToV1,
}

/// Session data from a successful V2 handshake.
pub struct V2Session {
    /// The TCP stream (ownership transferred from handshake).
    pub stream: TcpStream,
    /// The cipher session for encryption/decryption.
    pub cipher: CipherSession,
    /// Session ID for optional out-of-band MitM verification.
    pub session_id: [u8; 32],
}

/// V2 Handshake manager for BIP324 encrypted connections.
pub struct V2HandshakeManager {
    /// Network magic bytes for key derivation.
    magic: [u8; 4],
    /// Our role in the handshake (initiator or responder).
    role: Role,
    /// Peer address (for logging).
    peer_address: SocketAddr,
}

impl V2HandshakeManager {
    /// Create a new handshake manager for initiating connections.
    ///
    /// The initiator sends the first message (their ElligatorSwift pubkey).
    pub fn new_initiator(network: Network, peer_address: SocketAddr) -> Self {
        Self {
            magic: network.magic().to_le_bytes(),
            role: Role::Initiator,
            peer_address,
        }
    }

    /// Create a new handshake manager for responding to connections.
    ///
    /// The responder waits for the initiator's pubkey first.
    pub fn new_responder(network: Network, peer_address: SocketAddr) -> Self {
        Self {
            magic: network.magic().to_le_bytes(),
            role: Role::Responder,
            peer_address,
        }
    }

    /// Perform the V2 handshake on the given TCP stream.
    ///
    /// # Arguments
    /// * `stream` - A connected TCP stream
    ///
    /// # Returns
    /// * `V2HandshakeResult::Success(session)` - Handshake completed successfully
    /// * `V2HandshakeResult::FallbackToV1` - Detected v1-only peer
    ///
    /// # Errors
    /// Returns `NetworkError` if the handshake fails (e.g., timeout, protocol error).
    pub async fn perform_handshake(
        self,
        mut stream: TcpStream,
    ) -> NetworkResult<V2HandshakeResult> {
        tracing::debug!("V2 handshake: Starting as {:?} with {}", self.role, self.peer_address);

        // Create the handshake state machine
        let handshake = Handshake::new(self.magic, self.role).map_err(|e| {
            NetworkError::V2HandshakeFailed(format!("Failed to create handshake: {}", e))
        })?;

        // Step 1: Send our public key (no garbage for simplicity)
        let mut send_key_buffer = vec![0u8; Handshake::send_key_len(None)];
        let handshake = handshake.send_key(None, &mut send_key_buffer).map_err(|e| {
            NetworkError::V2HandshakeFailed(format!("Failed to prepare key: {}", e))
        })?;

        tracing::debug!(
            "V2 handshake: Sending our ElligatorSwift pubkey ({} bytes) to {}",
            send_key_buffer.len(),
            self.peer_address
        );

        tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write_all(&send_key_buffer))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| {
                NetworkError::V2HandshakeFailed(format!("Failed to send pubkey: {}", e))
            })?;

        stream
            .flush()
            .await
            .map_err(|e| NetworkError::V2HandshakeFailed(format!("Failed to flush: {}", e)))?;

        // Step 2: Read the remote's public key (64 bytes)
        // First, peek at the initial bytes to detect v1 magic
        let mut peek_buf = [0u8; 4];
        let peek_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut peek_buf)).await;

        match peek_result {
            Ok(Ok(n)) if n >= 4 => {
                if peek_buf == self.magic {
                    tracing::info!(
                        "V2 handshake: Detected V1-only peer {} (received magic bytes)",
                        self.peer_address
                    );
                    return Ok(V2HandshakeResult::FallbackToV1);
                }
            }
            Ok(Ok(_)) => {
                // Not enough bytes to determine, continue with v2
            }
            Ok(Err(e)) => {
                return Err(NetworkError::V2HandshakeFailed(format!(
                    "Failed to peek for v1 detection: {}",
                    e
                )));
            }
            Err(_) => {
                return Err(NetworkError::Timeout);
            }
        }

        // Read the full remote pubkey (64 bytes)
        let mut remote_pubkey = [0u8; ELLIGATOR_SWIFT_KEY_SIZE];
        tracing::debug!(
            "V2 handshake: Reading remote ElligatorSwift pubkey from {}",
            self.peer_address
        );

        tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut remote_pubkey))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| {
                NetworkError::V2HandshakeFailed(format!("Failed to read remote pubkey: {}", e))
            })?;

        // Step 3: Process the remote's public key and derive session keys
        let handshake = handshake.receive_key(remote_pubkey).map_err(|e| {
            NetworkError::V2HandshakeFailed(format!("Failed to process remote pubkey: {}", e))
        })?;

        tracing::debug!("V2 handshake: Derived session keys with {}", self.peer_address);

        // Step 4: Send garbage terminator + version packet
        let mut send_version_buffer = vec![0u8; Handshake::send_version_len(None)];
        let handshake = handshake.send_version(&mut send_version_buffer, None).map_err(|e| {
            NetworkError::V2HandshakeFailed(format!("Failed to prepare version: {}", e))
        })?;

        tracing::debug!(
            "V2 handshake: Sending garbage terminator + version ({} bytes) to {}",
            send_version_buffer.len(),
            self.peer_address
        );

        tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write_all(&send_version_buffer))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| {
                NetworkError::V2HandshakeFailed(format!("Failed to send version: {}", e))
            })?;

        stream
            .flush()
            .await
            .map_err(|e| NetworkError::V2HandshakeFailed(format!("Failed to flush: {}", e)))?;

        // Step 5: Receive remote garbage + terminator
        // Read up to MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_SIZE bytes
        let mut garbage_buffer = Vec::with_capacity(MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_SIZE);
        let mut handshake_state = handshake;

        tracing::debug!(
            "V2 handshake: Scanning for remote garbage terminator from {}",
            self.peer_address
        );

        let scan_start = std::time::Instant::now();
        loop {
            // Check timeout
            if scan_start.elapsed() > HANDSHAKE_TIMEOUT {
                return Err(NetworkError::Timeout);
            }

            // Read a chunk
            let mut chunk = [0u8; 256];
            let n = match tokio::time::timeout(
                HANDSHAKE_TIMEOUT.saturating_sub(scan_start.elapsed()),
                stream.read(&mut chunk),
            )
            .await
            {
                Ok(Ok(0)) => {
                    return Err(NetworkError::V2HandshakeFailed(
                        "Connection closed during garbage scan".to_string(),
                    ));
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    return Err(NetworkError::V2HandshakeFailed(format!(
                        "Failed to read garbage: {}",
                        e
                    )));
                }
                Err(_) => {
                    return Err(NetworkError::Timeout);
                }
            };

            garbage_buffer.extend_from_slice(&chunk[..n]);

            // Try to find the garbage terminator
            match handshake_state.receive_garbage(&garbage_buffer) {
                Ok(GarbageResult::FoundGarbage {
                    handshake,
                    consumed_bytes,
                }) => {
                    tracing::debug!(
                        "V2 handshake: Found garbage terminator after {} bytes from {}",
                        consumed_bytes,
                        self.peer_address
                    );

                    // Keep any remaining bytes after the garbage
                    let remaining = garbage_buffer[consumed_bytes..].to_vec();

                    // Step 6: Receive version packet
                    // The version packet follows the garbage terminator
                    let mut handshake = handshake;

                    // Read version packet: 3-byte length + encrypted content
                    let mut version_data = remaining;

                    // Read at least 3 bytes for the length prefix
                    while version_data.len() < 3 {
                        let mut more = [0u8; 64];
                        let n = tokio::time::timeout(
                            HANDSHAKE_TIMEOUT.saturating_sub(scan_start.elapsed()),
                            stream.read(&mut more),
                        )
                        .await
                        .map_err(|_| NetworkError::Timeout)?
                        .map_err(|e| {
                            NetworkError::V2HandshakeFailed(format!(
                                "Failed to read version packet length: {}",
                                e
                            ))
                        })?;
                        if n == 0 {
                            return Err(NetworkError::V2HandshakeFailed(
                                "Connection closed before version packet".to_string(),
                            ));
                        }
                        version_data.extend_from_slice(&more[..n]);
                    }

                    // Decrypt the packet length (first 3 bytes)
                    let length_bytes: [u8; 3] = version_data[..3].try_into().map_err(|_| {
                        NetworkError::V2HandshakeFailed(
                            "Failed to extract length bytes".to_string(),
                        )
                    })?;
                    let packet_len = handshake.decrypt_packet_len(length_bytes).map_err(|e| {
                        NetworkError::V2HandshakeFailed(format!(
                            "Failed to decrypt packet length: {}",
                            e
                        ))
                    })?;

                    tracing::debug!(
                        "V2 handshake: Version packet length is {} bytes from {}",
                        packet_len,
                        self.peer_address
                    );

                    // Read more data if needed to have the full packet
                    let total_needed = 3 + packet_len; // length prefix + packet content
                    while version_data.len() < total_needed {
                        let mut more = [0u8; 64];
                        let n = tokio::time::timeout(
                            HANDSHAKE_TIMEOUT.saturating_sub(scan_start.elapsed()),
                            stream.read(&mut more),
                        )
                        .await
                        .map_err(|_| NetworkError::Timeout)?
                        .map_err(|e| {
                            NetworkError::V2HandshakeFailed(format!(
                                "Failed to read version packet content: {}",
                                e
                            ))
                        })?;
                        if n == 0 {
                            return Err(NetworkError::V2HandshakeFailed(
                                "Connection closed before version packet complete".to_string(),
                            ));
                        }
                        version_data.extend_from_slice(&more[..n]);
                    }

                    // Extract just the packet content (excluding the 3-byte length prefix)
                    let mut packet_content = version_data[3..3 + packet_len].to_vec();

                    // Process version packet
                    match handshake.receive_version(&mut packet_content) {
                        Ok(VersionResult::Complete {
                            cipher,
                        }) => {
                            tracing::info!(
                                "V2 handshake: Completed successfully with {}",
                                self.peer_address
                            );

                            return Ok(V2HandshakeResult::Success(V2Session {
                                stream,
                                cipher,
                                session_id: [0u8; 32], // TODO: Get actual session ID
                            }));
                        }
                        Ok(VersionResult::Decoy(_handshake)) => {
                            // Received a decoy packet, need to continue reading
                            // For now, treat as error (can be enhanced later)
                            return Err(NetworkError::V2HandshakeFailed(
                                "Received decoy packet - not yet supported".to_string(),
                            ));
                        }
                        Err(e) => {
                            return Err(NetworkError::V2HandshakeFailed(format!(
                                "Failed to process version packet: {}",
                                e
                            )));
                        }
                    }
                }
                Ok(GarbageResult::NeedMoreData(hs)) => {
                    handshake_state = hs;
                    // Continue reading more data
                    if garbage_buffer.len() > MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_SIZE {
                        return Err(NetworkError::V2HandshakeFailed(
                            "Garbage terminator not found within limit".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(NetworkError::V2HandshakeFailed(format!(
                        "Failed to process garbage: {}",
                        e
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_manager_creation() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let initiator = V2HandshakeManager::new_initiator(Network::Dash, addr);
        assert_eq!(initiator.role, Role::Initiator);
        // Dash mainnet magic: 0xBD6B0CBF in little-endian
        assert_eq!(initiator.magic, [0xbf, 0x0c, 0x6b, 0xbd]);

        let responder = V2HandshakeManager::new_responder(Network::Dash, addr);
        assert_eq!(responder.role, Role::Responder);
    }

    #[test]
    fn test_testnet_magic() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let manager = V2HandshakeManager::new_initiator(Network::Testnet, addr);
        // Dash testnet magic: 0xFFCAE2CE in little-endian
        assert_eq!(manager.magic, [0xce, 0xe2, 0xca, 0xff]);
    }
}
