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
use dashcore::consensus::{encode::serialize, Decodable};
use dashcore::network::message::{CommandString, NetworkMessage, MAX_MSG_SIZE};
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

    /// Serialize the payload of a NetworkMessage.
    ///
    /// This mirrors the payload serialization logic from RawNetworkMessage's Encodable impl.
    fn serialize_payload(message: &NetworkMessage) -> Vec<u8> {
        match message {
            NetworkMessage::Version(ref dat) => serialize(dat),
            NetworkMessage::Addr(ref dat) => serialize(dat),
            NetworkMessage::Inv(ref dat) => serialize(dat),
            NetworkMessage::GetData(ref dat) => serialize(dat),
            NetworkMessage::NotFound(ref dat) => serialize(dat),
            NetworkMessage::GetBlocks(ref dat) => serialize(dat),
            NetworkMessage::GetHeaders(ref dat) => serialize(dat),
            NetworkMessage::Tx(ref dat) => serialize(dat),
            NetworkMessage::Block(ref dat) => serialize(dat),
            NetworkMessage::Headers(ref dat) => {
                // Headers need special serialization with trailing zero byte per header
                Self::serialize_headers(dat)
            }
            NetworkMessage::GetHeaders2(ref dat) => serialize(dat),
            NetworkMessage::Headers2(ref dat) => serialize(dat),
            NetworkMessage::Ping(ref dat) => serialize(dat),
            NetworkMessage::Pong(ref dat) => serialize(dat),
            NetworkMessage::MerkleBlock(ref dat) => serialize(dat),
            NetworkMessage::FilterLoad(ref dat) => serialize(dat),
            NetworkMessage::FilterAdd(ref dat) => serialize(dat),
            NetworkMessage::GetCFilters(ref dat) => serialize(dat),
            NetworkMessage::CFilter(ref dat) => serialize(dat),
            NetworkMessage::GetCFHeaders(ref dat) => serialize(dat),
            NetworkMessage::CFHeaders(ref dat) => serialize(dat),
            NetworkMessage::GetCFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::CFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::SendCmpct(ref dat) => serialize(dat),
            NetworkMessage::CmpctBlock(ref dat) => serialize(dat),
            NetworkMessage::GetBlockTxn(ref dat) => serialize(dat),
            NetworkMessage::BlockTxn(ref dat) => serialize(dat),
            NetworkMessage::Alert(ref dat) => serialize(dat),
            NetworkMessage::Reject(ref dat) => serialize(dat),
            NetworkMessage::FeeFilter(ref dat) => serialize(dat),
            NetworkMessage::AddrV2(ref dat) => serialize(dat),
            NetworkMessage::GetMnListD(ref dat) => serialize(dat),
            NetworkMessage::MnListDiff(ref dat) => serialize(dat),
            NetworkMessage::GetQRInfo(ref dat) => serialize(dat),
            NetworkMessage::QRInfo(ref dat) => serialize(dat),
            NetworkMessage::CLSig(ref dat) => serialize(dat),
            NetworkMessage::ISLock(ref dat) => serialize(dat),
            NetworkMessage::SendDsq(wants_dsq) => serialize(&(*wants_dsq as u8)),
            NetworkMessage::Unknown {
                payload: ref data,
                ..
            } => serialize(data),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::SendHeaders2
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr
            | NetworkMessage::WtxidRelay
            | NetworkMessage::FilterClear
            | NetworkMessage::SendAddrV2 => vec![],
        }
    }

    /// Serialize headers with trailing zero byte per header (matches HeaderSerializationWrapper).
    fn serialize_headers(headers: &[dashcore::block::Header]) -> Vec<u8> {
        use dashcore::consensus::Encodable;
        let mut buf = Vec::new();
        // VarInt for count
        let _ = dashcore::VarInt(headers.len() as u64).consensus_encode(&mut buf);
        // Each header + trailing zero
        for header in headers {
            let _ = header.consensus_encode(&mut buf);
            buf.push(0u8);
        }
        buf
    }

    /// Deserialize headers with trailing zero byte per header (matches HeaderDeserializationWrapper).
    fn deserialize_headers(payload: &[u8]) -> NetworkResult<Vec<dashcore::block::Header>> {
        let mut cursor = std::io::Cursor::new(payload);
        let count = dashcore::VarInt::consensus_decode(&mut cursor).map_err(|e| {
            NetworkError::ProtocolError(format!("Failed to decode headers count: {}", e))
        })?;

        let mut headers = Vec::with_capacity(count.0 as usize);
        for _ in 0..count.0 {
            let header = dashcore::block::Header::consensus_decode(&mut cursor).map_err(|e| {
                NetworkError::ProtocolError(format!("Failed to decode header: {}", e))
            })?;
            headers.push(header);
            // Read and discard the trailing zero byte
            let _trailing = u8::consensus_decode(&mut cursor).map_err(|e| {
                NetworkError::ProtocolError(format!("Failed to decode header trailing byte: {}", e))
            })?;
        }
        Ok(headers)
    }

    /// Encode a NetworkMessage into V2 plaintext format.
    ///
    /// Format:
    /// - Short format (common messages): payload bytes (header byte added by cipher)
    /// - Extended format (Dash-specific): 12-byte command + payload bytes
    fn encode_message(&self, message: &NetworkMessage) -> NetworkResult<Vec<u8>> {
        // Serialize the message payload
        let payload = Self::serialize_payload(message);

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

        if message_id == MSG_ID_EXTENDED {
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

            // Decode the NetworkMessage based on command
            self.decode_by_command(cmd, payload)
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

            self.decode_by_command(cmd, payload)
        }
    }

    /// Decode a NetworkMessage from command string and payload bytes.
    fn decode_by_command(&self, cmd: &str, payload: &[u8]) -> NetworkResult<NetworkMessage> {
        // Create a cursor for decoding
        let mut cursor = std::io::Cursor::new(payload);

        // Decode based on command
        // Note: This mirrors the NetworkMessage variants and their Decodable impls
        let message = match cmd {
            "addr" => {
                let addrs: Vec<(u32, dashcore::network::address::Address)> =
                    Decodable::consensus_decode(&mut cursor).map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode addr: {}", e))
                    })?;
                NetworkMessage::Addr(addrs)
            }
            "block" => {
                let block = dashcore::Block::consensus_decode(&mut cursor).map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode block: {}", e))
                })?;
                NetworkMessage::Block(block)
            }
            "blocktxn" => {
                let blocktxn =
                    dashcore::network::message_compact_blocks::BlockTxn::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode blocktxn: {}", e))
                    })?;
                NetworkMessage::BlockTxn(blocktxn)
            }
            "cmpctblock" => {
                let cmpctblock =
                    dashcore::network::message_compact_blocks::CmpctBlock::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode cmpctblock: {}", e))
                    })?;
                NetworkMessage::CmpctBlock(cmpctblock)
            }
            "feefilter" => {
                let fee = i64::consensus_decode(&mut cursor).map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode feefilter: {}", e))
                })?;
                NetworkMessage::FeeFilter(fee)
            }
            "filteradd" => {
                let filteradd =
                    dashcore::network::message_bloom::FilterAdd::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode filteradd: {}",
                                e
                            ))
                        })?;
                NetworkMessage::FilterAdd(filteradd)
            }
            "filterclear" => NetworkMessage::FilterClear,
            "filterload" => {
                let filterload =
                    dashcore::network::message_bloom::FilterLoad::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode filterload: {}",
                                e
                            ))
                        })?;
                NetworkMessage::FilterLoad(filterload)
            }
            "getblocks" => {
                let getblocks =
                    dashcore::network::message_blockdata::GetBlocksMessage::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode getblocks: {}", e))
                    })?;
                NetworkMessage::GetBlocks(getblocks)
            }
            "getblocktxn" => {
                let getblocktxn =
                    dashcore::network::message_compact_blocks::GetBlockTxn::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode getblocktxn: {}", e))
                    })?;
                NetworkMessage::GetBlockTxn(getblocktxn)
            }
            "getdata" => {
                let inv: Vec<dashcore::network::message_blockdata::Inventory> =
                    Decodable::consensus_decode(&mut cursor).map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode getdata: {}", e))
                    })?;
                NetworkMessage::GetData(inv)
            }
            "getheaders" => {
                let getheaders =
                    dashcore::network::message_blockdata::GetHeadersMessage::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode getheaders: {}", e))
                    })?;
                NetworkMessage::GetHeaders(getheaders)
            }
            "headers" => {
                // Headers have special deserialization (VarInt count + each header + trailing zero)
                let headers = Self::deserialize_headers(payload)?;
                NetworkMessage::Headers(headers)
            }
            "inv" => {
                let inv: Vec<dashcore::network::message_blockdata::Inventory> =
                    Decodable::consensus_decode(&mut cursor).map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode inv: {}", e))
                    })?;
                NetworkMessage::Inv(inv)
            }
            "mempool" => NetworkMessage::MemPool,
            "merkleblock" => {
                let merkleblock =
                    dashcore::MerkleBlock::consensus_decode(&mut cursor).map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode merkleblock: {}", e))
                    })?;
                NetworkMessage::MerkleBlock(merkleblock)
            }
            "notfound" => {
                let inv: Vec<dashcore::network::message_blockdata::Inventory> =
                    Decodable::consensus_decode(&mut cursor).map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode notfound: {}", e))
                    })?;
                NetworkMessage::NotFound(inv)
            }
            "ping" => {
                let nonce = u64::consensus_decode(&mut cursor).map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode ping: {}", e))
                })?;
                NetworkMessage::Ping(nonce)
            }
            "pong" => {
                let nonce = u64::consensus_decode(&mut cursor).map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode pong: {}", e))
                })?;
                NetworkMessage::Pong(nonce)
            }
            "sendcmpct" => {
                let sendcmpct =
                    dashcore::network::message_compact_blocks::SendCmpct::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode sendcmpct: {}", e))
                    })?;
                NetworkMessage::SendCmpct(sendcmpct)
            }
            "tx" => {
                let tx = dashcore::Transaction::consensus_decode(&mut cursor).map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode tx: {}", e))
                })?;
                NetworkMessage::Tx(tx)
            }
            "getcfilters" => {
                let getcfilters =
                    dashcore::network::message_filter::GetCFilters::consensus_decode(&mut cursor)
                        .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode getcfilters: {}", e))
                    })?;
                NetworkMessage::GetCFilters(getcfilters)
            }
            "cfilter" => {
                let cfilter =
                    dashcore::network::message_filter::CFilter::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!("Failed to decode cfilter: {}", e))
                        })?;
                NetworkMessage::CFilter(cfilter)
            }
            "getcfheaders" => {
                let getcfheaders =
                    dashcore::network::message_filter::GetCFHeaders::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode getcfheaders: {}",
                                e
                            ))
                        })?;
                NetworkMessage::GetCFHeaders(getcfheaders)
            }
            "cfheaders" => {
                let cfheaders =
                    dashcore::network::message_filter::CFHeaders::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode cfheaders: {}",
                                e
                            ))
                        })?;
                NetworkMessage::CFHeaders(cfheaders)
            }
            "getcfcheckpt" => {
                let getcfcheckpt =
                    dashcore::network::message_filter::GetCFCheckpt::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode getcfcheckpt: {}",
                                e
                            ))
                        })?;
                NetworkMessage::GetCFCheckpt(getcfcheckpt)
            }
            "cfcheckpt" => {
                let cfcheckpt =
                    dashcore::network::message_filter::CFCheckpt::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode cfcheckpt: {}",
                                e
                            ))
                        })?;
                NetworkMessage::CFCheckpt(cfcheckpt)
            }
            // Dash-specific messages (extended format)
            "version" => {
                let version = dashcore::network::message_network::VersionMessage::consensus_decode(
                    &mut cursor,
                )
                .map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode version: {}", e))
                })?;
                NetworkMessage::Version(version)
            }
            "verack" => NetworkMessage::Verack,
            "sendheaders" => NetworkMessage::SendHeaders,
            "getaddr" => NetworkMessage::GetAddr,
            "wtxidrelay" => NetworkMessage::WtxidRelay,
            "sendaddrv2" => NetworkMessage::SendAddrV2,
            "addrv2" => {
                let addrs: Vec<dashcore::network::address::AddrV2Message> =
                    Decodable::consensus_decode(&mut cursor).map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode addrv2: {}", e))
                    })?;
                NetworkMessage::AddrV2(addrs)
            }
            "reject" => {
                let reject =
                    dashcore::network::message_network::Reject::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!("Failed to decode reject: {}", e))
                        })?;
                NetworkMessage::Reject(reject)
            }
            // Dash-specific extended messages
            "mnlistdiff" => {
                let mnlistdiff =
                    dashcore::network::message_sml::MnListDiff::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode mnlistdiff: {}",
                                e
                            ))
                        })?;
                NetworkMessage::MnListDiff(mnlistdiff)
            }
            "getmnlistd" => {
                let getmnlistd =
                    dashcore::network::message_sml::GetMnListDiff::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode getmnlistd: {}",
                                e
                            ))
                        })?;
                NetworkMessage::GetMnListD(getmnlistd)
            }
            "qrinfo" => {
                let qrinfo =
                    dashcore::network::message_qrinfo::QRInfo::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!("Failed to decode qrinfo: {}", e))
                        })?;
                NetworkMessage::QRInfo(qrinfo)
            }
            "getqrinfo" => {
                let getqrinfo =
                    dashcore::network::message_qrinfo::GetQRInfo::consensus_decode(&mut cursor)
                        .map_err(|e| {
                            NetworkError::ProtocolError(format!(
                                "Failed to decode getqrinfo: {}",
                                e
                            ))
                        })?;
                NetworkMessage::GetQRInfo(getqrinfo)
            }
            "clsig" => {
                let clsig = dashcore::ChainLock::consensus_decode(&mut cursor).map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode clsig: {}", e))
                })?;
                NetworkMessage::CLSig(clsig)
            }
            "isdlock" => {
                let islock = dashcore::InstantLock::consensus_decode(&mut cursor).map_err(|e| {
                    NetworkError::ProtocolError(format!("Failed to decode isdlock: {}", e))
                })?;
                NetworkMessage::ISLock(islock)
            }
            "headers2" => {
                let headers2 =
                    dashcore::network::message_headers2::Headers2Message::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode headers2: {}", e))
                    })?;
                NetworkMessage::Headers2(headers2)
            }
            "getheaders2" => {
                // getheaders2 uses same format as getheaders
                let getheaders2 =
                    dashcore::network::message_blockdata::GetHeadersMessage::consensus_decode(
                        &mut cursor,
                    )
                    .map_err(|e| {
                        NetworkError::ProtocolError(format!("Failed to decode getheaders2: {}", e))
                    })?;
                NetworkMessage::GetHeaders2(getheaders2)
            }
            "sendheaders2" => NetworkMessage::SendHeaders2,
            "senddsq" => {
                // SendDsq is a single bool (serialized as u8)
                let wants_dsq = if payload.is_empty() {
                    false
                } else {
                    payload[0] != 0
                };
                NetworkMessage::SendDsq(wants_dsq)
            }
            // Unknown command - use Unknown variant
            _ => {
                tracing::warn!(
                    "V2Transport: Unknown command '{}' from {}, storing as raw bytes",
                    cmd,
                    self.peer_address
                );
                NetworkMessage::Unknown {
                    command: CommandString::try_from(cmd.to_string()).unwrap_or_else(|_| {
                        CommandString::try_from("unknown".to_string()).expect("valid")
                    }),
                    payload: payload.to_vec(),
                }
            }
        };

        Ok(message)
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
