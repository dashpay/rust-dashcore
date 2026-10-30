//! BIP324 V2 packet codec for the Dash P2P protocol.
//!
//! Each packet on the wire is:
//! - 3 bytes: Encrypted length
//! - 1 byte: Header (flags, set by the bip324 cipher)
//! - Variable: Contents (a short message ID + payload, or `0x00` + 12-byte command + payload)
//! - 16 bytes: Authentication tag (ChaCha20-Poly1305)

use bip324::{InboundCipher, OutboundCipher, PacketType, NUM_HEADER_BYTES, NUM_LENGTH_BYTES};
use dashcore::consensus::encode;
use dashcore::network::message::{NetworkMessage, RawNetworkMessage, MAX_MSG_SIZE};
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;

use super::message_ids::{network_message_to_short_id, short_id_to_command, MSG_ID_EXTENDED};

/// Extended command length in bytes.
const COMMAND_LEN: usize = 12;

/// Authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Largest packet (header + contents + tag) a peer may announce: a maximum-size
/// payload in the extended format. Above bip324's `decrypt_to_vec` cap, so packets are
/// decrypted with `decrypt` into a buffer sized here.
const MAX_PACKET_LEN: usize = NUM_HEADER_BYTES + 1 + COMMAND_LEN + MAX_MSG_SIZE + TAG_LEN;

/// Encode a NetworkMessage into V2 contents.
///
/// Format:
/// - Short format (common messages): `[short_id] + payload`
/// - Extended format: `[0x00] + 12-byte null-padded command + payload`
///
/// The bip324 cipher prepends its own packet-type header byte on encryption, so
/// this returns only the contents that follow it.
fn encode_message(message: &NetworkMessage) -> Vec<u8> {
    let payload = message.consensus_encode_payload();

    if let Some(short_id) = network_message_to_short_id(message) {
        let mut contents = Vec::with_capacity(1 + payload.len());
        contents.push(short_id);
        contents.extend_from_slice(&payload);
        contents
    } else {
        // Use `command()` rather than `cmd()`: the latter returns the static string
        // "unknown" for `NetworkMessage::Unknown`, which would discard the real command
        // name on the wire. `CommandString` is at most 12 bytes by construction.
        let command = message.command();
        let cmd_bytes = command.as_ref().as_bytes();
        let mut command_field = [0u8; COMMAND_LEN];
        let copy_len = std::cmp::min(cmd_bytes.len(), COMMAND_LEN);
        command_field[..copy_len].copy_from_slice(&cmd_bytes[..copy_len]);

        let mut contents = Vec::with_capacity(1 + COMMAND_LEN + payload.len());
        contents.push(MSG_ID_EXTENDED);
        contents.extend_from_slice(&command_field);
        contents.extend_from_slice(&payload);
        contents
    }
}

/// Encrypt `message` into one complete V2 packet.
pub fn encrypt_message(cipher: &mut OutboundCipher, message: &NetworkMessage) -> Vec<u8> {
    cipher.encrypt_to_vec(&encode_message(message), PacketType::Genuine, None)
}

/// Read the command of extended-format contents (after the `0x00` marker), following
/// Dash Core: printable ASCII up to the first NUL, and only NULs after it.
fn extended_command(field: &[u8]) -> Option<&str> {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let (command, padding) = field.split_at(len);
    if command.iter().any(|&b| !(b' '..=0x7f).contains(&b)) || padding.iter().any(|&b| b != 0) {
        return None;
    }
    std::str::from_utf8(command).ok()
}

/// Decode a V2 plaintext into a NetworkMessage.
///
/// `plaintext` is as returned by the bip324 cipher: the crate's packet-type header
/// byte, followed by the short ID (or `0x00` + 12-byte command), followed by the
/// payload.
///
/// Returns `Ok(None)` for contents Dash Core would drop without disconnecting: an
/// unassigned short ID (a newer peer may use IDs we don't know yet) or a malformed
/// command. A known command whose payload doesn't decode is an error.
fn decode_message(plaintext: &[u8]) -> Result<Option<NetworkMessage>, encode::Error> {
    let Some((&message_id, rest)) = plaintext.get(NUM_HEADER_BYTES..).and_then(<[u8]>::split_first)
    else {
        return Ok(None);
    };

    let (cmd, payload) = if message_id == MSG_ID_EXTENDED {
        if rest.len() < COMMAND_LEN {
            return Ok(None);
        }
        let (field, payload) = rest.split_at(COMMAND_LEN);
        match extended_command(field) {
            Some(cmd) => (cmd, payload),
            None => return Ok(None),
        }
    } else {
        match short_id_to_command(message_id) {
            Some(cmd) => (cmd, rest),
            None => {
                tracing::debug!("V2: dropping message with unknown short ID {}", message_id);
                return Ok(None);
            }
        }
    };

    NetworkMessage::consensus_decode_payload(cmd, payload).map(Some)
}

/// Frames V2 packets off a byte stream, yielding each decoded message with the
/// number of bytes its packet took on the wire.
///
/// Decoy packets are skipped, as are messages Dash Core drops: unassigned short IDs
/// and malformed commands. Any error leaves the inbound cipher unusable, so the
/// connection must be closed.
pub struct V2Decoder {
    magic: u32,
    cipher: InboundCipher,
    /// Decrypted length of the packet being buffered. `decrypt_packet_len` advances
    /// the cipher, so it must run exactly once per packet even across partial reads.
    packet_len: Option<usize>,
}

impl V2Decoder {
    /// `magic` is stamped on the decoded messages so they look like V1 frames to callers.
    pub fn new(magic: u32, cipher: InboundCipher) -> Self {
        Self {
            magic,
            cipher,
            packet_len: None,
        }
    }
}

impl Decoder for V2Decoder {
    type Item = (RawNetworkMessage, u64);
    type Error = encode::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            let packet_len = match self.packet_len {
                Some(len) => len,
                None => {
                    let Some(len_bytes) = src.get(..NUM_LENGTH_BYTES) else {
                        return Ok(None);
                    };
                    let len = self
                        .cipher
                        .decrypt_packet_len(len_bytes.try_into().expect("3 length bytes"));
                    if len > MAX_PACKET_LEN {
                        return Err(encode::Error::ParseFailed("V2 packet exceeds MAX_MSG_SIZE"));
                    }
                    self.packet_len = Some(len);
                    len
                }
            };

            let total_len = NUM_LENGTH_BYTES + packet_len;
            if src.len() < total_len {
                src.reserve(total_len - src.len());
                return Ok(None);
            }
            let packet = src.split_to(total_len);
            self.packet_len = None;

            let ciphertext = &packet[NUM_LENGTH_BYTES..];
            let mut plaintext = vec![0u8; ciphertext.len().saturating_sub(TAG_LEN)];
            let packet_type = self
                .cipher
                .decrypt(ciphertext, &mut plaintext, None)
                .map_err(|_| encode::Error::ParseFailed("V2 packet failed authentication"))?;
            if packet_type == PacketType::Decoy {
                continue;
            }
            if let Some(payload) = decode_message(&plaintext)? {
                let raw = RawNetworkMessage {
                    magic: self.magic,
                    payload,
                };
                return Ok(Some((raw, total_len as u64)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::network::message::CommandString;

    /// Decode contents as the bip324 cipher returns them, behind a genuine header byte.
    fn decode_contents(contents: &[u8]) -> Result<Option<NetworkMessage>, encode::Error> {
        let mut plaintext = vec![0u8];
        plaintext.extend_from_slice(contents);
        decode_message(&plaintext)
    }

    #[test]
    fn test_decode_drops_what_dash_core_drops() {
        // Only the crate header byte, no message ID
        assert!(matches!(decode_message(&[0u8]), Ok(None)));
        // Extended marker without a full 12-byte command
        assert!(matches!(decode_contents(&[MSG_ID_EXTENDED, b'v', b'e', b'r']), Ok(None)));
        // Unassigned short ID
        assert!(matches!(decode_contents(&[29u8, 0, 0]), Ok(None)));
        // Non-printable command, and a non-NUL byte after the padding starts
        let mut bad = [0u8; 1 + COMMAND_LEN];
        bad[1] = 0x01;
        assert!(matches!(decode_contents(&bad), Ok(None)));
        let mut bad = [0u8; 1 + COMMAND_LEN];
        bad[1..4].copy_from_slice(b"inv");
        bad[5] = b'x';
        assert!(matches!(decode_contents(&bad), Ok(None)));
    }

    #[test]
    fn test_decode_rejects_malformed_payload() {
        let ping = network_message_to_short_id(&NetworkMessage::Ping(0)).unwrap();
        // A ping nonce is 8 bytes.
        assert!(decode_contents(&[ping, 1, 2, 3]).is_err());
    }

    #[test]
    fn test_unknown_message_preserves_command_name() {
        let original = NetworkMessage::Unknown {
            command: CommandString::try_from_static("custom").unwrap(),
            payload: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };

        let encoded = encode_message(&original);

        // Unknown messages have no short ID, so they must use the extended format
        assert_eq!(encoded[0], MSG_ID_EXTENDED);

        // The real command name must be on the wire, not the static "unknown" from cmd()
        let cmd_bytes = &encoded[1..1 + COMMAND_LEN];
        let cmd = std::str::from_utf8(cmd_bytes).unwrap().trim_end_matches('\0');
        assert_eq!(cmd, "custom");

        // Payload is the raw bytes with no length prefix
        assert_eq!(&encoded[1 + COMMAND_LEN..], &[0xaa, 0xbb, 0xcc, 0xdd]);

        let decoded = decode_contents(&encoded).unwrap();
        assert_eq!(Some(original), decoded, "Unknown message round-trip failed");
    }

    #[test]
    fn test_short_id_round_trip_common_messages() {
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

        for original in short_format_messages {
            let encoded = encode_message(&original);
            assert_ne!(
                encoded[0],
                MSG_ID_EXTENDED,
                "{} should use short format, not extended",
                original.cmd()
            );

            let decoded = decode_contents(&encoded)
                .unwrap_or_else(|e| panic!("Failed to decode {}: {}", original.cmd(), e));
            assert_eq!(
                Some(&original),
                decoded.as_ref(),
                "Round-trip failed for {}",
                original.cmd()
            );
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

        let encoded = encode_message(&original);
        assert_eq!(encoded[0], MSG_ID_EXTENDED, "Version message should use extended format");

        let cmd_bytes = &encoded[1..1 + COMMAND_LEN];
        let cmd = std::str::from_utf8(cmd_bytes).unwrap().trim_end_matches('\0');
        assert_eq!(cmd, "version", "Command should be 'version'");

        let decoded = decode_contents(&encoded).expect("Failed to decode version message");
        assert_eq!(Some(original), decoded, "Version round-trip failed");
    }
}
