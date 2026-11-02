//! BIP324 V2 packet codec for the Dash P2P protocol.
//!
//! Each packet on the wire is:
//! - 3 bytes: Encrypted length
//! - 1 byte: Header (flags, set by the bip324 cipher)
//! - Variable: Contents (a short message ID + payload, or `0x00` + 12-byte command + payload)
//! - 16 bytes: Authentication tag (ChaCha20-Poly1305)
//!
//! The contents are encoded by [`NetworkMessage::consensus_encode_v2`].

use bip324::{InboundCipher, OutboundCipher, PacketType, NUM_HEADER_BYTES, NUM_LENGTH_BYTES};
use dashcore::consensus::encode;
use dashcore::network::message::{NetworkMessage, RawNetworkMessage, MAX_MSG_SIZE};
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;

/// Extended command length in bytes.
const COMMAND_LEN: usize = 12;

/// Authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Largest packet (header + contents + tag) a peer may announce: a maximum-size
/// payload in the extended format. Above bip324's `decrypt_to_vec` cap, so packets are
/// decrypted with `decrypt` into a buffer sized here.
const MAX_PACKET_LEN: usize = NUM_HEADER_BYTES + 1 + COMMAND_LEN + MAX_MSG_SIZE + TAG_LEN;

/// Encrypt `message` into one complete V2 packet.
pub(crate) fn encrypt_message(cipher: &mut OutboundCipher, message: &NetworkMessage) -> Vec<u8> {
    cipher.encrypt_to_vec(&message.consensus_encode_v2(), PacketType::Genuine, None)
}

/// Frames V2 packets off a byte stream, yielding each decoded message with the
/// number of bytes its packet took on the wire.
///
/// Decoy packets are skipped, as are messages Dash Core drops: unassigned short IDs
/// and malformed commands. Any error leaves the inbound cipher unusable, so the
/// connection must be closed.
pub(crate) struct V2Decoder {
    magic: u32,
    cipher: InboundCipher,
    /// Decrypted length of the packet being buffered. `decrypt_packet_len` advances
    /// the cipher, so it must run exactly once per packet even across partial reads.
    packet_len: Option<usize>,
}

impl V2Decoder {
    /// `magic` is stamped on the decoded messages so they look like V1 frames to callers.
    pub(crate) fn new(magic: u32, cipher: InboundCipher) -> Self {
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
                    let Some(&len_bytes) = src.first_chunk::<NUM_LENGTH_BYTES>() else {
                        return Ok(None);
                    };
                    let len = self.cipher.decrypt_packet_len(len_bytes);
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
            let contents = plaintext.get(NUM_HEADER_BYTES..).unwrap_or_default();
            if let Some(payload) = NetworkMessage::consensus_decode_v2(contents)? {
                let raw = RawNetworkMessage {
                    magic: self.magic,
                    payload,
                };
                return Ok(Some((raw, total_len as u64)));
            }
        }
    }
}
