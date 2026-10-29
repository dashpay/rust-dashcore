//! BIP324 V2 encrypted transport for Dash P2P connections.
//!
//! V1 framing is dashcore's `RawNetworkMessageCodec`; this module adds the V2
//! handshake and packet codec that peers use when both sides support it.

pub mod message_ids;
pub mod v2;
pub mod v2_handshake;

pub use v2::{encrypt_message, V2Decoder};
pub use v2_handshake::{V2HandshakeManager, V2HandshakeResult, V2Session};

/// Transport preference for peer connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPreference {
    /// Use V2 encrypted transport only (fail if peer doesn't support).
    V2Only,
    /// Prefer V2 encrypted transport, fallback to V1 if needed (default).
    #[default]
    V2Preferred,
    /// Use V1 unencrypted transport only (for compatibility testing).
    V1Only,
}
