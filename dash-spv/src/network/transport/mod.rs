//! BIP324 V2 encrypted transport for Dash P2P connections.
//!
//! V1 framing is dashcore's `RawNetworkMessageCodec`; the V2 handshake is
//! `bip324::futures::handshake`. This module adds the V2 packet codec.

mod v2;

pub(crate) use v2::{encrypt_message, V2Decoder};

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
