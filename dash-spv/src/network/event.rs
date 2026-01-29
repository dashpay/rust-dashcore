//! Network event system for peer connection state changes.
//!
//! This module provides events for network layer changes that sync managers
//! need to react to, such as peer connections and disconnections.

use dashcore::prelude::CoreBlockHeight;
use std::net::SocketAddr;

/// Events emitted by the network layer.
///
/// These events inform sync managers about network state changes,
/// allowing them to wait for connections before sending requests.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A peer has connected.
    PeerConnected {
        /// Socket address of the connected peer.
        address: SocketAddr,
    },

    /// A peer has disconnected.
    PeerDisconnected {
        /// Socket address of the disconnected peer.
        address: SocketAddr,
    },

    /// Summary of connected peers (emitted after connect/disconnect).
    ///
    /// This event provides the current state of connections after any change.
    PeersUpdated {
        /// Number of currently connected peers.
        connected_count: usize,
        /// Addresses of all connected peers.
        addresses: Vec<SocketAddr>,
        /// Best height of connected peers.
        best_height: Option<CoreBlockHeight>,
    },
}

impl NetworkEvent {
    /// Get a short description of this event for logging.
    pub fn description(&self) -> String {
        match self {
            NetworkEvent::PeerConnected {
                address,
            } => {
                format!("PeerConnected({})", address)
            }
            NetworkEvent::PeerDisconnected {
                address,
            } => {
                format!("PeerDisconnected({})", address)
            }
            NetworkEvent::PeersUpdated {
                connected_count,
                addresses: _,
                best_height,
            } => {
                format!(
                    "PeersUpdated(connected={}, best_height={})",
                    connected_count,
                    best_height.unwrap_or(0)
                )
            }
        }
    }
}
