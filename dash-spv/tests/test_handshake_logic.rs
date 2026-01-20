//! Unit tests for handshake logic

use dash_spv::network::{HandshakeManager, HandshakeState};
use dash_spv::MempoolStrategy;
use dashcore::Network;

#[test]
fn test_handshake_state_transitions() {
    let mut handshake = HandshakeManager::new(Network::Dash, MempoolStrategy::BloomFilter, None);

    // Initial state should be Init
    assert_eq!(*handshake.state(), HandshakeState::Init);

    // After reset, should be back to Init
    handshake.reset();
    assert_eq!(*handshake.state(), HandshakeState::Init);
}
