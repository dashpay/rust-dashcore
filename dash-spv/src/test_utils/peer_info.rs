use std::net::SocketAddr;

use crate::network::PeerInfo;

impl PeerInfo {
    pub fn dummy(addr: SocketAddr) -> Self {
        PeerInfo {
            addr,
            start_height: 0,
        }
    }
}
