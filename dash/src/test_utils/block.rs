use dash_network::Network;

use crate::{Block, constants::genesis_block};

impl Block {
    pub fn dummy(network: Network) -> Self {
        genesis_block(network)
    }
}
