use dashcore::{constants::genesis_block, Network};

use crate::chain::{ChainTip, ChainWork};

impl ChainTip {
    pub fn dummy(height: u32, work_value: u8) -> ChainTip {
        let mut header = genesis_block(Network::Dash).header;
        header.nonce = height; // Make it unique

        let chain_work = ChainWork::dummy(work_value);

        ChainTip::new(header, height, chain_work)
    }
}
