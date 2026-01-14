use dashcore::Header;

use crate::chain::{ChainTip, ChainWork};

impl ChainTip {
    pub fn dummy(height: u32, work_value: u8) -> ChainTip {
        let header = Header::dummy(height);
        let chain_work = ChainWork::dummy(work_value);

        ChainTip::new(header, height, chain_work)
    }
}
