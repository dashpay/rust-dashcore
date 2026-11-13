use dashcore::Header;

use crate::chain::checkpoints::CHECKPOINT_HEADERS;
use crate::chain::Checkpoint;
use crate::types::HashedBlockHeader;

impl Checkpoint {
    /// A checkpoint at `height` of dummy headers, which do not chain nor meet their bits.
    pub fn dummy(height: u32) -> Checkpoint {
        let start = height - (CHECKPOINT_HEADERS as u32 - 1);
        let headers = (start..=height).map(|h| HashedBlockHeader::from(Header::dummy(h))).collect();

        Checkpoint::new(height, headers).expect("dummy checkpoint height must fit its headers")
    }
}
