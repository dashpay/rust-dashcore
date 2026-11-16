use dashcore::Header;

use crate::chain::checkpoints::CHECKPOINT_HEADERS;
use crate::chain::{Checkpoint, CheckpointManager};
use crate::types::HashedBlockHeader;

impl Checkpoint {
    /// A checkpoint at `height` of dummy headers, which do not chain nor meet their bits.
    pub fn dummy(height: u32) -> Checkpoint {
        let start = height - (CHECKPOINT_HEADERS as u32 - 1);
        let headers = (start..=height).map(|h| HashedBlockHeader::from(Header::dummy(h))).collect();

        Checkpoint::new(height, headers).expect("dummy checkpoint height must fit its headers")
    }
}

impl CheckpointManager {
    /// Checkpoints at every 50th block of `chain`.
    pub fn dummy(chain: &[HashedBlockHeader]) -> Self {
        let checkpoints = (49..chain.len())
            .step_by(50)
            .map(|height| {
                let headers = chain[height + 1 - CHECKPOINT_HEADERS..=height].to_vec();
                Checkpoint::new(height as u32, headers).expect("dummy checkpoint must fit")
            })
            .collect();
        Self::new(checkpoints)
    }
}
