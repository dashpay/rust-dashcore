use dashcore::Header;

use crate::chain::{Checkpoint, CheckpointManager};

impl Checkpoint {
    pub fn dummy(height: u32) -> Checkpoint {
        let header = Header::dummy(height);

        Checkpoint::new(height, header.into())
    }
}

impl CheckpointManager {
    pub fn dummy(heights: &[u32]) -> CheckpointManager {
        let checkpoints =
            heights.iter().map(|height| Checkpoint::dummy(*height)).collect::<Vec<_>>();

        CheckpointManager::new_with_checkpoints(checkpoints)
    }
}
