use dashcore::Header;

use crate::FilterMatch;

impl FilterMatch {
    pub fn dummy(height: u32) -> Self {
        FilterMatch {
            block_hash: Header::dummy(height).block_hash(),
            height,
            block_requested: false,
        }
    }
}
