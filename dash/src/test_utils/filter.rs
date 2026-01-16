use std::ops::Range;

use hashes::Hash;

use crate::hash_types::FilterHeader;

impl FilterHeader {
    pub fn dummy(height: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[1..5].copy_from_slice(&height.to_le_bytes());
        FilterHeader::from_raw_hash(dashcore_hashes::sha256d::Hash::from_byte_array(bytes))
    }

    pub fn dummy_batch(heights: Range<u32>) -> Vec<Self> {
        heights.map(Self::dummy).collect()
    }
}
