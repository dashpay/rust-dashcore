use std::collections::HashMap;

use dashcore::BlockHash;
use dashcore_hashes::Hash;

const GROUP_SIZE: u32 = 4096;
const GROUPS: usize = (u32::MAX / GROUP_SIZE) as usize + 1;
const MERGE_THRESHOLD: usize = 50_000;

/// The heights of the hashes in each group of `GROUP_SIZE` values of their
/// first 4 bytes. A height only matches if its stored header has the hash.
pub struct HeaderHashIndex {
    /// `heights[offsets[g]..offsets[g + 1]]` are the heights of group `g`.
    offsets: Vec<u32>,
    heights: Vec<u32>,
    pending: HashMap<u32, Vec<u32>>,
    pending_len: usize,
}

impl Default for HeaderHashIndex {
    fn default() -> Self {
        Self {
            offsets: vec![0; GROUPS + 1],
            heights: Vec::new(),
            pending: HashMap::new(),
            pending_len: 0,
        }
    }
}

impl HeaderHashIndex {
    fn group(hash: &BlockHash) -> u32 {
        let bytes = hash.as_byte_array();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) / GROUP_SIZE
    }

    pub fn insert(&mut self, hash: &BlockHash, height: u32) {
        self.pending.entry(Self::group(hash)).or_default().push(height);
        self.pending_len += 1;
        if self.pending_len >= MERGE_THRESHOLD {
            self.rebuild(|_| true);
        }
    }

    /// The heights `hash` may be at, highest first.
    pub fn get(&self, hash: &BlockHash) -> Vec<u32> {
        let group = Self::group(hash) as usize;
        let mut heights =
            self.heights[self.offsets[group] as usize..self.offsets[group + 1] as usize].to_vec();
        heights.extend(self.pending.get(&(group as u32)).into_iter().flatten());
        heights.sort_unstable_by(|a, b| b.cmp(a));
        heights
    }

    pub fn truncate_above(&mut self, height: u32) {
        self.rebuild(|h| h <= height);
    }

    fn rebuild(&mut self, keep: impl Fn(u32) -> bool) {
        let mut offsets = Vec::with_capacity(GROUPS + 1);
        let mut heights = Vec::with_capacity(self.heights.len() + self.pending_len);
        offsets.push(0);

        for (group, range) in self.offsets.windows(2).enumerate() {
            let stored = &self.heights[range[0] as usize..range[1] as usize];
            heights.extend(stored.iter().copied().filter(|h| keep(*h)));

            let pending = self.pending.get(&(group as u32)).into_iter().flatten();
            heights.extend(pending.copied().filter(|h| keep(*h)));

            offsets.push(heights.len() as u32);
        }

        self.offsets = offsets;
        self.heights = heights;
        self.pending.clear();
        self.pending_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heights_survive_merges_and_truncation() {
        let mut index = HeaderHashIndex::default();
        let count = MERGE_THRESHOLD as u32 * 2 + 7;

        for height in 0..count {
            index.insert(&BlockHash::dummy(height), height);
        }

        for height in (0..count).step_by(1_000) {
            let heights = index.get(&BlockHash::dummy(height));
            assert!(heights.contains(&height));
            assert!(heights.windows(2).all(|w| w[0] >= w[1]));
        }

        index.truncate_above(count / 2);
        assert!(index.get(&BlockHash::dummy(count / 2)).contains(&(count / 2)));
        assert!(!index.get(&BlockHash::dummy(count / 2 + 1)).contains(&(count / 2 + 1)));
    }
}
