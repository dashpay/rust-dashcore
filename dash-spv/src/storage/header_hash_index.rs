use std::collections::HashMap;

use dashcore::BlockHash;

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
        // Only groups with pending heights are looked up in the map, so a merge hashes one key
        // per pending group rather than one per group. They are marked in `offsets[group + 1]`
        // before the walk overwrites that entry with the group's end.
        let mut offsets = vec![0; GROUPS + 1];
        for &group in self.pending.keys() {
            offsets[group as usize + 1] = 1;
        }
        let mut heights = Vec::with_capacity(self.heights.len() + self.pending_len);

        for (group, range) in self.offsets.windows(2).enumerate() {
            let stored = &self.heights[range[0] as usize..range[1] as usize];
            heights.extend(stored.iter().copied().filter(|h| keep(*h)));

            if offsets[group + 1] != 0 {
                if let Some(pending) = self.pending.get(&(group as u32)) {
                    heights.extend(pending.iter().copied().filter(|h| keep(*h)));
                }
            }

            offsets[group + 1] = heights.len() as u32;
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

    /// Every group holds exactly the heights inserted into it and not truncated, highest first,
    /// whether they were merged or are still pending: checked against a map of group to heights.
    #[test]
    fn groups_match_a_plain_map() {
        let mut index = HeaderHashIndex::default();
        let mut model: HashMap<u32, Vec<u32>> = HashMap::new();
        // Few groups, so most share one with others, merged and pending alike. One is the last.
        let group_of = |height: u32| match height % 97 {
            96 => GROUPS as u32 - 1,
            group => group,
        };
        let hash = |height: u32| {
            let mut bytes = [0; 32];
            bytes[..4]
                .copy_from_slice(&(group_of(height) * GROUP_SIZE + height % 13).to_le_bytes());
            bytes[4..8].copy_from_slice(&height.to_le_bytes());
            BlockHash::from_byte_array(bytes)
        };
        let check = |index: &HeaderHashIndex, model: &HashMap<u32, Vec<u32>>| {
            for slot in 0..97 {
                let group = group_of(slot);
                let mut want = model.get(&group).cloned().unwrap_or_default();
                want.sort_unstable_by(|a, b| b.cmp(a));
                let probe = hash(slot);
                assert_eq!(HeaderHashIndex::group(&probe), group);
                assert_eq!(index.get(&probe), want, "group {group}");
            }
        };

        let mut height = 0;
        for (inserts, truncate_to) in
            [(MERGE_THRESHOLD + 11, None), (300, Some(50_100)), (MERGE_THRESHOLD, Some(70_000))]
        {
            for _ in 0..inserts {
                index.insert(&hash(height), height);
                model.entry(HeaderHashIndex::group(&hash(height))).or_default().push(height);
                height += 1;
            }
            check(&index, &model);
            if let Some(top) = truncate_to {
                index.truncate_above(top);
                model.values_mut().for_each(|heights| heights.retain(|&h| h <= top));
                height = top + 1;
                check(&index, &model);
            }
        }
    }
}
