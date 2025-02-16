use std::fmt::{Display, Formatter};
use crate::sml::llmq_type::quorum_snapshot_skip_mode::LLMQSnapshotSkipMode;

#[derive(Clone, Debug)]
pub struct LLMQSnapshot {
    // The bitset of nodes already in quarters at the start of cycle at height n
    // (masternodeListSize + 7)/8
    pub member_list: Vec<u8>,
    // Skiplist at height n
    pub skip_list: Vec<i32>,
    //  Mode of the skip list
    pub skip_list_mode: LLMQSnapshotSkipMode,
}
impl Default for LLMQSnapshot {
    fn default() -> Self {
        Self {
            member_list: vec![],
            skip_list: vec![],
            skip_list_mode: LLMQSnapshotSkipMode::NoSkipping,
        }
    }
}

impl Display for LLMQSnapshot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let skip_list = self.skip_list.iter().fold(String::new(), |mut acc, i| {
            acc.push_str(format!("{},", *i).as_str());
            acc
        });
        write!(f, "members: {} {} {}", hex::encode(&self.member_list), self.skip_list_mode, skip_list)
    }
}

impl<'a> std::fmt::Debug for LLMQSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let member_list = hex::encode(&self.member_list);
        f.debug_struct("LLMQSnapshot")
            .field("member_list", &member_list)
            .field("skip_list", &self.skip_list.iter())
            .field("skip_list_mode", &self.skip_list_mode)
            .finish()
    }
}

impl LLMQSnapshot {
    pub fn new(member_list: Vec<u8>, skip_list: Vec<i32>, skip_list_mode: LLMQSnapshotSkipMode) -> Self {
        LLMQSnapshot {
            member_list,
            skip_list,
            skip_list_mode
        }
    }

    pub fn length(&self) -> usize {
        self.member_list.len() + 1 + 2 + self.skip_list.len() * 2
    }

    pub fn member_is_true_at_index(&self, i: u32) -> bool {
        self.member_list.as_slice().bit_is_true_at_le_index(i)
    }
}

