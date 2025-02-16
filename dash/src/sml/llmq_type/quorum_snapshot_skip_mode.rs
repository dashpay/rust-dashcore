use std::fmt::Formatter;

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub enum LLMQSnapshotSkipMode {
    // No skipping. The skip list is empty.
    NoSkipping = 0,
    // Skip the first entry of the list.
    // The following entries contain the relative position of subsequent skips.
    // For example, if during the initialization phase you skip entries x, y and z of the models
    // list, the skip list will contain x, y-x and z-y in this mode.
    SkipFirst = 1,
    // Contains the entries which were not skipped.
    // This is better when there are many skips.
    // Mode 2 is more efficient and should be used when 3/4*quorumSize ≥ 1/2*masternodeNb or
    // quorumsize ≥ 2/3*masternodeNb
    SkipExcept = 2,
    // Every node was skipped. The skip list is empty. DKG sessions were not attempted.
    SkipAll = 3,
}
impl std::fmt::Display for LLMQSnapshotSkipMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            LLMQSnapshotSkipMode::NoSkipping => "0_NoSkipping",
            LLMQSnapshotSkipMode::SkipFirst => "1_SkipFirst",
            LLMQSnapshotSkipMode::SkipExcept => "2_SkipExcept",
            LLMQSnapshotSkipMode::SkipAll => "3_SkipAll"
        })
    }
}
impl From<u32> for LLMQSnapshotSkipMode {
    fn from(orig: u32) -> Self {
        match orig {
            0 => LLMQSnapshotSkipMode::NoSkipping,
            1 => LLMQSnapshotSkipMode::SkipFirst,
            2 => LLMQSnapshotSkipMode::SkipExcept,
            3 => LLMQSnapshotSkipMode::SkipAll,
            _ => LLMQSnapshotSkipMode::NoSkipping,
        }
    }
}
impl From<LLMQSnapshotSkipMode> for u32 {
    fn from(orig: LLMQSnapshotSkipMode) -> Self {
        match orig {
            LLMQSnapshotSkipMode::NoSkipping => 0,
            LLMQSnapshotSkipMode::SkipFirst => 1,
            LLMQSnapshotSkipMode::SkipExcept => 2,
            LLMQSnapshotSkipMode::SkipAll => 3,
        }
    }
}
impl LLMQSnapshotSkipMode {
    pub fn index(&self) -> u32 {
        u32::from(self.clone())
    }
}


pub fn from_index(index: u32) -> LLMQSnapshotSkipMode {
    LLMQSnapshotSkipMode::from(index)
}
