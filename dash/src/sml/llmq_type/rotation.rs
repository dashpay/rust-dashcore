use crate::sml::llmq_type::snapshot::LLMQSnapshot;
use crate::sml::masternode_list_entry::MasternodeListEntry;

pub enum LLMQQuarterType {
    AtHeightMinus3Cycles,
    AtHeightMinus2Cycles,
    AtHeightMinusCycle,
    New,
}

#[derive(Clone, Copy)]
pub enum LLMQQuarterReconstructionType<'a> {
    Snapshot,
    New {
        previous_quarters: [&'a Vec<Vec<MasternodeListEntry>>; 3],
        skip_removed_masternodes: bool,
    }
}

pub enum LLMQQuarterUsageType {
    Snapshot(LLMQSnapshot),
    New(Vec<Vec<MasternodeListEntry>>)
}