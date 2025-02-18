use crate::network::message_qrinfo::QuorumSnapshot;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

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
        previous_quarters: [&'a Vec<Vec<QualifiedMasternodeListEntry>>; 3],
        skip_removed_masternodes: bool,
    }
}

pub enum LLMQQuarterUsageType {
    Snapshot(QuorumSnapshot),
    New(Vec<Vec<QualifiedMasternodeListEntry>>)
}