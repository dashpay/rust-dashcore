use crate::network::message_qrinfo::QuorumSnapshot;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

pub enum LLMQQuarterType {
    AtHeightMinus3Cycles,
    AtHeightMinus2Cycles,
    AtHeightMinusCycle,
    New,
}

#[derive(Clone, Copy)]
pub enum LLMQQuarterReconstructionType<'a: 'b, 'b> {
    Snapshot,
    New {
        previous_quarters: [&'b Vec<Vec<&'a QualifiedMasternodeListEntry>>; 3],
    },
}

pub enum LLMQQuarterUsageType<'a> {
    Snapshot(QuorumSnapshot),
    New(Vec<Vec<&'a QualifiedMasternodeListEntry>>),
}
