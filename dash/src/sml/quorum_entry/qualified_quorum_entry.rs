use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct QualifiedQuorumEntry {
    pub quorum_entry: QuorumEntry,
    pub verified: LLMQEntryVerificationStatus,
    pub commitment_hash: Option<[u8; 32]>,
    pub entry_hash: [u8;32],
}