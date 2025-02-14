use hashes::{sha256d, Hash};
use crate::consensus::Encodable;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::VarInt;

impl QualifiedQuorumEntry {
    pub fn ordering_hash_for_request_id(&self, request_id: [u8; 32]) -> [u8; 32] {
        let llmq_type = VarInt(self.quorum_entry.llmq_type as u64); // Ensure LLMQType is converted properly

        let mut writer = Vec::with_capacity(llmq_type.len() + 64);

        // Encode LLMQ type
        llmq_type.consensus_encode(&mut writer).expect("Encoding failed");

        // Encode Quorum Hash
        writer.extend_from_slice(&self.quorum_entry.quorum_hash.to_byte_array());
        // Encode Request ID
        writer.extend_from_slice(&request_id);

        // Compute double SHA-256 hash
        sha256d::Hash::hash(&writer).to_byte_array()
    }
}