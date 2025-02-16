use hashes::{sha256d, Hash};
use crate::consensus::Encodable;
use crate::consensus::encode::{write_compact_size, write_fixed_bitset};
use crate::hash_types::{QuorumCommitmentHash, QuorumEntryHash};
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

impl QuorumEntry {
    pub fn calculate_entry_hash(
        &self
    ) -> QuorumEntryHash {
        let mut writer = Vec::new();

        self.consensus_encode(&mut writer).expect("encoding failed");
        QuorumEntryHash::hash(&writer)
    }

    pub fn commitment_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();

        self.llmq_type.consensus_encode(&mut buffer).expect("encoding failed");
        // Encode the quorum hash
        self.quorum_hash
            .consensus_encode(&mut buffer).expect("encoding failed");
        write_compact_size(&mut buffer, self.valid_members.len() as u32).expect("encoding failed");
        write_fixed_bitset(&mut buffer, self.valid_members.as_slice(), self.valid_members.iter().len()).expect("encoding failed");
        self.quorum_public_key.consensus_encode(&mut buffer).expect("encoding failed");
        self.quorum_vvec_hash.consensus_encode(&mut buffer).expect("encoding failed");

        buffer
    }

    pub fn calculate_commitment_hash(
        &self
    ) -> QuorumCommitmentHash {
        let commitment_data = self.commitment_data();
        QuorumCommitmentHash::hash(&commitment_data)
    }

}