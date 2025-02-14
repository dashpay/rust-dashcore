use hashes::{sha256d, Hash};
use crate::consensus::Encodable;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

impl QuorumEntry {
    pub fn calculate_entry_hash(
        &self
    ) -> [u8; 32] {
        let mut writer = Vec::new();

        self.consensus_encode(&mut writer).expect("encoding failed");
        sha256d::Hash::hash(&writer).to_byte_array()
    }
}