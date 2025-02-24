use hashes::Hash;

use crate::consensus::Encodable;
use crate::consensus::encode::{write_compact_size, write_fixed_bitset};
use crate::hash_types::{QuorumCommitmentHash, QuorumEntryHash};
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

impl QuorumEntry {
    /// Calculates the hash of the entire quorum entry.
    ///
    /// This function serializes the quorum entry using consensus encoding and computes
    /// a hash from the serialized data. The resulting hash uniquely represents this
    /// specific quorum entry.
    ///
    /// # Returns
    ///
    /// * `QuorumEntryHash` - A hash representing the serialized quorum entry.
    pub fn calculate_entry_hash(&self) -> QuorumEntryHash {
        let mut writer = Vec::new();

        self.consensus_encode(&mut writer).expect("encoding failed");
        QuorumEntryHash::hash(&writer)
    }

    /// Constructs the commitment data required for computing the quorum commitment hash.
    ///
    /// This function serializes essential components of the quorum commitment, including:
    /// - LLMQ type
    /// - Quorum hash
    /// - Number of valid members
    /// - Bitset representing valid members
    /// - Quorum public key
    /// - Quorum verification vector hash
    ///
    /// The resulting byte vector serves as input for hashing functions.
    ///
    /// # Returns
    ///
    /// * A `Vec<u8>` containing the serialized commitment data.
    pub fn commitment_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();

        self.llmq_type.consensus_encode(&mut buffer).expect("encoding failed");
        // Encode the quorum hash
        self.quorum_hash.consensus_encode(&mut buffer).expect("encoding failed");
        write_compact_size(&mut buffer, self.valid_members.len() as u32).expect("encoding failed");
        write_fixed_bitset(
            &mut buffer,
            self.valid_members.as_slice(),
            self.valid_members.iter().len(),
        )
        .expect("encoding failed");
        self.quorum_public_key.consensus_encode(&mut buffer).expect("encoding failed");
        self.quorum_vvec_hash.consensus_encode(&mut buffer).expect("encoding failed");

        buffer
    }

    /// Calculates the quorum commitment hash.
    ///
    /// The commitment hash is derived from the serialized commitment data.
    /// It uniquely identifies a quorum commitment, ensuring integrity and consistency.
    ///
    /// # Returns
    ///
    /// * `QuorumCommitmentHash` - A hash representing the commitment data.
    pub fn calculate_commitment_hash(&self) -> QuorumCommitmentHash {
        let commitment_data = self.commitment_data();
        QuorumCommitmentHash::hash(&commitment_data)
    }
}
