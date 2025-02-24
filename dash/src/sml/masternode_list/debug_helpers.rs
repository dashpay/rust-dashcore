use hashes::Hash;

use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::masternode_list::MasternodeList;

impl<'a> std::fmt::Debug for MasternodeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeList")
            .field("block_hash", &self.block_hash)
            .field("known_height", &self.known_height)
            .field(
                "masternode_merkle_root",
                &self
                    .masternode_merkle_root
                    .unwrap_or(MerkleRootMasternodeList::from_byte_array([0u8; 32])),
            )
            .field(
                "llmq_merkle_root",
                &self.llmq_merkle_root.unwrap_or(MerkleRootQuorums::from_byte_array([0u8; 32])),
            )
            .field("masternodes", &self.masternodes)
            .field("quorums", &self.quorums)
            .finish()
    }
}

impl MasternodeList {
    pub fn short_description(&self) -> String {
        format!(
            "\t\t{}: {}:\n\t\t\tmn: \n\t\t\t\troot: {}\n\t\t\t\tcount: {}\n\t\t\tllmq:\n\t\t\t\troot: {}\n\t\t\t\tdesc:\n{}\n",
            self.known_height,
            hex::encode(self.block_hash),
            self.masternode_merkle_root.map_or("None".to_string(), hex::encode),
            self.masternode_count(),
            self.llmq_merkle_root.map_or("None".to_string(), hex::encode),
            self.quorums_short_description()
        )
    }

    pub fn quorums_short_description(&self) -> String {
        self.quorums.iter().fold(String::new(), |mut acc, (ty, map)| {
            let s = map.iter().fold(String::new(), |mut acc, (hash, q)| {
                acc.push_str(
                    format!("\t\t\t{}: {}\n", q.quorum_entry.quorum_hash, q.verified).as_str(),
                );
                acc
            });
            acc.push_str(format!("\t\t{ty}: \n{s}").as_str());
            acc
        })
    }
}
