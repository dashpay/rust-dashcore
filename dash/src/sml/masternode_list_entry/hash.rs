use hashes::{Hash, sha256d};

use crate::consensus::Encodable;
use crate::hash_types::Sha256dHash;
use crate::sml::masternode_list_entry::MasternodeListEntry;

impl MasternodeListEntry {
    pub fn calculate_entry_hash(&self) -> Sha256dHash {
        let mut writer = Vec::new();
        self.consensus_encode(&mut writer).expect("encoding failed");
        Sha256dHash::from_raw_hash(sha256d::Hash::hash(&writer))
    }
}
