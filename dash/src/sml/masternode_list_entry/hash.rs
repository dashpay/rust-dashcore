use hashes::{sha256d, Hash};

use crate::consensus::Encodable;
use crate::sml::masternode_list_entry::MasternodeListEntry;

impl MasternodeListEntry {
    pub fn calculate_entry_hash(&self) -> sha256d::Hash {
        let mut writer = Vec::new();

        self.consensus_encode(&mut writer).expect("encoding failed");
        sha256d::Hash::hash(&writer)
    }
}
