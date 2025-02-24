use hashes::{Hash, sha256d};

use crate::consensus::Encodable;
use crate::sml::masternode_list_entry::MasternodeListEntry;

impl MasternodeListEntry {
    pub fn calculate_entry_hash(&self) -> [u8; 32] {
        let mut writer = Vec::new();

        self.consensus_encode(&mut writer).expect("encoding failed");
        sha256d::Hash::hash(&writer).to_byte_array()
    }
}
