use crate::sml::masternode_list_entry::MasternodeListEntry;

impl MasternodeListEntry {
    pub fn use_legacy_bls_keys(&self) -> bool {
        // Only version 1 used legacy bls keys
        self.version == 1
    }
}
