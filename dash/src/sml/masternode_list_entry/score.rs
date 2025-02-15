use crate::hash_types::{QuorumModifierHash, ScoreHash};
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

impl QualifiedMasternodeListEntry {
    pub fn score(&self, modifier: QuorumModifierHash) -> Option<ScoreHash> {
        if !self.masternode_list_entry.is_valid ||
            self.masternode_list_entry.confirmed_hash.is_none() {
            return None;
        }
        Some(ScoreHash::create_score(self.confirmed_hash_hashed_with_pro_reg_tx, modifier))
    }
}