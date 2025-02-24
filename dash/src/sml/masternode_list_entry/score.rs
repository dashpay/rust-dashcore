use crate::hash_types::{QuorumModifierHash, ScoreHash};
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

impl QualifiedMasternodeListEntry {
    /// The score of a masternode list entry within a quorum expressed by a quorum modifier hash.
    pub fn score(&self, modifier: QuorumModifierHash) -> Option<ScoreHash> {
        if !self.masternode_list_entry.is_valid ||
            self.confirmed_hash_hashed_with_pro_reg_tx.is_none() {
            return None;
        }
        let score = ScoreHash::create_score(self.confirmed_hash_hashed_with_pro_reg_tx, modifier);
        Some(score)
    }
}