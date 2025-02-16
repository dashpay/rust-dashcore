use crate::hash_types::{QuorumModifierHash, ScoreHash};
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

impl QualifiedMasternodeListEntry {
    pub fn score(&self, modifier: QuorumModifierHash) -> Option<ScoreHash> {
        if !self.masternode_list_entry.is_valid ||
            self.confirmed_hash_hashed_with_pro_reg_tx.is_none() {
            return None;
        }
        println!("creating score for {}({})\nconfirmed_hash_hashed_with_pro_reg_tx: {}({})\nmodifier {}({})", self.masternode_list_entry.pro_reg_tx_hash, self.masternode_list_entry.pro_reg_tx_hash.reverse(), if let Some(confirmed_hash_hashed_with_pro_reg_tx) = self.confirmed_hash_hashed_with_pro_reg_tx { confirmed_hash_hashed_with_pro_reg_tx.to_string() } else {
            "None".to_string()
        },  if let Some(confirmed_hash_hashed_with_pro_reg_tx) = self.confirmed_hash_hashed_with_pro_reg_tx { confirmed_hash_hashed_with_pro_reg_tx.reverse().to_string() } else {
            "None".to_string()
        }, modifier, modifier.reverse());
        let score = ScoreHash::create_score(self.confirmed_hash_hashed_with_pro_reg_tx, modifier);
        println!("score is {}",score);
        Some(score)
    }
}