use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

impl MasternodeList {
    pub fn usage_info(&self, previous_quarters: [&Vec<Vec<QualifiedMasternodeListEntry>>; 3], skip_removed_masternodes: bool, quorum_count: usize) -> (Vec<QualifiedMasternodeListEntry>, Vec<QualifiedMasternodeListEntry>, Vec<Vec<QualifiedMasternodeListEntry>>) {
        let mut used_at_h_masternodes = Vec::<QualifiedMasternodeListEntry>::new();
        let mut used_at_h_indexed_masternodes = vec![Vec::<QualifiedMasternodeListEntry>::new(); quorum_count];
        for i in 0..quorum_count {
            // for quarters h - c, h -2c, h -3c
            for quarter in &previous_quarters {
                if let Some(quarter_nodes) = quarter.get(i) {
                    for node in quarter_nodes {
                        let hash = node.masternode_list_entry.pro_reg_tx_hash;
                        if (!skip_removed_masternodes || self.has_masternode(&hash)) &&
                            self.has_valid_masternode(&hash) {
                            if !used_at_h_masternodes.iter().any(|m| m.masternode_list_entry.pro_reg_tx_hash == hash) {
                                used_at_h_masternodes.push(node.clone());
                            }
                            if !used_at_h_indexed_masternodes[i].iter().any(|m| m.masternode_list_entry.pro_reg_tx_hash == hash) {
                                used_at_h_indexed_masternodes[i].push(node.clone());
                            }
                        }
                    }
                }
            }
        }
        let unused_at_h_masternodes = self.masternodes.values()
            .filter(|mn| mn.masternode_list_entry.is_valid && !used_at_h_masternodes.iter().any(|node| mn.masternode_list_entry.pro_reg_tx_hash == node.masternode_list_entry.pro_reg_tx_hash))
            .cloned()
            .collect();
        (used_at_h_masternodes, unused_at_h_masternodes, used_at_h_indexed_masternodes)

    }
}