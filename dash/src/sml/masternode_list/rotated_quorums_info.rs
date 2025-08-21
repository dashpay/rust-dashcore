use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

impl MasternodeList {
    /// Quorum count is the number of quorums at the same time, for mainnet and testnet this is 32.
    /// For Devnet and Regtest it is 2.
    pub fn usage_info<'a>(
        &'a self,
        previous_quarters: [&Vec<Vec<&'a QualifiedMasternodeListEntry>>; 3],
        quorum_count: usize,
    ) -> (
        Vec<&'a QualifiedMasternodeListEntry>,
        Vec<&'a QualifiedMasternodeListEntry>,
        Vec<Vec<&'a QualifiedMasternodeListEntry>>,
    ) {
        let mut used_masternodes = Vec::<&QualifiedMasternodeListEntry>::new();
        let mut used_indexed_masternodes =
            vec![Vec::<&QualifiedMasternodeListEntry>::new(); quorum_count];
        for (i, indexed_masternodes) in
            used_indexed_masternodes.iter_mut().enumerate().take(quorum_count)
        {
            // for quarters h - c, h -2c, h -3c
            for quarter in &previous_quarters {
                if let Some(quarter_nodes) = quarter.get(i) {
                    for node in quarter_nodes {
                        let hash = node.masternode_list_entry.pro_reg_tx_hash;
                        if self.has_valid_masternode(&hash.reverse()) {
                            if !used_masternodes
                                .iter()
                                .any(|m| m.masternode_list_entry.pro_reg_tx_hash == hash)
                            {
                                used_masternodes.push(node);
                            }
                            if !indexed_masternodes
                                .iter()
                                .any(|m| m.masternode_list_entry.pro_reg_tx_hash == hash)
                            {
                                indexed_masternodes.push(node);
                            }
                        }
                    }
                }
            }
        }
        let unused_at_h_masternodes = self
            .masternodes
            .values()
            .filter(|mn| {
                mn.masternode_list_entry.is_valid
                    && !used_masternodes.iter().any(|node| {
                        mn.masternode_list_entry.pro_reg_tx_hash
                            == node.masternode_list_entry.pro_reg_tx_hash
                    })
            })
            .collect();
        (used_masternodes, unused_at_h_masternodes, used_indexed_masternodes)
    }
}
