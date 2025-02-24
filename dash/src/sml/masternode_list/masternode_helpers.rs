use std::cmp::Ordering;
use std::net::IpAddr;

use hashes::Hash;

use crate::ProTxHash;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;

impl MasternodeList {
    pub fn masternode_for(
        &self,
        pro_reg_tx_hash: &ProTxHash,
    ) -> Option<&QualifiedMasternodeListEntry> {
        self.masternodes.get(pro_reg_tx_hash)
    }

    pub fn has_valid_masternode(&self, pro_reg_tx_hash: &ProTxHash) -> bool {
        self.masternodes
            .get(pro_reg_tx_hash)
            .map_or(false, |node| node.masternode_list_entry.is_valid)
    }

    pub fn has_masternode(&self, pro_reg_tx_hash: &ProTxHash) -> bool {
        self.masternodes.get(pro_reg_tx_hash).is_some()
    }
    pub fn has_masternode_at_location(&self, address: [u8; 16], port: u16) -> bool {
        self.masternodes.values().any(|node| {
            match node.masternode_list_entry.service_address.ip() {
                IpAddr::V4(ipv4) => {
                    let ipv4_bytes = ipv4.octets();
                    address[..4] == ipv4_bytes
                        && node.masternode_list_entry.service_address.port() == port
                }
                IpAddr::V6(ipv6) => {
                    let ipv6_bytes = ipv6.octets();
                    address == ipv6_bytes
                        && node.masternode_list_entry.service_address.port() == port
                }
            }
        })
    }
    pub fn masternode_count(&self) -> usize { self.masternodes.len() }

    pub fn masternode_by_pro_reg_tx_hash(
        &self,
        registration_hash: &ProTxHash,
    ) -> Option<QualifiedMasternodeListEntry> {
        self.masternodes.get(registration_hash).cloned()
    }

    pub fn reversed_pro_reg_tx_hashes_cloned(&self) -> Vec<ProTxHash> {
        self.masternodes.keys().cloned().collect()
    }
    pub fn reversed_pro_reg_tx_hashes(&self) -> Vec<&ProTxHash> {
        self.masternodes.keys().collect()
    }

    pub fn sorted_reversed_pro_reg_tx_hashes(&self) -> Vec<&ProTxHash> {
        let mut hashes = self.reversed_pro_reg_tx_hashes();
        hashes.sort_by(|&s1, &s2| s2.reverse().cmp(&s1.reverse()));
        hashes
    }

    pub fn provider_tx_ordered_hashes(&self) -> Vec<ProTxHash> {
        let mut vec = Vec::from_iter(self.masternodes.keys().cloned());
        vec.sort_by(|hash1, hash2| {
            if reverse_cmp_sup(hash1.to_byte_array(), hash2.to_byte_array()) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });
        vec
    }
    pub fn compare_provider_tx_ordered_hashes(&self, list: MasternodeList) -> bool {
        self.provider_tx_ordered_hashes().eq(&list.provider_tx_ordered_hashes())
    }

    pub fn compare_masternodes(&self, list: MasternodeList) -> bool {
        let mut vec1 = Vec::from_iter(self.masternodes.values());
        vec1.sort();
        let mut vec2 = Vec::from_iter(list.masternodes.values());
        vec2.sort();
        vec1.eq(&vec2)
    }
}

pub fn reverse_cmp_sup(lhs: [u8; 32], rhs: [u8; 32]) -> bool {
    for i in (0..32).rev() {
        if lhs[i] > rhs[i] {
            return true;
        } else if lhs[i] < rhs[i] {
            return false;
        }
    }
    // equal
    false
}
