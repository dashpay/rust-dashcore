use std::net::IpAddr;

use crate::sml::masternode_list::MasternodeList;
use crate::ProTxHash;

impl MasternodeList {
    pub fn has_valid_masternode(&self, pro_reg_tx_hash: &ProTxHash) -> bool {
        self.masternodes
            .get(pro_reg_tx_hash)
            .map_or(false, |node| node.masternode_list_entry.is_valid)
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

    pub fn reversed_pro_reg_tx_hashes(&self) -> Vec<&ProTxHash> {
        self.masternodes.keys().collect()
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
