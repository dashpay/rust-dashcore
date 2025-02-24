use std::cmp::Ordering;
use std::net::SocketAddr;

use hashes::Hash;

use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list::masternode_helpers::reverse_cmp_sup;

impl MasternodeList {
    /// Retrieves a list of peer addresses from the masternode list, sorted using a nonce for deterministic ordering.
    ///
    /// This function generates a sorted list of masternode addresses based on their registration transaction hashes,
    /// using a provided nonce to create a deterministic but unpredictable order. The resulting list is truncated
    /// to the specified maximum count.
    ///
    /// # Parameters
    ///
    /// - `nonce`: A 64-bit unsigned integer used to influence the sorting order.
    /// - `max_count`: The maximum number of peer addresses to return.
    ///
    /// # Returns
    ///
    /// - `Vec<SocketAddr>`: A list of masternode service addresses, sorted using the nonce and limited to `max_count`.
    ///
    /// # Notes
    ///
    /// - The sorting process appends the nonce to each masternode’s transaction hash and applies a BLAKE3 hash
    ///   to determine the order.
    /// - Only valid masternodes (i.e., those marked as valid in the masternode list) are included in the output.
    pub fn peer_addresses_with_connectivity_nonce(
        &self,
        nonce: u64,
        max_count: usize,
    ) -> Vec<SocketAddr> {
        let registration_transaction_hashes: Vec<_> = self.masternodes.keys().cloned().collect();
        let mut sorted_hashes = registration_transaction_hashes.clone();
        sorted_hashes.sort_by(|hash1, hash2| {
            let nonce_le = nonce.to_le_bytes();
            let mut hash1_nonce = hash1.to_byte_array().to_vec();
            hash1_nonce.extend_from_slice(&nonce_le);
            let mut hash2_nonce = hash2.to_byte_array().to_vec();
            hash2_nonce.extend_from_slice(&nonce_le);
            let hash1_blake = blake3::hash(&hash1_nonce).into();
            let hash2_blake = blake3::hash(&hash2_nonce).into();
            if reverse_cmp_sup(hash1_blake, hash2_blake) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });
        sorted_hashes
            .into_iter()
            .take(max_count.min(self.masternodes.len()))
            .filter_map(|hash| {
                self.masternodes.get(&hash).and_then(|entry| {
                    entry
                        .masternode_list_entry
                        .is_valid
                        .then_some(entry.masternode_list_entry.service_address.clone())
                })
            })
            .collect()
    }
}
