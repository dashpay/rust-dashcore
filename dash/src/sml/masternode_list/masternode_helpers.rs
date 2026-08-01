use std::net::IpAddr;

use crate::sml::masternode_list::MasternodeList;
use crate::{ProTxHash, PubkeyHash};

impl MasternodeList {
    /// Every masternode in the list whose voting key hash matches
    /// `voting_key_id`, returned as their registration proTxHashes.
    ///
    /// Mirrors dashj's `MasternodeList.getMasternodesByVotingKey(votingKeyId)`
    /// — the lookup contested-username voting uses to resolve which
    /// masternode(s) a given voting key is entitled to cast a vote for.
    /// `key_id_voting` is the 20-byte hash160 of the voting public key; a
    /// single voting key can back more than one masternode, so the result is
    /// a `Vec` (empty when no entry matches).
    ///
    /// # Ordering
    ///
    /// Results are returned in **ascending `ProTxHash` order**. This is a
    /// guaranteed part of the API, not an accident of the current
    /// implementation: the backing `masternodes` collection is a
    /// `BTreeMap<ProTxHash, _>`, whose iteration order is defined by the
    /// standard library to be ascending key order, and `ProTxHash` derives
    /// `Ord` over its 32 internal bytes. Because `ProTxHash` is a
    /// `#[hash_newtype(forward)]` hash, that internal byte order is also the
    /// order its hex `Display` reads in, so the returned sequence is sorted
    /// the same way it prints. Callers that need a deterministic vote order
    /// (contested-username voting does) may rely on this directly without
    /// re-sorting.
    pub fn masternodes_by_voting_key(&self, voting_key_id: &PubkeyHash) -> Vec<ProTxHash> {
        self.masternodes
            .values()
            .filter(|node| node.masternode_list_entry.key_id_voting == *voting_key_id)
            .map(|node| node.masternode_list_entry.pro_reg_tx_hash)
            .collect()
    }

    pub fn has_valid_masternode(&self, pro_reg_tx_hash: &ProTxHash) -> bool {
        self.masternodes
            .get(pro_reg_tx_hash)
            .is_some_and(|node| node.masternode_list_entry.is_valid)
    }

    pub fn has_masternode_at_location(&self, address: [u8; 16], port: u16) -> bool {
        self.masternodes.values().any(|node| {
            let Some(service_address) =
                node.masternode_list_entry.service_address.primary_service_address()
            else {
                return false;
            };
            match service_address.ip() {
                IpAddr::V4(ipv4) => {
                    let ipv4_bytes = ipv4.octets();
                    address[..4] == ipv4_bytes && service_address.port() == port
                }
                IpAddr::V6(ipv6) => {
                    let ipv6_bytes = ipv6.octets();
                    address == ipv6_bytes && service_address.port() == port
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use hashes::Hash;

    use crate::bls_sig_utils::BLSPublicKey;
    use crate::sml::masternode_list::MasternodeList;
    use crate::sml::masternode_list_entry::{
        EntryMasternodeType, MasternodeListEntry, MasternodeNetInfo,
    };
    use crate::{BlockHash, ProTxHash, PubkeyHash};

    /// Build a `MasternodeList` from `(proTxHash-seed, voting-key-id)` pairs so
    /// each entry gets a distinct proTxHash and a caller-chosen voting key.
    fn list_from(entries: Vec<(u8, [u8; 20])>) -> MasternodeList {
        let masternodes = entries
            .into_iter()
            .map(|(seed, voting_key_id)| {
                let mut hash_bytes = [0u8; 32];
                hash_bytes[0] = seed;
                let pro_tx_hash = ProTxHash::from_byte_array(hash_bytes);
                let entry = MasternodeListEntry {
                    version: 1,
                    pro_reg_tx_hash: pro_tx_hash,
                    confirmed_hash: None,
                    service_address: MasternodeNetInfo::Legacy(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(10, 0, 0, seed),
                        9999,
                    ))),
                    operator_public_key: BLSPublicKey::from([0u8; 48]),
                    key_id_voting: PubkeyHash::from_byte_array(voting_key_id),
                    is_valid: true,
                    mn_type: EntryMasternodeType::Regular,
                };
                (pro_tx_hash, entry.into())
            })
            .collect();
        MasternodeList::build(
            masternodes,
            Default::default(),
            BlockHash::from_byte_array([0u8; 32]),
            0,
        )
        .build()
    }

    /// The `ProTxHash` that `list_from` derives for a given seed byte.
    fn hash_for_seed(seed: u8) -> ProTxHash {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = seed;
        ProTxHash::from_byte_array(hash_bytes)
    }

    #[test]
    fn masternodes_by_voting_key_filters_and_collects() {
        let key_a = [0xAAu8; 20];
        let key_b = [0xBBu8; 20];
        // Two masternodes share voting key A, one uses key B.
        let list = list_from(vec![(1, key_a), (2, key_b), (3, key_a)]);

        // Asserted as a whole `Vec`, so this pins the documented ascending
        // `ProTxHash` ordering as well as the contents.
        let matched = list.masternodes_by_voting_key(&PubkeyHash::from_byte_array(key_a));
        assert_eq!(matched, vec![hash_for_seed(1), hash_for_seed(3)]);

        let single = list.masternodes_by_voting_key(&PubkeyHash::from_byte_array(key_b));
        assert_eq!(single, vec![hash_for_seed(2)]);

        // A voting key no masternode uses yields an empty vec.
        let none = list.masternodes_by_voting_key(&PubkeyHash::from_byte_array([0xCCu8; 20]));
        assert!(none.is_empty());
    }

    #[test]
    fn masternodes_by_voting_key_returns_ascending_pro_tx_hash_order() {
        // Seed the list in DESCENDING proTxHash order so a result that merely
        // echoed insertion order would come back reversed. The documented
        // guarantee is ascending order regardless of insertion order, which
        // only holds because `masternodes` is a `BTreeMap<ProTxHash, _>`.
        let key = [0xAAu8; 20];
        let list = list_from(vec![(9, key), (5, key), (7, key), (1, key)]);

        let matched = list.masternodes_by_voting_key(&PubkeyHash::from_byte_array(key));
        assert_eq!(
            matched,
            vec![hash_for_seed(1), hash_for_seed(5), hash_for_seed(7), hash_for_seed(9)],
            "results must be in ascending ProTxHash order, not insertion order"
        );

        // Belt and braces: the sequence is sorted by the same comparison the
        // public `Ord` impl exposes to callers.
        assert!(
            matched.windows(2).all(|w| w[0] < w[1]),
            "returned hashes must be strictly ascending under ProTxHash: Ord"
        );
    }
}
