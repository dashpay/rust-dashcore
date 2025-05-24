use hashes::{Hash, sha256d};

use crate::Transaction;
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::masternode_list::MasternodeList;
use crate::transaction::special_transaction::TransactionPayload;

/// Computes the Merkle root from a list of hashes.
///
/// This function constructs a Merkle tree from the provided vector of 32-byte hashes.
/// If the vector is empty, it returns `None`. Otherwise, it iteratively hashes pairs
/// of nodes until a single root hash is obtained.
///
/// # Parameters
///
/// - `hashes`: A vector of 32-byte hashes representing the leaves of the Merkle tree.
///
/// # Returns
///
/// - `Some([u8; 32])`: The computed Merkle root if at least one hash is provided.
/// - `None`: If the input vector is empty.
#[inline]
pub fn merkle_root_from_hashes(hashes: Vec<sha256d::Hash>) -> Option<sha256d::Hash> {
    let length = hashes.len();
    let mut level = hashes;
    match length {
        0 => None,
        _ => {
            while level.len() != 1 {
                let len = level.len();
                let mut higher_level =
                    Vec::<sha256d::Hash>::with_capacity((0.5 * len as f64).ceil() as usize);
                for pair in level.chunks(2) {
                    let mut buffer = Vec::with_capacity(64);
                    buffer.extend_from_slice(pair[0].as_byte_array());
                    buffer.extend_from_slice(pair.get(1).unwrap_or(&pair[0]).as_byte_array());
                    higher_level.push(sha256d::Hash::hash(&buffer));
                }
                level = higher_level;
            }
            Some(level[0])
        }
    }
}

impl MasternodeList {
    /// Validates whether the stored masternode list Merkle root matches the one in the coinbase transaction.
    ///
    /// This function compares the calculated masternode Merkle root with the one provided
    /// in the coinbase transaction payload to verify the integrity of the masternode list.
    ///
    /// # Parameters
    ///
    /// - `coinbase_transaction`: The coinbase transaction containing the expected Merkle root.
    ///
    /// # Returns
    ///
    /// - `true` if the Merkle root matches.
    /// - `false` otherwise.
    pub fn has_valid_mn_list_root(&self, coinbase_transaction: &Transaction) -> bool {
        let Some(TransactionPayload::CoinbasePayloadType(coinbase_payload)) =
            &coinbase_transaction.special_transaction_payload
        else {
            return false;
        };
        // we need to check that the coinbase is in the transaction hashes we got back
        // and is in the merkle block
        if let Some(mn_merkle_root) = self.masternode_merkle_root {
            coinbase_payload.merkle_root_masternode_list == mn_merkle_root
        } else {
            false
        }
    }

    /// Validates whether the stored LLMQ list Merkle root matches the one in the coinbase transaction.
    ///
    /// This function compares the calculated quorum Merkle root with the one provided
    /// in the coinbase transaction payload to verify the integrity of the quorum list.
    ///
    /// # Parameters
    ///
    /// - `coinbase_transaction`: The coinbase transaction containing the expected Merkle root.
    ///
    /// # Returns
    ///
    /// - `true` if the Merkle root matches.
    /// - `false` otherwise.
    pub fn has_valid_llmq_list_root(&self, coinbase_transaction: &Transaction) -> bool {
        let Some(TransactionPayload::CoinbasePayloadType(coinbase_payload)) =
            &coinbase_transaction.special_transaction_payload
        else {
            return false;
        };

        let q_merkle_root = self.llmq_merkle_root;
        let coinbase_merkle_root_quorums = coinbase_payload.merkle_root_quorums;
        let has_valid_quorum_list_root =
            q_merkle_root.is_some() && coinbase_merkle_root_quorums == q_merkle_root.unwrap();
        if !has_valid_quorum_list_root {
            // warn!("LLMQ Merkle root not valid for DML on block {} version {} ({:?} wanted - {:?} calculated)",
            //          tx.height,
            //          tx.base.version,
            //          tx.merkle_root_llmq_list.map(|q| q.to_hex()).unwrap_or("None".to_string()),
            //          self.llmq_merkle_root.map(|q| q.to_hex()).unwrap_or("None".to_string()));
        }
        has_valid_quorum_list_root
    }

    /// Computes the Merkle root for the masternode list at a given block height.
    ///
    /// This function generates a Merkle root for the masternode list based on the
    /// masternode entries at the specified block height.
    ///
    /// # Parameters
    ///
    /// - `block_height`: The block height at which to compute the Merkle root.
    ///
    /// # Returns
    ///
    /// - `Some(MerkleRootMasternodeList)`: The calculated Merkle root.
    /// - `None`: If no hashes are available for the given block height.
    pub fn calculate_masternodes_merkle_root(
        &self,
        block_height: u32,
    ) -> Option<MerkleRootMasternodeList> {
        self.hashes_for_merkle_root(block_height)
            .and_then(merkle_root_from_hashes)
            .map(MerkleRootMasternodeList::from_raw_hash)
    }

    /// Computes the Merkle root for the LLMQ (Long-Living Masternode Quorum) list.
    ///
    /// This function constructs a Merkle tree using the commitment hashes of all known LLMQs
    /// and returns the root hash.
    ///
    /// # Returns
    ///
    /// - `Some(MerkleRootQuorums)`: The calculated Merkle root.
    /// - `None`: If no quorum commitment hashes are available.
    pub fn calculate_llmq_merkle_root(&self) -> Option<MerkleRootQuorums> {
        merkle_root_from_hashes(self.hashes_for_quorum_merkle_root())
            .map(MerkleRootQuorums::from_raw_hash)
    }

    /// Retrieves the list of hashes required to compute the masternode list Merkle root.
    ///
    /// This function sorts the masternode list by pro-reg transaction hash and extracts
    /// the entry hashes for the given block height.
    ///
    /// # Parameters
    ///
    /// - `block_height`: The block height for which to retrieve the hashes.
    ///
    /// # Returns
    ///
    /// - `Some(Vec<sha256d::Hash>)`: A sorted list of masternode entry hashes.
    /// - `None`: If the block height is invalid (`u32::MAX`).
    pub fn hashes_for_merkle_root(&self, block_height: u32) -> Option<Vec<sha256d::Hash>> {
        (block_height != u32::MAX).then_some({
            let mut pro_tx_hashes = self.reversed_pro_reg_tx_hashes();
            pro_tx_hashes.sort_by(|&s1, &s2| s1.reverse().cmp(&s2.reverse()));
            pro_tx_hashes
                .into_iter()
                .map(|hash| self.masternodes[hash].entry_hash.to_raw_hash())
                .collect::<Vec<_>>()
        })
    }

    /// Retrieves the list of hashes required to compute the quorum Merkle root.
    ///
    /// This function collects and sorts the entry hashes of all known quorums
    /// to construct a Merkle tree.
    ///
    /// # Returns
    ///
    /// - `Vec<[u8; 32]>`: A sorted list of quorum commitment hashes.
    pub fn hashes_for_quorum_merkle_root(&self) -> Vec<sha256d::Hash> {
        let mut llmq_commitment_hashes = self
            .quorums
            .values()
            .flat_map(|q_map| q_map.values().map(|entry| entry.entry_hash.to_raw_hash()))
            .collect::<Vec<_>>();
        llmq_commitment_hashes.sort();
        llmq_commitment_hashes
    }
}
