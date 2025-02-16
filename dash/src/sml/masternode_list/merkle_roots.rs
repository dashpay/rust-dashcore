use hashes::{sha256d, Hash};
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums, QuorumCommitmentHash};
use crate::sml::masternode_list::MasternodeList;
use crate::Transaction;
use crate::transaction::special_transaction::TransactionPayload;

#[inline]
pub fn merkle_root_from_hashes(hashes: Vec<[u8; 32]>) -> Option<[u8; 32]> {
    let length = hashes.len();
    let mut level = hashes;
    match length {
        0 => None,
        _ => {
            while level.len() != 1 {
                let len = level.len();
                let mut higher_level = Vec::<[u8; 32]>::with_capacity((0.5 * len as f64).ceil() as usize);
                for pair in level.chunks(2) {
                    let mut buffer = Vec::with_capacity(64);
                    buffer.extend_from_slice(&pair[0]);
                    buffer.extend_from_slice(pair.get(1).unwrap_or(&pair[0]));
                    higher_level.push(sha256d::Hash::hash(&buffer).to_byte_array());
                }
                level = higher_level;
            }
            Some(level[0])
        }
    }
}

impl MasternodeList {
    pub fn has_valid_mn_list_root(&self, coinbase_transaction: &Transaction) -> bool {
        let Some(TransactionPayload::CoinbasePayloadType(coinbase_payload)) = &coinbase_transaction.special_transaction_payload else {
            return false;
        };
        // we need to check that the coinbase is in the transaction hashes we got back
        // and is in the merkle block
        if let Some(mn_merkle_root) = self.masternode_merkle_root {
            //println!("has_valid_mn_list_root: {} == {}", tx.merkle_root_mn_list, mn_merkle_root);
            coinbase_payload.merkle_root_masternode_list == mn_merkle_root
        } else {
            false
        }
    }

    pub fn has_valid_llmq_list_root(&self, coinbase_transaction: &Transaction) -> bool {
        let Some(TransactionPayload::CoinbasePayloadType(coinbase_payload)) = &coinbase_transaction.special_transaction_payload else {
            return false;
        };

        let q_merkle_root = self.llmq_merkle_root;
        let coinbase_merkle_root_quorums = coinbase_payload.merkle_root_quorums;
        let has_valid_quorum_list_root = q_merkle_root.is_some()
            && coinbase_merkle_root_quorums == q_merkle_root.unwrap();
        if !has_valid_quorum_list_root {
            // warn!("LLMQ Merkle root not valid for DML on block {} version {} ({:?} wanted - {:?} calculated)",
            //          tx.height,
            //          tx.base.version,
            //          tx.merkle_root_llmq_list.map(|q| q.to_hex()).unwrap_or("None".to_string()),
            //          self.llmq_merkle_root.map(|q| q.to_hex()).unwrap_or("None".to_string()));
        }
        has_valid_quorum_list_root
    }

    pub fn calculate_masternodes_merkle_root(&self, block_height: u32) -> Option<MerkleRootMasternodeList> {
        self.hashes_for_merkle_root(block_height)
            .and_then(merkle_root_from_hashes).map(|hash| MerkleRootMasternodeList::from_byte_array(hash))
    }
    // pub fn calculate_masternodes_merkle_root_with_block_height_lookup<BL: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>(
    //     &self,
    //     context: *const std::os::raw::c_void,
    //     block_height_lookup: BL
    // ) -> Option<[u8; 32]> {
    //     self.hashes_for_merkle_root_with_block_height_lookup(context, block_height_lookup)
    //         .and_then(merkle_root_from_hashes)
    // }

    pub fn calculate_llmq_merkle_root(&self) -> Option<MerkleRootQuorums> {
        merkle_root_from_hashes(self.hashes_for_quorum_merkle_root()).map(|hash| MerkleRootQuorums::from_byte_array(hash))
    }

    pub fn hashes_for_merkle_root(&self, block_height: u32) -> Option<Vec<[u8; 32]>> {
        (block_height != u32::MAX).then_some({
            let mut pro_tx_hashes = self.reversed_pro_reg_tx_hashes();
            pro_tx_hashes.sort_by(|&s1, &s2| s1.reverse().cmp(&s2.reverse()));
            pro_tx_hashes
                .into_iter()
                .map(|hash| self.masternodes[hash].entry_hash)
                .collect::<Vec<_>>()
            //this was the following: (with entry_hash_at)
            // pro_tx_hashes
            //     .into_iter()
            //     .map(|hash| (&self.masternodes[hash]).entry_hash_at(block_height))
            //     .collect::<Vec<_>>()
        })
    }

    // pub fn hashes_for_merkle_root_with_block_height_lookup<BL: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>(
    //     &self,
    //     context: *const std::os::raw::c_void,
    //     block_height_lookup: BL
    // ) -> Option<Vec<[u8; 32]>> {
    //     let pro_tx_hashes = self.provider_tx_ordered_hashes();
    //     let block_height = block_height_lookup(context, self.block_hash);
    //     if block_height == u32::MAX {
    //         println!("Block height lookup queried an unknown block {}", self.block_hash);
    //         return None; //this should never happen
    //     }
    //     Some(pro_tx_hashes
    //         .into_iter()
    //         .map(|hash| (&self.masternodes[&hash]).entry_hash_at(block_height))
    //         .collect::<Vec<_>>())
    // }

    pub fn hashes_for_quorum_merkle_root(&self) -> Vec<[u8; 32]> {
        let mut llmq_commitment_hashes = self.quorums
            .values()
            .flat_map(|q_map| q_map.values().map(|entry| entry.entry_hash.to_byte_array()))
            .collect::<Vec<_>>();
        llmq_commitment_hashes.sort();
        llmq_commitment_hashes
    }
}