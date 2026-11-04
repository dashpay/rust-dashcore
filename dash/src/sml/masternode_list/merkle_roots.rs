use hashes::{Hash, sha256d};

use crate::Transaction;
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::error::SmlError;
use crate::sml::masternode_list::MasternodeList;
use crate::transaction::special_transaction::coinbase::CoinbasePayload;

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
    /// The quorum root is in the coinbase payload from its version 2. An empty
    /// list hashes to the all-zero root, as in Dash Core. A payload of a
    /// version newer than this crate decodes is read as far as it knows the
    /// layout, see [`CoinbasePayload::from_coinbase_tx`].
    pub fn verify_coinbase_roots(
        &self,
        coinbase_transaction: &Transaction,
    ) -> Result<(), SmlError> {
        let Some(coinbase_payload) = CoinbasePayload::from_coinbase_tx(coinbase_transaction) else {
            return Err(SmlError::CoinbaseCommitmentMismatch(self.block_hash));
        };

        let calculated = self
            .calculate_masternodes_merkle_root(self.known_height)
            .unwrap_or_else(MerkleRootMasternodeList::all_zeros);
        if calculated != coinbase_payload.merkle_root_masternode_list {
            return Err(SmlError::CoinbaseCommitmentMismatch(self.block_hash));
        }

        if coinbase_payload.version >= 2 {
            let calculated =
                self.calculate_llmq_merkle_root().unwrap_or_else(MerkleRootQuorums::all_zeros);
            if calculated != coinbase_payload.merkle_root_quorums {
                return Err(SmlError::CoinbaseCommitmentMismatch(self.block_hash));
            }
        }

        Ok(())
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
            pro_tx_hashes.sort_by_key(|&s| s.reverse());
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

#[cfg(test)]
mod tests {
    use hashes::Hash;
    use test_case::test_case;

    use crate::consensus::{deserialize, serialize};
    use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
    use crate::network::message_sml::MnListDiff;
    use crate::sml::error::SmlError;
    use crate::sml::masternode_list::MasternodeList;
    use crate::test_utils::UNASSIGNED_SPECIAL_TX_TYPE;
    use crate::transaction::special_transaction::TransactionPayload;
    use crate::transaction::special_transaction::coinbase::CoinbasePayload;
    use crate::{BlockHash, Network, Transaction};

    #[test_case(|_| {}, None; "matching")]
    #[test_case(
        |payload| payload.merkle_root_masternode_list = MerkleRootMasternodeList::all_zeros(),
        Some(SmlError::CoinbaseCommitmentMismatch);
        "off the masternode list root"
    )]
    #[test_case(
        |payload| payload.merkle_root_quorums = MerkleRootQuorums::all_zeros(),
        Some(SmlError::CoinbaseCommitmentMismatch);
        "off the quorum list root"
    )]
    #[test_case(
        |payload| {
            payload.version = 1;
            payload.merkle_root_quorums = MerkleRootQuorums::all_zeros();
        },
        None;
        "a version 1 coinbase committing to no quorums"
    )]
    fn verify_coinbase_roots(
        tamper: fn(&mut CoinbasePayload),
        error: Option<fn(BlockHash) -> SmlError>,
    ) {
        let (list, mut coinbase) = fixture_list(|_| {});
        let Some(TransactionPayload::CoinbasePayloadType(payload)) =
            &mut coinbase.special_transaction_payload
        else {
            panic!("coinbase payload");
        };
        tamper(payload);

        let result = list.verify_coinbase_roots(&coinbase);

        assert_eq!(result, error.map_or(Ok(()), |error| Err(error(list.block_hash))));
    }

    /// The list of the 2227096 capture, built after `edit`, and the capture's
    /// coinbase committing to its masternodes.
    fn fixture_list(edit: fn(&mut MnListDiff)) -> (MasternodeList, Transaction) {
        let mut diff: MnListDiff = deserialize(include_bytes!(
            "../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
        .expect("expected to deserialize");
        edit(&mut diff);
        let mut coinbase = diff.coinbase_tx.clone();
        let list = MasternodeList::from_diff(diff, 2_227_096, Network::Mainnet).expect("builds");
        let Some(TransactionPayload::CoinbasePayloadType(payload)) =
            &mut coinbase.special_transaction_payload
        else {
            panic!("coinbase payload");
        };
        // The capture's masternodes do not hash to its coinbase's root, its quorums do.
        payload.merkle_root_masternode_list = list.masternode_merkle_root.expect("masternodes");
        (list, coinbase)
    }

    /// `coinbase` with its payload written as a version this crate does not
    /// decode, its type and bytes edited, and decoded back from the wire.
    fn newer_coinbase(
        coinbase: &Transaction,
        edit: impl FnOnce(&mut u16, &mut Vec<u8>),
    ) -> Transaction {
        let mut newer = coinbase.with_newer_coinbase_payload();
        let Some(TransactionPayload::RawPayloadType(tx_type, bytes)) =
            &mut newer.special_transaction_payload
        else {
            panic!("a raw payload");
        };
        edit(tx_type, bytes);
        let decoded: Transaction = deserialize(&serialize(&newer)).expect("decodes");
        assert_eq!(decoded, newer, "the decoder keeps the payload raw");
        decoded
    }

    /// A coinbase payload of a version this crate does not decode stays raw.
    /// Dash Core only appends fields in a new version, so the roots are read
    /// from the fields this crate knows, at bytes 6..38 and 38..70, and still
    /// have to match. A raw payload of a version this crate decodes, which
    /// Dash Core never produces, or of another transaction type commits to
    /// nothing.
    #[test_case(|_, _| {}, true; "of a newer version")]
    #[test_case(|_, bytes| bytes[6] ^= 1, false; "of a newer version off the masternode list root")]
    #[test_case(|_, bytes| bytes[38] ^= 1, false; "of a newer version off the quorum list root")]
    #[test_case(
        |_, bytes| bytes[..2].copy_from_slice(&4u16.to_le_bytes()),
        false;
        "of a known version with bytes left over"
    )]
    #[test_case(
        |tx_type, _| *tx_type = UNASSIGNED_SPECIAL_TX_TYPE,
        false;
        "of another transaction type"
    )]
    fn verify_coinbase_roots_of_a_raw_payload(edit: fn(&mut u16, &mut Vec<u8>), matches: bool) {
        let (list, coinbase) = fixture_list(|_| {});
        let coinbase = newer_coinbase(&coinbase, edit);

        let result = list.verify_coinbase_roots(&coinbase);

        let expected = if matches {
            Ok(())
        } else {
            Err(SmlError::CoinbaseCommitmentMismatch(list.block_hash))
        };
        assert_eq!(result, expected);
    }

    /// A newer coinbase payload cut short before its quorum list root commits
    /// to nothing, even for a list without quorums, whose root is all zeros.
    #[test]
    fn a_newer_coinbase_payload_cut_short_commits_to_nothing() {
        let (list, coinbase) = fixture_list(|diff| {
            diff.new_quorums.clear();
            diff.quorums_chainlock_signatures.clear();
        });
        assert!(list.quorums.is_empty());
        let coinbase = newer_coinbase(&coinbase, |_, bytes| bytes.truncate(38));
        assert_eq!(CoinbasePayload::from_coinbase_tx(&coinbase), None);

        let result = list.verify_coinbase_roots(&coinbase);

        assert_eq!(result, Err(SmlError::CoinbaseCommitmentMismatch(list.block_hash)));
    }
}
