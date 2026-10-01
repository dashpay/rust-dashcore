use hashes::{Hash, sha256d};

use crate::Transaction;
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::error::SmlError;
use crate::sml::masternode_list::MasternodeList;
use crate::transaction::special_transaction::TransactionPayload;

/// First coinbase payload version that carries `merkleRootQuorums`, Dash Core's
/// `CCbTx::Version::MERKLE_ROOT_QUORUMS`. Every version carries `merkleRootMNList`.
const COINBASE_PAYLOAD_VERSION_MERKLE_ROOT_QUORUMS: u16 = 2;

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
    /// Checks this list against the commitments of its block's coinbase, as Dash Core does when
    /// it validates the block (`CheckCbTxMerkleRoots`).
    ///
    /// `merkleRootMNList`, present in every coinbase payload version, must be the merkle root of
    /// the entry hashes ordered by ProRegTx hash. From payload version 2 on, `merkleRootQuorums`
    /// must be the merkle root of the sorted commitment hashes of every quorum in the list. An
    /// empty set has the all-zero root, as in Core's `ComputeMerkleRoot`.
    ///
    /// The roots are computed from the entries, never read from `masternode_merkle_root` or
    /// `llmq_merkle_root`.
    ///
    /// # Errors
    ///
    /// - `SmlError::MissingCoinbasePayload` if `coinbase_transaction` has no coinbase payload.
    /// - `SmlError::MasternodeListMerkleRootMismatch` if the masternode root differs.
    /// - `SmlError::QuorumMerkleRootMismatch` if the quorum root differs.
    pub fn verify_coinbase_merkle_roots(
        &self,
        coinbase_transaction: &Transaction,
    ) -> Result<(), SmlError> {
        let (masternode_root, quorum_root) = self.coinbase_merkle_roots();
        self.check_coinbase_merkle_roots(coinbase_transaction, masternode_root, quorum_root)
    }

    /// [`Self::verify_coinbase_merkle_roots`] with this list's roots already computed by
    /// [`Self::coinbase_merkle_roots`].
    pub(crate) fn check_coinbase_merkle_roots(
        &self,
        coinbase_transaction: &Transaction,
        masternode_root: MerkleRootMasternodeList,
        quorum_root: MerkleRootQuorums,
    ) -> Result<(), SmlError> {
        let Some(TransactionPayload::CoinbasePayloadType(coinbase_payload)) =
            &coinbase_transaction.special_transaction_payload
        else {
            return Err(SmlError::MissingCoinbasePayload(self.block_hash));
        };

        if masternode_root != coinbase_payload.merkle_root_masternode_list {
            return Err(SmlError::MasternodeListMerkleRootMismatch {
                block_hash: self.block_hash,
                expected: coinbase_payload.merkle_root_masternode_list,
                computed: masternode_root,
            });
        }
        if coinbase_payload.version >= COINBASE_PAYLOAD_VERSION_MERKLE_ROOT_QUORUMS
            && quorum_root != coinbase_payload.merkle_root_quorums
        {
            return Err(SmlError::QuorumMerkleRootMismatch {
                block_hash: self.block_hash,
                expected: coinbase_payload.merkle_root_quorums,
                computed: quorum_root,
            });
        }

        Ok(())
    }

    /// The `merkleRootMNList` and `merkleRootQuorums` a coinbase commits to for this list, with
    /// the all-zero root for an empty set. See [`Self::verify_coinbase_merkle_roots`].
    pub(crate) fn coinbase_merkle_roots(&self) -> (MerkleRootMasternodeList, MerkleRootQuorums) {
        let masternode_root = merkle_root_from_hashes(self.sorted_masternode_entry_hashes())
            .unwrap_or_else(sha256d::Hash::all_zeros);
        let quorum_root = merkle_root_from_hashes(self.hashes_for_quorum_merkle_root())
            .unwrap_or_else(sha256d::Hash::all_zeros);
        (
            MerkleRootMasternodeList::from_raw_hash(masternode_root),
            MerkleRootQuorums::from_raw_hash(quorum_root),
        )
    }

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
        (block_height != u32::MAX).then(|| self.sorted_masternode_entry_hashes())
    }

    /// The entry hashes ordered by ProRegTx hash, the leaves of `merkleRootMNList`. Core sorts
    /// with `uint256::Compare`, a byte-wise comparison of the hash as serialized.
    fn sorted_masternode_entry_hashes(&self) -> Vec<sha256d::Hash> {
        let mut pro_tx_hashes = self.reversed_pro_reg_tx_hashes();
        pro_tx_hashes.sort_by_key(|&s| s.reverse());
        pro_tx_hashes.into_iter().map(|hash| self.masternodes[hash].entry_hash).collect()
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
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::bls_sig_utils::BLSPublicKey;
    use crate::consensus::deserialize;
    use crate::network::constants::NetworkExt;
    use crate::network::message::{NetworkMessage, RawNetworkMessage};
    use crate::network::message_qrinfo::QRInfo;
    use crate::network::message_sml::MnListDiff;
    use crate::sml::masternode_list::from_diff::TryFromWithBlockHashLookup;
    use crate::sml::masternode_list_engine::qr_info_diffs;
    use crate::sml::masternode_list_entry::MasternodeNetInfo;
    use crate::transaction::special_transaction::coinbase::CoinbasePayload;
    use crate::{BlockHash, Network};

    fn mainnet_diff_0_2221605() -> MnListDiff {
        let hex = include_str!("../../../tests/data/test_DML_diffs/DML_0_2221605.hex");
        let message: RawNetworkMessage =
            deserialize(&hex::decode(hex).expect("hex")).expect("raw message");
        let NetworkMessage::MnListDiff(diff) = message.payload else {
            panic!("expected an mnlistdiff message");
        };
        diff
    }

    fn mainnet_qr_info_0_2224359() -> QRInfo {
        let hex = include_str!("../../../tests/data/test_DML_diffs/QR_INFO_0_2224359.hex");
        let message: RawNetworkMessage =
            deserialize(&hex::decode(hex).expect("hex")).expect("raw message");
        let NetworkMessage::QRInfo(qr_info) = message.payload else {
            panic!("expected a qrinfo message");
        };
        qr_info
    }

    fn list_from(diff: MnListDiff) -> Result<MasternodeList, SmlError> {
        MasternodeList::try_from_with_block_hash_lookup(diff, |_| Some(2_221_605), Network::Mainnet)
    }

    fn coinbase_payload(diff: &mut MnListDiff) -> &mut CoinbasePayload {
        match &mut diff.coinbase_tx.special_transaction_payload {
            Some(TransactionPayload::CoinbasePayloadType(payload)) => payload,
            _ => panic!("the fixture's coinbase carries a payload"),
        }
    }

    /// Applies `diffs` in whatever order their bases allow, from genesis or
    /// from a list an earlier one built, and returns how many applied. Every
    /// diff has to apply: the heights are left at 0, which only relaxes the
    /// post-V20 signature requirement, and no height enters the roots.
    fn apply_every_diff(label: &str, diffs: Vec<MnListDiff>, network: Network) -> usize {
        let genesis = network.known_genesis_block_hash();
        let mut lists: HashMap<BlockHash, MasternodeList> = HashMap::new();
        let mut pending = diffs;
        let mut applied = 0;
        while !pending.is_empty() {
            let before = pending.len();
            let mut waiting = Vec::new();
            for diff in pending {
                let block_hash = diff.block_hash;
                let result = if let Some(base) = lists.get(&diff.base_block_hash) {
                    base.apply_diff(diff, 0, None, network).map(|(list, _)| list)
                } else if diff.base_block_hash == BlockHash::all_zeros()
                    || Some(diff.base_block_hash) == genesis
                {
                    MasternodeList::try_from_with_block_hash_lookup(diff, |_| Some(0), network)
                } else {
                    waiting.push(diff);
                    continue;
                };
                let list = result.unwrap_or_else(|e| panic!("{label}: {block_hash}: {e}"));
                lists.insert(block_hash, list);
                applied += 1;
            }
            assert!(waiting.len() < before, "{label}: {} diffs have no base", waiting.len());
            pending = waiting;
        }
        applied
    }

    /// Every masternode list diff committed to the repository builds a list
    /// that matches the coinbase commitments of its block. A false refusal
    /// would stall SPV sync, so this sweeps them all: mainnet, testnet and a
    /// Core 23.1 devnet with ProTx v3 entries, raw captures and QRInfo
    /// payloads alike.
    ///
    /// Three captures are brought back to Core's bytes first, see
    /// [`MnListDiff::restore_core_service_addresses`] and
    /// [`MnListDiff::reverse_platform_node_ids`]. Their roots match only after
    /// that, which pins down those fields as the only difference.
    #[test]
    fn every_fixture_diff_matches_its_coinbase() {
        let mut applied = 0;

        applied +=
            apply_every_diff("DML_0_2221605", vec![mainnet_diff_0_2221605()], Network::Mainnet);

        let qr_info = mainnet_qr_info_0_2224359();
        applied += apply_every_diff(
            "QR_INFO_0_2224359",
            qr_info_diffs(&qr_info).into_iter().cloned().collect(),
            Network::Mainnet,
        );

        let paloma = include_str!("../../../tests/data/test_DML_diffs/qrinfo_core231_paloma.hex");
        let paloma: QRInfo =
            deserialize(&hex::decode(paloma.trim()).expect("hex")).expect("qrinfo");
        applied += apply_every_diff(
            "qrinfo_core231_paloma",
            qr_info_diffs(&paloma).into_iter().cloned().collect(),
            Network::Devnet,
        );

        applied += apply_every_diff(
            "mn_list_diff_0_2227096 and _2227096_2241332",
            vec![
                MnListDiff::mainnet_fixture_0_2227096(),
                MnListDiff::mainnet_fixture_2227096_2241332(),
            ],
            Network::Mainnet,
        );

        applied += apply_every_diff(
            "mn_list_diff_testnet_0_1296600",
            vec![MnListDiff::testnet_fixture_0_1296600()],
            Network::Testnet,
        );

        #[cfg(feature = "bincode")]
        {
            use std::collections::BTreeMap;

            fn decode<T: bincode::Decode<()>>(bytes: &[u8]) -> T {
                bincode::decode_from_slice(bytes, bincode::config::standard())
                    .expect("fixture decodes")
                    .0
            }

            let qr_info: QRInfo =
                decode(include_bytes!("../../../tests/data/test_DML_diffs/qrinfo_2518986.dat"));
            applied += apply_every_diff(
                "qrinfo_2518986",
                qr_info_diffs(&qr_info).into_iter().cloned().collect(),
                Network::Mainnet,
            );

            let diffs: BTreeMap<(u32, u32), MnListDiff> = decode(include_bytes!(
                "../../../tests/data/test_DML_diffs/mnlistdiffs_2240504.dat"
            ));
            let qr_info: QRInfo =
                decode(include_bytes!("../../../tests/data/test_DML_diffs/qrinfo_2240504.dat"));
            let mut diffs: Vec<MnListDiff> =
                diffs.into_values().chain(qr_info_diffs(&qr_info).into_iter().cloned()).collect();
            for diff in &mut diffs {
                diff.restore_core_service_addresses();
                diff.reverse_platform_node_ids();
            }
            applied +=
                apply_every_diff("mnlistdiffs_2240504 and qrinfo_2240504", diffs, Network::Mainnet);
        }

        #[cfg(feature = "bincode")]
        assert_eq!(applied, 59, "a fixture diff was skipped");
        #[cfg(not(feature = "bincode"))]
        assert_eq!(applied, 15, "a fixture diff was skipped");
    }

    /// Without the restore, the captures that wrote service addresses in
    /// another form are refused, which is what makes the restore necessary.
    #[test]
    fn a_capture_with_non_wire_service_addresses_is_refused() {
        let raw: MnListDiff = deserialize(include_bytes!(
            "../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
        .expect("fixture decodes");
        assert!(matches!(
            MasternodeList::try_from_with_block_hash_lookup(
                raw,
                |_| Some(2_227_096),
                Network::Mainnet
            ),
            Err(SmlError::MasternodeListMerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn a_list_built_from_a_diff_holds_the_roots_its_coinbase_commits_to() {
        let mut diff = mainnet_diff_0_2221605();
        let payload = coinbase_payload(&mut diff).clone();
        let list = list_from(diff).expect("the diff applies");
        assert_eq!(list.masternode_merkle_root, Some(payload.merkle_root_masternode_list));
        assert_eq!(list.llmq_merkle_root, Some(payload.merkle_root_quorums));
    }

    #[test]
    fn a_full_diff_with_an_edited_masternode_entry_is_refused() {
        fn first_ipv4(diff: &MnListDiff) -> usize {
            diff.new_masternodes
                .iter()
                .position(|entry| {
                    matches!(entry.service_address, MasternodeNetInfo::Legacy(SocketAddr::V4(_)))
                })
                .expect("the fixture has IPv4 entries")
        }
        type Edit = (&'static str, fn(&mut MnListDiff));
        let edits: [Edit; 4] = [
            ("service IP", |diff| {
                let index = first_ipv4(diff);
                let MasternodeNetInfo::Legacy(address) =
                    &mut diff.new_masternodes[index].service_address
                else {
                    unreachable!("picked a legacy address");
                };
                address.set_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
            }),
            ("validity flag", |diff| {
                diff.new_masternodes[0].is_valid = !diff.new_masternodes[0].is_valid;
            }),
            ("operator key", |diff| {
                diff.new_masternodes[0].operator_public_key = BLSPublicKey::from([7; 48]);
            }),
            ("dropped entry", |diff| {
                diff.new_masternodes.remove(0);
            }),
        ];

        assert!(list_from(mainnet_diff_0_2221605()).is_ok(), "the untouched diff applies");
        for (edit, apply_edit) in edits {
            let mut diff = mainnet_diff_0_2221605();
            apply_edit(&mut diff);
            assert!(
                matches!(list_from(diff), Err(SmlError::MasternodeListMerkleRootMismatch { .. })),
                "an edited {edit} must be refused"
            );
        }
    }

    #[test]
    fn a_full_diff_with_an_edited_quorum_is_refused() {
        let mut diff = mainnet_diff_0_2221605();
        diff.new_quorums[0].quorum_vvec_hash = crate::hash_types::QuorumVVecHash::all_zeros();
        assert!(matches!(list_from(diff), Err(SmlError::QuorumMerkleRootMismatch { .. })));

        // A dropped commitment also drops its slot from the signature groups,
        // so the signature checks still pass and the root is what refuses it.
        let mut diff = mainnet_diff_0_2221605();
        let last = (diff.new_quorums.len() - 1) as u16;
        diff.new_quorums.pop();
        for group in &mut diff.quorums_chainlock_signatures {
            group.index_set.retain(|index| *index != last);
        }
        assert!(matches!(list_from(diff), Err(SmlError::QuorumMerkleRootMismatch { .. })));
    }

    #[test]
    fn a_diff_carrying_another_blocks_coinbase_is_refused() {
        let mut diff = mainnet_diff_0_2221605();
        diff.coinbase_tx = mainnet_qr_info_0_2224359().mn_list_diff_tip.coinbase_tx;
        assert!(matches!(list_from(diff), Err(SmlError::MasternodeListMerkleRootMismatch { .. })));

        let mut diff = mainnet_diff_0_2221605();
        diff.coinbase_tx.special_transaction_payload = None;
        assert!(matches!(list_from(diff), Err(SmlError::MissingCoinbasePayload(_))));
    }

    /// Edits to a diff applied on a base list: a deletion the diff leaves
    /// out keeps an entry the coinbase does not count.
    #[test]
    fn an_applied_diff_that_leaves_out_a_change_is_refused() {
        let base = MasternodeList::try_from_with_block_hash_lookup(
            MnListDiff::mainnet_fixture_0_2227096(),
            |_| Some(2_227_096),
            Network::Mainnet,
        )
        .expect("base list");
        let apply = |diff: MnListDiff| base.apply_diff(diff, 2_241_332, None, Network::Mainnet);

        assert!(apply(MnListDiff::mainnet_fixture_2227096_2241332()).is_ok());

        let mut diff = MnListDiff::mainnet_fixture_2227096_2241332();
        diff.deleted_masternodes.pop().expect("the fixture deletes masternodes");
        assert!(matches!(apply(diff), Err(SmlError::MasternodeListMerkleRootMismatch { .. })));

        let mut diff = MnListDiff::mainnet_fixture_2227096_2241332();
        diff.new_masternodes[0].is_valid = !diff.new_masternodes[0].is_valid;
        assert!(matches!(apply(diff), Err(SmlError::MasternodeListMerkleRootMismatch { .. })));

        let mut diff = MnListDiff::mainnet_fixture_2227096_2241332();
        diff.deleted_quorums.pop().expect("the fixture deletes quorums");
        assert!(matches!(apply(diff), Err(SmlError::QuorumMerkleRootMismatch { .. })));
    }

    /// Coinbase payload version 1 carries `merkleRootMNList` but no
    /// `merkleRootQuorums`, so only the masternode root is compared. From
    /// version 2 on both are.
    #[test]
    fn coinbase_payload_version_decides_which_roots_are_compared() {
        let with_payload = |version: u16, masternode_root: Option<MerkleRootMasternodeList>| {
            let mut diff = mainnet_diff_0_2221605();
            let payload = coinbase_payload(&mut diff);
            *payload = CoinbasePayload {
                version,
                height: payload.height,
                merkle_root_masternode_list: masternode_root
                    .unwrap_or(payload.merkle_root_masternode_list),
                merkle_root_quorums: MerkleRootQuorums::all_zeros(),
                best_cl_height: None,
                best_cl_signature: None,
                asset_locked_amount: None,
            };
            list_from(diff)
        };
        let wrong_root = Some(MerkleRootMasternodeList::from_byte_array([7; 32]));

        assert!(with_payload(1, None).is_ok(), "version 1 has no quorum root to compare");
        assert!(matches!(
            with_payload(1, wrong_root),
            Err(SmlError::MasternodeListMerkleRootMismatch { .. })
        ));
        assert!(matches!(with_payload(2, None), Err(SmlError::QuorumMerkleRootMismatch { .. })));
    }

    /// Core's `ComputeMerkleRoot` gives an empty set the all-zero root.
    #[test]
    fn an_empty_list_matches_all_zero_roots() {
        let list = MasternodeList::empty(BlockHash::all_zeros(), 1);
        let empty = MnListDiff::dummy_between(0, 1);
        list.verify_coinbase_merkle_roots(&empty.coinbase_tx).expect("zero roots match");
        assert_eq!(
            list.coinbase_merkle_roots(),
            (MerkleRootMasternodeList::all_zeros(), MerkleRootQuorums::all_zeros())
        );
    }
}
