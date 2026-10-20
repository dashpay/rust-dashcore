use hashes::{Hash, sha256d};

use crate::consensus::{Decodable, serialize};
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::error::SmlError;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::MasternodeList;
use crate::transaction::special_transaction::coinbase::CoinbasePayload;
use crate::transaction::special_transaction::{TransactionPayload, TransactionType};
use crate::{BlockHash, Transaction};

/// First coinbase payload version that carries `merkleRootQuorums`, Dash Core's
/// `CCbTx::Version::MERKLE_ROOT_QUORUMS`. Every version carries `merkleRootMNList`.
const COINBASE_VERSION_MERKLE_ROOT_QUORUMS: u16 = 2;

/// Newest coinbase payload version this crate decodes.
const NEWEST_KNOWN_COINBASE_VERSION: u16 = 4;

/// Most commitments of types this crate does not know a list may hold for their type bytes to
/// be recovered. Dash Core keeps at most `signingActiveQuorumCount` active commitments per type,
/// 32 for any type it defines today.
const MAX_UNKNOWN_TYPE_COMMITMENTS: usize = 64;

/// Most commitments of any type a list may hold for the types of unknown ones to be recovered,
/// several times what Dash Core keeps active on any network it defines. It keeps a peer from
/// making each of the 242 candidate roots cost more than a few hundred hashes.
const MAX_QUORUMS_TO_RECOVER: usize = 256;

/// Offset of the LLMQ type byte in a serialized commitment, after its `u16` version.
const COMMITMENT_TYPE_BYTE_OFFSET: usize = 2;

/// What a coinbase commits to about the masternode list of its block (DIP-4).
pub(crate) struct CoinbaseCommitments {
    pub(crate) height: u32,
    pub(crate) merkle_root_masternode_list: MerkleRootMasternodeList,
    /// Present from payload version 2 on.
    pub(crate) merkle_root_quorums: Option<MerkleRootQuorums>,
}

impl CoinbaseCommitments {
    /// The commitments of `coinbase`, the coinbase of `block_hash`, or `None` if it carries no
    /// coinbase payload, as no block before DIP-3 activation does.
    ///
    /// They are read from the typed payload, or, for a payload whose layout this crate does not
    /// decode (a newer version kept raw), from the prefix every version shares: the version, the
    /// height, `merkleRootMNList` and from version 2 `merkleRootQuorums`. Reading a newer layout
    /// that way is safe: the roots still have to equal the ones recomputed from the list, over
    /// coinbase bytes the block's merkle proof authenticates, so a wrong guess can only refuse a
    /// list, never accept a wrong one.
    ///
    /// # Errors
    ///
    /// - `SmlError::InvalidCoinbasePayload` for version 0, which Dash Core refuses
    ///   (`bad-cbtx-version`), or a payload too short for its prefix.
    /// - `SmlError::MissingCoinbasePayload` for a payload of another type.
    pub(crate) fn of(
        coinbase: &Transaction,
        block_hash: BlockHash,
    ) -> Result<Option<Self>, SmlError> {
        let (version, commitments) = match &coinbase.special_transaction_payload {
            None => return Ok(None),
            Some(TransactionPayload::CoinbasePayloadType(payload)) => {
                (payload.version, Self::of_payload(payload))
            }
            Some(TransactionPayload::RawPayloadType(tx_type, bytes))
                if *tx_type == TransactionType::Coinbase.to_u16() =>
            {
                Self::of_prefix(bytes).ok_or(SmlError::InvalidCoinbasePayload(block_hash))?
            }
            Some(_) => return Err(SmlError::MissingCoinbasePayload(block_hash)),
        };
        if version == 0 {
            return Err(SmlError::InvalidCoinbasePayload(block_hash));
        }
        if version > NEWEST_KNOWN_COINBASE_VERSION {
            tracing::warn!(
                "Coinbase payload version {version} of block {block_hash} is newer than this \
                 library knows, reading its commitments from the prefix every version shares"
            );
        }
        Ok(Some(commitments))
    }

    fn of_payload(payload: &CoinbasePayload) -> Self {
        CoinbaseCommitments {
            height: payload.height,
            merkle_root_masternode_list: payload.merkle_root_masternode_list,
            merkle_root_quorums: (payload.version >= COINBASE_VERSION_MERKLE_ROOT_QUORUMS)
                .then_some(payload.merkle_root_quorums),
        }
    }

    fn of_prefix(mut bytes: &[u8]) -> Option<(u16, Self)> {
        let r = &mut bytes;
        let version = u16::consensus_decode(r).ok()?;
        let height = u32::consensus_decode(r).ok()?;
        let merkle_root_masternode_list = MerkleRootMasternodeList::consensus_decode(r).ok()?;
        let merkle_root_quorums = if version >= COINBASE_VERSION_MERKLE_ROOT_QUORUMS {
            Some(MerkleRootQuorums::consensus_decode(r).ok()?)
        } else {
            None
        };
        Some((
            version,
            CoinbaseCommitments {
                height,
                merkle_root_masternode_list,
                merkle_root_quorums,
            },
        ))
    }
}

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
    /// it validates the block (`CheckCbTx`, `CheckCbTxMerkleRoots`), and returns the roots
    /// `(merkleRootMNList, merkleRootQuorums)` of the list: the ones it computed, or the committed
    /// quorum root once the types of unknown commitments are recovered.
    ///
    /// - The payload height has to be the list's height.
    /// - `merkleRootMNList` has to be the merkle root of the entry hashes ordered by ProRegTx
    ///   hash.
    /// - From payload version 2 on, `merkleRootQuorums` has to be the merkle root of the sorted
    ///   commitment hashes of every quorum in the list.
    /// - An empty set has the all-zero root, as in Dash Core's `ComputeMerkleRoot`.
    /// - A coinbase without a coinbase payload commits to nothing, which is right only for a list
    ///   without masternodes or quorums: from DIP-3 activation on every coinbase carries the
    ///   payload, and no masternode registers before it.
    ///
    /// The roots are computed from the entries, never read from `masternode_merkle_root` or
    /// `llmq_merkle_root`.
    pub(crate) fn check_coinbase_commitments(
        &self,
        coinbase_transaction: &Transaction,
    ) -> Result<(MerkleRootMasternodeList, MerkleRootQuorums), SmlError> {
        let masternode_root = self
            .calculate_masternodes_merkle_root(self.known_height)
            .unwrap_or_else(MerkleRootMasternodeList::all_zeros);
        let quorum_root =
            self.calculate_llmq_merkle_root().unwrap_or_else(MerkleRootQuorums::all_zeros);

        let Some(commitments) = CoinbaseCommitments::of(coinbase_transaction, self.block_hash)?
        else {
            if self.masternodes.is_empty() && self.quorums.is_empty() {
                return Ok((masternode_root, quorum_root));
            }
            return Err(SmlError::MissingCoinbasePayload(self.block_hash));
        };
        if commitments.height != self.known_height {
            return Err(SmlError::CoinbaseHeightMismatch {
                block_hash: self.block_hash,
                expected: self.known_height,
                found: commitments.height,
            });
        }
        if masternode_root != commitments.merkle_root_masternode_list {
            return Err(SmlError::MasternodeListMerkleRootMismatch {
                block_hash: self.block_hash,
                computed: masternode_root,
            });
        }
        if let Some(committed) = commitments.merkle_root_quorums.filter(|root| *root != quorum_root)
        {
            if !self.recovers_unknown_quorum_types(committed) {
                return Err(SmlError::QuorumMerkleRootMismatch {
                    block_hash: self.block_hash,
                    computed: quorum_root,
                });
            }
            return Ok((masternode_root, committed));
        }
        Ok((masternode_root, quorum_root))
    }

    /// Whether the quorum root is `committed` once the commitments of types this crate does not
    /// know get their type byte back.
    ///
    /// Such a commitment decodes as `LlmqtypeUnknown` and re-encodes with type 0, so its hash is
    /// not the one Dash Core puts in `merkleRootQuorums`, and a network mining a type this crate
    /// does not know would otherwise have every list refused. Each type byte no known type decodes
    /// from is tried for all of them, which recovers one new type at a time. The match is exact,
    /// so a fabricated commitment cannot pass. A list holding more than
    /// [`MAX_UNKNOWN_TYPE_COMMITMENTS`] of them, or more than [`MAX_QUORUMS_TO_RECOVER`] in all,
    /// is not tried, which bounds the work a peer can cause.
    fn recovers_unknown_quorum_types(&self, committed: MerkleRootQuorums) -> bool {
        let Some(unknown) = self.quorums.get(&LLMQType::LlmqtypeUnknown) else {
            return false;
        };
        let quorums: usize = self.quorums.values().map(|quorums| quorums.len()).sum();
        if unknown.len() > MAX_UNKNOWN_TYPE_COMMITMENTS || quorums > MAX_QUORUMS_TO_RECOVER {
            return false;
        }
        let known: Vec<sha256d::Hash> = self
            .quorums
            .iter()
            .filter(|(llmq_type, _)| **llmq_type != LLMQType::LlmqtypeUnknown)
            .flat_map(|(_, quorums)| quorums.values().map(|quorum| quorum.entry_hash.to_raw_hash()))
            .collect();
        let mut unknown: Vec<Vec<u8>> =
            unknown.values().map(|quorum| serialize(&quorum.quorum_entry)).collect();
        (0..=u8::MAX).filter(|byte| LLMQType::from(*byte) == LLMQType::LlmqtypeUnknown).any(
            |byte| {
                let mut hashes = known.clone();
                for commitment in &mut unknown {
                    let Some(type_byte) = commitment.get_mut(COMMITMENT_TYPE_BYTE_OFFSET) else {
                        return false;
                    };
                    *type_byte = byte;
                    hashes.push(sha256d::Hash::hash(commitment));
                }
                hashes.sort();
                merkle_root_from_hashes(hashes).map(MerkleRootQuorums::from_raw_hash)
                    == Some(committed)
            },
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
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::Network;
    use crate::QuorumHash;
    use crate::bls_sig_utils::BLSPublicKey;
    use crate::consensus::{deserialize, serialize};
    use crate::network::constants::NetworkExt;
    use crate::network::message::{NetworkMessage, RawNetworkMessage};
    use crate::network::message_qrinfo::QRInfo;
    use crate::network::message_sml::MnListDiff;
    use crate::sml::masternode_list_entry::MasternodeNetInfo;
    use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

    fn decode_hex<T: Decodable>(hex: &str) -> T {
        deserialize(&hex_conservative::decode_to_vec(hex.trim()).expect("hex")).expect("decodes")
    }

    fn mainnet_qr_info_0_2224359() -> QRInfo {
        let message: RawNetworkMessage =
            decode_hex(include_str!("../../../tests/data/test_DML_diffs/QR_INFO_0_2224359.hex"));
        let NetworkMessage::QRInfo(qr_info) = message.payload else {
            panic!("expected a qrinfo message");
        };
        *qr_info
    }

    /// Every diff a QRInfo carries.
    fn qr_info_diffs(qr_info: QRInfo) -> Vec<MnListDiff> {
        let mut diffs = vec![
            qr_info.mn_list_diff_tip,
            qr_info.mn_list_diff_h,
            qr_info.mn_list_diff_at_h_minus_c,
            qr_info.mn_list_diff_at_h_minus_2c,
            qr_info.mn_list_diff_at_h_minus_3c,
        ];
        diffs.extend(qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.map(|(_, diff)| diff));
        diffs.extend(qr_info.mn_list_diff_list);
        diffs
    }

    fn coinbase_payload(diff: &mut MnListDiff) -> &mut CoinbasePayload {
        match &mut diff.coinbase_tx.special_transaction_payload {
            Some(TransactionPayload::CoinbasePayloadType(payload)) => payload,
            _ => panic!("the fixture's coinbase carries a payload"),
        }
    }

    /// The height the diff's coinbase commits to, which is its block's.
    fn coinbase_height(diff: &MnListDiff) -> u32 {
        CoinbaseCommitments::of(&diff.coinbase_tx, diff.block_hash)
            .expect("a valid payload")
            .expect("a coinbase payload")
            .height
    }

    fn list_from(diff: MnListDiff) -> Result<MasternodeList, SmlError> {
        MasternodeList::from_diff(diff, 2_221_605, Network::Mainnet)
    }

    /// Applies `diffs` in whatever order their bases allow, from genesis or
    /// from a list an earlier one built, each at the height of its block, and
    /// returns how many applied. Every diff has to apply.
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
                let height = coinbase_height(&diff);
                let result = if let Some(base) = lists.get(&diff.base_block_hash) {
                    base.apply_diff(diff, height, network)
                } else if diff.base_block_hash == BlockHash::all_zeros()
                    || Some(diff.base_block_hash) == genesis
                {
                    MasternodeList::from_diff(diff, height, network)
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
    /// Older captures are brought back to Core's bytes first, see
    /// [`MnListDiff::restore_core_service_addresses`] and
    /// [`MnListDiff::reverse_platform_node_ids`]. Their roots match only after
    /// that, which pins those fields as the only difference.
    #[test]
    fn every_fixture_diff_matches_its_coinbase() {
        let mut applied = 0;

        applied += apply_every_diff(
            "DML_0_2221605",
            vec![MnListDiff::mainnet_fixture_0_2221605()],
            Network::Mainnet,
        );
        applied += apply_every_diff(
            "QR_INFO_0_2224359",
            qr_info_diffs(mainnet_qr_info_0_2224359()),
            Network::Mainnet,
        );
        let paloma: QRInfo = decode_hex(include_str!(
            "../../../tests/data/test_DML_diffs/qrinfo_core231_paloma.hex"
        ));
        applied +=
            apply_every_diff("qrinfo_core231_paloma", qr_info_diffs(paloma), Network::Devnet);
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
            applied += apply_every_diff("qrinfo_2518986", qr_info_diffs(qr_info), Network::Mainnet);

            let diffs: BTreeMap<(u32, u32), MnListDiff> = decode(include_bytes!(
                "../../../tests/data/test_DML_diffs/mnlistdiffs_2240504.dat"
            ));
            let qr_info: QRInfo =
                decode(include_bytes!("../../../tests/data/test_DML_diffs/qrinfo_2240504.dat"));
            let mut diffs: Vec<MnListDiff> =
                diffs.into_values().chain(qr_info_diffs(qr_info)).collect();
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

    /// Without the restore, a capture that wrote service addresses in another
    /// form is refused, which is what makes the restore necessary.
    #[test]
    fn a_capture_with_non_wire_service_addresses_is_refused() {
        let raw: MnListDiff = deserialize(include_bytes!(
            "../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
        .expect("fixture decodes");
        assert!(matches!(
            MasternodeList::from_diff(raw, 2_227_096, Network::Mainnet),
            Err(SmlError::MasternodeListMerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn a_list_built_from_a_diff_holds_the_roots_its_coinbase_commits_to() {
        let mut diff = MnListDiff::mainnet_fixture_0_2221605();
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

        assert!(
            list_from(MnListDiff::mainnet_fixture_0_2221605()).is_ok(),
            "the untouched diff applies"
        );
        for (edit, apply_edit) in edits {
            let mut diff = MnListDiff::mainnet_fixture_0_2221605();
            apply_edit(&mut diff);
            assert!(
                matches!(list_from(diff), Err(SmlError::MasternodeListMerkleRootMismatch { .. })),
                "an edited {edit} must be refused"
            );
        }
    }

    #[test]
    fn a_full_diff_with_an_edited_quorum_is_refused() {
        let mut diff = MnListDiff::mainnet_fixture_0_2221605();
        diff.new_quorums[0].quorum_vvec_hash = crate::hash_types::QuorumVVecHash::all_zeros();
        assert!(matches!(list_from(diff), Err(SmlError::QuorumMerkleRootMismatch { .. })));

        // A dropped commitment also drops its slot from the signature groups,
        // so the signature checks still pass and the root is what refuses it.
        let mut diff = MnListDiff::mainnet_fixture_0_2221605();
        let last = (diff.new_quorums.len() - 1) as u16;
        diff.new_quorums.pop();
        for group in &mut diff.quorums_chainlock_signatures {
            group.index_set.retain(|index| *index != last);
        }
        assert!(matches!(list_from(diff), Err(SmlError::QuorumMerkleRootMismatch { .. })));
    }

    #[test]
    fn a_diff_carrying_another_blocks_coinbase_is_refused() {
        let mut diff = MnListDiff::mainnet_fixture_0_2221605();
        diff.coinbase_tx = mainnet_qr_info_0_2224359().mn_list_diff_tip.coinbase_tx;
        assert!(matches!(list_from(diff), Err(SmlError::CoinbaseHeightMismatch { .. })));

        let mut diff = MnListDiff::mainnet_fixture_0_2221605();
        let other = mainnet_qr_info_0_2224359().mn_list_diff_tip.coinbase_tx;
        diff.coinbase_tx = other.clone();
        *coinbase_payload(&mut diff) = CoinbasePayload {
            height: 2_221_605,
            ..match other.special_transaction_payload {
                Some(TransactionPayload::CoinbasePayloadType(payload)) => payload,
                _ => unreachable!("a coinbase payload"),
            }
        };
        assert!(matches!(list_from(diff), Err(SmlError::MasternodeListMerkleRootMismatch { .. })));

        let mut diff = MnListDiff::mainnet_fixture_0_2221605();
        diff.coinbase_tx.special_transaction_payload = None;
        assert!(matches!(list_from(diff), Err(SmlError::MissingCoinbasePayload(_))));
    }

    /// The coinbase payload commits to its block's height, as Dash Core
    /// checks (`bad-cbtx-height`), and version 0 is no valid payload
    /// (`bad-cbtx-version`).
    #[test]
    fn a_coinbase_for_another_height_or_of_version_0_is_refused() {
        let diff = MnListDiff::mainnet_fixture_0_2221605();
        assert!(matches!(
            MasternodeList::from_diff(diff.clone(), 2_221_604, Network::Mainnet),
            Err(SmlError::CoinbaseHeightMismatch {
                expected: 2_221_604,
                found: 2_221_605,
                ..
            })
        ));

        let mut diff = diff;
        coinbase_payload(&mut diff).version = 0;
        assert!(matches!(list_from(diff), Err(SmlError::InvalidCoinbasePayload(_))));
    }

    /// A diff on a mainnet list that flips one entry's validity flag, leaves
    /// out a deletion or keeps a deleted quorum builds a list its coinbase does
    /// not commit to, and is refused.
    #[test]
    fn an_applied_diff_that_leaves_out_a_change_is_refused() {
        let base = MasternodeList::from_diff(
            MnListDiff::mainnet_fixture_0_2227096(),
            2_227_096,
            Network::Mainnet,
        )
        .expect("base list");
        let apply = |diff: MnListDiff| base.apply_diff(diff, 2_241_332, Network::Mainnet);

        assert!(apply(MnListDiff::mainnet_fixture_2227096_2241332()).is_ok());

        let mut diff = MnListDiff::mainnet_fixture_2227096_2241332();
        diff.new_masternodes[0].is_valid = !diff.new_masternodes[0].is_valid;
        assert!(matches!(apply(diff), Err(SmlError::MasternodeListMerkleRootMismatch { .. })));

        let mut diff = MnListDiff::mainnet_fixture_2227096_2241332();
        diff.deleted_masternodes.pop().expect("the fixture deletes masternodes");
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
            let mut diff = MnListDiff::mainnet_fixture_0_2221605();
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
                merkle_root_asset_unlocks: None,
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

    /// A payload this crate does not decode, such as a newer version, is kept
    /// raw, and its commitments are read from the prefix every version shares.
    /// A payload too short for that prefix is refused.
    #[test]
    fn the_commitments_of_a_raw_coinbase_payload_are_read_from_its_prefix() {
        let mut diff = MnListDiff::mainnet_fixture_0_2221605();
        let payload = coinbase_payload(&mut diff).clone();
        let mut bytes = serialize(&5u16);
        bytes.extend(serialize(&payload.height));
        bytes.extend(serialize(&payload.merkle_root_masternode_list));
        bytes.extend(serialize(&payload.merkle_root_quorums));
        bytes.extend([0xAB; 17]);
        let raw = |bytes: Vec<u8>| {
            let mut diff = MnListDiff::mainnet_fixture_0_2221605();
            diff.coinbase_tx.special_transaction_payload =
                Some(TransactionPayload::RawPayloadType(TransactionType::Coinbase.to_u16(), bytes));
            list_from(diff)
        };

        let list = raw(bytes.clone()).expect("a version 5 coinbase commits like any other");
        assert_eq!(list.llmq_merkle_root, Some(payload.merkle_root_quorums));

        // Version, height and list root, and half the quorum root.
        bytes.truncate(2 + 4 + 32 + 16);
        assert!(matches!(raw(bytes), Err(SmlError::InvalidCoinbasePayload(_))));
    }

    /// Core v24 coinbases are version 4 and commit like the earlier versions.
    #[test]
    fn a_version_4_coinbase_commits_to_its_height_and_roots() {
        let block: crate::Block =
            decode_hex(include_str!("../../../tests/data/core_v24_devnet/block_15000.hex"));
        let coinbase = &block.txdata[0];
        let Some(TransactionPayload::CoinbasePayloadType(payload)) =
            &coinbase.special_transaction_payload
        else {
            panic!("a typed coinbase payload");
        };
        assert_eq!(payload.version, 4);

        let commitments = CoinbaseCommitments::of(coinbase, block.block_hash())
            .expect("a valid payload")
            .expect("a coinbase payload");
        assert_eq!(commitments.height, 15000);
        assert_eq!(commitments.merkle_root_masternode_list, payload.merkle_root_masternode_list);
        assert_eq!(commitments.merkle_root_quorums, Some(payload.merkle_root_quorums));
    }

    /// Before DIP-3 activation a coinbase carries no payload and commits to
    /// nothing, which is right only for a list without masternodes or quorums.
    #[test]
    fn a_coinbase_without_payload_passes_only_for_an_empty_list() {
        let no_payload = |diff: MnListDiff| MnListDiff {
            coinbase_tx: Transaction {
                special_transaction_payload: None,
                ..diff.coinbase_tx.clone()
            },
            ..diff
        };
        let empty = MasternodeList::empty(BlockHash::dummy(0), 0);
        assert!(
            empty
                .apply_diff(no_payload(MnListDiff::dummy_between(0, 1)), 1, Network::Regtest)
                .is_ok()
        );

        let one_masternode = MnListDiff::dummy(0x00, 0x01).committing_on(Some(&empty), 1);
        assert!(empty.apply_diff(one_masternode.clone(), 1, Network::Regtest).is_ok());
        assert!(matches!(
            empty.apply_diff(no_payload(one_masternode), 1, Network::Regtest),
            Err(SmlError::MissingCoinbasePayload(_))
        ));
    }

    /// `diff` with its first `count` commitments, or copies of its first one
    /// under other quorum hashes, served with type byte 200, which no type
    /// this crate knows decodes from, and a coinbase committing to Dash Core's
    /// hashes of them.
    fn with_unknown_type_commitments(mut diff: MnListDiff, count: usize) -> MnListDiff {
        let template = diff.new_quorums[0].clone();
        diff.new_quorums.remove(0);
        let mut core_hashes = Vec::new();
        for n in 0..count {
            let mut bytes = serialize(&QuorumEntry {
                quorum_hash: QuorumHash::from_byte_array([n as u8 + 1; 32]),
                ..template.clone()
            });
            bytes[COMMITMENT_TYPE_BYTE_OFFSET] = 200;
            core_hashes.push(sha256d::Hash::hash(&bytes));
            let served: QuorumEntry =
                deserialize(&bytes).expect("a commitment of any type decodes");
            assert_eq!(served.llmq_type, LLMQType::LlmqtypeUnknown);
            diff.new_quorums.push(served);
        }
        let slots = diff.new_quorums.len() as u16;
        diff.quorums_chainlock_signatures[0].index_set = (0..slots).collect();
        diff.quorums_chainlock_signatures.truncate(1);
        let mut hashes: Vec<sha256d::Hash> = diff.new_quorums[..diff.new_quorums.len() - count]
            .iter()
            .map(|quorum| quorum.calculate_entry_hash().to_raw_hash())
            .chain(core_hashes)
            .collect();
        hashes.sort();
        coinbase_payload(&mut diff).merkle_root_quorums =
            MerkleRootQuorums::from_raw_hash(merkle_root_from_hashes(hashes).expect("quorums"));
        diff
    }

    /// A commitment of a type this crate does not know decodes as
    /// `LlmqtypeUnknown`, and its hash is recovered by trying the type bytes
    /// no known type decodes from. A commitment the coinbase does not commit
    /// to cannot be passed off as one of an unknown type.
    #[test]
    fn a_quorum_of_a_type_this_library_does_not_know_is_recovered() {
        let mut diff = with_unknown_type_commitments(MnListDiff::mainnet_fixture_0_2221605(), 2);
        let committed = coinbase_payload(&mut diff).merkle_root_quorums;

        let list = list_from(diff.clone()).expect("the type byte is recovered");
        assert_eq!(list.llmq_merkle_root, Some(committed));

        let mut fabricated = diff;
        let extra = QuorumEntry {
            quorum_hash: QuorumHash::from_byte_array([0xEE; 32]),
            ..fabricated.new_quorums.last().expect("a commitment").clone()
        };
        fabricated.new_quorums.push(extra);
        fabricated.quorums_chainlock_signatures[0]
            .index_set
            .push(fabricated.new_quorums.len() as u16 - 1);
        assert!(matches!(list_from(fabricated), Err(SmlError::QuorumMerkleRootMismatch { .. })));
    }

    /// Recovering type bytes costs a merkle root per candidate, so a list
    /// holding more unknown-type commitments than any type keeps active is
    /// refused without trying.
    #[test]
    fn too_many_quorums_of_unknown_types_are_refused_without_recovery() {
        let within = with_unknown_type_commitments(
            MnListDiff::mainnet_fixture_0_2221605(),
            MAX_UNKNOWN_TYPE_COMMITMENTS,
        );
        assert!(list_from(within).is_ok());

        let beyond = with_unknown_type_commitments(
            MnListDiff::mainnet_fixture_0_2221605(),
            MAX_UNKNOWN_TYPE_COMMITMENTS + 1,
        );
        assert!(matches!(list_from(beyond), Err(SmlError::QuorumMerkleRootMismatch { .. })));
    }

    /// Each candidate type byte costs a merkle root over every commitment of
    /// the list, so a list holding more than any network keeps active is not
    /// tried either, however few of them are of unknown types.
    #[test]
    fn a_list_holding_too_many_quorums_is_refused_without_recovery() {
        for (quorums, recovered) in
            [(MAX_QUORUMS_TO_RECOVER, true), (MAX_QUORUMS_TO_RECOVER + 1, false)]
        {
            let mut diff = MnListDiff::mainnet_fixture_0_2221605();
            let template = diff.new_quorums[0].clone();
            diff.new_quorums = (0..quorums)
                .map(|n| {
                    let mut quorum_hash = [0xAA; 32];
                    quorum_hash[..2].copy_from_slice(&(n as u16).to_le_bytes());
                    QuorumEntry {
                        quorum_hash: QuorumHash::from_byte_array(quorum_hash),
                        ..template.clone()
                    }
                })
                .collect();
            let diff = with_unknown_type_commitments(diff, 1);
            assert_eq!(list_from(diff).is_ok(), recovered, "{quorums} quorums");
        }
    }

    /// Core's `ComputeMerkleRoot` gives an empty set the all-zero root.
    #[test]
    fn an_empty_list_matches_all_zero_roots() {
        let list = MasternodeList::empty(BlockHash::all_zeros(), 1);
        let empty = MnListDiff::dummy_between(0, 1);
        assert_eq!(
            list.check_coinbase_commitments(&empty.coinbase_tx).expect("zero roots match"),
            (MerkleRootMasternodeList::all_zeros(), MerkleRootQuorums::all_zeros())
        );
    }
}
