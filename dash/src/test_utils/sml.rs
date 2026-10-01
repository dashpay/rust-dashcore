use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use hashes::Hash;

use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
use crate::consensus::deserialize;
use crate::hash_types::{MerkleRootMasternodeList, ProTxHash};
use crate::network::message_qrinfo::{MNSkipListMode, QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::sml::masternode_list::{MasternodeList, QuorumMap};
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::masternode_list_entry::{
    EntryMasternodeType, MasternodeListEntry, MasternodeNetInfo,
};
use crate::transaction::special_transaction::TransactionPayload;
use crate::transaction::special_transaction::coinbase::CoinbasePayload;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
use crate::{
    BlockHash, Network, OutPoint, PlatformNodeId, PubkeyHash, ScriptBuf, Transaction, TxIn,
    TxMerkleNode, Witness,
};

fn dummy_hash(byte: u8) -> BlockHash {
    BlockHash::from_slice(&[byte; 32]).unwrap()
}

impl MasternodeListEntry {
    pub fn dummy(byte: u8) -> Self {
        MasternodeListEntry {
            version: 1,
            pro_reg_tx_hash: ProTxHash::from_slice(&[byte; 32]).unwrap(),
            confirmed_hash: None,
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from(([127, 0, 0, 1], 19999))),
            operator_public_key: BLSPublicKey::from([0u8; 48]),
            key_id_voting: PubkeyHash::from_slice(&[byte; 20]).unwrap(),
            is_valid: true,
            mn_type: EntryMasternodeType::Regular,
        }
    }
}

impl MnListDiff {
    /// Carries one masternode and one merkle hash, the minimum
    /// [`MasternodeList`] conversion accepts. Use this when the diff has to
    /// apply to an engine.
    ///
    /// The coinbase commits to a list holding only that masternode, which is
    /// what the diff builds from genesis. A diff applied on top of another
    /// list builds more, and needs [`Self::with_coinbase_committing_to`].
    pub fn dummy(base_byte: u8, tip_byte: u8) -> Self {
        let masternode = MasternodeListEntry::dummy(tip_byte);
        MnListDiff {
            new_masternodes: vec![masternode.clone()],
            ..MnListDiff::dummy_empty(base_byte, tip_byte)
        }
        .with_coinbase_committing_to(&[masternode], &[])
    }

    /// Hashes only. An engine rejects this as an incomplete diff, which is what
    /// makes it useful for exercising the rejection paths.
    pub fn dummy_empty(base_byte: u8, tip_byte: u8) -> Self {
        MnListDiff {
            version: 1,
            base_block_hash: dummy_hash(base_byte),
            block_hash: dummy_hash(tip_byte),
            total_transactions: 0,
            merkle_hashes: vec![],
            merkle_flags: vec![],
            coinbase_tx: Transaction::dummy_empty(),
            deleted_masternodes: vec![],
            new_masternodes: vec![],
            deleted_quorums: vec![],
            new_quorums: vec![],
            quorums_chainlock_signatures: vec![],
        }
    }

    /// An empty diff from `BlockHash::dummy(base)` to `BlockHash::dummy(tip)`,
    /// which an engine holding an empty list at `base` applies. On any other
    /// list it needs [`Self::with_coinbase_committing_to`].
    pub fn dummy_between(base: u32, tip: u32) -> Self {
        MnListDiff {
            base_block_hash: BlockHash::dummy(base),
            block_hash: BlockHash::dummy(tip),
            ..MnListDiff::dummy_empty(0x00, 0x00)
        }
        .with_coinbase_committing_to(&[], &[])
    }

    /// Replaces the coinbase with one whose payload commits to a list of
    /// exactly `masternodes` and `quorums`, and the merkle proof with that of a
    /// block holding only this coinbase. The diff then passes the coinbase
    /// checks wherever applying it builds that list, and its proof leads to
    /// [`Self::dummy_block_merkle_root`].
    pub fn with_coinbase_committing_to(
        mut self,
        masternodes: &[MasternodeListEntry],
        quorums: &[QuorumEntry],
    ) -> Self {
        let masternodes = masternodes
            .iter()
            .map(|entry| (entry.pro_reg_tx_hash.reverse(), Arc::new(entry.clone().into())))
            .collect::<BTreeMap<_, _>>();
        let mut quorum_map = QuorumMap::new();
        for quorum in quorums {
            quorum_map
                .entry(quorum.llmq_type)
                .or_default()
                .insert(quorum.quorum_hash, Arc::new(quorum.clone().into()));
        }
        let (masternode_root, quorum_root) =
            MasternodeList::build(masternodes, quorum_map, self.block_hash, 0)
                .build()
                .coinbase_merkle_roots();

        self.coinbase_tx = Transaction {
            version: 3,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            }],
            output: vec![],
            special_transaction_payload: Some(TransactionPayload::CoinbasePayloadType(
                CoinbasePayload::new(
                    0,
                    masternode_root,
                    quorum_root,
                    Some(0),
                    Some(BLSSignature::from([0; 96])),
                    Some(0),
                ),
            )),
        };
        self.total_transactions = 1;
        self.merkle_hashes =
            vec![MerkleRootMasternodeList::from_raw_hash(self.coinbase_tx.txid().to_raw_hash())];
        self.merkle_flags = vec![1];
        self
    }

    /// The merkle root of a block holding only this diff's coinbase, which the
    /// proof [`Self::with_coinbase_committing_to`] sets up leads to.
    pub fn dummy_block_merkle_root(&self) -> TxMerkleNode {
        TxMerkleNode::from_raw_hash(self.coinbase_tx.txid().to_raw_hash())
    }

    /// `tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin`, the mainnet
    /// diff from genesis to 2227096, with the service addresses restored by
    /// [`Self::restore_core_service_addresses`].
    pub fn mainnet_fixture_0_2227096() -> Self {
        Self::legacy_address_fixture(include_bytes!(
            "../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
    }

    /// `tests/data/test_DML_diffs/mn_list_diff_2227096_2241332.bin`, the
    /// mainnet diff from 2227096 to 2241332, with the service addresses
    /// restored by [`Self::restore_core_service_addresses`].
    pub fn mainnet_fixture_2227096_2241332() -> Self {
        Self::legacy_address_fixture(include_bytes!(
            "../../tests/data/test_DML_diffs/mn_list_diff_2227096_2241332.bin"
        ))
    }

    /// `artifacts/mn_list_diff_testnet_0_1296600.bin`, the testnet diff from
    /// genesis to 1296600, with the service addresses restored by
    /// [`Self::restore_core_service_addresses`].
    pub fn testnet_fixture_0_1296600() -> Self {
        Self::legacy_address_fixture(include_bytes!(
            "../../artifacts/mn_list_diff_testnet_0_1296600.bin"
        ))
    }

    fn legacy_address_fixture(bytes: &[u8]) -> Self {
        let mut diff: MnListDiff = deserialize(bytes).expect("fixture decodes");
        diff.restore_core_service_addresses();
        diff
    }

    /// Rewrites legacy service addresses into the bytes Dash Core sends: an
    /// IPv4 address as IPv4-mapped IPv6 (`::ffff:a.b.c.d`) and an unset one as
    /// all zeros (`::`).
    ///
    /// The `.bin` fixtures were written by an encoder that stored IPv4
    /// addresses as IPv4-compatible IPv6 (`::a.b.c.d`) or an unset address as
    /// `::ffff:0.0.0.0`, and bincode captures made before the decoder kept
    /// `::` apart from `0.0.0.0` hold unset addresses as `0.0.0.0`. The
    /// address is part of the entry hash, so the lists those fixtures build
    /// match `merkleRootMNList` of their coinbase only once this restores
    /// Core's bytes.
    pub fn restore_core_service_addresses(&mut self) {
        for entry in &mut self.new_masternodes {
            let MasternodeNetInfo::Legacy(address) = &mut entry.service_address else {
                continue;
            };
            match *address {
                SocketAddr::V6(v6) => {
                    let octets = v6.ip().octets();
                    if octets[..12] == [0; 12] && octets[12..] != [0; 4] {
                        let ip = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                        *address = SocketAddr::V4(SocketAddrV4::new(ip, v6.port()));
                    }
                }
                SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    *address =
                        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, v4.port(), 0, 0));
                }
                SocketAddr::V4(_) => {}
            }
        }
    }

    /// Reverses every platform node id. Bincode persists the id in canonical
    /// order, but captures made before it did hold Core's wire order, which
    /// the decoder then takes as canonical and the entry hash reverses once
    /// more. The bytes such a capture holds are the wire order.
    pub fn reverse_platform_node_ids(&mut self) {
        for entry in &mut self.new_masternodes {
            if let EntryMasternodeType::HighPerformance {
                platform_node_id,
                ..
            } = &mut entry.mn_type
            {
                *platform_node_id =
                    PlatformNodeId::from_bytes(platform_node_id.to_canonical_bytes());
            }
        }
    }
}

impl MasternodeListEngine {
    /// The mainnet engine of `tests/data/test_DML_diffs/masternode_list_engine.hex`,
    /// 29 lists up to 2243493.
    #[cfg(feature = "bincode")]
    pub fn mainnet_fixture() -> Self {
        let data =
            hex::decode(include_str!("../../tests/data/test_DML_diffs/masternode_list_engine.hex"))
                .unwrap();
        bincode::decode_from_slice(&data, bincode::config::standard()).unwrap().0
    }

    /// A mainnet engine holding an empty list at each of `heights`.
    pub fn dummy_with_lists(heights: &[u32]) -> Self {
        let mut engine = MasternodeListEngine::default_for_network(Network::Mainnet);
        for &height in heights {
            engine.feed_block_height(height, BlockHash::dummy(height));
            engine
                .masternode_lists
                .insert(height, MasternodeList::empty(BlockHash::dummy(height), height));
        }
        engine
    }
}

impl QuorumSnapshot {
    pub fn dummy() -> Self {
        QuorumSnapshot {
            skip_list_mode: MNSkipListMode::NoSkipping,
            active_quorum_members: vec![],
            skip_list: vec![],
        }
    }
}

impl QRInfo {
    /// Built from [`MnListDiff::dummy_empty`], so an engine rejects it. Only
    /// `mn_list_diff_tip` is distinguished, by `[tip_byte; 32]`.
    pub fn dummy(tip_byte: u8) -> Self {
        QRInfo {
            quorum_snapshot_at_h_minus_c: QuorumSnapshot::dummy(),
            quorum_snapshot_at_h_minus_2c: QuorumSnapshot::dummy(),
            quorum_snapshot_at_h_minus_3c: QuorumSnapshot::dummy(),
            mn_list_diff_tip: MnListDiff::dummy_empty(0x00, tip_byte),
            mn_list_diff_h: MnListDiff::dummy_empty(0x00, 0x00),
            mn_list_diff_at_h_minus_c: MnListDiff::dummy_empty(0x00, 0x00),
            mn_list_diff_at_h_minus_2c: MnListDiff::dummy_empty(0x00, 0x00),
            mn_list_diff_at_h_minus_3c: MnListDiff::dummy_empty(0x00, 0x00),
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c: None,
            last_commitment_per_index: vec![],
            quorum_snapshot_list: vec![],
            mn_list_diff_list: vec![],
        }
    }
}
