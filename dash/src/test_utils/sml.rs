use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use hashes::Hash;

use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
use crate::consensus::deserialize;
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums, ProTxHash};
use crate::network::message::{NetworkMessage, RawNetworkMessage};
use crate::network::message_qrinfo::{MNSkipListMode, QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::{
    EntryMasternodeType, MasternodeListEntry, MasternodeNetInfo,
};
use crate::transaction::special_transaction::TransactionPayload;
use crate::transaction::special_transaction::coinbase::CoinbasePayload;
use crate::{
    BlockHash, OutPoint, PlatformNodeId, PubkeyHash, ScriptBuf, Transaction, TxIn, TxMerkleNode,
    Witness,
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
    /// apply to an engine, with [`Self::committing_on`] for the list and
    /// height it builds.
    pub fn dummy(base_byte: u8, tip_byte: u8) -> Self {
        MnListDiff {
            total_transactions: 1,
            merkle_hashes: vec![MerkleRootMasternodeList::from([tip_byte; 32])],
            merkle_flags: vec![1],
            new_masternodes: vec![MasternodeListEntry::dummy(tip_byte)],
            ..MnListDiff::dummy_empty(base_byte, tip_byte)
        }
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
    /// whose coinbase commits to an empty list at height `tip`. An engine
    /// holding an empty list at `base` applies it; on any other list it needs
    /// [`Self::committing_on`].
    pub fn dummy_between(base: u32, tip: u32) -> Self {
        MnListDiff {
            base_block_hash: BlockHash::dummy(base),
            block_hash: BlockHash::dummy(tip),
            ..MnListDiff::dummy_empty(0x00, 0x00)
        }
        .committing_on(None, tip)
    }

    /// Replaces the coinbase with one whose payload commits, at `height`, to
    /// the list this diff builds on `base` (or from nothing), and the merkle
    /// proof with that of a block holding only this coinbase. The list is
    /// computed by applying the diff's changes without any check.
    pub fn committing_on(self, base: Option<&MasternodeList>, height: CoreBlockHeight) -> Self {
        let mut masternodes = base.map(|list| (*list.masternodes).clone()).unwrap_or_default();
        for pro_tx_hash in &self.deleted_masternodes {
            masternodes.remove(&pro_tx_hash.reverse());
        }
        for entry in &self.new_masternodes {
            masternodes.insert(entry.pro_reg_tx_hash.reverse(), Arc::new(entry.clone().into()));
        }
        let mut quorums = base.map(|list| (*list.quorums).clone()).unwrap_or_default();
        for deleted in &self.deleted_quorums {
            if let Some(of_type) = quorums.get_mut(&deleted.llmq_type) {
                of_type.remove(&deleted.quorum_hash);
                if of_type.is_empty() {
                    quorums.remove(&deleted.llmq_type);
                }
            }
        }
        for quorum in &self.new_quorums {
            quorums
                .entry(quorum.llmq_type)
                .or_default()
                .insert(quorum.quorum_hash, Arc::new(quorum.clone().into()));
        }
        let list = MasternodeList::build(masternodes, quorums, self.block_hash, height).build();
        self.with_coinbase_committing_to(
            height,
            list.masternode_merkle_root.unwrap_or_else(MerkleRootMasternodeList::all_zeros),
            list.llmq_merkle_root.unwrap_or_else(MerkleRootQuorums::all_zeros),
        )
    }

    /// Replaces the coinbase with one whose payload commits to `height` and
    /// the two roots, and the merkle proof with that of a block holding only
    /// this coinbase.
    fn with_coinbase_committing_to(
        mut self,
        height: CoreBlockHeight,
        merkle_root_masternode_list: MerkleRootMasternodeList,
        merkle_root_quorums: MerkleRootQuorums,
    ) -> Self {
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
                    height,
                    merkle_root_masternode_list,
                    merkle_root_quorums,
                    Some(0),
                    Some(BLSSignature::from([0; 96])),
                    Some(0),
                ),
            )),
        };
        self.prove_as_the_only_transaction()
    }

    /// Sets the height the coinbase payload commits to, for a test that
    /// applies the diff at another height than its block's. The merkle proof
    /// no longer holds.
    pub fn with_coinbase_height(mut self, height: CoreBlockHeight) -> Self {
        match &mut self.coinbase_tx.special_transaction_payload {
            Some(TransactionPayload::CoinbasePayloadType(payload)) => payload.height = height,
            _ => panic!("the coinbase carries no coinbase payload"),
        }
        self
    }

    /// Makes the merkle proof that of a block holding only the coinbase.
    fn prove_as_the_only_transaction(mut self) -> Self {
        self.total_transactions = 1;
        self.merkle_hashes =
            vec![MerkleRootMasternodeList::from_raw_hash(self.coinbase_tx.txid().to_raw_hash())];
        self.merkle_flags = vec![1];
        self
    }

    /// The merkle root the diff's own proof leads to: the merkle root of its
    /// block, if the proof holds.
    pub fn proven_merkle_root(&self) -> TxMerkleNode {
        self.coinbase_proof_tree()
            .extract_matches(&mut vec![], &mut vec![])
            .expect("a well-formed proof")
    }

    /// `tests/data/test_DML_diffs/DML_0_2221605.hex`, the mainnet `mnlistdiff`
    /// message from genesis to 2221605 as a peer sent it.
    pub fn mainnet_fixture_0_2221605() -> Self {
        let hex = include_str!("../../tests/data/test_DML_diffs/DML_0_2221605.hex");
        let message: RawNetworkMessage =
            deserialize(&hex_conservative::decode_to_vec(hex.trim()).expect("hex"))
                .expect("fixture decodes");
        let NetworkMessage::MnListDiff(diff) = message.payload else {
            panic!("expected an mnlistdiff message");
        };
        *diff
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
    /// Some `.bin` fixtures were written by an encoder that stored IPv4
    /// addresses as IPv4-compatible IPv6 (`::a.b.c.d`) or an unset address as
    /// `::ffff:0.0.0.0`, and older bincode captures hold unset addresses as
    /// `0.0.0.0`. The address is part of the entry hash, so the lists those
    /// fixtures build match `merkleRootMNList` of their coinbase only once
    /// this restores Core's bytes.
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

    /// Reverses every platform node id. Older bincode captures hold the id in
    /// Core's wire order, which the decoder takes as canonical and the entry
    /// hash reverses once more.
    pub fn reverse_platform_node_ids(&mut self) {
        for entry in &mut self.new_masternodes {
            if let EntryMasternodeType::HighPerformance {
                platform_node_id,
                ..
            } = &mut entry.mn_type
            {
                let mut bytes = platform_node_id.to_byte_array();
                bytes.reverse();
                *platform_node_id = PlatformNodeId::from_byte_array(bytes);
            }
        }
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
