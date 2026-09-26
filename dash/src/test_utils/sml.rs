use hashes::Hash;

use crate::network::message_qrinfo::{MNSkipListMode, QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::{BlockHash, Network, Transaction};

fn dummy_hash(byte: u8) -> BlockHash {
    BlockHash::from_slice(&[byte; 32]).unwrap()
}

impl MnListDiff {
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
    /// which an engine holding the list at `base` applies.
    pub fn dummy_between(base: u32, tip: u32) -> Self {
        MnListDiff {
            base_block_hash: BlockHash::dummy(base),
            block_hash: BlockHash::dummy(tip),
            total_transactions: 1,
            coinbase_tx: Transaction {
                version: 3,
                ..Transaction::dummy_empty()
            },
            ..MnListDiff::dummy_empty(0x00, 0x00)
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
