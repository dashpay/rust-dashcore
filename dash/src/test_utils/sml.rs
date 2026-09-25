use hashes::Hash;

use crate::network::message_qrinfo::{MNSkipListMode, QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::{BlockHash, Transaction};

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
