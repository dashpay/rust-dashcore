use std::net::SocketAddr;

use hashes::Hash;

use crate::bls_sig_utils::BLSPublicKey;
use crate::hash_types::{MerkleRootMasternodeList, ProTxHash};
use crate::network::message_qrinfo::{MNSkipListMode, QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::sml::masternode_list_entry::{
    EntryMasternodeType, MasternodeListEntry, MasternodeNetInfo,
};
use crate::{BlockHash, PubkeyHash, Transaction};

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
    /// [`MasternodeList`](crate::sml::masternode_list::MasternodeList) conversion
    /// accepts. Use this when the diff has to apply to an engine.
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
