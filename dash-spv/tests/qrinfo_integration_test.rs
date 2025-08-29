//! Integration tests for QRInfo message handling

use dash_spv::client::ClientConfig;
use dashcore::{
    bls_sig_utils::{BLSPublicKey, BLSSignature},
    hash_types::QuorumVVecHash,
    network::message_qrinfo::{GetQRInfo, MNSkipListMode, QRInfo, QuorumSnapshot},
    network::message_sml::MnListDiff,
    sml::llmq_type::LLMQType,
    transaction::special_transaction::quorum_commitment::QuorumEntry,
    BlockHash, Network, QuorumHash, Transaction,
};
use dashcore_hashes::Hash;
use std::time::Duration;

/// Helper to generate test QRInfo data
fn create_test_qr_info(_base_height: u32, tip_height: u32) -> QRInfo {
    let cycle_length = 24u32; // Test network cycle length

    // Create test quorum snapshots
    let create_snapshot = |_height: u32| -> QuorumSnapshot {
        QuorumSnapshot {
            skip_list_mode: MNSkipListMode::NoSkipping,
            active_quorum_members: vec![true, false, true], // Small test set
            skip_list: vec![],
        }
    };

    // Create test MnListDiff
    let create_diff = |base: u32, tip: u32| -> MnListDiff {
        MnListDiff {
            version: 1,
            base_block_hash: BlockHash::from_slice(&[base as u8; 32]).unwrap(),
            block_hash: BlockHash::from_slice(&[tip as u8; 32]).unwrap(),
            total_transactions: 100,
            merkle_hashes: vec![],
            merkle_flags: vec![],
            coinbase_tx: Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            deleted_masternodes: vec![],
            new_masternodes: vec![],
            deleted_quorums: vec![],
            new_quorums: vec![],
            quorums_chainlock_signatures: vec![],
        }
    };

    // Create test quorum entries
    let create_quorum_entry = |index: u32| -> QuorumEntry {
        QuorumEntry {
            version: 1,
            llmq_type: LLMQType::Llmqtype50_60,
            quorum_hash: QuorumHash::from_slice(&[index as u8; 32]).unwrap(),
            quorum_index: Some(index as i16),
            signers: vec![true, false, true],
            valid_members: vec![true, false, true],
            quorum_public_key: BLSPublicKey::from([0u8; 48]),
            quorum_vvec_hash: QuorumVVecHash::from_slice(&[0u8; 32]).unwrap(),
            threshold_sig: BLSSignature::from([0u8; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([0u8; 96]),
        }
    };

    QRInfo {
        quorum_snapshot_at_h_minus_c: create_snapshot(tip_height - cycle_length),
        quorum_snapshot_at_h_minus_2c: create_snapshot(tip_height - 2 * cycle_length),
        quorum_snapshot_at_h_minus_3c: create_snapshot(tip_height - 3 * cycle_length),

        mn_list_diff_tip: create_diff(tip_height - 1, tip_height),
        mn_list_diff_h: create_diff(tip_height - 8, tip_height),
        mn_list_diff_at_h_minus_c: create_diff(
            tip_height - cycle_length - 8,
            tip_height - cycle_length,
        ),
        mn_list_diff_at_h_minus_2c: create_diff(
            tip_height - 2 * cycle_length - 8,
            tip_height - 2 * cycle_length,
        ),
        mn_list_diff_at_h_minus_3c: create_diff(
            tip_height - 3 * cycle_length - 8,
            tip_height - 3 * cycle_length,
        ),

        quorum_snapshot_and_mn_list_diff_at_h_minus_4c: Some((
            create_snapshot(tip_height - 4 * cycle_length),
            create_diff(tip_height - 4 * cycle_length - 8, tip_height - 4 * cycle_length),
        )),

        last_commitment_per_index: vec![
            create_quorum_entry(0),
            create_quorum_entry(1),
            create_quorum_entry(2),
            create_quorum_entry(3),
        ],

        quorum_snapshot_list: vec![],
        mn_list_diff_list: vec![],
    }
}

#[tokio::test]
async fn test_qrinfo_message_creation() {
    // Test that QRInfo messages can be created
    let qr_info = create_test_qr_info(1000, 2000);

    // Verify basic structure
    assert_eq!(qr_info.last_commitment_per_index.len(), 4);
    assert!(qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some());

    // Verify quorum snapshots have expected properties
    assert_eq!(qr_info.quorum_snapshot_at_h_minus_c.skip_list_mode, MNSkipListMode::NoSkipping);
    assert_eq!(qr_info.quorum_snapshot_at_h_minus_c.active_quorum_members.len(), 3);
}

#[tokio::test]
#[ignore]
async fn test_qrinfo_config_defaults() {
    // Test default configuration values
    let config = ClientConfig::default();

    // QR info extra share is disabled by default
    assert!(!config.qr_info_extra_share);
    assert_eq!(config.qr_info_timeout, Duration::from_secs(30));
}

#[tokio::test]
async fn test_qrinfo_config_builders() {
    // Test configuration builder methods
    let config = ClientConfig::new(Network::Testnet)
        .with_qr_info_extra_share(false)
        .with_qr_info_timeout(Duration::from_secs(60));

    assert!(!config.qr_info_extra_share);
    assert_eq!(config.qr_info_timeout, Duration::from_secs(60));
}

#[tokio::test]
async fn test_get_qrinfo_message_creation() {
    // Test GetQRInfo message creation
    let base_hashes = vec![
        BlockHash::from_slice(&[1u8; 32]).unwrap(),
        BlockHash::from_slice(&[2u8; 32]).unwrap(),
    ];
    let request_hash = BlockHash::from_slice(&[3u8; 32]).unwrap();

    let get_qr_info = GetQRInfo {
        base_block_hashes: base_hashes.clone(),
        block_request_hash: request_hash,
        extra_share: true,
    };

    assert_eq!(get_qr_info.base_block_hashes.len(), 2);
    assert_eq!(get_qr_info.block_request_hash, request_hash);
    assert!(get_qr_info.extra_share);

    // Test serialization
    use dashcore::consensus::{deserialize, serialize};
    let serialized = serialize(&get_qr_info);
    let deserialized: GetQRInfo = deserialize(&serialized).expect("Should deserialize");

    assert_eq!(get_qr_info.base_block_hashes, deserialized.base_block_hashes);
    assert_eq!(get_qr_info.extra_share, deserialized.extra_share);
}

#[test]
fn test_quorum_snapshot_skip_list_modes() {
    // Test different skip list modes
    let modes = vec![
        MNSkipListMode::NoSkipping,
        MNSkipListMode::SkipFirst,
        MNSkipListMode::SkipExcept,
        MNSkipListMode::SkipAll,
    ];

    for mode in modes {
        let snapshot = QuorumSnapshot {
            skip_list_mode: mode,
            active_quorum_members: vec![true, false, true],
            skip_list: vec![1, 2, 3],
        };

        // Test that mode is preserved
        assert_eq!(snapshot.skip_list_mode, mode);
    }
}
