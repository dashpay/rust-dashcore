use dash_spv::sync::batching::{NetworkConditions, QRInfoBatchingStrategy};
use dash_spv::sync::discovery::{DiscoveryResult, MasternodeDiscoveryService, QRInfoRequest};
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use std::collections::BTreeMap;
use std::str::FromStr;

#[test]
fn test_discovery_result_creation() {
    let mut missing_by_height = BTreeMap::new();
    missing_by_height.insert(
        1000,
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap(),
    );
    missing_by_height.insert(
        2000,
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap(),
    );

    let discovery = DiscoveryResult {
        missing_by_height,
        total_discovered: 2,
        requires_qr_info: true,
    };

    assert_eq!(discovery.total_discovered, 2);
    assert!(discovery.requires_qr_info);
    assert_eq!(discovery.missing_by_height.len(), 2);
}

#[test]
fn test_qr_info_request_planning() {
    let discovery_service = MasternodeDiscoveryService::new();

    // Create discovery result with scattered missing heights
    let mut missing_by_height = BTreeMap::new();
    missing_by_height.insert(
        1000,
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap(),
    );
    missing_by_height.insert(
        1001,
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap(),
    );
    missing_by_height.insert(
        1002,
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap(),
    );
    missing_by_height.insert(
        1100,
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000004")
            .unwrap(),
    );
    missing_by_height.insert(
        1200,
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap(),
    );

    let discovery = DiscoveryResult {
        missing_by_height,
        total_discovered: 5,
        requires_qr_info: true,
    };

    let requests = discovery_service.plan_qr_info_requests(&discovery, 50);

    // Should create multiple requests based on gaps
    assert!(!requests.is_empty());

    // Check that all requests have valid data
    for request in &requests {
        assert!(request.tip_height >= request.base_height);
        assert!(request.extra_share);
        assert!(request.priority > 0);
    }

    // Check priorities (higher for more recent)
    if requests.len() > 1 {
        for window in requests.windows(2) {
            assert!(window[0].priority >= window[1].priority);
        }
    }
}

#[test]
fn test_batching_strategy_optimization() {
    let strategy = QRInfoBatchingStrategy::new();
    let conditions = NetworkConditions {
        high_latency: false,
        low_bandwidth: false,
        unstable_connection: false,
    };

    let requests = vec![
        QRInfoRequest {
            base_height: 1000,
            tip_height: 1100,
            base_hash: BlockHash::all_zeros(),
            tip_hash: BlockHash::all_zeros(),
            extra_share: true,
            priority: 1100,
        },
        QRInfoRequest {
            base_height: 1200,
            tip_height: 1300,
            base_hash: BlockHash::all_zeros(),
            tip_hash: BlockHash::all_zeros(),
            extra_share: true,
            priority: 1300,
        },
    ];

    let optimized = strategy.optimize_requests(requests, &conditions);

    assert!(!optimized.is_empty());

    // Check that batches are valid
    for batch in &optimized {
        assert!(!batch.requests.is_empty());
        assert!(batch.priority > 0);
        assert!(batch.estimated_response_size > 0);
    }
}

#[test]
fn test_batching_with_poor_network() {
    let strategy = QRInfoBatchingStrategy::new();
    let conditions = NetworkConditions {
        high_latency: true,
        low_bandwidth: true,
        unstable_connection: true,
    };

    let mut requests = vec![];
    for i in 0..10 {
        requests.push(QRInfoRequest {
            base_height: i * 100,
            tip_height: (i + 1) * 100,
            base_hash: BlockHash::all_zeros(),
            tip_hash: BlockHash::all_zeros(),
            extra_share: true,
            priority: (i + 1) * 100,
        });
    }

    let optimized = strategy.optimize_requests(requests, &conditions);

    // Should create smaller batches for poor network
    let avg_batch_size: f32 =
        optimized.iter().map(|b| b.requests.len()).sum::<usize>() as f32 / optimized.len() as f32;

    assert!(
        avg_batch_size <= 3.0,
        "Average batch size should be small for poor network conditions"
    );
}
