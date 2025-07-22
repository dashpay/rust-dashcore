//! Advanced batching strategies for QRInfo requests.
//!
//! This module provides intelligent batching and optimization of QRInfo
//! requests based on network conditions. It helps minimize network overhead
//! while maximizing sync efficiency.

use crate::sync::discovery::QRInfoRequest;
use std::time::Duration;
use tracing;

/// Advanced batching strategies for QRInfo requests
#[derive(Debug)]
pub struct QRInfoBatchingStrategy {
    /// Expected network latency
    network_latency: Duration,
    /// Optional bandwidth limit in bytes per second
    bandwidth_limit: Option<u32>,
    /// Maximum concurrent requests allowed
    max_concurrent_requests: usize,
}

impl QRInfoBatchingStrategy {
    /// Create a new batching strategy with default settings.
    pub fn new() -> Self {
        Self {
            network_latency: Duration::from_millis(100), // Conservative default
            bandwidth_limit: None,
            max_concurrent_requests: 3, // Conservative for SPV
        }
    }
    
    /// Create a batching strategy with custom settings.
    pub fn with_settings(
        network_latency: Duration,
        bandwidth_limit: Option<u32>,
        max_concurrent_requests: usize,
    ) -> Self {
        Self {
            network_latency,
            bandwidth_limit,
            max_concurrent_requests,
        }
    }
    
    /// Optimize QRInfo requests based on network conditions.
    ///
    /// This method:
    /// - Groups requests into efficient batches
    /// - Considers network latency and bandwidth
    /// - Prioritizes important requests
    /// - Determines which batches can run in parallel
    pub fn optimize_requests(
        &self,
        requests: Vec<QRInfoRequest>,
        network_conditions: &NetworkConditions,
    ) -> Vec<OptimizedQRInfoBatch> {
        let mut optimized = Vec::new();
        
        // Adjust strategy based on network conditions
        let effective_latency = if network_conditions.high_latency {
            self.network_latency * 2
        } else {
            self.network_latency
        };
        
        let batch_size = if network_conditions.low_bandwidth {
            2 // Smaller batches for slow connections
        } else {
            5 // Larger batches for fast connections
        };
        
        // Group requests into batches
        for chunk in requests.chunks(batch_size) {
            let batch = OptimizedQRInfoBatch {
                requests: chunk.to_vec(),
                priority: chunk.iter().map(|r| r.priority).max().unwrap_or(0),
                estimated_response_size: self.estimate_response_size(chunk),
                can_execute_parallel: chunk.len() <= self.max_concurrent_requests,
                estimated_latency: effective_latency,
            };
            
            optimized.push(batch);
        }
        
        // Sort batches by priority and network efficiency
        optimized.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| a.estimated_response_size.cmp(&b.estimated_response_size))
        });
        
        tracing::debug!(
            "Optimized {} requests into {} batches (conditions: high_latency={}, low_bandwidth={})",
            requests.len(),
            optimized.len(),
            network_conditions.high_latency,
            network_conditions.low_bandwidth
        );
        
        optimized
    }
    
    /// Estimate the response size for a batch of QRInfo requests.
    ///
    /// This helps in:
    /// - Bandwidth planning
    /// - Timeout calculation
    /// - Batch size optimization
    fn estimate_response_size(&self, requests: &[QRInfoRequest]) -> usize {
        // Rough estimation based on typical QRInfo content
        const BASE_SIZE: usize = 1024; // Base QRInfo overhead
        const PER_DIFF_SIZE: usize = 2048; // Average MnListDiff size  
        const PER_SNAPSHOT_SIZE: usize = 512; // Average QuorumSnapshot size
        
        requests.iter().map(|req| {
            let height_span = req.tip_height - req.base_height + 1;
            let estimated_diffs = height_span / 8; // Diffs every ~8 blocks typically
            let estimated_snapshots = 4; // h-c, h-2c, h-3c, h-4c
            
            BASE_SIZE + 
            (estimated_diffs * PER_DIFF_SIZE as u32) as usize +
            (estimated_snapshots * PER_SNAPSHOT_SIZE)
        }).sum()
    }
    
    /// Calculate optimal timeout for a batch based on estimated size and network conditions.
    pub fn calculate_timeout(&self, batch: &OptimizedQRInfoBatch) -> Duration {
        // Base timeout on estimated size and latency
        let size_factor = (batch.estimated_response_size as f64 / 1024.0).max(1.0);
        let base_timeout = Duration::from_secs(5); // 5 seconds base
        
        // Adjust for network latency
        let latency_factor = batch.estimated_latency.as_secs_f64() / 0.1; // Normalized to 100ms
        
        // Calculate final timeout
        let timeout_secs = base_timeout.as_secs_f64() * size_factor * latency_factor.max(1.0);
        Duration::from_secs_f64(timeout_secs.min(30.0)) // Cap at 30 seconds
    }
    
    /// Determine if we should use fallback (MnListDiff) for a failed batch.
    pub fn should_use_fallback(&self, batch: &OptimizedQRInfoBatch, failure_count: u32) -> bool {
        // Use fallback if:
        // - Large batch failed multiple times
        // - High priority batch failed
        // - Estimated size is very large
        failure_count > 2 || 
        batch.priority > 1000 ||
        batch.estimated_response_size > 100_000
    }
}

impl Default for QRInfoBatchingStrategy {
    fn default() -> Self {
        Self::new()
    }
}

/// An optimized batch of QRInfo requests
#[derive(Debug)]
pub struct OptimizedQRInfoBatch {
    /// The requests in this batch
    pub requests: Vec<QRInfoRequest>,
    /// Overall priority of the batch
    pub priority: u32,
    /// Estimated total response size in bytes
    pub estimated_response_size: usize,
    /// Whether this batch can be executed in parallel with others
    pub can_execute_parallel: bool,
    /// Estimated network latency for this batch
    pub estimated_latency: Duration,
}

/// Current network conditions
#[derive(Debug, Default)]
pub struct NetworkConditions {
    /// Whether the network has high latency
    pub high_latency: bool,
    /// Whether the network has low bandwidth
    pub low_bandwidth: bool,
    /// Whether the connection is unstable
    pub unstable_connection: bool,
}

impl NetworkConditions {
    /// Create network conditions for a good connection.
    pub fn good() -> Self {
        Self {
            high_latency: false,
            low_bandwidth: false,
            unstable_connection: false,
        }
    }
    
    /// Create network conditions for a poor connection.
    pub fn poor() -> Self {
        Self {
            high_latency: true,
            low_bandwidth: true,
            unstable_connection: true,
        }
    }
    
    /// Detect network conditions from recent request history.
    pub fn detect_from_history(
        recent_latencies: &[Duration],
        recent_failures: u32,
        total_requests: u32,
    ) -> Self {
        let avg_latency = if !recent_latencies.is_empty() {
            recent_latencies.iter().sum::<Duration>() / recent_latencies.len() as u32
        } else {
            Duration::from_millis(100)
        };
        
        let failure_rate = if total_requests > 0 {
            recent_failures as f64 / total_requests as f64
        } else {
            0.0
        };
        
        Self {
            high_latency: avg_latency > Duration::from_millis(500),
            low_bandwidth: avg_latency > Duration::from_secs(1),
            unstable_connection: failure_rate > 0.1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::BlockHash;
    
    fn create_test_qr_info_request(height: u32) -> QRInfoRequest {
        QRInfoRequest {
            base_height: height,
            tip_height: height + 100,
            base_hash: BlockHash::all_zeros(),
            tip_hash: BlockHash::all_zeros(),
            extra_share: true,
            priority: height,
        }
    }
    
    fn create_test_qr_info_requests(count: usize) -> Vec<QRInfoRequest> {
        (0..count)
            .map(|i| create_test_qr_info_request((i * 100) as u32))
            .collect()
    }
    
    #[test]
    fn test_batching_optimization() {
        let strategy = QRInfoBatchingStrategy::new();
        let conditions = NetworkConditions::good();
        
        let requests = create_test_qr_info_requests(10);
        let optimized = strategy.optimize_requests(requests, &conditions);
        
        // Should create efficient batches
        assert!(!optimized.is_empty());
        assert!(optimized.len() <= 5); // Should batch multiple requests together
        
        // Higher priority batches should come first
        let priorities: Vec<u32> = optimized.iter().map(|b| b.priority).collect();
        assert!(priorities.windows(2).all(|w| w[0] >= w[1]));
    }
    
    #[test]
    fn test_batching_with_poor_network() {
        let strategy = QRInfoBatchingStrategy::new();
        let conditions = NetworkConditions::poor();
        
        let requests = create_test_qr_info_requests(10);
        let optimized = strategy.optimize_requests(requests, &conditions);
        
        // Should create smaller, more conservative batches
        let avg_batch_size: f32 = optimized.iter()
            .map(|b| b.requests.len())
            .sum::<usize>() as f32 / optimized.len() as f32;
        
        assert!(avg_batch_size <= 3.0); // Smaller batches for poor network
    }
    
    #[test]
    fn test_timeout_calculation() {
        let strategy = QRInfoBatchingStrategy::new();
        let batch = OptimizedQRInfoBatch {
            requests: create_test_qr_info_requests(5),
            priority: 100,
            estimated_response_size: 50_000,
            can_execute_parallel: true,
            estimated_latency: Duration::from_millis(200),
        };
        
        let timeout = strategy.calculate_timeout(&batch);
        
        // Should be reasonable
        assert!(timeout >= Duration::from_secs(5));
        assert!(timeout <= Duration::from_secs(30));
    }
    
    #[test]
    fn test_network_condition_detection() {
        let recent_latencies = vec![
            Duration::from_millis(600),
            Duration::from_millis(700),
            Duration::from_millis(800),
        ];
        
        let conditions = NetworkConditions::detect_from_history(&recent_latencies, 5, 50);
        
        assert!(conditions.high_latency);
        assert!(!conditions.low_bandwidth); // Not quite that bad
        assert!(conditions.unstable_connection); // 10% failure rate
    }
}