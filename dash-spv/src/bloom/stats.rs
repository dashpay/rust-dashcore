//! Bloom filter performance statistics and monitoring

use std::time::{Duration, Instant};

/// Detailed statistics for bloom filter performance
#[derive(Debug, Clone)]
pub struct DetailedBloomStats {
    /// Basic statistics
    pub basic: BloomFilterStats,
    /// Query performance metrics
    pub query_performance: QueryPerformance,
    /// Filter health metrics
    pub filter_health: FilterHealth,
    /// Network impact metrics
    pub network_impact: NetworkImpact,
}

/// Basic bloom filter statistics
#[derive(Debug, Clone, Default)]
pub struct BloomFilterStats {
    /// Number of items added to the filter
    pub items_added: u64,
    /// Number of positive matches
    pub matches: u64,
    /// Number of queries performed
    pub queries: u64,
    /// Number of times filter was recreated
    pub recreations: u64,
    /// Current estimated false positive rate
    pub current_false_positive_rate: f64,
}

/// Query performance metrics
#[derive(Debug, Clone, Default)]
pub struct QueryPerformance {
    /// Average query time in microseconds
    pub avg_query_time_us: f64,
    /// Maximum query time in microseconds
    pub max_query_time_us: u64,
    /// Minimum query time in microseconds
    pub min_query_time_us: u64,
    /// Total query time in microseconds
    pub total_query_time_us: u64,
}

/// Filter health metrics
#[derive(Debug, Clone, Default)]
pub struct FilterHealth {
    /// Current filter size in bytes
    pub filter_size_bytes: usize,
    /// Number of bits set in the filter
    pub bits_set: usize,
    /// Total bits in the filter
    pub total_bits: usize,
    /// Filter saturation percentage (0-100)
    pub saturation_percent: f64,
    /// Time since last recreation
    pub time_since_recreation: Option<Duration>,
}

/// Network impact metrics
#[derive(Debug, Clone, Default)]
pub struct NetworkImpact {
    /// Number of transactions received due to filter
    pub transactions_received: u64,
    /// Number of false positive transactions
    pub false_positive_transactions: u64,
    /// Estimated bandwidth saved (in bytes)
    pub bandwidth_saved_bytes: u64,
    /// Number of filter update messages sent
    pub filter_updates_sent: u64,
}

/// Tracks bloom filter performance over time
pub struct BloomStatsTracker {
    /// Current statistics
    stats: DetailedBloomStats,
    /// Last filter recreation time
    last_recreation: Option<Instant>,
    /// Query timing accumulator
    query_times: Vec<Duration>,
}

impl BloomStatsTracker {
    /// Create a new stats tracker
    pub fn new() -> Self {
        Self {
            stats: DetailedBloomStats {
                basic: BloomFilterStats::default(),
                query_performance: QueryPerformance::default(),
                filter_health: FilterHealth::default(),
                network_impact: NetworkImpact::default(),
            },
            last_recreation: None,
            query_times: Vec::with_capacity(1000),
        }
    }

    /// Record a query operation
    pub fn record_query(&mut self, duration: Duration, matched: bool) {
        self.stats.basic.queries += 1;
        if matched {
            self.stats.basic.matches += 1;
        }

        // Update query performance
        let micros = duration.as_micros() as u64;
        self.stats.query_performance.total_query_time_us += micros;
        
        if self.stats.query_performance.min_query_time_us == 0 
            || micros < self.stats.query_performance.min_query_time_us {
            self.stats.query_performance.min_query_time_us = micros;
        }
        
        if micros > self.stats.query_performance.max_query_time_us {
            self.stats.query_performance.max_query_time_us = micros;
        }

        // Keep last 1000 query times for moving average
        if self.query_times.len() >= 1000 {
            self.query_times.remove(0);
        }
        self.query_times.push(duration);
        
        // Update average
        let total_micros: u64 = self.query_times.iter()
            .map(|d| d.as_micros() as u64)
            .sum();
        self.stats.query_performance.avg_query_time_us = 
            total_micros as f64 / self.query_times.len() as f64;
    }

    /// Record an item addition
    pub fn record_addition(&mut self) {
        self.stats.basic.items_added += 1;
    }

    /// Record a filter recreation
    pub fn record_recreation(&mut self, filter_size: usize, bits_set: usize, total_bits: usize) {
        self.stats.basic.recreations += 1;
        self.last_recreation = Some(Instant::now());
        
        // Update filter health
        self.stats.filter_health.filter_size_bytes = filter_size;
        self.stats.filter_health.bits_set = bits_set;
        self.stats.filter_health.total_bits = total_bits;
        self.stats.filter_health.saturation_percent = 
            (bits_set as f64 / total_bits as f64) * 100.0;
    }

    /// Record a transaction received
    pub fn record_transaction(&mut self, is_false_positive: bool, tx_size: usize) {
        self.stats.network_impact.transactions_received += 1;
        if is_false_positive {
            self.stats.network_impact.false_positive_transactions += 1;
        } else {
            // Estimate bandwidth saved by not downloading unrelated transactions
            // Assume average transaction size if this was a true positive
            self.stats.network_impact.bandwidth_saved_bytes += (tx_size * 10) as u64; // Rough estimate
        }
    }

    /// Record a filter update sent
    pub fn record_filter_update(&mut self) {
        self.stats.network_impact.filter_updates_sent += 1;
    }

    /// Update false positive rate estimate
    pub fn update_false_positive_rate(&mut self, rate: f64) {
        self.stats.basic.current_false_positive_rate = rate;
    }

    /// Get current statistics
    pub fn get_stats(&mut self) -> DetailedBloomStats {
        // Update time since recreation
        if let Some(last) = self.last_recreation {
            self.stats.filter_health.time_since_recreation = Some(last.elapsed());
        }
        
        self.stats.clone()
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get a summary report
    pub fn summary_report(&self) -> String {
        let stats = &self.stats;
        format!(
            "Bloom Filter Statistics:\n\
             Items Added: {}\n\
             Queries: {} (Matches: {}, Rate: {:.2}%)\n\
             Current FP Rate: {:.4}%\n\
             Filter Recreations: {}\n\
             \n\
             Query Performance:\n\
             Avg: {:.2}μs, Min: {}μs, Max: {}μs\n\
             \n\
             Filter Health:\n\
             Size: {} bytes, Saturation: {:.1}%\n\
             \n\
             Network Impact:\n\
             Transactions: {} (FP: {}, Rate: {:.2}%)\n\
             Bandwidth Saved: ~{:.2} MB\n\
             Filter Updates: {}",
            stats.basic.items_added,
            stats.basic.queries,
            stats.basic.matches,
            if stats.basic.queries > 0 {
                (stats.basic.matches as f64 / stats.basic.queries as f64) * 100.0
            } else {
                0.0
            },
            stats.basic.current_false_positive_rate * 100.0,
            stats.basic.recreations,
            stats.query_performance.avg_query_time_us,
            stats.query_performance.min_query_time_us,
            stats.query_performance.max_query_time_us,
            stats.filter_health.filter_size_bytes,
            stats.filter_health.saturation_percent,
            stats.network_impact.transactions_received,
            stats.network_impact.false_positive_transactions,
            if stats.network_impact.transactions_received > 0 {
                (stats.network_impact.false_positive_transactions as f64 
                    / stats.network_impact.transactions_received as f64) * 100.0
            } else {
                0.0
            },
            stats.network_impact.bandwidth_saved_bytes as f64 / 1_048_576.0,
            stats.network_impact.filter_updates_sent
        )
    }
}

impl Default for BloomStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}