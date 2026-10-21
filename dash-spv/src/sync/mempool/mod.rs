mod filter;
mod manager;
mod progress;
mod sync_manager;

pub(crate) use manager::MempoolManager;
pub use progress::MempoolProgress;

/// Bloom filter false positive rate for BIP37 mempool filtering.
// TODO: probably expose via config, e.g. as a privacy level enum (low/medium/high) instead of a raw f64
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.0005;
