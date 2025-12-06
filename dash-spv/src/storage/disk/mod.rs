//! Disk-based storage implementation with segmented files and async background saving.
//!
//! ## Segmented Storage Design
//! Headers are stored in segments of 50,000 headers each. Benefits:
//! - Better I/O patterns (read entire segment vs random access)
//! - Easier corruption recovery (lose max 50K headers, not all)
//! - Simpler index management
//!
//! ## Performance Considerations:
//! - ❌ No compression (filters could compress ~70%)
//! - ❌ No checksums (corruption not detected)
//! - ❌ No write-ahead logging (crash may corrupt)
//! - ✅ Atomic writes via temp files
//! - ✅ Async background saving
//!
//! ## Alternative: Consider embedded DB (RocksDB/Sled) for:
//! - Built-in compression
//! - Crash recovery
//! - Better concurrency
//! - Simpler code

mod filters;
mod headers;
mod manager;
mod segments;
mod state;

pub use manager::DiskStorageManager;

/// Number of headers per segment file
const HEADERS_PER_SEGMENT: u32 = 50_000;

/// Maximum number of segments to keep in memory
const MAX_ACTIVE_SEGMENTS: usize = 10;
