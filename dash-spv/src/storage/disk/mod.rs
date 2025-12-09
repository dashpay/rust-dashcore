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
