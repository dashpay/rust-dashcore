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
pub(crate) mod io;
mod lockfile;
mod manager;
mod segments;
mod state;

pub use manager::DiskStorageManager;

// Filter data constants

/// Filter data segment magic bytes: "FDSF" (Filter Data Segment Format)
const FILTER_DATA_SEGMENT_MAGIC: [u8; 4] = [0x46, 0x44, 0x53, 0x46];
/// Filter data segment format version
const FILTER_DATA_SEGMENT_VERSION: u16 = 1;
/// Filter data segment header size: magic (4) + version (2) + count (2) + data_offset (4)
const FILTER_DATA_HEADER_SIZE: u32 = 12;
/// Filter data index entry size: offset (8) + length (4)
const FILTER_DATA_INDEX_ENTRY_SIZE: u32 = 12;
/// Number of filters per segment file
pub const FILTERS_PER_SEGMENT: u32 = 50_000;
/// Maximum number of filter data segments to keep in memory
const MAX_ACTIVE_FILTER_DATA_SEGMENTS: usize = 5;
