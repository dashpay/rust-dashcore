use crate::error::SyncResult;
use crate::storage::FilterHeaderStorage;
use crate::SyncError;
use dashcore::hash_types::FilterHeader;
use dashcore_hashes::Hash;

/// Get previous filter header for verification.
///
/// Returns `FilterHeader::all_zeros()` for height 0, otherwise loads from storage.
pub(super) async fn get_prev_filter_header<S: FilterHeaderStorage>(
    storage: &S,
    height: u32,
) -> SyncResult<FilterHeader> {
    if height == 0 {
        return Ok(FilterHeader::all_zeros());
    }

    storage.get_filter_header(height - 1).await?.ok_or_else(|| {
        SyncError::InvalidState(format!(
            "Missing filter header at height {} for verification",
            height - 1
        ))
    })
}
