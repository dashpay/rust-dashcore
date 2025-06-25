# Fix Summary: Segment Boundary Storage Issue

## Problem
The dash-spv client was encountering an error where headers at certain heights couldn't be retrieved, specifically showing:
```
Header offset 41606 is beyond segment size 41000 for height 2291606
```

This occurred because the disk storage system uses segments of 50,000 headers each, but when loading segments from disk, they only contained the actual headers stored (e.g., 41,000) rather than being padded to the full segment size.

## Root Cause
1. Headers are stored in segments of 50,000 (HEADERS_PER_SEGMENT)
2. Height 2291606 maps to segment 45, offset 41606
3. When segment 45 was loaded from disk, it only had 41,000 headers (not the full 50,000)
4. Trying to access offset 41606 in a segment with only 41,000 headers failed

## Solution Implemented

### 1. Enhanced ensure_segment_loaded() in disk.rs
- When loading a segment from disk, now ensure it's padded to the full HEADERS_PER_SEGMENT size
- Use default/placeholder headers for padding to maintain proper indexing
- This ensures all offsets within a segment are valid

### 2. Improved get_header() validation
- Added check to distinguish between real headers and padding headers
- Padding headers (with time=0, nonce=0, prev_blockhash=all_zeros) return None
- This prevents returning invalid data while maintaining proper segment structure

### 3. Updated save_segment_to_disk()
- Only save actual headers to disk, skipping padding headers
- This keeps disk files compact while allowing proper in-memory representation

## Files Modified
- `dash-spv/src/storage/disk.rs` - Fixed segment loading, header retrieval, and saving logic
- `dash-spv/tests/test_cfheader_tip_edge_case.rs` - Added test_segment_boundary_header_access

## Testing
The new test `test_segment_boundary_header_access` specifically tests:
- Access to headers at segment boundaries (49,998-50,002, 99,998-100,002)
- Access to headers in partially-filled segments (like height 141,606)
- Ensures the exact error case (height 2291606) would be handled correctly

## Key Insight
The issue arose from a mismatch between:
- How heights are mapped to segment positions (assumes full 50,000 header segments)
- How segments are actually stored on disk (only contains actual headers)

The fix ensures segments are always properly sized in memory, regardless of how many headers they actually contain.