# Detailed Removal Plan for masternodes.rs

## Overview
The file is too large (2000+ lines) to edit effectively with automated tools. Manual removal is recommended.

## Methods to Remove (with line numbers):

### 1. Terminal Block Methods
- `validate_terminal_block()` - Lines 105-149
- `validate_terminal_block_with_base()` - Lines 154-214
- `load_terminal_block_data()` - Line 744+ (find exact range)
- `get_next_terminal_block()` - Lines 1804-1817
- `terminal_block_manager()` getter - Lines 1799-1801

### 2. Sequential Sync Methods
- `start_sync_with_height()` - Line 536+ (large method)
- `request_masternode_diffs_smart()` - Line 1418+ (large method)
- `request_masternode_diffs_for_chainlock_validation_with_base()` - Lines 1091+

### 3. References to Remove
- All `self.terminal_block_manager` references throughout the file
- All terminal block validation checks
- DKG window calculations

### 4. Struct Fields to Remove
- Find and remove `terminal_block_manager` field from struct definition
- Already removed: `expected_diffs_count`, `received_diffs_count`

### 5. Imports to Clean
- Remove unused imports after method removal
- Remove `DKGWindow` (already done)
- Remove terminal block related imports

## Recommendation
Due to file size and complexity, manual editing in an IDE is recommended:
1. Back up the file (already done)
2. Use IDE's "Find Usages" to identify all references
3. Remove methods and their usages systematically
4. Run `cargo check` frequently to catch issues
5. Clean up imports last

## Alternative Approach
Create a new file `masternodes_cleaned.rs` with only the methods we want to keep:
- `request_masternode_diff()`
- `handle_mnlistdiff_message()`
- `process_masternode_diff()`
- Basic sync management methods
- Engine access methods