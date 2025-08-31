# FFI Documentation Guide

## Overview

The `FFI_API.md` file contains comprehensive documentation for all FFI functions in the dash-spv-ffi library. This documentation is automatically generated from the source code to ensure it stays up-to-date.

## Keeping Documentation Updated

### Automatic Verification

A GitHub Action automatically verifies that the FFI documentation is up-to-date on every push and pull request. If the documentation is out of sync, the CI will fail and provide instructions on how to update it.

### Manual Updates

To update the FFI documentation after making changes to FFI functions:

```bash
# Using Make
make update-docs

# Or directly with Python
cd dash-spv-ffi
python3 scripts/generate_ffi_docs.py
```

### Checking Documentation

To verify the documentation is current without updating:

```bash
# Using Make
make check-docs

# Or directly with the script
bash scripts/check_ffi_docs.sh
```

## Documentation Structure

The `FFI_API.md` file includes:

1. **Table of Contents** - Quick navigation to different sections
2. **Function Reference** - Categorized list of all functions
3. **Detailed Documentation** - Full signatures and descriptions
4. **Type Definitions** - Core FFI types used
5. **Memory Management** - Important rules for FFI usage
6. **Usage Examples** - Sample code for common operations

## Categories

Functions are automatically categorized into:

- Client Management
- Configuration
- Synchronization
- Wallet Operations
- Address Monitoring
- Transaction Management
- Balance & UTXOs
- Mempool Operations
- Platform Integration
- Event Callbacks
- Error Handling
- Utility Functions

## Adding New FFI Functions

When adding new FFI functions:

1. Add the function with `#[no_mangle]` and `extern "C"` attributes
2. Include doc comments with `///`
3. Add safety documentation if the function is `unsafe`
4. Run `make update-docs` to regenerate documentation
5. Commit both the code changes and updated `FFI_API.md`

## Example FFI Function

```rust
/// Sync the SPV client to the chain tip
///
/// # Safety
///
/// - `client` must be a valid pointer to an FFIDashSpvClient
/// - `on_progress` callback may be invoked from any thread
/// - `on_completion` will be called exactly once
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_sync_to_tip(
    client: *mut FFIDashSpvClient,
    on_progress: Option<SyncProgressCallback>,
    on_completion: Option<CompletionCallback>,
) -> i32 {
    // Implementation
}
```

## CI/CD Integration

The documentation verification is integrated into the CI pipeline:

1. **On Push/PR**: Verifies documentation is up-to-date
2. **On Failure**: Comments on PR with update instructions
3. **Required Check**: Must pass before merging

## Tools

- `scripts/generate_ffi_docs.py` - Python script that parses Rust files and generates documentation
- `scripts/check_ffi_docs.sh` - Bash script to verify documentation is current
- `.github/workflows/verify-ffi-docs.yml` - GitHub Action for CI verification
- `Makefile` - Convenient commands for documentation tasks