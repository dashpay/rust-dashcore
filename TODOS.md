# TODOs for Rust Dashcore Key Wallet System

## Critical Issues (Prevent Compilation)

### dashcore crate compilation errors
The underlying `dashcore` crate has pre-existing compilation errors that prevent `key-wallet-manager` from building:

1. **Missing imports in crypto/sighash.rs**: Two unresolved imports are causing E0432 errors
2. **65 warnings in dashcore**: Various deprecated method usage and unused variables

**Impact**: key-wallet-manager cannot compile until dashcore is fixed.
**Priority**: Critical - blocks all high-level wallet functionality.

## Remaining Features (Optional)

### Serialization support
The last pending feature from the original plan:

1. **Create wallet serialization**: Add serde support for saving/loading wallets from disk
2. **Encrypted wallet storage**: Add password protection for saved wallets
3. **Backup and restore**: Implement mnemonic and xprv/xpub backup functionality

**Impact**: Wallets cannot be persisted between application runs.
**Priority**: Medium - useful for production applications.

### Testing improvements
1. **Multi-language mnemonic tests**: Currently marked as `#[ignore]` - need actual multi-language support
2. **Integration tests**: More comprehensive testing of key-wallet + key-wallet-manager integration
3. **Transaction building tests**: Test actual transaction creation and signing

## Known Limitations

### Watch-only wallet derivation
The current watch-only wallet implementation creates its own derivation paths rather than using the exact same addresses as the original wallet. This is due to the separation between account-level xpubs and the AddressPool API requirements.

### dashcore dependency issues
The architecture assumes dashcore will eventually compile. If dashcore continues to have issues, key-wallet-manager may need to:
1. Use a different transaction library
2. Implement transaction types internally
3. Wait for dashcore fixes

## Status Summary

✅ **Completed Successfully:**
- Restructured crate architecture (key-wallet + key-wallet-manager)
- Fixed all key-wallet compilation issues
- Added comprehensive tests for mnemonics and address management
- Created watch-only wallet functionality
- Enhanced derivation module with builder pattern
- Separated low-level primitives from high-level operations

❌ **Blocked by External Issues:**
- key-wallet-manager compilation (blocked by dashcore)
- Transaction building functionality (blocked by dashcore)
- Integration tests (blocked by dashcore)

✅ **Architecture Goals Met:**
- Clean separation of concerns
- No circular dependencies
- Proper use of existing dashcore types
- Extensible design for future features
