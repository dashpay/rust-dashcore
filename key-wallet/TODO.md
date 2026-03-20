# TODOs and Pending Work

## Key-Wallet Library

### 1. ManagedAccount Integration
**Location**: Various files  
**Priority**: HIGH  
**Description**: The Account/ManagedAccount split needs to be fully integrated. Currently:
- `Account` holds immutable identity (keys, derivation paths)
- `ManagedAccount` holds mutable state (address pools, balances, metadata)
- Need to properly connect these for address generation

**Files affected**:
- `address_metadata_tests.rs` - Tests need updating for new architecture
- `wallet_comprehensive_tests.rs` - Advanced tests need reimplementation

### 2. PSBT (Partially Signed Bitcoin Transaction) Support
**Location**: `psbt/serialize.rs`, `psbt/map/input.rs`  
**Priority**: MEDIUM  
**TODOs**:
- Add support for writing into a writer for key-source
- Implement Proof of reserves commitment

## Enhanced Wallet Manager

### 1. Real Address Derivation
**Location**: `enhanced_wallet_manager.rs` - `derive_address()` method  
**Priority**: HIGH  
**Description**: Currently creates dummy addresses instead of deriving real ones.

**What's needed**:
- Access to wallet's master key
- Proper BIP32 derivation using the path
- Integration with Account/ManagedAccount system

### 2. Private Key Management
**Location**: `enhanced_wallet_manager.rs` - `build_transaction()` method  
**Priority**: HIGH  
**Description**: Transaction signing requires private keys which aren't currently accessible.

### 3. Address Generation Integration
**Location**: `enhanced_wallet_manager.rs`  
**Priority**: MEDIUM  
**Description**: The "should generate addresses" check is commented out and needs proper implementation.

## Filter Client / SPV Implementation

### 1. Async Support
**Location**: `filter_client.rs`  
**Priority**: MEDIUM  
**Description**: The `sync_filters` method is marked async but we're in no_std context.

**Options**:
- Remove async and use blocking calls
- Add async runtime support with feature flag
- Use callback-based approach

### 2. Network Implementation
**Location**: `filter_client.rs` - trait implementations  
**Priority**: HIGH  
**Description**: Need actual network implementation for:
- `BlockFetcher` trait
- `FilterFetcher` trait

### 3. Persistence
**Priority**: MEDIUM  
**Description**: No persistence layer for:
- Filter headers chain
- Cached filters
- Wallet state
- Transaction history

## Missing Core Functionality

### 1. Proper Key Derivation Integration
**Problem**: The separation between Account (immutable) and ManagedAccount (mutable) isn't fully bridged.

**Solution needed**:
```rust
struct AccountManager {
    account: Account,           // Immutable keys
    managed: ManagedAccount,    // Mutable state
    
    fn generate_address(&mut self, is_change: bool) -> Address {
        // 1. Get next index from ManagedAccount
        // 2. Derive key using Account
        // 3. Update ManagedAccount state
        // 4. Return address
    }
}
```

### 2. Transaction Signing
**Problem**: No clear path from UTXO to private key for signing.

**Solution needed**:
- Track derivation path for each address
- Store path -> address mapping
- Retrieve private key using path when signing

### 3. Wallet Persistence
**Problem**: All state is in-memory only.

**Solution needed**:
- Serialize wallet state
- Store encrypted on disk
- Load/save methods
- Migration support

## Testing Gaps

1. **Integration tests** for the complete flow:
   - Create wallet
   - Generate addresses  
   - Receive transactions
   - Build and sign transactions
   - Process blocks

2. **Network tests** with mock P2P layer

3. **Persistence tests** (once implemented)

4. **Performance tests** for filter matching with large wallets

## Priority Order

1. **Fix ManagedAccount integration** - Core functionality is broken without this
2. **Implement proper address derivation** - Essential for wallet to work
3. **Complete transaction building/signing** - Needed for spending
4. **Add persistence layer** - Required for production use
5. **Network implementation** - Connect to real Dash network
6. **Testing suite** - Ensure reliability
7. **Performance optimizations** - Improve user experience

## Notes

- The enhanced_wallet_manager partially reimplements functionality to work around the ManagedAccount issues
- The filter_client is complete but needs network integration
- Consider whether to maintain both wallet_manager and enhanced_wallet_manager or merge them
