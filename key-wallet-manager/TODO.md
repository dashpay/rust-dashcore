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

## Key-Wallet-Manager Library

### 1. ManagedAccount Integration for Address Generation
**Location**: `wallet_manager.rs` lines 282, 296  
**Priority**: HIGH  
**Description**: Address generation methods are currently disabled and return errors.

**Methods affected**:
- `get_receive_address()` - Returns error, needs ManagedAccount
- `get_change_address()` - Returns error, needs ManagedAccount
- `send_transaction()` - Partially broken due to address generation

**What needs to be done**:
```rust
// Current (broken):
pub fn get_receive_address(&mut self, wallet_id: &WalletId, account_index: u32) 
    -> Result<Address, WalletError> {
    Err(WalletError::AddressGeneration("..."))
}

// Needed:
// 1. Get the Account from Wallet
// 2. Get or create ManagedAccount with address pools
// 3. Generate next address using derivation path
// 4. Update address pool state
// 5. Return the address
```

### 2. Transaction Building Completion
**Location**: `wallet_manager.rs` line 336  
**Priority**: HIGH  
**Description**: Transaction building is incomplete with `unimplemented!()` macro.

**Issues**:
- Need to get actual addresses from ManagedAccount
- Need to properly select UTXOs for spending
- Need to sign transactions with private keys
- Fee calculation needs to be accurate

### 3. Fee Calculation
**Location**: `wallet_manager.rs` line 348  
**Priority**: MEDIUM  
**Description**: Fee calculation is currently set to `None` and needs proper implementation.

### 4. Coin Selection Improvements
**Location**: `coin_selection.rs`  
**Priority**: LOW  
**Description**: Random shuffling for privacy is not implemented in coin selection.

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
