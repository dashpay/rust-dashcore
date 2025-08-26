# CLAUDE.md - AI Assistant Guide for key-wallet

This document provides comprehensive technical guidance for AI assistants working with the key-wallet crate. It contains architectural insights, design patterns, and implementation details that are essential for understanding and modifying this codebase.

## Architectural Overview

The key-wallet crate implements a sophisticated hierarchical wallet system with clear separation of concerns:

### Core Architecture Principles

1. **Immutable vs Mutable Separation**
   - `Account`: Immutable structure containing only identity information (keys, derivation paths)
   - `ManagedAccount`: Mutable wrapper with state (address pools, metadata, balances)
   - `Wallet`: Immutable wallet core with account collections
   - `ManagedWalletInfo`: Mutable wallet state and metadata

2. **Layered Design**
   ```
   Application Layer
        ↓
   Wallet Management (wallet module)
        ↓
   Account Management (account/managed_account modules)
        ↓
   Address Generation (address_pool module)
        ↓
   Key Derivation (bip32/derivation modules)
        ↓
   Cryptographic Primitives (secp256k1, BLS, EdDSA)
   ```

3. **Type Safety Through Enums**
   - `AccountType`: Strongly typed account variants (Standard, Identity, Masternode, etc.)
   - `WalletType`: Wallet creation method variants (Mnemonic, Seed, WatchOnly, etc.)
   - `PublicKeyType`: Different key types (ECDSA, BLS, EdDSA)

## Component Relationships

### Wallet Hierarchy
```
Wallet
├── wallet_id (SHA256 of root public key)
├── wallet_type (Mnemonic, Seed, ExtendedPrivKey, etc.)
└── accounts: BTreeMap<Network, AccountCollection>
    └── AccountCollection
        ├── standard_accounts: Vec<Account>
        ├── identity_accounts: Vec<Account>
        ├── masternode_accounts: Vec<Account>
        └── blockchain_user_accounts: Vec<Account>
```

### Account Structure
```
Account (Immutable)
├── parent_wallet_id: Option<[u8; 32]>
├── account_type: AccountType
├── network: Network
├── account_xpub: ExtendedPubKey
└── is_watch_only: bool

ManagedAccount (Mutable)
├── account_type: ManagedAccountType (contains address pools)
├── metadata: AccountMetadata
├── balance: WalletBalance
├── transactions: BTreeMap<Txid, TransactionRecord>
├── monitored_addresses: BTreeSet<Address>
└── utxos: BTreeMap<OutPoint, Utxo>
```

### Address Pool Architecture
```
AddressPool
├── pool_type: AddressPoolType (External/Internal/Absent)
├── addresses: Vec<AddressInfo>
├── used_addresses: HashSet<u32>
├── next_index: u32
├── gap_limit: u32
└── pre_generated_count: u32
```

## Important Design Decisions

### 1. Account Type System

The crate uses a sophisticated enum-based type system for accounts:

```rust
pub enum AccountType {
    Standard { 
        index: u32,
        standard_account_type: StandardAccountType 
    },
    IdentityAuthentication { 
        identity_index: u32,
        key_index: u32 
    },
    IdentityEncryption { ... },
    MasternodeOperator { ... },
    // ... many more variants
}
```

**Rationale**: This provides compile-time safety and clear semantics for different account purposes. Each variant has specific derivation paths and capabilities.

### 2. Transaction Checking System

The transaction checking system uses optimized routing:

```rust
// Transaction classification determines which accounts to check
TransactionRouter::classify_transaction(tx) -> TransactionType
TransactionRouter::get_relevant_account_types(tx_type) -> Vec<AccountType>
```

**Rationale**: Avoids checking all accounts for every transaction. For example, CoinJoin transactions only check CoinJoin accounts.

### 3. Gap Limit Management

Gap limit tracking uses a staged approach:

```rust
pub struct GapLimitStage {
    last_used_index: Option<u32>,
    used_indices: HashSet<u32>,
}
```

**Rationale**: Enables efficient address discovery without loading entire address chains into memory.

### 4. Key Source Abstraction

Address pools can be initialized from different key sources:

```rust
pub enum KeySource {
    Private(ExtendedPrivKey),
    Public(ExtendedPubKey),
    NoKeySource,
}
```

**Rationale**: Supports both full wallets and watch-only wallets with the same interface.

## Testing Strategies

### Unit Test Organization

Tests are organized by functionality:
- `tests/bip32_tests.rs`: Key derivation correctness
- `tests/mnemonic_tests.rs`: Mnemonic generation and validation
- `tests/address_tests.rs`: Address generation and validation
- `tests/derivation_tests.rs`: Path derivation testing
- `tests/psbt.rs`: PSBT serialization/deserialization

### Test Patterns

1. **Deterministic Testing**: Use known test vectors with fixed seeds
   ```rust
   let seed = [0x01; 64]; // Fixed seed for reproducible tests
   ```

2. **Property-Based Testing**: For complex invariants
   ```rust
   // Gap limit property: no more than N consecutive unused addresses
   assert!(consecutive_unused <= gap_limit);
   ```

3. **Integration Testing**: Test complete workflows
   ```rust
   // Full wallet creation -> account -> address -> transaction flow
   ```

## Common Patterns

### 1. Account Creation Pattern

```rust
// Standard pattern for account creation
let account_xpriv = derive_account_key(master, account_type)?;
let account_xpub = ExtendedPubKey::from_priv(&secp, &account_xpriv);
let account = Account::new(wallet_id, account_type, account_xpub, network)?;
let managed_account = ManagedAccount::from_account(&account);
```

### 2. Address Generation Pattern

```rust
// Pre-generate addresses for performance
let pool = &mut managed_account.account_type.receive_pool_mut()?;
pool.ensure_addresses_generated(current_index + lookahead)?;
```

### 3. Transaction Checking Pattern

```rust
// Efficient transaction checking with routing
let tx_type = TransactionRouter::classify_transaction(&tx);
let relevant_accounts = get_relevant_accounts(tx_type);
for account in relevant_accounts {
    if account.check_transaction(&tx).is_relevant {
        account.update_state(&tx);
    }
}
```

## Anti-Patterns to Avoid

### 1. Direct Private Key Exposure
**Wrong**: Returning or logging private keys
```rust
// NEVER do this
println!("Private key: {:?}", extended_priv_key);
```

**Right**: Use public keys or key fingerprints for identification
```rust
println!("Key fingerprint: {:?}", extended_pub_key.fingerprint());
```

### 2. Unbounded Address Generation
**Wrong**: Generating unlimited addresses without gap limit
```rust
// Can cause memory/performance issues
for i in 0..u32::MAX {
    addresses.push(derive_address(i)?);
}
```

**Right**: Use gap limit and staged generation
```rust
let stage = GapLimitStage::new();
while !stage.should_stop(index, gap_limit) {
    // Generate and check address
}
```

### 3. Ignoring Network Types
**Wrong**: Mixing mainnet and testnet
```rust
let address = Address::from_script(&script, Network::Dash)?;
// Using on testnet without checking
```

**Right**: Always validate network consistency
```rust
assert_eq!(account.network, expected_network);
let address = Address::from_script(&script, account.network.into())?;
```

## Integration Guidelines with dash-spv

### Wallet Integration Flow

1. **Initialization**
   ```rust
   let wallet = Wallet::from_mnemonic(mnemonic, None, network)?;
   let mut wallet_info = wallet.to_managed_wallet_info();
   ```

2. **SPV Sync Integration**
   ```rust
   // In SPV callbacks
   on_transaction_received(tx) {
       let result = wallet_info.check_transaction(
           &tx, 
           network,
           TransactionContext::Mempool,
           Some(&wallet)
       );
       if result.is_relevant {
           update_wallet_state(result);
       }
   }
   ```

3. **Address Monitoring**
   ```rust
   // Register addresses with SPV
   let addresses = managed_account.get_all_addresses();
   spv_client.monitor_addresses(addresses)?;
   ```

### State Synchronization

The wallet maintains consistency between:
- Address usage state
- UTXO set
- Transaction history
- Balance calculations

Always update all related state atomically:
```rust
// Atomic state update
managed_account.add_transaction(tx_record);
managed_account.update_utxos(&tx);
managed_account.recalculate_balance();
managed_account.mark_addresses_used(&tx);
```

## Performance Considerations

### 1. Address Pre-generation
- Generate addresses in batches (typically 20-100)
- Store pre-generated addresses in pools
- Only derive on-demand when pool is exhausted

### 2. Transaction Checking Optimization
- Use transaction type routing to avoid checking irrelevant accounts
- Maintain bloom filters for quick address matching
- Cache script pubkeys for repeated checks

### 3. Memory Management
- Use `BTreeMap` for ordered data (accounts, transactions)
- Use `HashMap` for lookups (address -> index mapping)
- Clear old transaction data periodically

### 4. Derivation Performance
- Cache intermediate derivation results
- Use hardened derivation only when required
- Batch derive child keys when possible

## Security Considerations

### 1. Key Material Handling
- Never serialize private keys in production logs
- Use secure random for key generation (`getrandom` crate)
- Clear sensitive memory after use (though Rust helps here)
- Support hardware wallet integration for key isolation

### 2. Watch-Only Wallets
- Clearly separate watch-only from full wallets
- Never attempt signing operations on watch-only accounts
- Validate that external signatures match expected pubkeys

### 3. Network Isolation
- Never mix mainnet and testnet operations
- Validate all addresses against expected network
- Use separate wallet instances for different networks

### 4. Gap Limit Security
- Prevent address exhaustion attacks
- Limit pre-generation to reasonable amounts
- Monitor for unusual address usage patterns

## Common Integration Points

### 1. FFI Bindings (key-wallet-ffi)
```rust
// Expose safe C interfaces
#[no_mangle]
pub extern "C" fn wallet_from_mnemonic(
    mnemonic: *const c_char,
    network: u8
) -> *mut Wallet
```

### 2. Swift Integration
```swift
// Swift SDK uses the FFI bindings
let wallet = DashWallet(mnemonic: "...", network: .mainnet)
```

### 3. RPC Integration
```rust
// Sync with Dash Core node
let client = RpcClient::new(url)?;
let utxos = client.list_unspent(addresses)?;
wallet.update_utxos(utxos)?;
```

## Debugging Tips

### 1. Derivation Path Debugging
```rust
// Log derivation paths for debugging
log::debug!("Deriving path: {}", path);
log::debug!("Account type: {:?}", account_type);
log::debug!("Resulting xpub: {}", xpub);
```

### 2. Address Pool State
```rust
// Inspect pool state
println!("Pool stats: {:?}", pool.get_stats());
println!("Next index: {}", pool.next_index);
println!("Used addresses: {:?}", pool.used_addresses);
```

### 3. Transaction Checking
```rust
// Debug transaction routing
let tx_type = TransactionRouter::classify_transaction(&tx);
println!("Transaction type: {:?}", tx_type);
println!("Checking accounts: {:?}", relevant_accounts);
```

## Future Considerations

### Planned Improvements
1. **Schnorr/Taproot Support**: Preparation for future Dash upgrades
2. **Descriptor Wallets**: Support for output script descriptors
3. **Multi-signature**: Native multisig account types
4. **Lightning Network**: Payment channel key management

### Maintenance Guidelines
1. Keep test vectors updated with Dash Core
2. Monitor for new DIPs affecting wallet structure
3. Maintain backward compatibility for serialized wallets
4. Update derivation paths for new Platform features

## Critical Files to Understand

1. **lib.rs**: Public API surface and module organization
2. **wallet/mod.rs**: Core wallet implementation
3. **account/mod.rs**: Account type system
4. **managed_account/managed_account_type.rs**: Mutable account management
5. **transaction_checking/wallet_checker.rs**: Transaction ownership detection
6. **bip32.rs**: HD key derivation implementation
7. **dip9.rs**: Dash-specific derivation paths

## Error Handling Philosophy

The crate uses a custom `Error` type with specific variants:
- Use `?` operator for propagation
- Provide context in error messages
- Never panic in library code
- Return `Result<T>` for all fallible operations

## Version Compatibility

- Minimum Supported Rust Version (MSRV): 1.89
- Compatible with Dash Core: 0.18.0 - 0.21.0
- Follows semantic versioning (currently 0.x.x = unstable API)

Remember: This crate is security-critical. Always prioritize correctness over performance, and never compromise on key material safety.