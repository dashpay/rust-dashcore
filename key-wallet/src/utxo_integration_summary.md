# UTXO Integration Summary

## Existing UTXO Implementation in dash-spv

### What's Already Available

1. **UTXO Tracking** (`dash-spv/src/wallet/utxo.rs`)
   - Complete `Utxo` struct with:
     - `outpoint`: Transaction hash + output index
     - `txout`: Value and script
     - `address`: Associated address
     - `height`: Block height
     - `is_coinbase`: Coinbase flag
     - `is_confirmed`: Confirmation status
     - `is_instantlocked`: InstantLock status
   - Serialization/deserialization support
   - Spendability checks (coinbase maturity)

2. **UTXO Rollback Manager** (`dash-spv/src/wallet/utxo_rollback.rs`)
   - Handles blockchain reorganizations
   - Snapshot mechanism for UTXO state
   - Transaction status tracking
   - Persistence to storage

3. **Transaction Processing** (`dash-spv/src/wallet/transaction_processor.rs`)
   - Block processing
   - UTXO extraction from transactions
   - Spent UTXO tracking
   - NOT transaction creation

4. **Wallet State** (`dash-spv/src/wallet/wallet_state.rs`)
   - Transaction height tracking
   - Confirmation management
   - Balance calculation

## What's Missing for key-wallet

### Transaction Creation & Management
1. **Transaction Builder**
   - Input selection from UTXOs
   - Output creation
   - Change calculation
   - Fee estimation

2. **UTXO Selection Algorithms**
   - Smallest first (minimize UTXO set)
   - Largest first (minimize fees)
   - Branch and bound (optimal selection)
   - Privacy-aware selection
   - Manual coin control

3. **Transaction Signing**
   - Sign inputs with private keys
   - Support for different script types
   - Partial signatures for multisig

4. **Fee Management**
   - Dynamic fee estimation
   - RBF (Replace-By-Fee) support
   - CPFP (Child-Pays-For-Parent)

## Integration Strategy

### Option 1: Reuse dash-spv UTXO (Recommended)
**Pros:**
- Already battle-tested
- Includes rollback management
- Storage integration exists
- Consistent with SPV implementation

**Cons:**
- Dependency on dash-spv
- May include unnecessary SPV-specific features
- Requires careful coordination

**Implementation:**
```rust
// In key-wallet, reference dash-spv types
use dash_spv::wallet::Utxo;
use dash_spv::wallet::UTXORollbackManager;
```

### Option 2: Duplicate UTXO in key-wallet
**Pros:**
- Complete control over implementation
- Can optimize for HD wallet use case
- No external dependencies

**Cons:**
- Code duplication
- Maintenance burden
- Risk of divergence

### Option 3: Extract UTXO to Shared Crate
**Pros:**
- Single source of truth
- Both crates can use it
- Clean separation of concerns

**Cons:**
- Requires refactoring dash-spv
- More complex project structure
- Breaking changes

## Recommended Next Steps

1. **For Now: Create transaction.rs in key-wallet**
   ```rust
   // key-wallet/src/transaction.rs
   pub struct TransactionBuilder {
       inputs: Vec<TxIn>,
       outputs: Vec<TxOut>,
       change_address: Option<Address>,
       fee_rate: FeeRate,
   }
   
   pub trait UTXOSelector {
       fn select_utxos(&self, target: Amount, utxos: &[Utxo]) -> Result<Vec<Utxo>>;
   }
   
   pub struct SmallestFirstSelector;
   pub struct LargestFirstSelector;
   pub struct BranchAndBoundSelector;
   ```

2. **Use dash-spv Utxo type**
   - Import as external dependency
   - Or copy just the Utxo struct for now

3. **Focus on Transaction Building**
   - UTXO selection algorithms
   - Fee calculation
   - Change output generation
   - Transaction signing

4. **Later: Consider Refactoring**
   - Extract common UTXO types to shared crate
   - Coordinate with dash-spv maintainers

## Files to Create

1. `key-wallet/src/transaction.rs` - Transaction building and signing
2. `key-wallet/src/utxo_selection.rs` - UTXO selection algorithms
3. `key-wallet/src/fee.rs` - Fee estimation and management

## Tests Needed

1. UTXO selection with various amounts
2. Fee calculation accuracy
3. Change output generation
4. Transaction signing
5. Edge cases (dust outputs, insufficient funds)