# key-wallet-manager

High-level wallet management for Dash using key-wallet primitives and dashcore transaction types.

## Overview

`key-wallet-manager` provides a comprehensive, high-level interface for managing Dash wallets, building transactions, and handling UTXOs. It bridges the gap between low-level cryptographic primitives in `key-wallet` and the transaction structures in `dashcore`.

### Architecture

- **High-level operations**: Transaction building, fee management, coin selection
- **UTXO management**: Track and manage unspent transaction outputs
- **Integration layer**: Seamlessly combines `key-wallet` and `dashcore` types
- **No circular dependencies**: Clean separation from low-level wallet primitives

## Features

- 🔑 **Wallet Management**: Create, configure, and manage HD wallets
- 💰 **Transaction Building**: Construct, sign, and broadcast Dash transactions
- 🎯 **Coin Selection**: Multiple strategies (smallest first, largest first, optimal)
- 📊 **UTXO Tracking**: Comprehensive unspent output management
- 💸 **Fee Management**: Dynamic fee calculation and levels
- 🔒 **Watch-Only Support**: Monitor addresses without private keys
- 🌐 **Multi-Account**: BIP44 account management
- ⚡ **Optimized**: Efficient algorithms for large transaction sets

## Quick Start

### Add Dependency

```toml
[dependencies]
key-wallet-manager = { path = "../key-wallet-manager" }
```

### Basic Usage

```rust
use key_wallet_manager::{
    WalletManager, TransactionBuilder, FeeLevel,
    CoinSelector, SelectionStrategy
};

// Create a new wallet manager
let mut wallet_manager = WalletManager::new("my_wallet", Network::Testnet)?;

// Add an account
wallet_manager.create_account(0, AccountType::BIP44)?;

// Get a receive address
let address = wallet_manager.get_receive_address(0)?;
println!("Send funds to: {}", address);

// Build a transaction
let recipient = "yNsWkgPLN1u7p1dfAXnpRPqPsWg6uqhqBr".parse()?;
let amount = 100_000; // 0.001 DASH in duffs

let tx = TransactionBuilder::new(Network::Testnet)
    .add_recipient(recipient, amount)?
    .set_fee_level(FeeLevel::Normal)
    .build_and_sign(&wallet_manager, 0)?;

println!("Transaction built: {}", tx.txid());
```

## Core Components

### WalletManager

The main interface for wallet operations:

```rust
use key_wallet_manager::WalletManager;

// Create from mnemonic
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mut wallet = WalletManager::from_mnemonic(mnemonic, "password", Network::Testnet)?;

// Or create new random wallet
let mut wallet = WalletManager::new("my_wallet", Network::Testnet)?;

// Account management
wallet.create_account(0, AccountType::BIP44)?;
let accounts = wallet.accounts();

// Address generation
let receive_addr = wallet.get_receive_address(0)?;
let change_addr = wallet.get_change_address(0)?;

// Transaction history
let history = wallet.transaction_history();
```

### TransactionBuilder

Construct and sign transactions:

```rust
use key_wallet_manager::{TransactionBuilder, FeeLevel};

let mut builder = TransactionBuilder::new(Network::Testnet);

// Add recipients
builder.add_recipient("yNsWkgPLN1u7p1dfAXnpRPqPsWg6uqhqBr".parse()?, 50_000)?;
builder.add_recipient("yTtGbtjKJay7r4KdRWQ4aKM8bMFsQ3xvp2".parse()?, 75_000)?;

// Set fee strategy
builder.set_fee_level(FeeLevel::High);
// Or manual fee rate
builder.set_fee_rate(FeeRate::from_sat_per_vb(10)?);

// Add data (OP_RETURN)
builder.add_data(b"Hello Dash!")?;

// Build and sign
let transaction = builder.build_and_sign(&wallet_manager, 0)?;
```

### UTXO Management

Track unspent outputs:

```rust
use key_wallet_manager::{Utxo, UtxoSet};

// Create UTXO set
let mut utxo_set = UtxoSet::new();

// Add UTXOs
let utxo = Utxo::new(outpoint, txout, address, 100);
utxo_set.add_utxo(utxo);

// Query UTXOs
let available = utxo_set.get_available_utxos();
let total_value = utxo_set.total_value();

// Rollback transactions
utxo_set.rollback_to_height(12345);
```

### Coin Selection

Choose optimal UTXOs for transactions:

```rust
use key_wallet_manager::{CoinSelector, SelectionStrategy};

let selector = CoinSelector::new();

// Different strategies
let selection = selector.select_coins(
    &utxo_set, 
    100_000, // target amount
    SelectionStrategy::SmallestFirst
)?;

let selection = selector.select_coins(
    &utxo_set,
    100_000,
    SelectionStrategy::LargestFirst  
)?;

let selection = selector.select_coins(
    &utxo_set,
    100_000,
    SelectionStrategy::BranchAndBound
)?;

// Use selected coins
for utxo in selection.selected_utxos {
    builder.add_input(utxo, None)?; // None = unsigned
}
```

### Watch-Only Wallets

Monitor addresses without private keys:

```rust
use key_wallet::{WatchOnlyWallet, WatchOnlyWalletBuilder};

// Create from extended public key
let xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";

let watch_wallet = WatchOnlyWalletBuilder::new()
    .xpub_string(xpub)?
    .network(Network::Testnet)
    .name("Watch Wallet")
    .index(0)
    .build()?;

// Generate addresses to monitor
let addr1 = watch_wallet.get_next_receive_address()?;
let addr2 = watch_wallet.get_next_receive_address()?;

// Check for activity
let result = watch_wallet.scan_for_activity(|addr| {
    // Your logic to check if address has been used
    check_address_on_blockchain(addr)
});
```

## Fee Management

### Fee Levels

```rust
use key_wallet_manager::{FeeLevel, FeeRate};

// Predefined levels
builder.set_fee_level(FeeLevel::Low);     // ~1-3 blocks
builder.set_fee_level(FeeLevel::Normal);  // Next block
builder.set_fee_level(FeeLevel::High);    // Priority

// Custom fee rate
builder.set_fee_rate(FeeRate::from_sat_per_vb(5)?);
builder.set_fee_rate(FeeRate::from_sat_per_kvb(1000)?);
```

### Fee Estimation

```rust
// Estimate fees before building
let estimated_fee = builder.estimate_fee(&utxo_set)?;
println!("Estimated fee: {} duffs", estimated_fee);

// Check if amount is dust
if builder.is_dust_amount(546) {
    println!("Amount too small to spend efficiently");
}
```

## Advanced Usage

### Multi-Account Operations

```rust
// Create multiple accounts
for i in 0..5 {
    wallet.create_account(i, AccountType::BIP44)?;
}

// Send from specific account
let tx = TransactionBuilder::new(Network::Testnet)
    .add_recipient(recipient, amount)?
    .build_and_sign(&wallet, 2)?; // Use account 2

// Get account balances
for account in wallet.accounts() {
    let balance = wallet.get_account_balance(account.index())?;
    println!("Account {}: {} DASH", account.index(), balance / 100_000_000);
}
```

### Transaction Serialization

```rust
// Get raw transaction bytes
let raw_tx = transaction.serialize();

// Broadcast ready hex
let hex = transaction.serialize().to_hex();
println!("Broadcast: {}", hex);

// Parse from hex
let parsed_tx = Transaction::deserialize(&Vec::from_hex(&hex)?)?;
```

### Error Handling

```rust
use key_wallet_manager::{WalletError, BuilderError};

match wallet.create_account(0, AccountType::BIP44) {
    Ok(account) => println!("Account created"),
    Err(WalletError::AccountExists(index)) => {
        println!("Account {} already exists", index);
    }
    Err(WalletError::InvalidNetwork) => {
        println!("Network configuration error");
    }
    Err(e) => println!("Other error: {}", e),
}

match builder.build_and_sign(&wallet, 0) {
    Ok(tx) => println!("Transaction built: {}", tx.txid()),
    Err(BuilderError::InsufficientFunds { required, available }) => {
        println!("Need {} duffs, only have {}", required, available);
    }
    Err(BuilderError::SigningFailed(msg)) => {
        println!("Signing failed: {}", msg);
    }
    Err(e) => println!("Build error: {}", e),
}
```

## Best Practices

### Security

- **Never log private keys**: WalletManager redacts sensitive data in Debug output
- **Use strong passphrases**: For mnemonic-based wallets
- **Validate addresses**: Always verify recipient addresses
- **Check transaction fees**: Avoid overpaying due to fee calculation errors

### Performance

- **Reuse UTXOSet**: Don't recreate for each transaction
- **Batch operations**: Group multiple recipients in single transaction
- **Optimize coin selection**: Use appropriate strategy for your use case
- **Cache address pools**: Avoid regenerating addresses unnecessarily

### Transaction Building

```rust
// Good: Build complete transaction
let tx = TransactionBuilder::new(Network::Testnet)
    .add_recipient(addr1, 50_000)?
    .add_recipient(addr2, 25_000)?
    .set_fee_level(FeeLevel::Normal)
    .build_and_sign(&wallet, 0)?;

// Avoid: Partial transactions that may fail to build
```

### UTXO Management

```rust
// Update UTXO set after transactions
utxo_set.add_transaction(&tx, block_height);

// Regular cleanup of spent outputs  
utxo_set.remove_spent_outputs(&tx);

// Handle chain reorganizations
if reorg_detected {
    utxo_set.rollback_to_height(safe_height);
}
```

## Integration Examples

### With dashcore-rpc

```rust
// Assuming you have an RPC client
let tx = builder.build_and_sign(&wallet, 0)?;
let txid = rpc.send_raw_transaction(&tx.serialize())?;
println!("Broadcast transaction: {}", txid);
```

### With electrum client

```rust
// Update UTXO set from electrum
let script_hash = address.script_pubkey().to_script_hash();
let utxos = electrum.script_get_list_unspent(&script_hash)?;

for utxo in utxos {
    let outpoint = OutPoint::new(utxo.tx_hash, utxo.tx_pos);
    utxo_set.add_utxo(Utxo::new(outpoint, utxo.value, address.clone(), utxo.height));
}
```

## Testing

Run the test suite:

```bash
# Run all tests
cargo test -p key-wallet-manager

# Run specific test modules
cargo test -p key-wallet-manager transaction_builder
cargo test -p key-wallet-manager utxo_management

# Run with output
cargo test -p key-wallet-manager -- --nocapture
```

## Examples

See the `examples/` directory for complete working examples:

- `basic_wallet.rs` - Simple wallet creation and transaction
- `multi_account.rs` - Multi-account management  
- `watch_only.rs` - Watch-only wallet setup
- `coin_selection.rs` - Different coin selection strategies
- `fee_estimation.rs` - Fee calculation examples

## Error Types

| Error | Description | Common Causes |
|-------|-------------|---------------|
| `InsufficientFunds` | Not enough balance | UTXO set outdated, incorrect amount |
| `InvalidAddress` | Malformed address | Wrong network, typo in address |
| `SigningFailed` | Transaction signing error | Wrong private key, malformed transaction |
| `InvalidNetwork` | Network mismatch | Testnet key on mainnet, etc. |
| `AccountNotFound` | Account doesn't exist | Wrong index, account not created |
| `DustAmount` | Amount too small | Below dust threshold (~546 duffs) |

## Compatibility

- **Rust**: 1.70.0+
- **Networks**: Mainnet, Testnet, Devnet, Regtest
- **Standards**: BIP32, BIP39, BIP44, DIP9
- **Dependencies**: `key-wallet`, `dashcore`, `secp256k1`

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make changes and add tests
4. Run tests (`cargo test -p key-wallet-manager`)
5. Commit changes (`git commit -am 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Create a Pull Request

## License

This project is licensed under CC0-1.0 - see the [LICENSE](../LICENSE) file for details.

## Support

- 📖 **Documentation**: Run `cargo doc --open -p key-wallet-manager`
- 🐛 **Issues**: Report bugs via GitHub Issues
- 💬 **Discussions**: Community discussions on GitHub

---

Built with ❤️ for the Dash ecosystem