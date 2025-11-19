# Key Wallet

A comprehensive Rust library for Dash cryptocurrency wallet functionality, providing hierarchical deterministic (HD) wallets, multiple key derivation schemes, and advanced wallet management features.

## Overview

The key-wallet crate is a core component of the rust-dashcore ecosystem, offering:

- Complete HD wallet implementation with BIP32/BIP39 support
- Dash-specific features including CoinJoin and Platform identity management
- Multiple cryptographic schemes (ECDSA, BLS, EdDSA)
- Advanced account and address management with gap limit tracking
- Transaction checking and UTXO management
- FFI bindings for cross-platform integration
- No-std support for embedded systems

## Architecture

The library is organized into several key modules:

- **Core Wallet Management**: Complete wallet lifecycle including creation, backup, and recovery
- **Account System**: Multi-account support with different account types for various use cases
- **Address Pools**: Efficient address generation and management with gap limit tracking
- **Transaction Processing**: Transaction checking, UTXO tracking, and balance calculation
- **Cryptographic Primitives**: Support for ECDSA (secp256k1), BLS, and EdDSA (Ed25519)

## Key Features

### HD Wallet Support
- **BIP32**: Hierarchical deterministic key derivation
- **BIP39**: Mnemonic phrase generation and validation (multiple languages)
- **BIP38**: Encrypted private key support (optional feature)
- **SLIP-10**: Ed25519 key derivation for Platform identities

### Dash-Specific Features (DIP9)
- **Standard Accounts**: BIP44-compliant accounts for regular transactions
- **CoinJoin Accounts**: Privacy-enhanced mixing accounts
- **Identity Keys**: Platform identity authentication and encryption keys
- **Masternode Keys**: Provider and voting keys for masternode operations
- **Blockchain User Keys**: Keys for Platform blockchain users

### Account Types
- **Standard ECDSA Accounts**: Traditional HD wallet accounts
- **BLS Accounts**: For masternode operations and Platform voting
- **EdDSA Accounts**: For Platform identity operations
- **Watch-Only Accounts**: Monitor addresses without private keys
- **External Signable**: Integration with hardware wallets

### Advanced Features
- **Gap Limit Management**: Automatic address discovery with configurable gap limits
- **Address Pool Management**: Pre-generated address pools for performance
- **Transaction Checking**: Efficient transaction ownership detection
- **UTXO Management**: Track unspent outputs and calculate balances
- **PSBT Support**: Partially Signed Bitcoin Transaction format
- **Multi-Network**: Support for mainnet, testnet, and other networks

## Usage Examples

### Creating a New Wallet

```rust
use key_wallet::{Wallet, Mnemonic, Network};
use key_wallet::mnemonic::Language;

// Generate a new mnemonic
let mnemonic = Mnemonic::generate(24, Language::English)?;
println!("Mnemonic: {}", mnemonic.phrase());

// Create wallet from mnemonic
let wallet = Wallet::from_mnemonic(mnemonic.clone(), None, Network::Dash)?;

// Get wallet ID (unique identifier)
println!("Wallet ID: {:?}", hex::encode(wallet.wallet_id));
```

### Managing Accounts

```rust
use key_wallet::account::{Account, AccountType, StandardAccountType};
use key_wallet::managed_account::ManagedAccount;

// Create a standard BIP44 account
let account = wallet.create_account(
    Network::Dash,
    AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    }
)?;

// Convert to managed account for mutable operations
let mut managed_account = ManagedAccount::from_account(&account);

// Generate receive addresses
let addresses = managed_account.generate_receive_addresses(10)?;
for (index, address) in addresses.iter().enumerate() {
    println!("Address {}: {}", index, address);
}
```

### Address Generation with Gap Limit

```rust
use key_wallet::gap_limit::{GapLimit, GapLimitStage};

// Create gap limit manager
let gap_limit = GapLimit::new(20); // Standard gap limit of 20

// Track address usage
let mut stage = GapLimitStage::new();
for i in 0..100 {
    let address = account.derive_receive_address(i)?;
    
    // Check if address has been used (would come from blockchain scan)
    let is_used = check_address_on_blockchain(&address);
    
    if is_used {
        stage.mark_used(i);
    }
    
    // Check if we've reached gap limit
    if stage.should_stop(i, gap_limit.gap()) {
        break;
    }
}
```

### CoinJoin Account

```rust
// Create CoinJoin account for privacy
let coinjoin_account = wallet.create_account(
    Network::Dash,
    AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::CoinJoinAccount,
    }
)?;

// CoinJoin uses multiple address pools
let pool_0_address = coinjoin_account.derive_address_at_pool(0, 0)?;
let pool_1_address = coinjoin_account.derive_address_at_pool(1, 0)?;
```

### Platform Identity Keys

```rust
#[cfg(feature = "eddsa")]
{
    use key_wallet::account::EdDSAAccount;
    
    // Create identity authentication key
    let identity_account = wallet.create_account(
        Network::Dash,
        AccountType::IdentityAuthentication {
            identity_index: 0,
            key_index: 0,
        }
    )?;
    
    // Get Ed25519 public key for Platform
    let pubkey = identity_account.get_public_key_bytes();
    println!("Identity public key: {}", hex::encode(pubkey));
}
```

### Transaction Checking

```rust
use key_wallet::transaction_checking::{WalletTransactionChecker, TransactionContext};
use dashcore::Transaction;

// Check if transaction belongs to wallet
let mut wallet_info = wallet.to_managed_wallet_info();
let tx: Transaction = get_transaction_from_network();

let result = wallet_info.check_transaction(
    &tx,
    Network::Dash,
    TransactionContext::Mempool,
    Some(&wallet), // Update state if transaction is ours
);

if result.is_relevant {
    println!("Transaction affects {} accounts", result.affected_accounts.len());
    println!("Total amount: {} duffs", result.total_amount);
}
```

## Feature Flags

- `default`: Enables `std` feature
- `std`: Standard library support (enabled by default)
- `serde`: Serialization/deserialization support
- `bincode`: Binary serialization support
- `bip38`: BIP38 encrypted private key support
- `eddsa`: Ed25519 support for Platform identities
- `bls`: BLS signature support for masternodes

## API Overview

### Core Types

- `Wallet`: Main wallet structure managing accounts and keys
- `Account`: Individual account within a wallet
- `ManagedAccount`: Mutable account with address pools and metadata
- `Mnemonic`: BIP39 mnemonic phrase handling
- `ExtendedPrivKey`/`ExtendedPubKey`: BIP32 extended keys
- `DerivationPath`: HD wallet derivation paths
- `Address`: Dash address representation

### Key Modules

- `wallet`: Complete wallet management
- `account`: Account types and operations
- `managed_account`: Mutable account state and pools
- `bip32`: Hierarchical deterministic key derivation
- `mnemonic`: BIP39 mnemonic generation and validation
- `dip9`: Dash-specific derivation paths
- `transaction_checking`: Transaction ownership detection
- `utxo`: UTXO set management
- `gap_limit`: Address discovery gap limit tracking

## Migration Notes

### From v0.39 to v0.40

- Account structure split into immutable `Account` and mutable `ManagedAccount`
- New transaction checking system with optimized routing
- Enhanced address pool management with pre-generation support
- Improved gap limit tracking with staged discovery
- Better separation of concerns between wallet and account management

## Performance Considerations

- Address pools are pre-generated for better performance
- Transaction checking uses optimized routing based on transaction type
- Gap limit discovery uses staged approach to minimize blockchain queries
- Supports batch operations for efficiency

## Security Considerations

- Private keys are never exposed in logs or debug output
- Supports watch-only wallets for cold storage scenarios
- Compatible with hardware wallet integration
- Memory-safe Rust implementation
- Optional encryption via BIP38

## Dependencies

Core dependencies:
- `dashcore`: Core Dash protocol implementation
- `secp256k1`: ECDSA cryptography
- `bip39`: Mnemonic phrase support
- `hkdf`: Key derivation functions
- Additional optional dependencies for specialized features

## Contributing

Contributions are welcome! Please ensure:
- All tests pass with `cargo test --all-features`
- Code follows project style guidelines
- New features include appropriate tests
- Documentation is updated for API changes

## License

This project is licensed under the CC0 1.0 Universal license.
