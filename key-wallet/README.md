# Key Wallet

A Rust library for Dash key derivation and wallet functionality, including BIP32 hierarchical deterministic wallets, BIP39 mnemonic support, and Dash-specific derivation paths (DIP9).

## Features

- **BIP32 HD Wallets**: Full implementation of hierarchical deterministic wallets
- **BIP39 Mnemonics**: Generate and validate mnemonic phrases in multiple languages
- **Dash-specific paths**: Support for DIP9 derivation paths (BIP44, CoinJoin, Identity)
- **Address generation**: P2PKH and P2SH address support for Dash networks
- **No-std support**: Can be used in embedded environments
- **Secure**: Memory-safe Rust implementation

## Usage

### Creating a wallet from mnemonic

```rust
use key_wallet::prelude::*;
use key_wallet::mnemonic::Language;
use key_wallet::derivation::HDWallet;
use key_wallet::bip32::Network;

// Create or restore from mnemonic
let mnemonic = Mnemonic::from_phrase(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    Language::English
)?;

// Generate seed
let seed = mnemonic.to_seed("");

// Create HD wallet
let wallet = HDWallet::from_seed(&seed, Network::Dash)?;

// Derive BIP44 account
let account = wallet.bip44_account(0)?;
```

### Address generation

```rust
use key_wallet::address::{Address, AddressGenerator, Network};

// Create address generator
let generator = AddressGenerator::new(Network::Dash);

// Generate addresses from account
let addresses = generator.generate_range(&account_xpub, true, 0, 10)?;
```

### Dash-specific derivation paths

```rust
// CoinJoin account
let coinjoin_account = wallet.coinjoin_account(0)?;

// Identity authentication key
let identity_key = wallet.identity_authentication_key(0, 0)?;
```

## Derivation Paths (DIP9)

The library implements Dash Improvement Proposal 9 (DIP9) derivation paths:

- **BIP44**: `m/44'/5'/account'` - Standard funds
- **CoinJoin**: `m/4'/5'/account'` - CoinJoin mixing
- **Identity**: `m/5'/5'/3'/identity'/key'` - Platform identities
- **Masternode**: Various paths for masternode operations

## Security

- Private keys are handled securely in memory
- Supports both mainnet and testnet
- Compatible with hardware wallet derivation

## License

This project is licensed under the CC0 1.0 Universal license.