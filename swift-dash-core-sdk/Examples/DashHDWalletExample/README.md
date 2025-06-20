# Dash HD Wallet Example

A comprehensive iOS and macOS example application demonstrating HD (Hierarchical Deterministic) wallet functionality using the SwiftDashCoreSDK.

## Features

### Wallet Management
- **Multiple HD Wallets**: Create and manage multiple wallets with different networks
- **BIP39 Mnemonics**: Generate or import 12/24 word recovery phrases
- **Network Support**: Mainnet, Testnet, Regtest, and Devnet
- **Secure Storage**: Password-encrypted seed storage with SwiftData persistence

### Account Management (BIP44)
- **Multiple Accounts**: Create multiple accounts per wallet following BIP44 standard
- **Derivation Paths**: Standard Dash derivation paths (m/44'/5'/account' for mainnet)
- **Account Labels**: Custom naming for easy identification
- **Balance Tracking**: Real-time balance updates per account

### Address Management
- **HD Address Generation**: Automatic address derivation with gap limit
- **Address Types**: External (receive) and internal (change) addresses
- **Address Discovery**: Automatic discovery of used addresses during sync
- **QR Codes**: Generate QR codes for receiving addresses

### Blockchain Synchronization
- **SPV Sync**: Lightweight blockchain synchronization
- **Progress Tracking**: Real-time sync progress with block height and percentage
- **Time Estimation**: ETA calculation for sync completion
- **Network Stats**: Connected peers, data transfer, and uptime

### Transaction Features
- **Send Transactions**: Create and broadcast transactions
- **Fee Estimation**: Dynamic fee calculation with multiple fee levels
- **Transaction History**: View all transactions per account
- **InstantSend**: Support for Dash InstantSend transactions
- **UTXO Management**: View and manage unspent outputs

## Architecture

### Data Models
- `HDWallet`: Root wallet with encrypted seed
- `HDAccount`: BIP44 account with extended public key
- `WatchedAddress`: Individual addresses with transaction history
- `SyncState`: Blockchain synchronization progress

### Services
- `WalletService`: Main service managing wallets and SDK interaction
- `HDWalletService`: Key derivation and mnemonic handling
- `AddressDiscoveryService`: Blockchain address discovery

### Views
- **iOS**: Navigation stack with adaptive layouts for iPhone and iPad
- **macOS**: Split view design with sidebar navigation
- Detailed account view with tabs for transactions, addresses, and UTXOs
- Modal sheets for wallet creation, receiving, and sending

## Usage

### Creating a Wallet

1. Click "Create New Wallet"
2. Enter wallet name and select network
3. Set a secure password (min 8 characters)
4. Generate and save the recovery phrase
5. Confirm you've written down the phrase

### Importing a Wallet

1. Click "Import Wallet"
2. Enter your 12 or 24 word recovery phrase
3. Select the correct network
4. Set a password for encryption

### Connecting and Syncing

1. Select a wallet from the list
2. Click "Connect" in the toolbar
3. Click "Sync" to start blockchain synchronization
4. Monitor progress in the sync dialog

### Receiving Dash

1. Select an account
2. Click "Receive" button
3. Share the QR code or copy the address
4. Generate new addresses as needed

### Sending Dash

1. Select an account with balance
2. Click "Send" button
3. Enter recipient address and amount
4. Select fee level
5. Review and confirm transaction

## Technical Details

### BIP44 Derivation Paths
- **Mainnet**: m/44'/5'/account'/change/index
- **Testnet**: m/44'/1'/account'/change/index

### Gap Limit
Default gap limit of 20 addresses for discovery

### Storage
- SwiftData for persistence
- Encrypted seed storage
- Transaction and UTXO caching

## Security Considerations

1. **Seed Encryption**: Seeds are encrypted with user password
2. **No Plain Text**: Recovery phrases never stored in plain text
3. **Memory Safety**: Sensitive data cleared from memory
4. **Input Validation**: Address and amount validation

## Limitations

This example uses mock implementations for:
- BIP32/BIP39 key derivation (would use key-wallet-ffi in production)
- Address generation (would derive from actual HD keys)
- Transaction signing (would use actual private keys)

In a production app, integrate with:
- `key-wallet-ffi` for real HD wallet functionality
- `dash-spv-ffi` extended with HD wallet support
- Proper key management and signing

## Future Enhancements

1. **Hardware Wallet Support**: Integration with Ledger/Trezor
2. **Multi-Signature**: Support for multi-sig accounts
3. **CoinJoin**: Privacy features using DIP9 paths
4. **Export/Import**: Wallet backup and restore
5. **Transaction Details**: Enhanced transaction viewer
6. **Address Book**: Save frequent recipients
7. **Price Integration**: Fiat value display
8. **Notifications**: Transaction alerts

## Platform Support

### iOS Requirements
- iOS 17.0 or later
- Supports iPhone and iPad
- Adaptive layouts for different screen sizes

### macOS Requirements
- macOS 14.0 or later
- Native macOS UI with sidebar navigation

### Building for iOS
```bash
# Build the example app for iOS
swift build --product DashHDWalletExample

# Or build from the main SDK directory
cd ../..
swift build --product DashHDWalletExample
```

### Building for macOS
The example app builds for both platforms by default. The UI automatically adapts based on the target platform using Swift's conditional compilation.