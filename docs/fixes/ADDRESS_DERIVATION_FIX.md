# Address Derivation Fix Summary

## Problem
The HD wallet implementation in the Swift example app was using mock address derivation, returning addresses like "XMockAddress00" instead of real Dash addresses.

## Solution
Updated the `HDWalletService.swift` to use the actual key-wallet-ffi Rust FFI bindings for proper BIP32/BIP44 HD wallet derivation.

### Changes Made:

1. **Updated `deriveExtendedPublicKey` function**:
   - Now uses `HdWallet.fromSeed()` to create a proper HD wallet
   - Uses `hdWallet.getAccountXpub()` to derive account extended public keys
   - Falls back to mock implementation only if FFI fails

2. **Updated `deriveAddress` function**:
   - Uses `AddressGenerator` from key-wallet-ffi to generate real addresses
   - Properly handles external/internal (change) address derivation
   - Falls back to mock addresses only if FFI fails

3. **Updated `deriveAddresses` function**:
   - Uses `AddressGenerator.generateRange()` for batch address generation
   - More efficient than generating addresses one by one

4. **Added `convertToFFINetwork` helper**:
   - Converts between `DashNetwork` and `KeyWalletFFISwift.Network` enums

5. **Updated `KeyWalletBridge`**:
   - Now uses real `HdWallet` from FFI instead of mock implementation
   - Properly creates wallets from mnemonics using FFI

6. **Updated `createAccount` in WalletService**:
   - Now generates 5 initial receive addresses and 1 change address
   - Ensures new accounts have addresses immediately available

## Results
- Addresses are now properly derived using BIP32/BIP44 standards
- Correct coin types: 5 for Dash mainnet, 1 for testnet/devnet/regtest
- Real Dash addresses starting with 'X' for mainnet, 'y' for testnet
- Proper HD wallet functionality with deterministic address generation

## Testing
To verify the fix:
1. Run the DashHDWalletExample app
2. Create a new wallet with a mnemonic
3. Check that addresses start with proper prefixes ('X' or 'y')
4. Verify addresses are deterministic (same mnemonic produces same addresses)

## Technical Details
The implementation uses:
- UniFFI for Rust-Swift interop
- key-wallet crate for BIP32/BIP39/BIP44 implementation
- Proper secp256k1 cryptography for key derivation
- Base58Check encoding for Dash address format