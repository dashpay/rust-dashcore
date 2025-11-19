# Wallet Address to SPV Client Integration

## Summary

This document describes how wallet addresses are connected to the SPV client in the Swift SDK.

## Architecture

### 1. SPVClient Methods

Added two new public methods to `SPVClient`:
- `addWatchItem(type: WatchItemType, data: String)` - Adds address/script/outpoint to watch list
- `removeWatchItem(type: WatchItemType, data: String)` - Removes from watch list

These methods:
- Check if client is connected
- Create appropriate FFI watch item based on type
- Call the FFI function with the client's internal pointer
- Clean up memory appropriately

### 2. WalletManager Integration

Updated `WalletManager` to use the new SPVClient methods:
- `watchAddress()` now calls `client.addWatchItem(.address, data: address)`
- `unwatchAddress()` now calls `client.removeWatchItem(.address, data: address)`
- `watchScript()` converts script data to hex and calls `client.addWatchItem(.script, data: scriptHex)`

### 3. Persistence Integration

Updated `PersistentWalletManager`:
- When loading persisted addresses, it re-watches them in the SPV client if connected
- This ensures addresses are tracked after app restart

### 4. Connection Flow

Updated `DashSDK.connect()`:
- After starting SPV client, calls `syncPersistedAddresses()`
- This triggers reload of watched addresses from storage

## Address Watching Flow

1. **New Address Generation**:
   - Wallet generates new address
   - Calls `watchAddress(address)`
   - WalletManager calls `client.addWatchItem(.address, data: address)`
   - SPVClient creates FFI watch item and registers with Rust SPV client
   - Address is now tracked for balance/transaction updates

2. **App Restart**:
   - DashSDK.connect() is called
   - SPV client starts
   - PersistentWalletManager loads addresses from storage
   - Each address is re-watched via `client.addWatchItem()`
   - SPV client resumes tracking all addresses

3. **Balance/Transaction Updates**:
   - SPV client detects changes for watched addresses
   - Events are sent through the event callback system
   - WalletManager handles events and updates balances

## Key Design Decisions

1. **Encapsulation**: WalletManager doesn't need direct FFI access - SPVClient handles all FFI interactions
2. **Type Safety**: Using `WatchItemType` enum to ensure correct watch item creation
3. **Memory Management**: Proper cleanup of FFI watch items using defer blocks
4. **Error Handling**: Proper error propagation with meaningful error messages

## FFI Functions Used

## Testing

To test the integration:

1. Generate a new address in the wallet
2. Verify it's watched via SPV client logs
3. Send funds to the address
4. Verify balance updates are received
5. Restart app and verify addresses are re-watched
