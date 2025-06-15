# Network Handling Fixes Summary

This document summarizes all the network handling fixes applied to rust-dashcore based on code review feedback.

## Issues Fixed

### 1. **dash/src/consensus/params.rs**
- **Issue**: Catch-all arm silently mapped unknown networks to "regtest-like" params
- **Fix**: Replaced with explicit panic for unknown networks
```rust
// Before: _ => Params { ... regtest-like params ... }
// After:  other => panic!("Unsupported network variant: {other:?}")
```

### 2. **dash/src/blockdata/constants.rs**
- **Issue**: Unknown networks silently treated as Regtest for genesis block
- **Fix**: Added explicit unreachable! for unknown networks
```rust
// Before: _ => Block { ... regtest genesis ... }
// After:  other => unreachable!("genesis_block(): unsupported network variant {other:?}")
```

### 3. **dash/src/address.rs**
- **Issue**: Unknown networks defaulted to testnet prefixes, risking fund loss
- **Fix**: Added unreachable! for all prefix matches
```rust
// Before: _ => PUBKEY_ADDRESS_PREFIX_TEST
// After:  other => unreachable!("Unknown network {other:?} – add explicit prefix")
```

### 4. **dash/src/sml/llmq_type/network.rs**
- **Issue**: Wildcard arm could mask incorrect LLMQ selection
- **Fix**: Replaced all catch-all arms with unreachable!
```rust
// Before: _ => LLMQType::LlmqtypeTestInstantSend
// After:  other => unreachable!("Unsupported network variant {other:?}")
```

### 5. **dash-network/src/lib.rs**
- **Issue**: TODO placeholder returned misleading value for core_v20_activation_height
- **Fix**: Added explicit values for all networks with panic for unknown
```rust
Network::Devnet => 1,  // v20 active from genesis on devnet
Network::Regtest => 1, // v20 active from genesis on regtest
#[allow(unreachable_patterns)]
other => panic!("Unknown activation height for network {:?}", other)
```

### 6. **dash-network-ffi/src/lib.rs**
- **Issue**: Unknown variants silently mapped to Testnet
- **Fix**: Added panic for unknown network variants
```rust
// Before: _ => Network::Testnet, // Default for unknown networks
// After:  unknown => panic!("Unhandled Network variant {:?}", unknown)
```

### 7. **key-wallet/src/address.rs**
- **Issue**: from_str required network parameter when version byte already identifies it
- **Fix**: Modified to infer network from version byte
```rust
// Before: pub fn from_str(s: &str, network: Network) -> Result<Self>
// After:  pub fn from_str(s: &str) -> Result<Self>
// Infers network from version byte (76=Dash mainnet, 140=testnet, etc.)
```

### 8. **key-wallet-ffi/src/lib.rs**
- **Issue 1**: Hard-coded coin-type breaks Testnet/Devnet
- **Fix**: Use network-specific coin types
```rust
let coin_type = match self.network {
    Network::Dash => 5,  // Dash mainnet
    _ => 1,              // Testnet/devnet/regtest
};
```

- **Issue 2**: Network enum needs repr(u8) for FFI stability
- **Fix**: Added repr attribute
```rust
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Dash = 0,
    Testnet = 1,
    Regtest = 2,
    Devnet = 3,
}
```

- **Issue 3**: Pattern matching Base58 variant incorrectly
- **Fix**: Changed from tuple variant to unit variant
```rust
// Before: kw::Error::Base58(err) => ...
// After:  kw::Error::Base58 => ...
```

## Testing Impact

- All catch-all patterns now explicitly panic or use unreachable!, preventing silent misconfigurations
- Network inference in address parsing maintains backward compatibility while being more correct
- FFI bindings now have stable enum representations
- Coin type derivation now follows BIP44 standards for test networks

## Migration Notes

For users of `key_wallet::Address::from_str`:
- The function no longer requires a network parameter
- Network is inferred from the address version byte
- For validation against a specific network, use the returned address's network field

For FFI users:
- The Network enum now has stable numeric values (0-3)
- Address parsing still accepts a network parameter for validation