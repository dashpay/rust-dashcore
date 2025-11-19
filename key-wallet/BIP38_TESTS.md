# BIP38 Test Documentation

## Overview

BIP38 tests are computationally intensive due to the scrypt key derivation function used in the BIP38 specification. To keep regular test runs fast, all BIP38 tests are marked with `#[ignore]` and can be run separately using dedicated scripts.

## Why Are BIP38 Tests Slow?

BIP38 uses scrypt with the following parameters:
- N = 16384 (iterations)
- r = 8 (block size)
- p = 8 (parallelization factor)

This makes each encryption/decryption operation take several seconds, which is intentional for security (to prevent brute-force attacks) but makes tests slow.

## Running BIP38 Tests

### Quick Method
```bash
# Run all BIP38 tests
./test_bip38.sh
```

### Advanced Method
```bash
# Run with various options
./test_bip38_advanced.sh --help

# Run in release mode (faster)
./test_bip38_advanced.sh --release

# Run only quick tests (skip performance benchmarks)
./test_bip38_advanced.sh --quick

# Run a specific test
./test_bip38_advanced.sh --single test_bip38_encryption

# Run with verbose output and timing
./test_bip38_advanced.sh --verbose --timing
```

### Manual Method
```bash
# Run all ignored BIP38 tests
cargo test --lib -- --ignored bip38

# Run specific BIP38 test module
cargo test --lib bip38::tests -- --ignored

# Run with output
cargo test --lib bip38_tests -- --ignored --nocapture
```

## Test Coverage

The BIP38 test suite includes:

### Core Module Tests (`src/bip38.rs`)
- `test_bip38_encryption` - Basic encryption functionality
- `test_bip38_decryption` - Basic decryption functionality
- `test_bip38_compressed_uncompressed` - Key compression handling
- `test_bip38_builder` - Builder pattern API
- `test_intermediate_code_generation` - EC multiply mode support
- `test_address_hash` - Address hash calculation
- `test_scrypt_parameters` - Scrypt parameter validation

### Comprehensive Tests (`src/bip38_tests.rs`)
- `test_bip38_encryption_no_compression` - Uncompressed key encryption
- `test_bip38_encryption_with_compression` - Compressed key encryption
- `test_bip38_wrong_password` - Wrong password error handling
- `test_bip38_scrypt_parameters` - Comprehensive scrypt testing
- `test_bip38_unicode_password` - Unicode password support
- `test_bip38_network_differences` - Network-specific encryption
- `test_bip38_edge_cases` - Edge case handling
- `test_bip38_round_trip` - Multiple encryption/decryption cycles
- `test_bip38_invalid_prefix` - Invalid input handling
- `test_bip38_performance` - Performance benchmarks

## Performance Expectations

On modern hardware:
- Single encryption: 2-5 seconds
- Single decryption: 2-5 seconds
- Full test suite: 30-60 seconds in debug mode
- Full test suite: 10-20 seconds in release mode

## CI/CD Integration

For CI pipelines, you can:

1. **Skip BIP38 tests entirely** (default behavior)
   ```yaml
   cargo test --lib
   ```

2. **Run BIP38 tests in a separate job**
   ```yaml
   cargo test --lib -- --ignored bip38 --release
   ```

3. **Run only on specific conditions** (e.g., nightly builds)
   ```yaml
   if: github.event_name == 'schedule'
   run: ./test_bip38.sh --release
   ```

## Troubleshooting

If tests are failing:

1. **Timeout Issues**: BIP38 operations can take several seconds. Ensure your test timeout is sufficient.

2. **Memory Issues**: Scrypt is memory-intensive. Ensure adequate RAM is available.

3. **Platform Differences**: Different platforms may have slightly different performance characteristics.

## Adding New BIP38 Tests

When adding new BIP38 tests, always mark them with:

```rust
#[test]
#[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
fn test_new_bip38_feature() {
    // Test implementation
}
```

This ensures they don't slow down regular test runs while remaining available for comprehensive testing.
