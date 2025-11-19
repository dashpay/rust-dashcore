# CI Testing Configuration

## Skipping BIP38 Tests in CI

BIP38 tests use scrypt for key derivation which is intentionally slow (for security). These tests can take several minutes to complete, making them unsuitable for CI environments.

To skip BIP38 tests during CI runs, use the `--cfg ci` flag:

```bash
# Run tests with BIP38 tests skipped
RUSTFLAGS="--cfg ci" cargo test -p key-wallet

# Or for all tests in the workspace
RUSTFLAGS="--cfg ci" cargo test
```

The BIP38 tests are marked with:
```rust
#[cfg_attr(ci, ignore = "BIP38 tests are slow and skipped in CI")]
```

This means they will be ignored when the `ci` cfg flag is set, but will run normally during local development.

## GitHub Actions Example

In your GitHub Actions workflow:

```yaml
- name: Run tests
  env:
    RUSTFLAGS: "--cfg ci"
  run: cargo test --workspace
```

## Local Testing

To run all tests including BIP38 locally:
```bash
cargo test -p key-wallet
```

To simulate CI and skip BIP38 tests locally:
```bash
RUSTFLAGS="--cfg ci" cargo test -p key-wallet
```
