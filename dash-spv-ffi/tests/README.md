# Dash SPV FFI Test Suite

This directory contains a comprehensive test suite for the dash-spv-ffi crate, covering all aspects of the FFI bindings.

## Test Categories

### 1. Unit Tests (`unit/`)
Located in the source tree and included via `src/lib.rs`.

- **test_type_conversions.rs**: Tests FFI type conversions, string handling, array operations, and edge cases
- **test_error_handling.rs**: Tests error propagation, thread-local error storage, and error code mappings
- **test_configuration.rs**: Tests configuration creation, validation, and parameter handling
- **test_client_lifecycle.rs**: Tests client creation, destruction, state management, and concurrent operations
- **test_async_operations.rs**: Tests callback mechanisms, event handling, and async operation patterns
- **test_wallet_operations.rs**: Tests address/script watching, balance queries, transaction operations
- **test_memory_management.rs**: Tests memory allocation, deallocation, alignment, and leak prevention

### 2. Integration Tests (`integration/`)
End-to-end tests that verify complete workflows.

- **test_full_workflow.rs**: Tests complete sync workflows, wallet monitoring, transaction broadcast
- **test_cross_language.rs**: Tests C compatibility, struct alignment, calling conventions

### 3. Performance Tests (`performance/`)
Benchmarks and performance measurements.

- **test_benchmarks.rs**: Measures performance of string/array allocation, type conversions, concurrent operations

### 4. Security Tests (`security/`)
Security-focused tests for vulnerability prevention.

- **test_security.rs**: Tests buffer overflow protection, null pointer handling, input validation, DoS resistance

### 5. C Test Suite (`c_tests/`)
Native C tests to verify the FFI interface from C perspective.

- **test_basic.c**: Basic functionality tests (config, client creation, error handling)
- **test_advanced.c**: Advanced features (wallet ops, concurrency, callbacks)
- **test_integration.c**: Integration scenarios (full workflow, persistence, transactions)
- **Makefile**: Build system for C tests

## Running the Tests

### Rust Tests
```bash
# Run all Rust tests
cargo test -p dash-spv-ffi

# Run specific test category
cargo test -p dash-spv-ffi test_type_conversions
cargo test -p dash-spv-ffi test_memory_management

# Run with output
cargo test -p dash-spv-ffi -- --nocapture
```

### C Tests
```bash
cd tests/c_tests

# Build Rust library first
make rust-lib

# Generate C header
make header

# Build and run all C tests
make test

# Run individual C test
make test_basic
./test_basic
```

## Test Coverage

The test suite covers:

1. **API Surface**: All public FFI functions
2. **Error Conditions**: Null pointers, invalid inputs, error propagation
3. **Memory Safety**: Allocation, deallocation, alignment, leaks
4. **Thread Safety**: Concurrent access, race conditions
5. **Cross-Language**: C compatibility, struct layout, calling conventions
6. **Performance**: Throughput, latency, scalability
7. **Security**: Input validation, buffer overflows, DoS resistance
8. **Integration**: Real-world usage patterns, persistence, network operations

## Adding New Tests

When adding new functionality to dash-spv-ffi:

1. Add unit tests in the appropriate `unit/test_*.rs` file
2. Add integration tests if the feature involves multiple components
3. Add C tests to verify the C API works correctly
4. Add performance benchmarks for performance-critical operations
5. Add security tests for any input validation or unsafe operations

## Test Dependencies

- `serial_test`: Ensures tests run serially to avoid conflicts
- `tempfile`: Creates temporary directories for test data
- `env_logger`: Optional logging for debugging

## Known Limitations

Some tests may fail in environments without network access or when dash-spv services are unavailable. These tests are designed to handle such failures gracefully.