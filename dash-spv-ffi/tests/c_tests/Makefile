# Makefile for Dash SPV FFI C tests

# Build profile (can be overridden: make PROFILE=release)
PROFILE ?= debug

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -I../.. -I../../../key-wallet-ffi/include -g -O0
LDFLAGS = -L../../../target/$(PROFILE) -ldash_spv_ffi -lkey_wallet_ffi -lpthread -ldl -lm

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS += -Wl,-rpath,../../../target/$(PROFILE)
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -Wl,-rpath,@loader_path/../../../target/$(PROFILE)
endif

# Test programs
TESTS = test_basic test_advanced test_integration test_event_draining test_configuration

# Build all tests
all: $(TESTS)

# Build individual tests
test_basic: test_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_advanced: test_advanced.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_integration: test_integration.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_event_draining: test_event_draining.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_configuration: test_configuration.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Run all tests
test: all
	@echo "Running C tests..."
	@for test in $(TESTS); do \
		if [ -f $$test ]; then \
			echo "\nRunning $$test:"; \
			./$$test || exit 1; \
		fi; \
	done
	@echo "\nAll C tests passed!"

# Clean build artifacts
clean:
	rm -f $(TESTS) *.o

# Generate header file
header:
	cd ../.. && cbindgen --config cbindgen.toml --crate dash-spv-ffi --output dash_spv_ffi.h

# Build Rust library first
rust-lib:
ifeq ($(PROFILE),release)
	cd ../.. && cargo build --release
else
	cd ../.. && cargo build
endif

# Full build: Rust library, header, then tests
full: rust-lib header all

.PHONY: all test clean header rust-lib full
