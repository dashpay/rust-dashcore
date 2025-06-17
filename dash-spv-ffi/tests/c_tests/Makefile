# Makefile for Dash SPV FFI C tests

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -I../.. -g -O0
LDFLAGS = -L../../target/debug -ldash_spv_ffi -lpthread -ldl -lm

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS += -Wl,-rpath,../../target/debug
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -Wl,-rpath,@loader_path/../../target/debug
endif

# Test programs
TESTS = test_basic test_advanced test_integration

# Build all tests
all: $(TESTS)

# Build individual tests
test_basic: test_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_advanced: test_advanced.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_integration: test_integration.c
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
	cd ../.. && cargo build

# Full build: Rust library, header, then tests
full: rust-lib header all

.PHONY: all test clean header rust-lib full