.PHONY: all build test clean docs check-docs update-docs

# Default target
all: build

# Build the library
build:
	cargo build --release

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean
	rm -f include/dash_spv_ffi.h

# Generate C header
header:
	cargo build --release
	@echo "Generated header at include/dash_spv_ffi.h"

# Update FFI documentation
update-docs:
	@echo "Generating FFI API documentation..."
	@python3 scripts/generate_ffi_docs.py
	@echo "Documentation updated at FFI_API.md"

# Check if FFI documentation is up to date
check-docs:
	@bash scripts/check_ffi_docs.sh

# Generate all documentation
docs: header update-docs
	@echo "All documentation generated"

# Build for iOS
ios:
	cargo build --release --target aarch64-apple-ios
	cargo build --release --target aarch64-apple-ios-sim
	cargo build --release --target x86_64-apple-ios

# Full build with documentation
full: clean build header update-docs
	@echo "Full build complete with documentation"

# Help
help:
	@echo "Available targets:"
	@echo "  make build       - Build the library"
	@echo "  make test        - Run tests"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make header      - Generate C header"
	@echo "  make update-docs - Update FFI API documentation"
	@echo "  make check-docs  - Check if FFI docs are up to date"
	@echo "  make docs        - Generate all documentation"
	@echo "  make ios         - Build for iOS platforms"
	@echo "  make full        - Full build with documentation"
	@echo "  make help        - Show this help message"
