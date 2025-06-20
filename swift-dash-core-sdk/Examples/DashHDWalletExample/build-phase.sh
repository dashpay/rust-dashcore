#!/bin/bash
# Build phase script to ensure library is available

# Create a local lib directory
mkdir -p "${BUILT_PRODUCTS_DIR}/lib"

# Copy the library files
cp /Users/quantum/src/rust-dashcore/target/release/libdash_spv_ffi.* "${BUILT_PRODUCTS_DIR}/lib/" || true

# Add to library search paths
export LIBRARY_SEARCH_PATHS="${BUILT_PRODUCTS_DIR}/lib:${LIBRARY_SEARCH_PATHS}"