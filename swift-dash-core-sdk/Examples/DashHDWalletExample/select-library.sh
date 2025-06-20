#!/bin/bash
# Script to select the correct library based on SDK

# Print debug info
echo "SDK_NAME: $SDK_NAME"
echo "PLATFORM_NAME: $PLATFORM_NAME"
echo "Current directory: $(pwd)"

# Check if files exist
if [ ! -f "libdash_spv_ffi_ios.a" ]; then
    echo "ERROR: libdash_spv_ffi_ios.a not found!"
    exit 1
fi

if [ ! -f "libdash_spv_ffi_sim.a" ]; then
    echo "ERROR: libdash_spv_ffi_sim.a not found!"
    exit 1
fi

# Select the appropriate library
if [ "$SDK_NAME" = "iphoneos" ] || [ "$PLATFORM_NAME" = "iphoneos" ]; then
    echo "Using iOS device library"
    cp -f libdash_spv_ffi_ios.a libdash_spv_ffi.a
else
    echo "Using iOS simulator library"
    cp -f libdash_spv_ffi_sim.a libdash_spv_ffi.a
fi

# Verify the copy worked
if [ -f "libdash_spv_ffi.a" ]; then
    echo "Successfully created libdash_spv_ffi.a"
else
    echo "ERROR: Failed to create libdash_spv_ffi.a"
    exit 1
fi