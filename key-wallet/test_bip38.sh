#!/bin/bash

# BIP38 Test Runner Script
# 
# This script runs all BIP38-related tests that are normally ignored due to their
# slow execution time (caused by the computationally intensive scrypt algorithm).
#
# Usage: ./test_bip38.sh [additional cargo test options]

set -e  # Exit on error

echo "========================================="
echo "         BIP38 Test Runner"
echo "========================================="
echo ""
echo "Running BIP38 encryption/decryption tests..."
echo "Note: These tests are slow due to the scrypt algorithm"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to the script's directory
cd "$(dirname "$0")"

# Function to run tests and display results
run_test_module() {
    local module=$1
    local description=$2
    
    echo -e "${YELLOW}Running $description...${NC}"
    
    if cargo test --lib $module -- --ignored --nocapture "$@" 2>&1; then
        echo -e "${GREEN}✓ $description passed${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ $description failed${NC}"
        echo ""
        return 1
    fi
}

# Track overall test status
ALL_PASSED=true

# Run BIP38 tests in the main module
if ! run_test_module "bip38::tests::" "BIP38 core module tests"; then
    ALL_PASSED=false
fi

# Run BIP38 tests in the separate test file
if ! run_test_module "bip38_tests::" "BIP38 comprehensive tests"; then
    ALL_PASSED=false
fi

# Also run any BIP38 tests that might be in wallet module
if cargo test --lib wallet::bip38 -- --ignored --nocapture "$@" 2>&1 | grep -q "test result"; then
    echo -e "${YELLOW}Running wallet BIP38 tests...${NC}"
    if ! cargo test --lib wallet::bip38 -- --ignored --nocapture "$@" 2>&1; then
        ALL_PASSED=false
    fi
fi

echo "========================================="

# Display final summary
if [ "$ALL_PASSED" = true ]; then
    echo -e "${GREEN}All BIP38 tests passed successfully!${NC}"
    exit 0
else
    echo -e "${RED}Some BIP38 tests failed. Please review the output above.${NC}"
    exit 1
fi