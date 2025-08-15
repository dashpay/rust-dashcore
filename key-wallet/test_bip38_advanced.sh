#!/bin/bash

# Advanced BIP38 Test Runner Script
# 
# This script provides more control over running BIP38 tests with various options.
#
# Usage: 
#   ./test_bip38_advanced.sh              # Run all BIP38 tests
#   ./test_bip38_advanced.sh --quick      # Run only quick BIP38 tests (skip performance)
#   ./test_bip38_advanced.sh --single <test_name>  # Run a specific test
#   ./test_bip38_advanced.sh --verbose    # Run with verbose output
#   ./test_bip38_advanced.sh --release    # Run tests in release mode (faster)

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default settings
VERBOSE=false
RELEASE_MODE=false
QUICK_MODE=false
SINGLE_TEST=""
SHOW_TIMING=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --release|-r)
            RELEASE_MODE=true
            shift
            ;;
        --quick|-q)
            QUICK_MODE=true
            shift
            ;;
        --single|-s)
            SINGLE_TEST="$2"
            shift 2
            ;;
        --timing|-t)
            SHOW_TIMING=true
            shift
            ;;
        --help|-h)
            echo "Advanced BIP38 Test Runner"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v      Show detailed test output"
            echo "  --release, -r      Run tests in release mode (faster execution)"
            echo "  --quick, -q        Skip slow tests (performance tests)"
            echo "  --single, -s TEST  Run only the specified test"
            echo "  --timing, -t       Show timing information for each test"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Run all BIP38 tests"
            echo "  $0 --release --verbose                # Fast mode with details"
            echo "  $0 --single test_bip38_encryption     # Run specific test"
            echo "  $0 --quick                            # Skip slow tests"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Change to the script's directory
cd "$(dirname "$0")"

echo "========================================="
echo "      Advanced BIP38 Test Runner"
echo "========================================="
echo ""

# Build configuration string
CONFIG=""
if [ "$RELEASE_MODE" = true ]; then
    CONFIG="$CONFIG --release"
    echo -e "${CYAN}Mode: Release (optimized)${NC}"
else
    echo -e "${CYAN}Mode: Debug${NC}"
fi

if [ "$VERBOSE" = true ]; then
    echo -e "${CYAN}Output: Verbose${NC}"
else
    CONFIG="$CONFIG --quiet"
    echo -e "${CYAN}Output: Summary only${NC}"
fi

if [ "$QUICK_MODE" = true ]; then
    echo -e "${CYAN}Test Set: Quick tests only${NC}"
fi

if [ -n "$SINGLE_TEST" ]; then
    echo -e "${CYAN}Running single test: $SINGLE_TEST${NC}"
fi

echo ""
echo "========================================="
echo ""

# Function to format duration
format_duration() {
    local duration=$1
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    if [ $minutes -gt 0 ]; then
        echo "${minutes}m ${seconds}s"
    else
        echo "${seconds}s"
    fi
}

# Function to run a test or test module
run_test() {
    local test_pattern=$1
    local description=$2
    local start_time=$(date +%s)
    
    echo -e "${YELLOW}Running: $description${NC}"
    
    # Build the test command
    local cmd="cargo test $CONFIG --lib $test_pattern -- --ignored"
    
    if [ "$VERBOSE" = true ]; then
        cmd="$cmd --nocapture"
    fi
    
    # Execute the test
    if eval $cmd 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [ "$SHOW_TIMING" = true ]; then
            echo -e "${GREEN}✓ $description passed${NC} ($(format_duration $duration))"
        else
            echo -e "${GREEN}✓ $description passed${NC}"
        fi
        echo ""
        return 0
    else
        echo -e "${RED}✗ $description failed${NC}"
        echo ""
        return 1
    fi
}

# Track test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
FAILED_TEST_NAMES=()

# Start timing
OVERALL_START=$(date +%s)

# If running a single test
if [ -n "$SINGLE_TEST" ]; then
    if run_test "$SINGLE_TEST" "$SINGLE_TEST"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$SINGLE_TEST")
    fi
    TOTAL_TESTS=1
else
    # List of test modules and their descriptions
    declare -A TEST_MODULES=(
        ["bip38::tests::test_bip38_encryption"]="Basic encryption test"
        ["bip38::tests::test_bip38_decryption"]="Basic decryption test"
        ["bip38::tests::test_bip38_compressed_uncompressed"]="Compressed/uncompressed key test"
        ["bip38::tests::test_bip38_builder"]="Builder pattern test"
        ["bip38::tests::test_intermediate_code_generation"]="Intermediate code generation"
        ["bip38::tests::test_address_hash"]="Address hash calculation"
        ["bip38::tests::test_scrypt_parameters"]="Scrypt parameter validation"
        ["bip38_tests::tests::test_bip38_encryption_no_compression"]="No compression encryption"
        ["bip38_tests::tests::test_bip38_encryption_with_compression"]="With compression encryption"
        ["bip38_tests::tests::test_bip38_wrong_password"]="Wrong password handling"
        ["bip38_tests::tests::test_bip38_scrypt_parameters"]="Scrypt parameters comprehensive"
        ["bip38_tests::tests::test_bip38_unicode_password"]="Unicode password support"
        ["bip38_tests::tests::test_bip38_network_differences"]="Network-specific encryption"
        ["bip38_tests::tests::test_bip38_edge_cases"]="Edge case handling"
        ["bip38_tests::tests::test_bip38_round_trip"]="Round-trip encryption/decryption"
        ["bip38_tests::tests::test_bip38_invalid_prefix"]="Invalid prefix handling"
    )
    
    # Add performance test if not in quick mode
    if [ "$QUICK_MODE" = false ]; then
        TEST_MODULES["bip38_tests::tests::test_bip38_performance"]="Performance benchmark"
    fi
    
    # Run each test module
    for test in "${!TEST_MODULES[@]}"; do
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        if run_test "$test" "${TEST_MODULES[$test]}"; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_TEST_NAMES+=("$test")
        fi
    done
fi

# Calculate overall duration
OVERALL_END=$(date +%s)
OVERALL_DURATION=$((OVERALL_END - OVERALL_START))

# Display summary
echo "========================================="
echo -e "${BLUE}           Test Summary${NC}"
echo "========================================="
echo ""
echo -e "Total tests run: ${CYAN}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ "$SHOW_TIMING" = true ]; then
    echo -e "Total time: ${CYAN}$(format_duration $OVERALL_DURATION)${NC}"
fi

echo ""

# Show failed tests if any
if [ ${#FAILED_TEST_NAMES[@]} -gt 0 ]; then
    echo -e "${RED}Failed tests:${NC}"
    for test in "${FAILED_TEST_NAMES[@]}"; do
        echo -e "  ${RED}• $test${NC}"
    done
    echo ""
fi

# Exit with appropriate code
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All BIP38 tests passed successfully! 🎉${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the output above.${NC}"
    exit 1
fi