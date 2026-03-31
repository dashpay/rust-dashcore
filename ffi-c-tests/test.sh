#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEADER_TESTS_DIR="$SCRIPT_DIR/header-tests"

TARGET_DIR="$SCRIPT_DIR/../target"
LIB_DIR="$TARGET_DIR/debug"

# Build FFI crates to generate static libraries and header files
cargo build -p dash-spv-ffi --profile dev
cargo build -p key-wallet-ffi --profile dev

# Move to ffi-c-tests directory, where the script lives, and run tests
cd "$SCRIPT_DIR" || exit 1

EXIT_CODE=0

for file in "$HEADER_TESTS_DIR"/*.c; do
    if gcc "$file" -o test.bin -g -L"$LIB_DIR" -ldash_spv_ffi -lkey_wallet_ffi; then
      echo -e "${GREEN}Passed: $file${NC}"
    else
      echo -e "${RED}Failed: $file${NC}"
      EXIT_CODE=1
    fi
done

rm -f test.bin

exit $EXIT_CODE
