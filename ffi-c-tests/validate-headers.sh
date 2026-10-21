#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEADER_TESTS_DIR="$SCRIPT_DIR/header-tests"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <include_dir>"
    exit 1
fi

INCLUDE_DIR="$1"

if [ ! -d "$INCLUDE_DIR" ]; then
    echo "Error: INCLUDE_DIR '$INCLUDE_DIR' does not exist or is not a directory."
    exit 1
fi

EXIT_CODE=0

for file in "$HEADER_TESTS_DIR"/*.c; do
    if gcc -c "$file" -I"$INCLUDE_DIR" -o /dev/null; then
      echo -e "${GREEN}Passed: $file${NC}"
    else
      echo -e "${RED}Failed: $file${NC}"
      EXIT_CODE=1
    fi
done

exit $EXIT_CODE
