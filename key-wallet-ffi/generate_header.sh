#!/bin/bash

# Script to generate C header file from Rust FFI code using cbindgen
# Usage: ./generate_header.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Generating C header file for key-wallet-ffi...${NC}"

# Check if cbindgen is installed
if ! command -v cbindgen &> /dev/null; then
    echo -e "${YELLOW}cbindgen is not installed. Installing...${NC}"
    cargo install cbindgen
fi

# Create include directory if it doesn't exist
mkdir -p include

# Generate the header file
echo -e "${GREEN}Running cbindgen...${NC}"
cbindgen \
    --config cbindgen.toml \
    --crate key-wallet-ffi \
    --output include/key_wallet_ffi.h \
    --lang c \
    .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Header file generated successfully at include/key_wallet_ffi.h${NC}"

    # Show statistics
    echo -e "${GREEN}Header file statistics:${NC}"
    echo "  Functions: $(grep -c "^[^/]*(" include/key_wallet_ffi.h 2>/dev/null || echo 0)"
    echo "  Structs:   $(grep -c "^typedef struct" include/key_wallet_ffi.h 2>/dev/null || echo 0)"
    echo "  Enums:     $(grep -c "^typedef enum" include/key_wallet_ffi.h 2>/dev/null || echo 0)"

else
    echo -e "${RED}✗ Failed to generate header file${NC}"
    exit 1
fi

# Optional: Verify the header compiles
echo -e "${GREEN}Verifying header compilation...${NC}"
cat > /tmp/test_header.c << EOF
#include "$(pwd)/include/key_wallet_ffi.h"
int main() { return 0; }
EOF

if cc -c /tmp/test_header.c -o /tmp/test_header.o 2>/dev/null; then
    echo -e "${GREEN}✓ Header file compiles successfully${NC}"
    rm -f /tmp/test_header.c /tmp/test_header.o
else
    echo -e "${YELLOW}⚠ Warning: Header file may have compilation issues${NC}"
    echo -e "${YELLOW}  This might be normal if some types are platform-specific${NC}"
    rm -f /tmp/test_header.c
fi

echo -e "${GREEN}Done!${NC}"
