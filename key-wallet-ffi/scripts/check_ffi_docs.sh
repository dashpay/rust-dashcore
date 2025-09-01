#!/bin/bash

# Check if FFI documentation is up to date

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Checking FFI documentation..."

cd "$PROJECT_DIR"

# Generate new documentation
python3 scripts/generate_ffi_docs.py > /dev/null 2>&1

# Check if there are any changes (tracked, staged, or untracked)
if ! git diff --quiet --exit-code -- FFI_API.md \
   || ! git diff --quiet --cached -- FFI_API.md \
   || [ -n "$(git ls-files --others --exclude-standard -- FFI_API.md)" ]; then
    echo "❌ FFI documentation is out of date!"
    echo ""
    echo "Please regenerate the documentation by running:"
    echo "  cd key-wallet-ffi && python3 scripts/generate_ffi_docs.py"
    echo ""
    echo "Or use the make command:"
    echo "  make update-ffi-docs"
    echo ""
    exit 1
else
    echo "✅ FFI documentation is up to date"
fi
