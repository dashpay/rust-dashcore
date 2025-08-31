#!/bin/bash

# Check if FFI documentation is up to date

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Checking FFI documentation..."

cd "$PROJECT_DIR"

# Generate new documentation
python3 scripts/generate_ffi_docs.py > /dev/null 2>&1

# Check if there are any changes
if ! git diff --quiet FFI_API.md; then
    echo "❌ FFI documentation is out of date!"
    echo ""
    echo "Please regenerate the documentation by running:"
    echo "  cd dash-spv-ffi && python3 scripts/generate_ffi_docs.py"
    echo ""
    echo "Or use the make command:"
    echo "  make update-docs"
    echo ""
    exit 1
else
    echo "✅ FFI documentation is up to date"
fi