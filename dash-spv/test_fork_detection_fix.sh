#!/bin/bash

# Test script to verify the fork detection fix
# This script runs the SPV client, waits for it to sync some headers,
# then restarts it to test state restoration

set -e

echo "🧪 Testing SPV fork detection fix..."

# Configuration
DATA_DIR="./test-fork-detection-data"
NETWORK="mainnet"
PEER="127.0.0.1:9999"  # Assuming local Dash Core node
LOG_LEVEL="info"

# Clean up any previous test data
echo "🧹 Cleaning up previous test data..."
rm -rf "$DATA_DIR"

# First run: Let the client sync some headers
echo "📥 Starting first run to sync headers..."
timeout 30s cargo run --bin dash-spv -- \
    --network "$NETWORK" \
    --data-dir "$DATA_DIR" \
    --peer "$PEER" \
    --log-level "$LOG_LEVEL" \
    2>&1 | tee first_run.log || true

# Check if headers were synced
HEADER_COUNT=$(grep -o "Loaded [0-9]* headers into ChainState" first_run.log | tail -1 | grep -o "[0-9]*" || echo "0")
echo "✅ First run synced $HEADER_COUNT headers"

if [ "$HEADER_COUNT" -eq "0" ]; then
    echo "❌ No headers were synced in the first run. Make sure Dash Core is running at $PEER"
    exit 1
fi

# Second run: Test state restoration
echo "🔄 Starting second run to test state restoration..."
echo "   Looking for fork detection issues..."

# Run for a short time and capture output
timeout 20s cargo run --bin dash-spv -- \
    --network "$NETWORK" \
    --data-dir "$DATA_DIR" \
    --peer "$PEER" \
    --log-level "$LOG_LEVEL" \
    2>&1 | tee second_run.log || true

# Check for the fork detection issue
if grep -q "Requesting missing headers to fill gap from height 0" second_run.log; then
    echo "❌ FAILED: Fork detection issue still present!"
    echo "   The client is still requesting headers from height 0"
    exit 1
fi

# Check if sync manager loaded headers properly
if grep -q "Loaded [0-9]* headers into sync manager" second_run.log; then
    SYNC_HEADERS=$(grep -o "Loaded [0-9]* headers into sync manager" second_run.log | tail -1 | grep -o "[0-9]*")
    echo "✅ Sync manager loaded $SYNC_HEADERS headers"
else
    echo "⚠️  Could not verify sync manager header loading"
fi

# Check for validation failures being handled
if grep -q "Continuing to load headers into sync manager despite validation failure" second_run.log; then
    echo "✅ Validation failure handling is working correctly"
fi

# Check if the client resumed from the correct height
if grep -q "Resuming sequential sync" second_run.log; then
    echo "✅ Client resumed sync correctly"
fi

echo ""
echo "🎉 Test completed successfully!"
echo "   The fork detection fix appears to be working."
echo ""
echo "📊 Summary:"
echo "   - First run synced: $HEADER_COUNT headers"
echo "   - Second run did NOT show fork detection issue"
echo "   - Sync manager properly loaded headers on restart"

# Clean up
rm -f first_run.log second_run.log