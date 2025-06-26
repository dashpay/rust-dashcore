#!/bin/bash

# Test headers2 implementation

echo "🚀 Testing headers2 implementation..."
echo "This will connect to a mainnet Dash node and attempt to sync headers"
echo

cd dash-spv

# Run with debug logging to see detailed protocol messages
echo "Running test with debug logging..."
echo "Watch for:"
echo "  - 🤝 Sending SendHeaders2"
echo "  - 📤 Sending GetHeaders2"
echo "  - 📨 Received Headers2 message"
echo "  - ❌ Connection dropped"
echo

RUST_LOG=dash_spv=info cargo run --example test_headers2