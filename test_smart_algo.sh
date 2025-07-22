#!/bin/bash
# Test the smart algorithm with debug logging enabled

# Enable debug logging for the relevant modules
export RUST_LOG=dash_spv::sync::masternodes=debug,dash_spv::sync::sequential=debug

# Run with checkpoint at 1100000 to trigger the smart algorithm for the range 1260302-1290302
./target/debug/dash-spv \
    --network testnet \
    --data-dir ./test-smart-algo \
    --checkpoint 1100000 \
    --checkpoint-hash 00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c \
    2>&1 | tee smart_algo_debug.log

echo "Debug log saved to smart_algo_debug.log"