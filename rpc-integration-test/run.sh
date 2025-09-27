#!/bin/sh

set -e

TESTDIR=/tmp/rust_dashcore_rpc_test

rm -rf "${TESTDIR}"
mkdir -p "${TESTDIR}/dash"

# Kill any remaining dashd to avoid port conflicts
if command -v killall >/dev/null 2>&1; then
  killall -9 dashd 2>/dev/null || true
fi

# Start Dash Core on regtest using standard Dash RPC port 19898
dashd -regtest \
  -datadir="${TESTDIR}/dash" \
  -rpcport=19898 \
  -server=1 \
  -txindex=1 \
  -printtoconsole=0 &
PID=$!

# Allow time for startup
sleep 5

# Pre-create faucet wallet "main" so the test can fund addresses
dash-cli -regtest -datadir="${TESTDIR}/dash" -rpcport=19898 -named createwallet wallet_name=main descriptors=false >/dev/null 2>&1 || true

# Fund the faucet wallet with mature coins
FAUCET_ADDR=$(dash-cli -regtest -datadir="${TESTDIR}/dash" -rpcport=19898 -rpcwallet=main getnewaddress)
dash-cli -regtest -datadir="${TESTDIR}/dash" -rpcport=19898 generatetoaddress 110 "$FAUCET_ADDR" >/dev/null

# Export per-node env vars expected by the test (both point to same node)
export WALLET_NODE_RPC_URL="http://127.0.0.1:19898"
export EVO_NODE_RPC_URL="http://127.0.0.1:19898"
export WALLET_NODE_RPC_COOKIE="${TESTDIR}/dash/regtest/.cookie"
export EVO_NODE_RPC_COOKIE="${TESTDIR}/dash/regtest/.cookie"

cargo run

RESULT=$?

kill -9 $PID 2>/dev/null || true

exit $RESULT
