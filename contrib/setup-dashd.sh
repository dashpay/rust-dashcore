#!/usr/bin/env bash
# Setup and download script for dashd and test blockchain data for integration tests.
#
# Usage:
#   ./contrib/setup-dashd.sh
#
# Environment variables:
#   DASHVERSION        - Dash Core version (default: 23.0.2)
#   TEST_DATA_VERSION  - Test data release version (default: v0.0.1)
#   TEST_DATA_REPO     - GitHub repo for test data (default: xdustinface/regtest-blockchain)
#   CACHE_DIR          - Cache directory (default: ~/.cache/rust-dashcore-test)

set -euo pipefail

DASHVERSION="${DASHVERSION:-23.0.2}"
TEST_DATA_VERSION="${TEST_DATA_VERSION:-v0.0.1}"
TEST_DATA_REPO="${TEST_DATA_REPO:-xdustinface/regtest-blockchain}"

CACHE_DIR="${CACHE_DIR:-$HOME/.rust-dashcore-test}"

# Detect platform and set asset name
case "$(uname -s)" in
  Linux*)
    DASHD_ASSET="dashcore-${DASHVERSION}-x86_64-linux-gnu.tar.gz"
    ;;
  Darwin*)
    case "$(uname -m)" in
      arm64) DASHD_ASSET="dashcore-${DASHVERSION}-arm64-apple-darwin.tar.gz" ;;
      *)     DASHD_ASSET="dashcore-${DASHVERSION}-x86_64-apple-darwin.tar.gz" ;;
    esac
    ;;
  *)
    echo "Unsupported platform: $(uname -s)"
    exit 1
    ;;
esac

mkdir -p "$CACHE_DIR"

# Download dashd if not cached
DASHD_DIR="$CACHE_DIR/dashcore-${DASHVERSION}"
DASHD_BIN="$DASHD_DIR/bin/dashd"
if [ -x "$DASHD_BIN" ]; then
  echo "dashd ${DASHVERSION} already available"
else
  echo "Downloading dashd ${DASHVERSION}..."
  curl -L "https://github.com/dashpay/dash/releases/download/v${DASHVERSION}/${DASHD_ASSET}" \
    -o "$CACHE_DIR/${DASHD_ASSET}"
  tar -xzf "$CACHE_DIR/${DASHD_ASSET}" -C "$CACHE_DIR"
  rm "$CACHE_DIR/${DASHD_ASSET}"
  echo "Downloaded dashd to $DASHD_DIR"
fi

# Download test data if not cached
TEST_DATA_DIR="$CACHE_DIR/regtest-blockchain-${TEST_DATA_VERSION}/regtest-1000"
if [ -d "$TEST_DATA_DIR/regtest/blocks" ]; then
  echo "Test blockchain data ${TEST_DATA_VERSION} already available"
else
  echo "Downloading test blockchain data ${TEST_DATA_VERSION}..."
  mkdir -p "$CACHE_DIR/regtest-blockchain-${TEST_DATA_VERSION}"
  curl -L "https://github.com/${TEST_DATA_REPO}/releases/download/${TEST_DATA_VERSION}/regtest-1000.tar.gz" \
    -o "$CACHE_DIR/regtest-1000.tar.gz"
  tar -xzf "$CACHE_DIR/regtest-1000.tar.gz" -C "$CACHE_DIR/regtest-blockchain-${TEST_DATA_VERSION}"
  rm "$CACHE_DIR/regtest-1000.tar.gz"
  echo "Downloaded test data to $TEST_DATA_DIR"
fi

# Set environment variables
export DASHD_PATH="$DASHD_DIR/bin/dashd"
export DASHD_DATADIR="$TEST_DATA_DIR"

echo ""
echo "Environment configured:"
echo "  DASHD_PATH=$DASHD_PATH"
echo "  DASHD_DATADIR=$DASHD_DATADIR"
echo ""

# Reset strict mode (important when sourcing)
set +euo pipefail
