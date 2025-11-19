#!/usr/bin/env bash

set -xe
set -o pipefail

# Just echo all the relevant env vars to help debug.
echo "DASHVERSION: \"$DASHVERSION\""
echo "PATH: \"$PATH\""


# Pin dependencies for Rust v1.29
if [ -n "$PIN_VERSIONS" ]; then
    cargo generate-lockfile --verbose

    cargo update --verbose --package "log" --precise "0.4.13"
    cargo update --verbose --package "cc" --precise "1.0.41"
    cargo update --verbose --package "cfg-if" --precise "0.1.9"
    cargo update --verbose --package "serde_json" --precise "1.0.39"
    cargo update --verbose --package "serde" --precise "1.0.98"
    cargo update --verbose --package "serde_derive" --precise "1.0.98"
    cargo update --verbose --package "byteorder" --precise "1.3.4"
fi

# Integration test.
if [ -n "$DASHVERSION" ]; then
    ASSET="dashcore-$DASHVERSION-x86_64-linux-gnu.tar.gz"

    # Download the Dash binary
    echo "Downloading $ASSET..."
    if ! wget "https://github.com/dashpay/dash/releases/download/v$DASHVERSION/$ASSET"; then
        echo "Error: Failed to download $ASSET" >&2
        exit 1
    fi

    # Verify the downloaded file exists
    if [ ! -f "$ASSET" ]; then
        echo "Error: Downloaded file $ASSET not found" >&2
        exit 1
    fi

    # Extract and determine the actual extracted directory
    echo "Extracting $ASSET..."
    if ! tar -xzvf "$ASSET"; then
        echo "Error: Failed to extract $ASSET" >&2
        exit 1
    fi

    # Find the extracted directory (should be dashcore-$DASHVERSION)
    EXTRACT_DIR="dashcore-$DASHVERSION"
    if [ ! -d "$EXTRACT_DIR" ]; then
        echo "Error: Expected directory $EXTRACT_DIR not found after extraction" >&2
        exit 1
    fi

    # Add the bin directory to PATH (avoid SC2155)
    DASH_BIN_PATH="$(pwd)/$EXTRACT_DIR/bin"
    PATH="$PATH:$DASH_BIN_PATH"
    export PATH

    echo "Added $DASH_BIN_PATH to PATH"

    # Change to the correct integration test directory
    if [ -d "rpc-integration-test" ]; then
        cd rpc-integration-test
    else
        echo "Error: rpc-integration-test directory not found" >&2
        exit 1
    fi

    # Run the integration tests
    if [ -f "./run.sh" ]; then
        ./run.sh
    else
        echo "Error: run.sh script not found in rpc-integration-test" >&2
        exit 1
    fi

    exit 0
else
  # Regular build/unit test.
  cargo build --verbose
  cargo test --verbose
  cargo build --verbose --examples
fi
