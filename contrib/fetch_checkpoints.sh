#!/bin/sh
# Fetch checkpoint data from Dash network
#
# This script fetches block information at specific heights to create checkpoints
# for the rust-dashcore SPV client.
#
# Usage:
#   # Fetch specific heights using block explorer
#   ./fetch_checkpoints.sh mainnet 2400000 2450000
#
#   # Fetch using RPC (requires running Dash Core node)
#   RPC_URL=http://localhost:9998 RPC_USER=user RPC_PASS=pass ./fetch_checkpoints.sh mainnet 2400000

set -e

NETWORK=${1:-mainnet}
shift || true

# Configuration
if [ "$NETWORK" = "mainnet" ]; then
    EXPLORER_URL="https://insight.dash.org/insight-api"
elif [ "$NETWORK" = "testnet" ]; then
    EXPLORER_URL="https://testnet-insight.dashevo.org/insight-api"
else
    echo "Error: Invalid network. Use 'mainnet' or 'testnet'"
    exit 1
fi

# Check for required tools
if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required but not installed"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required but not installed. Install with: sudo apt install jq"
    exit 1
fi

# Function to get current blockchain height
get_current_height() {
    if [ -n "$RPC_URL" ] && [ -n "$RPC_USER" ] && [ -n "$RPC_PASS" ]; then
        # Use RPC
        curl -s -u "$RPC_USER:$RPC_PASS" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":"checkpoint","method":"getblockchaininfo","params":[]}' \
            "$RPC_URL" | jq -r '.result.blocks'
    else
        # Use explorer
        curl -s "$EXPLORER_URL/status?q=getInfo" | jq -r '.info.blocks'
    fi
}

# Function to get block by height using explorer
get_block_explorer() {
    height=$1

    # Get block hash at height
    block_hash=$(curl -s "$EXPLORER_URL/block-index/$height" | jq -r '.blockHash')

    if [ -z "$block_hash" ] || [ "$block_hash" = "null" ]; then
        echo "Error: Failed to get block hash for height $height" >&2
        return 1
    fi

    # Get full block data
    curl -s "$EXPLORER_URL/block/$block_hash"
}

# Function to get block by height using RPC
get_block_rpc() {
    height=$1

    # Get block hash
    block_hash=$(curl -s -u "$RPC_USER:$RPC_PASS" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"checkpoint\",\"method\":\"getblockhash\",\"params\":[$height]}" \
        "$RPC_URL" | jq -r '.result')

    if [ -z "$block_hash" ] || [ "$block_hash" = "null" ]; then
        echo "Error: Failed to get block hash for height $height" >&2
        return 1
    fi

    # Get block data
    curl -s -u "$RPC_USER:$RPC_PASS" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"checkpoint\",\"method\":\"getblock\",\"params\":[\"$block_hash\",2]}" \
        "$RPC_URL" | jq -r '.result'
}

# Function to format checkpoint as Rust code
format_checkpoint() {
    block_json=$1

    height=$(echo "$block_json" | jq -r '.height')
    hash=$(echo "$block_json" | jq -r '.hash')
    prev_hash=$(echo "$block_json" | jq -r '.previousblockhash // "0000000000000000000000000000000000000000000000000000000000000000"')
    timestamp=$(echo "$block_json" | jq -r '.time')
    bits=$(echo "$block_json" | jq -r '.bits')
    merkle_root=$(echo "$block_json" | jq -r '.merkleroot')
    nonce=$(echo "$block_json" | jq -r '.nonce')
    chain_work=$(echo "$block_json" | jq -r '.chainwork // "0x0000000000000000000000000000000000000000000000000000000000000000"')

    # Ensure chainwork has 0x prefix
    if ! echo "$chain_work" | grep -q "^0x"; then
        chain_work="0x$chain_work"
    fi

    # Convert bits to hex format
    if echo "$bits" | grep -q "^[0-9a-fA-F]\+$"; then
        bits_hex="0x$bits"
    else
        bits_hex="$bits"
    fi

    # Format as Rust code
    cat <<EOF
        // Block $height ($hash)
        create_checkpoint(
            $height,
            "$hash",
            "$prev_hash",
            $timestamp,
            $bits_hex,
            "$chain_work",
            "$merkle_root",
            $nonce,
            None,  // TODO: Add masternode list if available (format: Some("ML${height}__<protocol_version>"))
        ),
EOF
}

# Main script
echo "Fetching checkpoints for $NETWORK..." >&2
echo "" >&2

# Get current height
current_height=$(get_current_height)
if [ -z "$current_height" ]; then
    echo "Error: Failed to get current blockchain height" >&2
    exit 1
fi
echo "Current blockchain height: $current_height" >&2
echo "" >&2

# If no heights specified, show usage
if [ $# -eq 0 ]; then
    echo "Usage: $0 <network> <height1> [height2] [height3] ..." >&2
    echo "" >&2
    echo "Current height: $current_height" >&2
    echo "Suggested checkpoint heights:" >&2
    if [ "$NETWORK" = "mainnet" ]; then
        echo "  2400000 - Block 2.4M" >&2
        echo "  2450000 - Block 2.45M" >&2
        echo "  2500000 - Block 2.5M (if available)" >&2
    else
        echo "  1200000 - Block 1.2M" >&2
        echo "  1300000 - Block 1.3M" >&2
    fi
    echo "" >&2
    echo "Examples:" >&2
    echo "  $0 mainnet 2400000" >&2
    echo "  RPC_URL=http://localhost:9998 RPC_USER=user RPC_PASS=pass $0 mainnet 2400000" >&2
    exit 1
fi

# Output header
echo "// Generated checkpoints for $NETWORK"
echo "// Add these to dash-spv/src/chain/checkpoints.rs"
echo ""

# Fetch each requested height
for height in "$@"; do
    if [ "$height" -gt "$current_height" ]; then
        echo "// Skipping height $height (exceeds current height $current_height)"
        continue
    fi

    echo "Fetching block at height $height..." >&2

    # Get block data
    if [ -n "$RPC_URL" ] && [ -n "$RPC_USER" ] && [ -n "$RPC_PASS" ]; then
        block_data=$(get_block_rpc "$height")
    else
        block_data=$(get_block_explorer "$height")
    fi

    if [ $? -ne 0 ] || [ -z "$block_data" ]; then
        echo "// Error: Failed to fetch block at height $height"
        continue
    fi

    # Format and output
    format_checkpoint "$block_data"
done

echo ""
echo "// NOTE: Update masternode_list_name values if the blocks have DML (Deterministic Masternode List)"
echo "// Check coinbase transaction for masternode list information"
