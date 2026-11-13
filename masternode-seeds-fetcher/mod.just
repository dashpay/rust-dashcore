# Seed fetcher recipes, run as `just masternode-seeds-fetcher::<recipe>`

import "../mod.just"

seeds := root / "dash-network-seeds" / "seeds"

export RUST_LOG := env("RUST_LOG", "info")

# Refresh one network's seed file from the live P2P network
refresh network="mainnet" concurrency="100":
    cargo run --release -p masternode-seeds-fetcher -- \
        --network {{ network }} \
        --out {{ quote(seeds / network + ".txt") }} \
        --max-peers 16 \
        --probe-concurrency {{ concurrency }}

# Refresh both networks' seed files, then check they still parse
refresh-all: (refresh "mainnet" "100") (refresh "testnet" "64")
    cargo test -p dash-network-seeds --lib
