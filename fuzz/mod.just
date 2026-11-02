# dash-fuzz recipes, run as `just dash-fuzz::<recipe>`

import "../mod.just"

# Run every fuzz target briefly, or only the one named (e.g. `hashes_cbor`)
[unix]
run target="":
    ./fuzz.sh {{ target }}

# Run every fuzz target briefly, or only the one named (e.g. `hashes_cbor`)
[windows]
run target="":
    {{ error(unix_only) }}

# Regenerate `Cargo.toml` after adding or removing a fuzz target
[unix]
generate:
    ./generate-files.sh

# Regenerate `Cargo.toml` after adding or removing a fuzz target
[windows]
generate:
    {{ error(unix_only) }}
