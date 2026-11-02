# Workspace-wide recipes; crate recipes run as `just <crate>::<recipe>`

import "mod.just"

mod gha ".github/mod.just"

# List every recipe
default:
    @{{ just_executable() }} --list --list-submodules

# Format the workspace
fmt:
    cargo fmt --all

# Run clippy with every lint profile
lint:
    {{ python }} contrib/run_clippy.py

# Run the pre-commit hooks, push stage included
check:
    pre-commit run --all-files --hook-stage push

# Build the docs with warnings denied
[env("RUSTDOCFLAGS", "-D warnings")]
doc:
    cargo doc --workspace --all-features --no-deps

# Check that the workspace compiles on the MSRV
msrv:
    cargo check --workspace --all-features

# Audit dependencies with cargo-deny
deny:
    cargo deny check

# Run test groups from `.github/ci-groups.yml`, or all when none are given
test *groups:
    {{ python }} .github/scripts/ci_config.py run-group {{ groups }}

# CI skips the summary, as its next step writes the lcov report
# Run test groups under cargo-llvm-cov and print a coverage summary
coverage *groups:
    cargo llvm-cov clean --workspace
    {{ python }} .github/scripts/ci_config.py run-group --coverage {{ groups }}
    {{ if env("GITHUB_ACTIONS", "") == "true" { "" } else { "cargo llvm-cov report --summary-only" } }}

# Defaults to the FFI crates for C interop and core crypto for unsafe code
# Run crates' tests under AddressSanitizer on nightly
[script("bash")]
[unix]
asan *crates="key-wallet-ffi dashcore dashcore_hashes":
    set -euo pipefail
    export RUST_BACKTRACE=1 SKIP_DASHD_TESTS=1
    export RUSTFLAGS="-Zsanitizer=address -Cdebuginfo=2 -Cforce-frame-pointers=yes"
    export ASAN_OPTIONS="symbolize=1:allow_addr2line=1" LSAN_OPTIONS="fast_unwind_on_malloc=0"
    host=$(rustc +nightly -vV | sed -n 's/^host: //p')
    for crate in {{ crates }}; do
        cargo +nightly test -Zbuild-std --target "$host" -p "$crate" --lib --tests
    done

# Run crates' tests under AddressSanitizer on nightly
[windows]
asan *crates:
    {{ error(unix_only) }}

# Defaults to dash-spv for its concurrent async code
# Run crates' tests under ThreadSanitizer on nightly
[script("bash")]
[unix]
tsan *crates="dash-spv":
    set -euo pipefail
    export RUST_BACKTRACE=1 SKIP_DASHD_TESTS=1
    export RUSTFLAGS="-Zsanitizer=thread -Cdebuginfo=2" TSAN_OPTIONS="second_deadlock_stack=1"
    host=$(rustc +nightly -vV | sed -n 's/^host: //p')
    for crate in {{ crates }}; do
        cargo +nightly test -Zbuild-std --target "$host" -p "$crate" --lib --tests
    done

# Run crates' tests under ThreadSanitizer on nightly
[windows]
tsan *crates:
    {{ error(unix_only) }}
