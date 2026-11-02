# key-wallet-ffi recipes, run as `just key-wallet-ffi::<recipe>`

import "../mod.just"

macos_only := "unsupported on this platform, requires macOS"
target := env("CARGO_TARGET_DIR", root / "target")

# Build the static libraries for iOS devices and the simulator
[macos]
build-ios:
    ./build-ios.sh

# Build the static libraries for iOS devices and the simulator
[linux]
[windows]
build-ios:
    {{ error(macos_only) }}

# Regenerate `FFI_API.md` after changing FFI functions
update-docs:
    {{ python }} scripts/generate_ffi_docs.py

# Build the C header, then compile the header tests against it
[unix]
headers:
    cargo build -p key-wallet-ffi
    bash {{ quote(root / "ffi-c-tests" / "validate-headers.sh") }} {{ quote(target / "debug" / "include") }}

# Build the C header, then compile the header tests against it
[windows]
headers:
    {{ error(unix_only) }}
