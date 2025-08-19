<div align="center">
  <h1>Rust Dash</h1>

  <img alt="Rust Dash logo by Rostislav Gorbachenko, UX engineer at Dash Core Group, see license and source files under /logo" src="./logo/rust-dash-together.png" width="300" />

  <p>Library with support for de/serialization, parsing and executing on data-structures
    and network messages related to Dash Core payment chain. Core RPC client.
  </p>

  <p>
    <a href="https://crates.io/crates/dash"><img alt="Crate Info" src="https://img.shields.io/crates/v/dash.svg"/></a>
    <a href="https://github.com/dashevo/rust-dashcore/blob/master/LICENSE"><img alt="MIT or Apache-2.0 Licensed" src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg"/></a>
    <a href="https://github.com/dashevo/rust-dashcore/actions?query=workflow%3AContinuous%20integration"><img alt="CI Status" src="https://github.com/dashevo/rust-dashcore/workflows/Continuous%20integration/badge.svg"></a>
    <a href="https://docs.rs/bitcoin"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-bitcoin-green"/></a>
    <a href="https://blog.rust-lang.org/2018/09/13/Rust-1.29.html"><img alt="Rustc Version 1.29+" src="https://img.shields.io/badge/rustc-1.29%2B-lightgrey.svg"/></a>
    <img alt="Lines of code" src="https://img.shields.io/tokei/lines/github/dashevo/rust-dashcore">
  </p>
</div>

**Heads up for contributors: upcoming edition change**

[Documentation](https://dashcore.readme.io/docs)

Supports (or should support)

* De/serialization of Dash protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP32 support)
* PSBT creation, manipulation, merging and finalization
* Pay-to-contract support as in Appendix A of the [Blockstream sidechains whitepaper](https://www.blockstream.com/sidechains.pdf)
* JSONRPC interaction with Dash Core
* FFI bindings for C/Swift integration (dash-spv-ffi, key-wallet-ffi)
* [Unified SDK](UNIFIED_SDK.md) option for iOS that combines Core and Platform functionality
* [High-level wallet management](key-wallet-manager/README.md) with transaction building and UTXO management

# Known limitations

## Consensus

This library **must not** be used for consensus code (i.e. fully validating
blockchain data). It technically supports doing this, but doing so is very
ill-advised because there are many deviations, known and unknown, between
this library and the Dash Core reference implementation. In a consensus
based cryptocurrency such as Dash it is critical that all parties are
using the same rules to validate data, and this library does not and might
never implement the same rules as Core.

Given the complexity of both C++ and Rust, it is unlikely that this will
ever be fixed, and there are no plans to do so. Of course, patches to
fix specific consensus incompatibilities are welcome.

## Support for 16-bit pointer sizes

16-bit pointer sizes are not supported and we can't promise they will be.
It will be dependent on rust-bitcoin implementing them first.

# Usage
Given below is an example of how to connect to the Dash Core JSON-RPC for a Dash Core node running on `localhost`
and print out the hash of the latest block.

It assumes that the node has password authentication setup, the RPC interface is enabled at port `8332` and the node
is set up to accept RPC connections.

```rust
extern crate dashcore_rpc;

use dashcore_rpc::{Auth, Client, RpcApi};

fn main() {

    let rpc = Client::new(
        "localhost:19998",
                          Auth::UserPass("<FILL RPC USERNAME>".to_string(),
                                         "<FILL RPC PASSWORD>".to_string())).unwrap();
    let best_block_hash = rpc.get_best_block_hash().unwrap();
    println!("best block hash: {}", best_block_hash);
}
```

See `client/examples/` for more usage examples.

# Wallet Management

This library provides comprehensive wallet functionality through multiple components:

* **key-wallet**: Low-level cryptographic primitives for HD wallets, mnemonic generation, and key derivation
* **[key-wallet-manager](key-wallet-manager/README.md)**: High-level wallet management with transaction building, UTXO tracking, and coin selection
* **key-wallet-ffi**: C/Swift FFI bindings for mobile integration
* **dash-spv**: SPV (Simplified Payment Verification) client implementation

For most applications, start with [key-wallet-manager](key-wallet-manager/README.md) which provides a complete, easy-to-use interface for wallet operations.

# Supported Dash Core Versions
The following versions are officially supported and automatically tested:
* 0.18.0
* 0.18.1
* 0.19.0.1
* 0.19.1
* 0.20.0
* 0.20.1
* 0.21.0

# Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features on **Rust 1.29**.

Because some dependencies have broken the build in minor/patch releases, to
compile with 1.29.0 you will need to run the following version-pinning command:
```
cargo update --package "cc" --precise "1.0.41"
cargo update --package "log:0.4.x" --precise "0.4.13" # x being the highest patch version, currently 14
cargo update --package "cfg-if" --precise "0.1.9"
cargo update --package "serde_json" --precise "1.0.39"
cargo update --package "serde" --precise "1.0.98"
cargo update --package "serde_derive" --precise "1.0.98"
cargo update --package "byteorder" --precise "1.3.4"
```


# Documentation

Documentation can be found on [dashcore.readme.io/docs](https://dashcore.readme.io/docs).

## Component Documentation

* **[key-wallet-manager](key-wallet-manager/README.md)** - High-level wallet management guide
* **[Unified SDK](UNIFIED_SDK.md)** - iOS SDK combining Core and Platform functionality

# Contributing

Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches.

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.89**.

## Installing Rust

Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-bitcoin` since we support much older
versions than the current stable one (see MSRV section).

## Building

The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:dashpay/rust-dashcore.git
cd rust-bitcoin
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more detailed instructions.

## Pull Requests

Every PR needs at least two reviews to get merged. During the review phase
maintainers and contributors are likely to leave comments and request changes.
Please try to address them, otherwise your PR might get closed without merging
after a longer time of inactivity. If your PR isn't ready for review yet please
mark it by prefixing the title with `WIP: `.

### CI Pipeline

The CI pipeline requires approval before being run on each MR.

In order to speed up the review process the CI pipeline can be run locally using
[act](https://github.com/nektos/act). The `fuzz` and `Cross` jobs will be
skipped when using `act` due to caching being unsupported at this time. We do
not *actively* support `act` but will merge PRs fixing `act` issues.


## Release Notes

See [CHANGELOG.md](CHANGELOG.md).


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE).
