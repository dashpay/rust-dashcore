# PSBT Migration: key-wallet → dash

## Current situation

`key-wallet/src/psbt/` contains a full BIP174 PSBT implementation (~4100 lines across 9 files). It is exported from `key-wallet` as `pub mod psbt` and consumed only by `key-wallet/tests/psbt.rs`. Nothing inside `key-wallet`'s own wallet/account/transaction logic imports it.

```
key-wallet/src/psbt/
├── mod.rs          — PartiallySignedTransaction, signing logic  (1894 lines)
├── map/
│   ├── input.rs    — PSBT Input map                             (616 lines)
│   ├── output.rs   — PSBT Output map                           (187 lines)
│   ├── global.rs   — PSBT Global map                           (251 lines)
│   └── mod.rs      — Map trait                                  (34 lines)
├── serialize.rs    — BIP174 binary serialization               (486 lines)
├── raw.rs          — Raw key/value encoding                    (228 lines)
├── error.rs        — Error types                               (240 lines)
└── macros.rs       — Internal macros                           (179 lines)
```

### Why it doesn't belong in key-wallet

PSBT is a **transaction serialization and signing coordination format** defined in BIP174. It operates on `Transaction`, `TxIn`, `TxOut`, `Script`, and ECDSA signatures — all types that live in the `dash/` crate. It has no dependency on HD wallet accounts, address pools, gap limits, mnemonics, or any other concept from `key-wallet`.

The only reason it ended up in `key-wallet` is that `key-wallet`'s `bip32` module provides `ExtendedPrivKey`, `ExtendedPubKey`, and `KeySource`, which PSBT uses for BIP32 derivation metadata in the global map. Because `dash/` has no `bip32` module at all, there was nowhere else to put it.

### The actual dependency graph

```
key-wallet::psbt
    ├── dashcore::Transaction, TxOut, Script, PublicKey, PrivateKey
    ├── dashcore::sighash::{EcdsaSighashType, SighashCache}
    ├── dashcore::crypto::ecdsa
    └── key-wallet::bip32::{ExtendedPrivKey, ExtendedPubKey, KeySource}
                                                    ↑
                                         only dependency on key-wallet
```

`bip32` is the only thing tying PSBT to `key-wallet`. If `bip32` were in `dash/`, PSBT could move there without any further changes.

---

## Why the correct home is `dash/`

`dash/` is the Dash protocol library. It already contains:
- `blockdata/transaction/` — `Transaction`, `TxIn`, `TxOut`
- `crypto/` — ECDSA keys and signatures
- `sighash/` — sighash computation
- `bip143.rs`, `bip152.rs`, `bip158.rs` — other Bitcoin protocol extensions

PSBT belongs in this layer. It is a protocol-level transaction format, not a wallet-level concept. The correct import for consumers should be `dashcore::psbt::Psbt`, not `key_wallet::psbt::Psbt`.

---

## Migration plan

### Step 1 — Move `bip32` into `dash/`

This is the prerequisite. `key-wallet`'s `bip32` module wraps and extends `ExtendedPrivKey`/`ExtendedPubKey` with Dash-specific derivation (256-bit `Normal256` child numbers for DashPay). It needs to move to `dash/src/bip32/` and be re-exported from `dashcore`.

`key-wallet` then imports `bip32` from `dashcore` instead of defining it locally. This is independently valuable — `bip32` types are already used in `dashcore`'s signer interface and have no reason to be wallet-only.

### Step 2 — Move `psbt/` into `dash/src/psbt/`

Once `bip32` is in `dash/`, all PSBT imports become:

```rust
// Before
use crate::bip32::{ExtendedPrivKey, ExtendedPubKey, KeySource};
use dashcore::blockdata::transaction::Transaction;

// After (from inside dash/)
use crate::bip32::{ExtendedPrivKey, ExtendedPubKey, KeySource};
use crate::blockdata::transaction::Transaction;
```

The internal `crate::psbt::*` references stay unchanged. Only the crate boundary moves.

### Step 3 — Re-export from `key-wallet` for backwards compatibility

Add a re-export in `key-wallet/src/lib.rs` so existing consumers do not break:

```rust
// key-wallet/src/lib.rs
pub use dashcore::psbt;
```

This keeps `key_wallet::psbt::Psbt` working while the canonical path becomes `dashcore::psbt::Psbt`. The re-export can be deprecated and removed in a later breaking release.

### Step 4 — Wire PSBT into the transaction builder

The transaction builder at `key-wallet/src/wallet/managed_wallet_info/transaction_builder.rs` currently builds transactions without PSBT. Once PSBT is in `dash/` and easily importable, the builder should:

1. Construct a `Psbt` from the unsigned transaction and UTXO set
2. Add BIP32 derivation metadata for each input (the account xpub and child derivation path)
3. Return `Psbt` from `build_transaction()` instead of raw `Transaction`
4. Sign via `Psbt::sign()` when a private key is available
5. Finalize and extract the signed `Transaction` for broadcast

This is the original motivation for including PSBT in `key-wallet` in the first place — it was added in anticipation of this signing flow but never connected.

---

## File mapping

| Current path | Target path |
|---|---|
| `key-wallet/src/psbt/mod.rs` | `dash/src/psbt/mod.rs` |
| `key-wallet/src/psbt/map/input.rs` | `dash/src/psbt/map/input.rs` |
| `key-wallet/src/psbt/map/output.rs` | `dash/src/psbt/map/output.rs` |
| `key-wallet/src/psbt/map/global.rs` | `dash/src/psbt/map/global.rs` |
| `key-wallet/src/psbt/map/mod.rs` | `dash/src/psbt/map/mod.rs` |
| `key-wallet/src/psbt/serialize.rs` | `dash/src/psbt/serialize.rs` |
| `key-wallet/src/psbt/raw.rs` | `dash/src/psbt/raw.rs` |
| `key-wallet/src/psbt/error.rs` | `dash/src/psbt/error.rs` |
| `key-wallet/src/psbt/macros.rs` | `dash/src/psbt/macros.rs` |
| `key-wallet/tests/psbt.rs` | `dash/tests/psbt.rs` |

---

## Import changes required in PSBT source files

All `crate::psbt::*` internal references stay unchanged. The only imports that need updating are the cross-crate ones:

```rust
// Current (inside key-wallet)
use crate::bip32::KeySource;
use crate::bip32::{self, ExtendedPrivKey, ExtendedPubKey};
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::blockdata::transaction::Transaction;
use dashcore::crypto::ecdsa;
use dashcore::crypto::key::{PrivateKey, PublicKey};
use dashcore::sighash::{self, EcdsaSighashType, SighashCache};
use dashcore::Amount;

// After move (inside dash/)
use crate::bip32::KeySource;                              // bip32 now in dash/
use crate::bip32::{self, ExtendedPrivKey, ExtendedPubKey};
use crate::blockdata::script::ScriptBuf;                  // already in dash/
use crate::blockdata::transaction::txout::TxOut;          // already in dash/
use crate::blockdata::transaction::Transaction;           // already in dash/
use crate::crypto::ecdsa;                                 // already in dash/
use crate::crypto::key::{PrivateKey, PublicKey};          // already in dash/
use crate::sighash::{self, EcdsaSighashType, SighashCache}; // already in dash/
use crate::Amount;                                        // already in dash/
```

Every `dashcore::` prefix becomes `crate::` — a mechanical find-and-replace.

---

## Summary

| Concern | Status |
|---|---|
| PSBT is used by key-wallet wallet logic | No — zero imports from `wallet/` |
| PSBT is used by external crates (ffi, spv) | No — only `key-wallet/tests/psbt.rs` |
| PSBT has non-protocol dependencies on key-wallet | Only `bip32`, which itself should move to `dash/` |
| Migration is a breaking API change | Only if `key_wallet::psbt` re-export is removed; can be done gradually |
| Transaction builder should use PSBT after migration | Yes — that was the original intent |
