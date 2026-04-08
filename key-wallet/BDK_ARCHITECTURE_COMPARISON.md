# key-wallet vs BDK: Architecture Comparison

Reference: [Bitcoin Dev Kit (BDK)](https://github.com/bitcoindevkit/bdk/tree/master)

This document compares the key-wallet architecture against BDK, identifies structural weaknesses in the current design, and lists concrete ideas worth adopting.

---

## What BDK Is

BDK is a suite of modular Rust libraries for building descriptor-based Bitcoin wallets. Its philosophy:

> **"Data source agnostic and persistence agnostic"** — BDK doesn't care where blockchain data comes from or how it's stored.

### BDK Crate Structure

```
bdk_core        — Shared data types
bdk_chain       — Pure blockchain data structures (TxGraph, LocalChain) — zero I/O
bdk_wallet      — Wallet logic (address generation, tx building, signing)
bdk_electrum    — Electrum sync backend
bdk_esplora     — Esplora HTTP sync backend
bdk_bitcoind_rpc — Bitcoin Core RPC sync backend
bdk_file_store  — Append-only flat-file persistence (dev/test only)
```

Each crate has a single responsibility. `bdk_chain` can be used without any wallet logic; sync adapters can be swapped without touching wallet logic.

---

## BDK Core Concepts

### 1. `TxGraph<A>` — Monotonic Transaction Store

The most important design decision in BDK. Transactions are **never deleted**. Conflicting transactions (reorgs, RBF replacements) **coexist** in the graph. The canonical view is computed on-demand from the current chain state.

```
TxGraph
├── txid → Transaction (full or partial "floating output")
├── spend relationships (which tx spends which outpoint)
├── anchors (block confirmations per tx)
└── timestamps (first-seen, last-seen, evicted)
```

**Why this matters:** A chain reorganization doesn't require rolling back state — the evicted transactions simply become non-canonical. There is no "rollback" operation needed.

### 2. `LocalChain` — Chain Header State

Separate from the transaction graph. Maintains a `tip` via a linked `CheckPoint` structure. Applying a header update identifies the "point of agreement" between old and new chain, enabling clean reorg detection.

### 3. `IndexedTxGraph<A, I>` — Filtered View

Wraps `TxGraph` with an `Indexer` implementation:

```rust
pub trait Indexer {
    fn index_txout(&mut self, outpoint: OutPoint, txout: &TxOut);
    fn index_tx(&mut self, tx: &Transaction);
    fn is_tx_relevant(&self, tx: &Transaction) -> bool;
}
```

The indexer decides what's relevant (e.g. "does this output pay to one of my script pubkeys"). BDK ships `KeychainTxOutIndex` as a standard indexer, but any implementation works.

### 4. `ChangeSet` Pattern — Atomic Persistence

Every state mutation produces a `ChangeSet`:

```rust
wallet.apply_update(update)?;
let changes = wallet.take_staged(); // ChangeSet ready to persist
db.write(&changes)?;
```

Changes are:
- **Atomic** — persist all or nothing
- **Replayable** — rebuild state from the full changelog
- **Composable** — changesets can be merged

### 5. `TxBuilder` — Fluent Transaction Construction

```rust
let psbt = wallet
    .build_tx()
    .add_recipient(script, amount)
    .fee_rate(FeeRate::from_sat_per_vb(2.0))
    .coin_selection(BranchAndBoundCoinSelection::default())
    .finish()?;
```

Terminal `finish()` produces a PSBT. All configuration is chainable on `&mut self`.

### 6. Descriptor-First Key Management

A descriptor like `wpkh([fingerprint/44'/0'/0']xpub/0/*)` completely encodes:
- Which key to use
- The derivation path
- The script type (P2PKH, P2WPKH, P2TR, etc.)

BDK generates addresses and identifies relevant outputs purely from descriptors. There is no hardcoded account type system.

### 7. Pluggable Sync Backends

Each backend implements a thin adapter over `bdk_chain`:

```rust
// Electrum
let update = client.full_scan(wallet.start_full_scan(), ...)?;
wallet.apply_update(update)?;

// Esplora (async)
let update = client.full_scan(wallet.start_full_scan(), ...).await?;
wallet.apply_update(update)?;
```

The wallet has no awareness of which backend is used.

---

## key-wallet Architecture (Current)

### Strengths

- **Dash-specific DIP9 account types** — BDK has no concept of masternodes, DashPay 256-bit identity derivation, CoinJoin pools, or Platform payment accounts. The `AccountType` enum encodes Dash's entire derivation hierarchy explicitly with compile-time safety.
- **Multi-key-type address pools** — `KeySource` handles ECDSA + BLS + EdDSA in a single pool, which BDK cannot do (ECDSA/Schnorr only).
- **InstantSend awareness** — `Utxo.is_instantlocked` has no BDK equivalent.
- **Chainlock / special transaction support** — DIP2/DIP3 special transactions are first-class.

### Structural Weaknesses

#### 1. No Reorg Safety

`ManagedCoreAccount` stores transactions in a plain `BTreeMap<Txid, TransactionRecord>` and UTXOs in `BTreeMap<OutPoint, Utxo>`. There is no conflict-aware store.

A chain reorganization requires:
- Identifying which transactions are no longer canonical
- Reversing UTXO changes
- Recalculating balance

None of this logic exists. The current design **silently produces incorrect state** after a reorg.

**BDK solution:** `TxGraph` is monotonic — transactions are never removed, canonical view is computed from current `LocalChain` state on demand.

#### 2. No Persistence Contract

`ManagedCoreAccount` is a plain in-memory struct. There is no defined mechanism for:
- Atomically persisting a state change
- Recovering from a partial write (crash mid-update)
- Replaying history to rebuild state

The current CLAUDE.md guidance shows non-atomic sequential updates:

```rust
// CURRENT: not atomic — crash between any two steps corrupts state
managed_account.add_transaction(tx_record);
managed_account.update_utxos(&tx);
managed_account.recalculate_balance();
managed_account.mark_addresses_used(&tx);
```

**BDK solution:** `ChangeSet` captures all mutations as a single unit. Persist the changeset atomically, or don't persist anything.

#### 3. `AccountType` Enum is a 4-File Bottleneck

Adding any new DIP account type requires simultaneous changes to:
1. `account/account_type.rs` — add `AccountType` variant
2. `managed_account/managed_account_type.rs` — add `ManagedAccountType` variant
3. `transaction_checking/transaction_router/mod.rs` — add routing rule
4. `managed_account/address_pool.rs` — add pool configuration

This is a **shotgun surgery** anti-pattern. Each new Dash feature multiplies the required change surface.

**BDK solution:** Descriptors are self-contained. Adding a new address type is adding a new descriptor string, not modifying core enum dispatch.

#### 4. Sync Coupling

The wallet is tightly coupled to dash-spv via callback injection:

```rust
// From CLAUDE.md integration guide
on_transaction_received(tx) {
    let result = wallet_info.check_transaction(&tx, network, context, Some(&wallet));
    if result.is_relevant { update_wallet_state(result); }
}
```

dash-spv calls directly into wallet mutation. There is no clean boundary — testing wallet logic requires simulating dash-spv callbacks.

**BDK solution:** `apply_update(update)` is the single entry point. The sync layer produces an opaque `Update` value; the wallet consumes it. They share no mutable state.

#### 5. No Canonical Transaction View

The wallet assumes one definitive version of each transaction. When the same txid arrives from different data sources (mempool, block, rebroadcast), the wallet has no strategy for reconciliation.

**BDK solution:** `TxGraph` anchors track all known confirmations per transaction. The canonical version is whichever is confirmed deepest in the current `LocalChain`.

---

## Ideas Worth Adopting

### High Value

| BDK Concept | Proposed Adaptation |
|---|---|
| **`ChangeSet` pattern** | Wrap all `ManagedCoreAccount` mutations to produce a `WalletChangeSet`. Persistence layer writes changesets atomically. Enables crash recovery and audit log. |
| **Monotonic transaction store** | Replace `BTreeMap<Txid, TransactionRecord>` with a conflict-aware `TxStore` that retains evicted transactions and computes canonical view from chain state. |
| **`apply_update()` boundary** | Define `WalletUpdate` as an opaque value produced by dash-spv. `ManagedWalletInfo::apply_update(update)` is the single mutation entry point. Decouples sync from wallet state. |

### Medium Value

| BDK Concept | Proposed Adaptation |
|---|---|
| **`Indexer` trait** | Extract `TransactionRouter` into an `Indexer` trait. New account types implement the trait rather than modifying core router dispatch. |
| **Pluggable persistence** | Add a `WalletStore` trait so `ManagedCoreAccount` can be backed by SQLite, in-memory, or custom storage without changing wallet logic. |
| **Balance categories** | BDK's 4-tier balance (Immature / TrustedPending / UntrustedPending / Confirmed) maps cleanly to `WalletCoreBalance`. Consider adding `is_trusted` distinction between self-generated and external unconfirmed transactions. |

### Low Value / Dash-Specific Override

| BDK Concept | Why Not Applicable |
|---|---|
| **Descriptor-first keys** | DashPay 256-bit paths and DIP9 hierarchy cannot be expressed in miniscript descriptors. The `AccountType` enum is the right abstraction for Dash. |
| **Single key type** | BLS + EdDSA + ECDSA coexistence in a single pool is a genuine requirement with no BDK equivalent. |

---

## Proposed Architectural Target

```
┌─────────────────────────────────────────────┐
│                Application                  │
└────────────────────┬────────────────────────┘
                     │ apply_update(WalletUpdate)
┌────────────────────▼────────────────────────┐
│           ManagedWalletInfo                 │
│  ┌──────────────────────────────────────┐   │
│  │  apply_update() → WalletChangeSet    │   │
│  │  canonical_balance()                 │   │
│  │  list_unspent()                      │   │
│  └──────────────────────────────────────┘   │
│           ↓ state                           │
│  ┌──────────────────────────────────────┐   │
│  │  TxStore (conflict-aware)            │   │
│  │  ChainState (LocalChain equivalent)  │   │
│  │  AddressPools (per AccountType)      │   │
│  └──────────────────────────────────────┘   │
└────────────────────┬────────────────────────┘
                     │ WalletChangeSet
┌────────────────────▼────────────────────────┐
│           WalletStore (trait)               │
│  impl: SQLite | in-memory | bincode file    │
└─────────────────────────────────────────────┘

Sync layer (dash-spv) produces WalletUpdate independently.
No shared mutable state with wallet.
```

---

## Summary

| Concern | Current key-wallet | BDK approach |
|---|---|---|
| Reorg safety | ❌ No rollback mechanism | ✅ Monotonic TxGraph |
| Persistence | ❌ Implicit, non-atomic | ✅ ChangeSet pattern |
| Sync coupling | ❌ Direct callback mutation | ✅ `apply_update()` boundary |
| New account types | ❌ 4-file change minimum | ✅ New descriptor / Indexer impl |
| Multi-key types (BLS/EdDSA) | ✅ First-class | ❌ Not supported |
| DIP9 account hierarchy | ✅ Explicit, compile-safe | ❌ No equivalent |
| InstantSend / ChainLock | ✅ Modeled | ❌ No equivalent |

The two highest-priority improvements are **ChangeSet-based persistence** and the **`apply_update()` sync boundary**. Both can be introduced incrementally without redesigning the `AccountType` system.
