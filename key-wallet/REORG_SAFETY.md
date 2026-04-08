# Reorg Safety Issue

## Where reorg handling currently lives

`dash-spv` has a `ChainTipManager` (`dash-spv/src/chain/chain_tip.rs`) that tracks multiple chain tips and can detect when a competing chain has more work. It exposes `should_reject_fork()` (checkpoint protection against deep reorgs) and `update_active_tip()` (switches the active tip to the highest-work chain).

However, **`ChainTipManager` never notifies the wallet**. When the active tip switches, no callback is fired, no wallet method is called, and no transaction state is updated.

The `WalletInterface` trait (`key-wallet-manager/src/wallet_interface.rs`) — the contract between dash-spv and the wallet — has no reorg-related method at all:

```rust
pub trait WalletInterface: Send + Sync + 'static {
    async fn process_block(&mut self, block: &Block, height: CoreBlockHeight) -> BlockProcessingResult;
    async fn process_mempool_transaction(&mut self, tx: &Transaction);
    fn monitored_addresses(&self) -> Vec<Address>;
    fn synced_height(&self) -> CoreBlockHeight;
    fn update_synced_height(&mut self, height: CoreBlockHeight);
    // ... no process_reorg, no on_block_disconnected, nothing
}
```

The `BlocksManager` (`dash-spv/src/sync/blocks/manager.rs`) calls `wallet.process_block()` for each new block but has no corresponding `wallet.disconnect_block()` or `wallet.process_reorg()` call anywhere in the sync pipeline.

**The gap is at the interface boundary.** The chain layer knows about forks; the wallet layer has no way to receive that information.

---

## Problem

`ManagedCoreAccount` stores transactions and UTXOs in plain maps:

```rust
pub transactions: BTreeMap<Txid, TransactionRecord>,
pub utxos: BTreeMap<OutPoint, Utxo>,
pub balance: WalletCoreBalance,
```

There is no concept of chain state. A transaction is either present or absent. A UTXO is either spendable or not. When a chain reorganization happens — blocks are rolled back and replaced by a competing chain — the wallet has no mechanism to respond correctly.

### What a reorg requires

1. **Identify evicted transactions** — transactions confirmed in the rolled-back blocks that are no longer canonical
2. **Restore spent UTXOs** — outputs spent by evicted transactions must become spendable again
3. **Remove created UTXOs** — outputs created by evicted transactions must be removed
4. **Recalculate balance** — derived from UTXO set, so wrong after steps 2-3 if not recomputed
5. **Handle re-confirmed transactions** — an evicted transaction may reappear in the new chain; its state must transition from "evicted" back to "confirmed" without duplication
6. **Update address usage** — if an evicted transaction was the first to use an address, that address is no longer "used" from a gap-limit perspective

None of this logic exists. After a reorg the wallet silently holds:
- Stale confirmed transactions that no longer exist on chain
- Missing UTXOs that were spent by evicted transactions (i.e. spendable funds not visible)
- Phantom UTXOs created by evicted transactions (i.e. unspendable funds appearing spendable)
- Wrong balance

This is a **silent data corruption** — no error is returned, no flag is set, the wallet simply operates on incorrect state.

---

## How BDK solves it

BDK's `TxGraph` is **monotonic**: transactions are never deleted. Instead, each transaction accumulates anchors (block confirmations) and timestamps. The canonical view — which transactions are confirmed, which are in mempool, which are evicted — is computed on demand from the current `LocalChain` tip.

```
TxGraph
├── txid → Transaction
├── anchors: Map<(txid, BlockId) → A>   — all known confirmations
├── last_seen: Map<txid → timestamp>     — mempool first-seen
└── last_evicted: Map<txid → timestamp>  — eviction timestamp
```

A reorg is handled by updating `LocalChain` to the new tip. No transactions are removed from `TxGraph`. The canonical balance query walks the graph filtered by the new chain state — evicted transactions simply stop contributing to the canonical view.

This also means a transaction that was evicted and then re-confirmed in the new chain does not need special handling: it already exists in the graph, a new anchor is added, and it becomes canonical again.

---

## Current state in key-wallet

### `TransactionRecord` has no chain state

```rust
pub struct TransactionRecord {
    pub transaction: Transaction,
    pub block_hash: Option<BlockHash>,
    pub block_height: Option<u32>,
    pub timestamp: u64,
    // no: is_evicted, confirmations_at_tip, competing_txids
}
```

`block_height: Option<u32>` is set once when a block is processed and never cleared. There is no field to express "this transaction was confirmed at height 1000 but that block was reorganized away."

### `Utxo` has no chain state

```rust
pub struct Utxo {
    pub outpoint: OutPoint,
    pub tx_out: TxOut,
    pub address: Address,
    pub is_instantlocked: bool,
    // no: confirmed_at_height, is_from_evicted_tx
}
```

### Balance is a snapshot, not a view

`WalletCoreBalance` is recalculated from the UTXO set. If the UTXO set is wrong (stale entries from evicted transactions, missing entries from restored outputs), the balance is wrong with no indication of the error.

---

## Proposed fix

### 0. Add `process_reorg` to `WalletInterface`

This is the missing link. `key-wallet-manager/src/wallet_interface.rs` needs a new method:

```rust
pub trait WalletInterface: Send + Sync + 'static {
    // ... existing methods ...

    /// Called when a chain reorganization is detected.
    /// `disconnected_heights` is the range of block heights that have been rolled back.
    /// The wallet should mark any transactions confirmed at those heights as evicted,
    /// restore spent UTXOs, and recalculate balances.
    async fn process_reorg(&mut self, disconnected_heights: RangeInclusive<CoreBlockHeight>);
}
```

And `dash-spv`'s sync pipeline must call it when `ChainTipManager` switches the active tip to a shorter chain, passing the height range of the disconnected blocks.

### 1. Add `confirmation_status` to `TransactionRecord`

Replace the flat `block_hash` / `block_height` fields with an explicit status type:

```rust
pub enum ConfirmationStatus {
    /// In mempool, not yet confirmed.
    Unconfirmed { first_seen: u64 },
    /// Confirmed in a block at a given height.
    Confirmed { block_hash: BlockHash, height: u32, timestamp: u64 },
    /// Was confirmed, but that block was reorganized away.
    /// The transaction may re-confirm later.
    Evicted { evicted_at_tip: u32, last_confirmed_height: u32 },
}

pub struct TransactionRecord {
    pub transaction: Transaction,
    pub status: ConfirmationStatus,
    // InstantSend lock survives reorgs — it is a separate protocol guarantee
    pub is_instantlocked: bool,
}
```

Evicted transactions are retained, not deleted. They can transition back to `Confirmed` if they reappear in the new chain.

### 2. Add `confirmed_at_height` to `Utxo`

```rust
pub struct Utxo {
    pub outpoint: OutPoint,
    pub tx_out: TxOut,
    pub address: Address,
    pub confirmed_at_height: Option<u32>,  // None = unconfirmed/mempool
    pub is_instantlocked: bool,
}
```

### 3. Add a `apply_reorg(evicted_heights: RangeInclusive<u32>)` method

```rust
impl ManagedCoreAccount {
    /// Apply a chain reorganization. All transactions confirmed at heights
    /// within `evicted_heights` are marked as evicted. UTXOs are updated
    /// accordingly and balance is recalculated.
    pub fn apply_reorg(&mut self, evicted_heights: RangeInclusive<u32>) {
        // 1. Find all transactions confirmed in evicted range
        // 2. Mark them Evicted
        // 3. Remove UTXOs created by those transactions
        // 4. Restore UTXOs spent by those transactions
        // 5. Recalculate balance
        // 6. Revert address usage marks if applicable
    }
}
```

### 4. Compute canonical balance from status

```rust
impl ManagedCoreAccount {
    pub fn recalculate_balance(&mut self) {
        // Only UTXOs from Confirmed or InstantSend-locked transactions
        // contribute to the trusted balance.
        // UTXOs from Unconfirmed transactions are "pending".
        // UTXOs from Evicted transactions are excluded entirely.
    }
}
```

---

## Interaction with InstantSend

Dash's InstantSend is relevant here. A transaction that is InstantSend-locked has a quorum-signed lock that is independent of block confirmation. An IS-locked transaction that gets reorganized out of a block is still IS-locked — it will be re-included in the next block.

This means:
- `is_instantlocked` on a `TransactionRecord` should survive a reorg (keep the field as-is)
- An IS-locked evicted transaction should still show its outputs as spendable in balance calculations, because re-inclusion is guaranteed by the IS lock
- A non-IS-locked evicted transaction's outputs should be excluded from balance until re-confirmed

This is the main place where Dash diverges from BDK's reorg model and needs custom logic.

---

## Interaction with ChainLocks

ChainLocked blocks cannot be reorganized away. If a transaction is confirmed in a ChainLocked block, `apply_reorg` should be a no-op for that transaction — ChainLocks provide finality stronger than any number of confirmations.

`TransactionRecord` should optionally track whether its confirming block is ChainLocked:

```rust
Confirmed {
    block_hash: BlockHash,
    height: u32,
    timestamp: u64,
    is_chainlocked: bool,  // if true, this confirmation is final
}
```

`apply_reorg` skips any transaction with `is_chainlocked: true`.

---

## Summary

| Concern | Current state | Required change | Location |
| --- | --- | --- | --- |
| Reorg notification to wallet | ❌ Not wired | `process_reorg()` in `WalletInterface` | `key-wallet-manager` + `dash-spv` |
| Evicted transaction detection | ❌ Not possible | `ConfirmationStatus::Evicted` variant | `key-wallet` |
| UTXO rollback on reorg | ❌ Not implemented | `apply_reorg()` method | `key-wallet` |
| Balance after reorg | ❌ Silently wrong | Recompute from status-filtered UTXO set | `key-wallet` |
| Re-confirmation of evicted tx | ❌ Would duplicate | Retained in map, status updated | `key-wallet` |
| IS-locked tx survives reorg | ❌ Not modeled | `is_instantlocked` flag in status | `key-wallet` |
| ChainLocked block finality | ❌ Not modeled | `is_chainlocked` in `Confirmed` variant | `key-wallet` |

The minimum viable fix is adding `ConfirmationStatus` to `TransactionRecord` and implementing `apply_reorg`. The ChainLock and InstantSend refinements can follow as the SPV sync layer provides that data.
