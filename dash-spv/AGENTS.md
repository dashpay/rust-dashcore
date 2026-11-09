# dash-spv

The SPV client: peer networking, on-disk storage and event-driven sync. The root `AGENTS.md` applies here too. This file adds what is specific to this crate.

## Module map

- `client/`: `DashSpvClient`, its `ClientConfig` and the `EventHandler` callbacks. It wires storage, network, wallet and sync together.
- `network/`: `PeerNetworkManager` and the `NetworkManager` trait the sync layer depends on. `broker.rs` queues, de-duplicates, times out and retries requests. `transport/` adds the BIP324 v2 encrypted transport next to v1. `bans.rs` handles dial backoff and bans, `costs.rs` estimates response sizes, `discovery.rs` finds peers.
- `sync/`: one directory per sync manager (`block_headers`, `filter_headers`, `filters`, `blocks`, `masternodes`, `chainlock`, `instantsend`, `mempool`). In each, `manager.rs` holds the state and logic, `sync_manager.rs` implements the `SyncManager` trait, `pipeline.rs` batches requests where there is one, and `progress.rs` reports progress. `sync_coordinator.rs` spawns the managers.
- `storage/`: private. `DiskStorageManager` keeps headers, filter headers, filters, blocks, masternode state and metadata in fixed-size segments (`segments.rs`). `migrator/` upgrades older on-disk versions.
- `sml_engine/`: `MasternodeListEngine`, which builds and validates masternode lists and quorums from `mnlistdiff` and `qrinfo` messages.
- `validation/`: header, block, filter, ChainLock and InstantLock validation.
- `chain/`: checkpoints, chain tips and chain work.
- `test_utils/`: `MockNetworkManager`, `DashdTestContext`, `DashCoreNode` and other helpers, behind the `test-utils` feature.

The wallet is not in this crate. The client drives any `key_wallet_manager::WalletInterface`.

## Invariants

- Each sync manager runs in its own task (`SyncManager::run`). Managers never call each other. They return `SyncEvent`s, the coordinator broadcasts them, and the other managers react in `handle_sync_event`.
- Send requests with `SendRequest::send` or `NetworkManager::enqueue`. The broker de-duplicates keyed requests and handles timeouts and retries. A key stays registered until the manager calls `release_request`, and enqueuing it again before that is a no-op. Release a key once its answer arrives or the data is no longer wanted.
- `on_disconnect` drops only state tied to the lost peer. Progress that storage or batch bookkeeping can rebuild must survive, so a reconnect resumes instead of restarting.
- Time-based work (expiry, retries the broker does not own) belongs in `tick`, which runs every 100 ms.
- Use `tokio::sync` locks. `std::sync::Mutex` and `std::sync::RwLock` are denied by `clippy.toml`.
- Changing the on-disk format needs a new migrator in `storage/migrator/` and a bump of `CURRENT_VERSION`. A migration that hits corrupt data wipes the storage and syncs again.
- Storage treats an item equal to its type's `Persistable::sentinel()` as missing. For filter headers that is all zeros, so test data must use non-zero values.

## Tests

- Unit tests that set a manager's state by hand can pass on a path production never takes. A change to sync, restart or disconnect handling needs a dashd test in `tests/dashd_sync/` or `tests/dashd_masternode/`. See "dashd integration tests" in the root `AGENTS.md` for setup.
- The CLI binary helps with manual runs: `cargo run -p dash-spv --features cli --bin dash-spv -- --network testnet --data-dir <dir>`.
