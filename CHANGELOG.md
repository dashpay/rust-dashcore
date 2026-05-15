# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.42.0 - 2026-05-15

### Highlights

This is a large release that reworks the SPV client, wallet, and FFI surface. The most impactful changes:

- **Sync architecture rewrite:** the block, filter, and masternode sync pipelines were rewritten end-to-end, with explicit state machines, hardened reconnect and resume paths, deadlock fixes, and a long tail of correctness fixes around filter batching, in-flight state on disconnect, and post-sync header handling (#411, #440, #451, #452, #738).
- **`dashd` integration tests:** end-to-end SPV sync tests against a real regtest `dashd` covering sync, restarts, disconnections, transactions, masternodes, and multi-wallet, gating the `spv` and `ffi` CI groups (#464, #697, #740).
- **Mempool support:** a real mempool path through the SPV client with a `--mempool-strategy` CLI argument, plus a `CoinSelector` that can spend mempool UTXOs, driving a new transaction confirmation lifecycle (#558, #540, #552, #748).
- **Hardcoded masternode seeds:** vendored masternode seed files with weekly CI auto-refresh so cold-start bootstrapping no longer waits for a full `QRInfo` sync (#678).
- **Wallet manager extraction and atomic events:** core transaction building and signing moved into a dedicated wallet manager, wallet events are now atomic, and per-account balance diffs are carried on events (#594, #727, #696, #706).
- **FFI surface expansion:** full `TransactionRecord` exposed through FFI and wallet events, asset-lock builder, `MasternodeListEngine` accessor, transaction broadcast, error callback registration, and an async `Signer` trait for iOS workflows (#614, #600, #608, #458, #661).
- **Platform and Asset Lock:** a new `PlatformPayment` managed account to track Platform balances, plus Asset Lock derivation subfeatures 4 and 5 and a corrected `AssetLockTx` structure (#365, #368, #454, #659).
- **`no-std` support dropped:** incomplete `no-std` support was removed across `dashcore`, `hashes`, `internals`, and `key-wallet` to simplify the codebase (#518, #519, #520, #521).

### Added

- Bump `rs-x11-hash` to `0.1.9` for windows support (#319) @xdustinface
- Track `synced_height` per `ManagedWalletInfo` (#305) @xdustinface
- Capture new addresses from `maintain_gap_limit` (#287) @xdustinface
- Store block hashes along with the headers in segments (#351) @ZocoLini
- Add `wallet_manager_network` FFI function (#360) @QuantumExplorer
- Add PlatformPayment account specifications and creation logic (#365) @QuantumExplorer
- Introduce `BlockHeaderStorage.get_tip` helper (#359) @xdustinface
- Introduce `MessageDispatcher` in network manager (#383) @xdustinface
- Implement parallel filter matching (#303) @xdustinface
- Include module names in the log output (#391) @xdustinface
- Add synced height to the wallet interface (#396) @xdustinface
- Introduce `PersistentBlockStorage` (#397) @xdustinface
- New managed platform account to track platform balances (#368) @QuantumExplorer
- Add `--mnemonic-file`, `--data-dir` and logfiles to ffi-cli (#408) @xdustinface
- Add logging for InstantLock quorum lookup (#412) @xdustinface
- Hardcoded checkpoints every 50k blocks (#410) @xdustinface
- Rewrite, fix and improve the sync architecture (#411) @xdustinface
- Add more InstantSend debug logs (#413) @xdustinface
- Collect addresses from connected peers (#421) @xdustinface
- Persist best `ChainLock` to disk via `MetadataStorage` (#419) @xdustinface
- Validate received headers were actually requested (#438) @xdustinface
- React to network events in maintenance loop (#433) @xdustinface
- Add Asset Lock derivation path subfeatures 4 and 5 (#454) @QuantumExplorer
- Transaction broadcast ffi function (#458) @ZocoLini
- Add `cycle` to `SyncEvent::SyncComplete` (#459) @xdustinface
- Report/propagate client start/run failures (#432) @xdustinface
- Persist and restore target height via `MetadataStorage` (#476) @xdustinface
- Dispatch progress callback on registration (#473) @xdustinface
- Add `thread-local` logging support for parallel test isolation (#485) @xdustinface
- Add `dashd` integration tests for SPV sync (#464) @xdustinface
- Add `--mempool-strategy` CLI argument (#526) @xdustinface
- Log wallet events in the client's run loop (#525) @xdustinface
- Format wallet event amounts as DASH (#530) @xdustinface
- Wallet transaction confirmation lifecycle (#540) @xdustinface
- Add `TransactionStatusChanged` event and emit wallet events (#552) @xdustinface
- Add mempool support (#558) @xdustinface
- Expose asset lock transaction builder (#600) @QuantumExplorer
- Expose MasternodeListEngine accessor on FFIDashSpvClient (#608) @QuantumExplorer
- Track input/output details and direction in `TransactionRecord` (#605) @xdustinface
- Expose full `TransactionRecord` through FFI and wallet events (#614) @xdustinface
- Validate transaction label size (#617) @xdustinface
- Include `InstantLock` in `TransactionContext::InstantSend` variant (#615) @xdustinface
- Add address and value fields to FFIOutputDetail (#640) @llbartekll
- Enabled and updated key-wallet-ffi unit tests defined out of scope (#644) @ZocoLini
- Rebroadcast unconfirmed self-sent transactions (#627) @xdustinface
- Add async Signer trait and build_asset_lock_with_signer (#661) @QuantumExplorer
- Enforce required peer capabilities (#671) @xdustinface
- New more ergonomic FFIError implementation (#670) @ZocoLini
- Implement From and Drop traits for FFITransactionRecord and its members if needed (#676) @ZocoLini
- Hardcoded masternode seed files + weekly auto-refresh (#678) @QuantumExplorer
- Support multiple spv event handlers (#682) @xdustinface
- Make wallet events atomic (#696) @xdustinface
- Add mutable-pair accessors + insert_wallet (#685) @QuantumExplorer
- Expose bls and eddsa features (#700) @QuantumExplorer
- Per-wallet filter scan and runtime wallet catch-up (#694) @xdustinface
- Carry per-account balance diff on WalletEvent (#706) @QuantumExplorer
- Expose `instant_send_locks` accessor on `ManagedWalletInfo` (#712) @QuantumExplorer
- Carry addresses_derived on TransactionDetected / BlockProcessed (#725) @QuantumExplorer
- Add keep-finalized-transactions Cargo feature (#733) @QuantumExplorer
- Drive masternode sync via `PipelineMode` state machine (#738) @xdustinface
- Add `build_and_sign_transaction_with_signer` (#735) @ZocoLini
- Add `managed_core_account_set_transaction_label` FFI function (#618) @xdustinface
- Add chainlock handling to the wallet (#756) @xdustinface
- Add serde derives for AssetLockFundingType and DerivedAddress (#761) @lklimek
- Always emit `ChainLockProcessed` on chainlock advance (#769) @shumkov
- Log version with git commit for dev builds (#770) @xdustinface

### Changed

- Add explicit UTF-8 encoding for FFI doc generation (#322) @xdustinface
- Add `.gitattributes` to enforce LF line endings (#321) @xdustinface
- Exclude `dash-fuzz` from clippy on Windows (#320) @xdustinface
- Update `pre-commit` hooks to latest versions (#315) @xdustinface
- Rework storage to periodically persist (#278) @ZocoLini
- Instant lock validation cleanup/simplify (#329) @ZocoLini
- Move `Send + Sync + 'static` bounds into trait definitions (#331) @xdustinface
- Use separate target dirs for pre-commit (#330) @xdustinface
- Overhaul CI (#253) @xdustinface
- Cleanup `WalletBalance` (#335) @xdustinface
- Consolidate balance calculations (#338) @xdustinface
- Consolidate UTXO helpers in `test_utils` module (#334) @xdustinface
- Ignore bincode unmaintained advisory `RUSTSEC-2025-0141` (#343) @xdustinface
- Simplify immature transactions handling (#307) @xdustinface
- Storage manager trait splitted into multiple subtraits (#311) @ZocoLini
- Cleanup unused config parameters (#346) @xdustinface
- Cleanup message handler re-enable skipped tests (#352) @ZocoLini
- Add `test_utils` modules (#347) @ZocoLini
- Move `Headers2` processing into network layer (#369) @xdustinface
- Move storage tests into unit tests and drop duplicated tests (#371) @ZocoLini
- Unify validation with a `Validator` trait (#355) @ZocoLini
- Move sync system into `sync/legacy` (#379) @xdustinface
- Streamline peer related data storage (#327) @ZocoLini
- Replace some test helpers with test-utils dummy helpers (#389) @ZocoLini
- Unify all `MockNetworkManager` into one (#388) @ZocoLini
- Build `DiskStorageManager` from config path (#366) @ZocoLini
- Move `get_peer_best_height` into `PeerPool` (#392) @xdustinface
- Rename `storage::blocks` to `storage::block_headers` (#393) @xdustinface
- One storage type per file (#395) @xdustinface
- Cleanup `WalletTransactionChecker::check_core_transaction` (#402) @xdustinface
- Cleanup storage usage in `DashSpvClient` constructor (#418) @xdustinface
- Simplify DNS discovery fallback (#423) @xdustinface
- Move manager clone into `start_maintenance_loop` task (#426) @xdustinface
- Introduce `ProgressPercentage` trait (#431) @xdustinface
- Split network maintenance loop into smaller functions (#430) @xdustinface
- Fix formatting in `start_maintenance_loop` (#445) @xdustinface
- Split `FiltersProgress.current_height` into committed/stored (#446) @xdustinface
- Simplify `FiltersManager.start_download` (#450) @xdustinface
- Make `DashSpvClient` cloneable (#453) @xdustinface
- Replace FFI OS threads with tokio tasks (#456) @xdustinface
- Extract methods for fee calculation (#461) @ZocoLini
- Cleanup `DashSpvClient` to have single `run()` entry point (#457) @xdustinface
- Add `ensure_not_started()` guard (#466) @xdustinface
- Change wallet_build_and_sign_transaction signature to be used in iOS (#463) @ZocoLini
- Add `RUST_BACKTRACE=1` to CI test runs (#478) @xdustinface
- Fix ffi api docs (#479) @xdustinface
- Improve ASAN stack trace and symbolization (#475) @xdustinface
- Move manager initialization from trait method to constructors (#467) @xdustinface
- Add `clear_in_flight_state()` to `SyncManager` trait (#484) @xdustinface
- Extract shared `send_message_to_peer` helper (#488) @xdustinface
- Add codecov coverage tracking (#493) @xdustinface
- Fix codecov uploads (#494) @xdustinface
- Add `__pycache__/` to `.gitignore` (#495) @xdustinface
- Move `Network` struct into  `dashcore` crate (#497) @ZocoLini
- Make `codecov/patch` informational (#506) @xdustinface
- Use target 0% for `codecov/patch` (#510) @xdustinface
- Make `codecov/project` wait for all uploads (#508) @xdustinface
- Fix `PeerPool.get_best_height()` logs (#505) @xdustinface
- Move `fuzz` profile settings to workspace root (#501) @xdustinface
- Update docs of `Network` entries (#499) @xdustinface
- Replace `ServiceFlags::from(1)` with `NETWORK` (#507) @xdustinface
- Address CodeRabbit feedback from #493 (#516) @PastaPastaPasta
- Rename `Dash` network entries to `Mainnet` (#500) @xdustinface
- Update key-wallet documentation to match current codebase (#524) @shumkov
- Disable `carryforward` flags to flush stale data (#543) @xdustinface
- Enable CodeRabbit `request_changes_workflow` (#531) @xdustinface
- Re-enable `carryforward` flags (#543) (#544) @xdustinface
- Re-disable `carryforward` flags (#545) @xdustinface
- Consolidate fuzz CI to nightly schedule (#549) @xdustinface
- Add `ready-for-review` label automation on CodeRabbit approval (#550) @xdustinface
- Add polling wait for wallet callbacks in FFI test (#546) @xdustinface
- Move counter increments after payload writes in FFI callbacks (#547) @xdustinface
- Extract `snapshot_balances`/`emit_balance_changes` helpers (#542) @xdustinface
- Add 200 block regtest blockchain support (#537) @xdustinface
- Default to `relay=false` in P2P handshake (#536) @xdustinface
- Extract wallet setup into `TestWalletContext` (#539) @xdustinface
- Consolidate test transaction creation (#538) @xdustinface
- Extract capability lookup into `PeerPool` helpers (#509) @xdustinface
- Gate `ready-for-review` label on CodeRabbit approval + CI passing (#561) @xdustinface
- Add PR title prefix enforcement (#532) @xdustinface
- Use `runner.temp` for dashd log path instead of hardcoded `/tmp` (#563) @xdustinface
- Wrap test execution in `try`/`finally` (#564) @xdustinface
- Decouple `verify-groups` from test matrix (#562) @xdustinface
- Fix `gh api` review-state query in `ready-for-review` workflow (#566) @xdustinface
- Merge `key-wallet-manager` crate into `key-wallet` (#503) @ZocoLini
- Guard `ready-for-review` label against draft PRs and handle undraft (#570) @xdustinface
- Move event callback dispatch into `DashSpvClient` (#572) @xdustinface
- Extract `BlockInfo` from `TransactionContext` (#578) @xdustinface
- Gate manager module behind feature flag (#584) @QuantumExplorer
- Extract `key-wallet-manager` crate from `key-wallet` (#594) @xdustinface
- Move header files generation to the target directory (#579) @ZocoLini
- Extract WalletManager accessors and error types (#599) @QuantumExplorer
- Adjust `CLAUDE.md` that `dashd` integration tests should be run (#601) @xdustinface
- Add generated FFI header directories to `.gitignore` (#603) @xdustinface
- Store `TransactionContext` in `TransactionRecord` (#582) @xdustinface
- Rename FFI context structs to match `key-wallet` naming (#612) @xdustinface
- Update stale `wallet_check_transaction` docs (#613) @xdustinface
- Add FFI header validation step (#609) @ZocoLini
- Move `broadcast`/`disconnect_peer` to `NetworkManager` trait (#623) @xdustinface
- Use clap derive in CLI (#620) @xdustinface
- Use `String` for `TransactionRecord::label` (#624) @xdustinface
- Cleanup unused dependencies (#633) @xdustinface
- Unify logging on tracing (#635) @xdustinface
- Ignore `RUSTSEC-2026-0097` until `blsful` updates `rand` (#639) @xdustinface
- Inline `MempoolState` into `MempoolManager` (#628) @xdustinface
- Move spendable_utxos from wallet to account (#643) @QuantumExplorer
- Consolidate `FFINetwork` in dashcore new `ffi` feature (#642) @ZocoLini
- Make WatchOnly / ExternalSignable unit variants (#654) @QuantumExplorer
- Bump pinned Rust toolchain to `1.94.1` (#648) @xdustinface
- Bump pinned Rust toolchain to 1.95.0 (#662) @QuantumExplorer
- Loosen wallet recovery perf threshold to 70ms (#663) @QuantumExplorer
- Fix `setup-dashd.py` script env var export (#677) @ZocoLini
- Extract Network into standalone dash-network crate (#679) @QuantumExplorer
- Rename wallet heights to reflect their meaning better (#683) @xdustinface
- Replace match patterns where we can use `error.rs` macros (#691) @ZocoLini
- Track wallet heights per wallet (#689) @xdustinface
- Cleanup useless statements in `cbindgen.toml` (#629) @ZocoLini
- Rename `ManagedCoreAccount.account_type` (#704) @xdustinface
- Format wallet amounts as DASH in logs (#703) @xdustinface
- Split `ManagedCoreAccount` into funds + keys variants (#711) @QuantumExplorer
- Fix ffi docs (#737) @xdustinface
- Move core tx building and signing into the key-wallet-manager crate (#727) @ZocoLini
- Add multi-wallet integration tests (#697) @xdustinface
- Forbid `std::sync::Mutex` / `RwLock` via clippy (#739) @ZocoLini
- Wire ManagedCoreKeysAccount into the collection (#742) @QuantumExplorer
- Bump `actions/cache` to v5 and `codecov/codecov-action` to v6 (#741) @xdustinface
- Refactor TransactionBuilder to centralize as much logic as possible (#744) @ZocoLini
- Add masternode integration tests (#740) @xdustinface
- Fix `create_test_wallet` import in `tests_transaction` (#751) @xdustinface
- Make logging a built-in event handler (#745) @xdustinface
- Inline event logging into monitor tasks (#757) @xdustinface
- Change `DerivedAddress::public_key` to `PublicKey` (#765) @xdustinface
- Stop caching `~/.cargo/bin` (#767) @xdustinface
- Return chainlock height from `wait_for_wallet_tx_chainlocked` (#766) @xdustinface
- Replace `run` token and `running` flag with `watch` (#772) @xdustinface

### Fixed

- Avoid X11 hash with wrong input size in tests (#324) @xdustinface
- Single file handle in `atomic_write` (#317) @xdustinface
- Use `from_byte_array` for dummy block hash in tests (#310) @xdustinface
- Qualify `Hash` trait in macros for `--no-default-features` (#313) @xdustinface
- Add missing license fields for cargo-deny audit (#314) @xdustinface
- Add test-only `LockFile::read_pid` for cross-platform testing (#316) @xdustinface
- Prevent memory leaks in FFI tests (#323) @xdustinface
- Use RFC 5737 TEST-NET-1 IP for timeout testing (#308) @xdustinface
- Address Windows filename issues (#312) @xdustinface
- Reject empty hostname in peer address in FFI (#318) @xdustinface
- Update wallet heights when processing blocks (#309) @xdustinface
- Fail sync on timeout (#342) @xdustinface
- Correct confirmations for UTXOs in wallet FFI (#306) @xdustinface
- Store checkpoints at checkpoint height not 0 (#345) @xdustinface
- Unify immature balance tracking with remaining balances (#341) @xdustinface
- Distinguish between new and existing transactions in wallet (#378) @xdustinface
- Add missing `Devnet` and `Regtest` for `PlatformPayment` (#390) @xdustinface
- Store checkpoint filter header at the correct height (#399) @xdustinface
- Add missing transaction types in serialization (#401) @xdustinface
- Look up quorum by actual `quorum_index` not by array position (#406) @xdustinface
- Use `borrow_and_update` to avoid duplicate progress dispatches in ffi (#415) @ZocoLini
- Require chainlock signatures only after V20 activation (#405) @xdustinface
- Use `masternode_lists_around_height` for quorum lookups (#407) @PastaPastaPasta
- Store all peers in storage (#420) @xdustinface
- Make use of stored peers (#422) @xdustinface
- Clear up failed connection attempts (#425) @xdustinface
- Avoid panic for sentinel blocks in debug builds (#427) @xdustinface
- Avoid re-inserting previous filter header on sync resume (#428) @xdustinface
- Prevent invalid header response routing (#439) @xdustinface
- Maintenance loop stops connecting at 1 peer (#437) @xdustinface
- Ensure `PeerDisconnected` is emitted on write-path disconnects (#435) @xdustinface
- Handle missing fields in `ProUpServTx` v2 encode (#417) @xdustinface
- Use `Interval` for maintenance tick and delay the first dns tick (#434) @xdustinface
- Emit `FiltersSyncComplete` for incremental updates (#443) @xdustinface
- Separate filter scan height from synced height (#442) @xdustinface
- Reset `FilterManager` in flight state when all peers disconnect (#441) @xdustinface
- Correct state and `PeerDisconnected` events in removal paths (#436) @xdustinface
- Fix shutdown deadlock and ordering (#440) @lklimek
- Create filter batches at queue time to fix overlaps/gaps (#452) @xdustinface
- Correct wrong transaction data pointer creation (#462) @ZocoLini
- Correct state transitions in filter sync manager (#451) @xdustinface
- Disconnect peers after pong timeout (#424) @xdustinface
- Correct initial percentage to only average active managers (#471) @xdustinface
- Consolidate duplicate `FFISyncProgress` destroy functions (#474) @xdustinface
- Avoid extra `GetHeaders` after post-sync header processing (#486) @xdustinface
- Align bloom filter size/hash calculation with Dash Core (#529) @xdustinface
- Make `DMNState.service` and `MasternodeStatus.service` optional for Core v24 (#523) @PastaPastaPasta
- Route `getdata` requests to the peer that sent the `inv` (#527) @xdustinface
- Dashify the units (#250) @kxcd
- Cap `Vec::with_capacity` in `Headers2Message` deserialization (#63) (#581) @xdustinface
- Clean up `key-wallet` feature flags after `no-std` removal (#588) @xdustinface
- Disable key-wallet default features (#596) @shumkov
- Initialize everything correctly in `FiltersManager::new` (#598) @xdustinface
- Replace `abort()` with cooperative wait in `wait_for_run_task` (#576) @xdustinface
- Handle and propagate errors in event channel monitors (#573) @xdustinface
- Detect coinbase by input pattern in `classify_transaction` (#606) @xdustinface
- Extract asset lock builder into key-wallet (#604) @QuantumExplorer
- Register error callback in FFI CLI binary (#575) @xdustinface
- Make `broadcast` not return an error on success (#625) @xdustinface
- Gate `FilterHeadersSyncComplete` on block header sync completion (#631) @xdustinface
- Process broadcast transactions via `dispatch_local` (#626) @xdustinface
- Subscribe to SPV event monitors before startup (#636) @xdustinface
- Announce tip to new peers when synced (#490) @xdustinface
- Drop `max_retries` from `DownloadCoordinator` to prevent sync stall (#632) @xdustinface
- Index rotated quorums by `quorum_index` and rebuild per cycle (#637) @xdustinface
- Correct AssetLockTx structure per DIP-00X (#659) @QuantumExplorer
- Address<NetworkChecked> serde deserialize no longer hardcodes Mainnet (#657) @QuantumExplorer
- Remove overly-strict is_synced gate from broadcast (#656) @QuantumExplorer
- Feed `last_commitment_per_index` heights to engine (#665) @xdustinface
- Use platform LLMQ type for regtest in `platform_type()` (#667) @xdustinface
- Align `LLMQ_TEST_DIP0024` params with Dash Core (#666) @xdustinface
- Use single historical anchor for `QRInfo` base hashes (#668) @xdustinface
- Replace `hickory-resolver` with `tokio::net::lookup_host` (#690) @ZocoLini
- Gate serde-only imports in BLS derivation (#701) @QuantumExplorer
- Seed sync checkpoints from `birth_height` in `ManagedWalletInfo` ctors (#692) @xdustinface
- Track self-send change in confirmed balance (#707) @QuantumExplorer
- Ignore special transactions on block version 0 (pre DIP-0002) (#675) @owl352
- Preserve buffered block headers across disconnect (#702) @xdustinface
- Preserve raw nTxType bytes on pre-DIP-0002 (version 0) transactions (#726) @QuantumExplorer
- Classify missing infrastructure errors as `Skipped` (#721) @xdustinface
- Make SerdeHash tolerant of ContentDeserializer's HR-quirk (#729) @shumkov
- Make OutPoint serde tolerant of ContentDeserializer's HR-quirk (#708) @shumkov
- Make `feed_qr_info` resilient to missing rotation CL sigs (#736) @xdustinface
- Fire catch-up QRInfo past `Incremental` mining window (#743) @xdustinface
- Let `CoinSelector` spend mempool UTXOs (#748) @ZocoLini
- Preserve in-progress sync state on peer disconnect (#746) @xdustinface
- Prevent filter sync stalls from stale progress guards (#754) @xdustinface

### Removed

- Drop unused `utxo.rs` in `key-wallet` crate (#304) @xdustinface
- Remove `headers` from `ChainState` (#292) @ZocoLini
- Drop pointless `utxo_tests.rs` (#333) @xdustinface
- Remove more unused `ClientConfig` fields (#348) @ZocoLini
- Remove an empty file (#354) @ZocoLini
- Drop redundant block processing (#349) @xdustinface
- Remove pointless `skip_mock_implementation_incomplete` feature (#340) @ZocoLini
- Remove unused `bloom` module (#280) @ZocoLini
- Drop unused integration tests (#362) @xdustinface
- Drop headers2 stats (#367) @xdustinface
- Drop useless `DashSpvClient.sync_to_tip` (#363) @xdustinface
- Remove mempool tracking config mutation method (#373) @ZocoLini
- Drop redundant network message logs (#380) @xdustinface
- Drop incomplete dsq preference updates (#382) @xdustinface
- Remove not needed `PeerInfo` struct (#386) @ZocoLini
- Drop unused "peer sent headers2" tracking (#387) @xdustinface
- Drop `SpvStats` statistics (#394) @xdustinface
- Unused ffi functions removed from dash-spv-ffi crate (#377) @ZocoLini
- Remove legacy sync code (#414) @xdustinface
- Drop unused ffi functions (#449) @ZocoLini
- Remove duplicate `get_peer_count` method (#455) @xdustinface
- Drop unused transaction ffi functions (#460) @ZocoLini
- Remove broken ffi integration tests (#468) @ZocoLini
- Remove `SyncState::Initializing` variant (#465) @xdustinface
- Remove unified sdk references (#302) @xdustinface
- Drop unused `completed_count` in `BlocksPipeline` (#477) @xdustinface
- Drop unused `_TestCallbackData` (#472) @xdustinface
- Drop `FeeEstimator` (#480) @ZocoLini
- Remove some unused files (#296) @xdustinface
- Drop `FeeLevel` (#481) @ZocoLini
- Drop unsigned transactions creation in `WalletManager` and in `ManagedWalletInfo` (#483) @ZocoLini
- Drop `dashcore::FeeRate` (#482) @ZocoLini
- Drop unused `UtxoSet` struct (#491) @ZocoLini
- Drop unused `NetworkManager` functions (#504) @xdustinface
- Removed `hkdf` dependency (#512) @ZocoLini
- Remove unnecessary code in `internals::macros` (#513) @ZocoLini
- Drop `no-std` CI jobs (#522) @ZocoLini
- Drop unused modules in `dashcore` crate (#534) @ZocoLini
- Drop out-of-scope crates inside `hashes` crate (#535) @ZocoLini
- Drop `tools` CI test group (#548) @xdustinface
- Remove `current_sync_peer` from network manager (#511) @xdustinface
- Drop unused `update_wallet_balance` from `WalletManager` (#560) @xdustinface
- Drop `no-std` support in internals (#519) @ZocoLini
- Drop `no-std` support for `hashes` (#520) @ZocoLini
- Drop `no-std` support in `dashcore` (#521) @ZocoLini
- Remove orphaned `key-wallet-manager` directory (#568) @xdustinface
- Remove FFI header generation from `pre-commit` FFI step (#565) @xdustinface
- Remove `ready-for-review` label when `merge-conflict` is added (#571) @xdustinface
- Remove flaky `handshake_test.rs` integration tests (#574) @xdustinface
- Drop out of date c tests (#583) @ZocoLini
- Revert "fix(rpc-json): make `DMNState.service` and `MasternodeStatus.service`…" (#586) @QuantumExplorer
- Drop incomplete `no-std` support for `key-wallet` (#518) @ZocoLini
- Remove `default_peers_for_network` from `ClientConfig` (#592) @xdustinface
- Remove dead `transaction_effect` from `WalletInterface` (#621) @xdustinface
- Remove legacy mempool leftovers (#619) @xdustinface
- Remove and replaced FFIExtendedPrivateKey with FFIExtendedPrivKey (#645) @ZocoLini
- Remove and replace `FFIExtendedPublicKey` with `FFIExtendedPubKey` (#646) @ZocoLini
- Drop random tests (#653) @ZocoLini
- Remove unused dev-dependencies (#652) @ZocoLini
- Remove redundant `HDWallet` + `AccountDerivation` struct (#674) @QuantumExplorer
- Drop unused `Option<FH>` callback from `feed_qr_info` (#669) @xdustinface
- Remove unused `consecutive_resyncs` counter on `Peer` (#705) @xdustinface
- Drop unused `AccountMetadata` struct (#717) @QuantumExplorer
- Drop unused `first_loaded_at` and `total_transactions` from `WalletMetadata` (#719) @QuantumExplorer
- Remove `wallet_create_managed_wallet` (#710) @xdustinface
- Drop unused `is_watch_only` from `ManagedCoreAccount` (#718) @QuantumExplorer
- Remove unused error variants (#364) @ZocoLini
- Revert "feat(ffi): add dash_spv_ffi_config_clear_peers (#591)" (#593) @xdustinface
- Remove `MnemonicWithPassphrase` wallet type (#747) @QuantumExplorer
- Drop `description()`, use `Display` for events (#758) @xdustinface
- Drop unreachable `WouldBlock`/`TimedOut` (#753) @xdustinface
- Remove dead `dash/embedded` crate and unused `fuzz/Cargo.lock` (#773) @xdustinface

## 0.41.1 - 2026-01-23

### Changed

- Bump `bincode` to `2.0.1` (#356) @lklimek

## 0.41.0 - 2025-12-30

### Added

- Use feature for console UI (#158) @QuantumExplorer
- Code analysis documentation (#159) @QuantumExplorer
- InstantLock BLS signature verification and peer reputation (#163) @PastaPastaPasta
- Buffered stateful framing for TCP connections (#167) @PastaPastaPasta
- Enhanced storage clear and balance display (#174) @PastaPastaPasta
- Comprehensive wallet FFI transaction builder (#175) @PastaPastaPasta
- DashPay support (#177) @QuantumExplorer
- Async check transaction (#178) @QuantumExplorer
- Broadcast transaction support (#180) @pauldelucia
- Update FFI headers (#183) @xdustinface
- Flush header index on shutdown and after header sync (#197) @pauldelucia
- Add `pre-commit` infrastructure (#201) @xdustinface
- Introduce `DashSpvClientInterface` (#214) @xdustinface
- DIP-17 Platform Payment account support in key-wallet (#229) @pauldelucia
- Add data directory lockfile protection (#241) @xdustinface
- Validate headers during sync (#242) @xdustinface
- Parallelize header validation with `rayon` (#243) @xdustinface
- Add `atomic_write` for atomic file writing (#245) @xdustinface
- Add logging module with file rotation support (#252) @xdustinface
- Add workflow to label PRs with merge conflicts (#265) @xdustinface
- Filter storage using segmentscache (#267) @ZocoLini
- Height based storage (#272) @ZocoLini
- Add benchmarks with criterion (#277) @ZocoLini
- Add `--mnemonic-file` CLI argument (#285) @xdustinface
- Add `network` to `FFIWalletManager` struct (#325) @xdustinface

### Changed

- Split big files in dash-spv (#160) @QuantumExplorer
- Update GitHub Actions to use ubuntu-22.04-arm (#169) @PastaPastaPasta
- Drop unused code in `dash-spv::network` (#179) @xdustinface
- Rename `MultiPeerNetworkManager` to `PeerNetworkManager` (#184) @xdustinface
- Improve SPV shutdown handling with `CancellationToken` (#187) @xdustinface
- Rename `TcpConnection` to `Peer` and `ConnectionPool` to `PeerPool` (#190) @xdustinface
- Drop unused code in `dash-spv::network` (#192) @xdustinface
- Clippy auto fixes (#198) @pauldelucia
- Make flow control syncing default (#211) @xdustinface
- Rename `HeaderSyncManagerWithReorg` to `HeaderSyncManager` (#221) @xdustinface
- Don't add a dummy in `mark_filter_received` (#222) @xdustinface
- Cleanup and simplify `MemoryStorageManager` (#224) @xdustinface
- Make `synced_from_checkpoint` based on `sync_base_height` (#226) @xdustinface
- More address matching in typo checker (#230) @xdustinface
- Use `genesis_block` for all nets in `initialize_genesis_block` (#231) @xdustinface
- Rename `SequentialSyncManager` to `SyncManager` (#235) @xdustinface 
- Some restructuring in `dash-spv::sync` (#236) @xdustinface
- Cleanup SPV validation (#237) @xdustinface
- Move header validation into `sync::headers::validation` (#238) @xdustinface
- Replace SyncPhase matches wildcard usage with exhaustive match (#239) @ZocoLini
- Storage segments cleanup (#244) @ZocoLini
- Pin rust version in `rust-toolchain.toml` (#266) @xdustinface
- Less cloning in SPV message handling (#268) @xdustinface
- Make filter loading range based (#269) @xdustinface
- Single network `Wallet` and `ManagedWalletInfo` (#271) @xdustinface
- Remove all use of `dyn` (#274) @ZocoLini
- Some `ChainState` cleanups (#289) @ZocoLini
- Drop `FFINetworks` and use `FFINetwork` only (#294) @xdustinface
- Single network `WalletManager` (#299) @xdustinface
- Make wallet birth height non-optional (#300) @xdustinface

### Removed

- Drop unused sync code (#208) @xdustinface
- Drop `ChainHash` and related tests from `dash` (#228) @xdustinface
- Drop unused code in `dash-spv::sync` (#232) @xdustinface
- Drop unused code in `dash-spv::checkpoint` (#233) @xdustinface
- Remove unused struct `StorageConfig` (#273) @ZocoLini
- Remove `MemoryStorageManager` (#275) @ZocoLini
- Drop persistent sync state (#279) @ZocoLini
- Remove unused `ChainLockStats` (#281) @ZocoLini
- Remove unused orphan pool module (#282) @ZocoLini
- Remove `StorageStats` (#283) @ZocoLini
- Remove duplicate quorum validation logic (#284) @ZocoLini
- Drop unused `lookahead` (#288) @xdustinface
- Remove unused filters field from `ChainState` (#293) @xdustinface
- Move logo and protx test data files to contrib (#295) @xdustinface
- Remove unused `swift-dash-core-sdk` (#301) @xdustinface

### Fixed

- CFHeaders overlap verification and underflow prevention (#163) @PastaPastaPasta
- FFI event flooding and memory leak in progress callbacks (#173) @PastaPastaPasta
- `PeerNetworkManager` cast in `broadcast_transaction` (#185) @xdustinface
- Use non-blocking `TcpStream` in TCP connection (#188) @xdustinface
- Locking issue after #190 (#191) @xdustinface
- Follow-up fixes to #190 (#193) @xdustinface
- Let the examples start the network monitoring (#194) @xdustinface
- Wait for MnListDiff responses before transitioning to next phase (#199) @pauldelucia
- SPV Regtest/Devnet support (#227) @xdustinface
- Drop duplicated received filter update (#248) @xdustinface
- Compressed headers protocol compatibility with Dash Core (#256) @PastaPastaPasta
- Stop loading headers twice into `ChainState::headers` (#258) @xdustinface
- FILTER_REQUEST_BATCH_SIZE should be 1000, not 100 (#260) @PastaPastaPasta
- Return the correct block hash in `prepare_sync` (#262) @xdustinface
- FFI CLI percentage display (#263) @ZocoLini
- `maintain_gap_limit` target calculation off by one (#286) @xdustinface
- Docs build issues (#297) @xdustinface

# 0.28 - 2022-04-20 "The Taproot Release"

At nearly nine months, this is our longest release cycle ever, and thanks
to a huge increase in the number of active contributors this year and last,
it is also **by far** our largest release ever, at 148 PRs merged from 23
different contributors. Our primary goal in this release was to introduce
support for Taproot and its associated data structures: addresses, taptrees,
sighashes, PSBT fields, and more. As it turned out, these changes required
(or at least, incentivized) changing a lot of our APIs, causing a significant
increase in scope.

We have more big changes coming down the pike. 2022 is going to be a big
year for `rust-bitcoin`, which we know is exciting for us but disruptive to
downstream users who ultimately want the library to just work. Our hope is
that by 2023 we will have eliminated large amounts of technical debt,
modernized our APIs to meet current Rust conventions, and clarified the scope
of the individual crates in this ecosystem while still providing the essential
functionality needed by our downstream users, especially wallet projects.

We will also develop a plan to make our releases more predictable and manageable,
likely by having scheduled releases with limited scope. We would like to reach
a point where we no longer have frequent breaking releases, but right now we
are nowhere close.

Upcoming changes will include
- A quick new release which updates our MRSV from 1.29 to 1.41 and does little else
- Updating our codebase to take advantage of the new MSRV, especially regarding
nostd and wasm support
- A comprehensive rethinking and flattening of our public-facing APIs
- Richer support for PSBT, Script, and BIP-0340/Schnorr signatures

With so many changes since 0.27, we cannot list every PR. Here are the highlights:

- Remove dangerous `fuzztarget` cargo feature [#634](https://github.com/rust-bitcoin/rust-bitcoin/pull/634)
- Improve serde serialization for `Script` [#596](https://github.com/rust-bitcoin/rust-bitcoin/pull/596)
- Documentation improvements [#623](https://github.com/rust-bitcoin/rust-bitcoin/pull/623) [#633](https://github.com/rust-bitcoin/rust-bitcoin/pull/633) [#663](https://github.com/rust-bitcoin/rust-bitcoin/pull/663) [#689](https://github.com/rust-bitcoin/rust-bitcoin/pull/689) [#704](https://github.com/rust-bitcoin/rust-bitcoin/pull/704) [#744](https://github.com/rust-bitcoin/rust-bitcoin/pull/744) [#852](https://github.com/rust-bitcoin/rust-bitcoin/pull/852) [#869](https://github.com/rust-bitcoin/rust-bitcoin/pull/869) [#865](https://github.com/rust-bitcoin/rust-bitcoin/pull/865) [#864](https://github.com/rust-bitcoin/rust-bitcoin/pull/864) [#858](https://github.com/rust-bitcoin/rust-bitcoin/pull/858) [#806](https://github.com/rust-bitcoin/rust-bitcoin/pull/806) [#877](https://github.com/rust-bitcoin/rust-bitcoin/pull/877) [#912](https://github.com/rust-bitcoin/rust-bitcoin/pull/912) [#923](https://github.com/rust-bitcoin/rust-bitcoin/pull/923)
- Introduce `WitnessVersion` type [#617](https://github.com/rust-bitcoin/rust-bitcoin/pull/617)
- Improve error types and API [#625](https://github.com/rust-bitcoin/rust-bitcoin/pull/625)
- Implement `Block.get_strippedsize()` and `Transaction.get_vsize()` [#626](https://github.com/rust-bitcoin/rust-bitcoin/pull/626)
- Add Bloom filter network messages [#580](https://github.com/rust-bitcoin/rust-bitcoin/pull/580)
- **Taproot:** add signature hash support [#628](https://github.com/rust-bitcoin/rust-bitcoin/pull/628) [#702](https://github.com/rust-bitcoin/rust-bitcoin/pull/702) [#722](https://github.com/rust-bitcoin/rust-bitcoin/pull/722) [#835](https://github.com/rust-bitcoin/rust-bitcoin/pull/835) [#903](https://github.com/rust-bitcoin/rust-bitcoin/pull/903) [#796](https://github.com/rust-bitcoin/rust-bitcoin/pull/796)
- **Taproot:** add new Script opcodes [#644](https://github.com/rust-bitcoin/rust-bitcoin/pull/644) [#721](https://github.com/rust-bitcoin/rust-bitcoin/pull/721) [#868](https://github.com/rust-bitcoin/rust-bitcoin/pull/868) [#920](https://github.com/rust-bitcoin/rust-bitcoin/pull/920)
- **Taproot:** add bech32m support, addresses and new key types [#563](https://github.com/rust-bitcoin/rust-bitcoin/pull/563) [#691](https://github.com/rust-bitcoin/rust-bitcoin/pull/691) [#697](https://github.com/rust-bitcoin/rust-bitcoin/pull/697) [#728](https://github.com/rust-bitcoin/rust-bitcoin/pull/728) [#696](https://github.com/rust-bitcoin/rust-bitcoin/pull/696) [#757](https://github.com/rust-bitcoin/rust-bitcoin/pull/757)
- **Taproot:** add taptree data structures [#677](https://github.com/rust-bitcoin/rust-bitcoin/pull/677) [#703](https://github.com/rust-bitcoin/rust-bitcoin/pull/703) [#701](https://github.com/rust-bitcoin/rust-bitcoin/pull/701) [#718](https://github.com/rust-bitcoin/rust-bitcoin/pull/718) [#845](https://github.com/rust-bitcoin/rust-bitcoin/pull/845) [#901](https://github.com/rust-bitcoin/rust-bitcoin/pull/901) [#910](https://github.com/rust-bitcoin/rust-bitcoin/pull/910) [#909](https://github.com/rust-bitcoin/rust-bitcoin/pull/909) [#914](https://github.com/rust-bitcoin/rust-bitcoin/pull/914)
- no-std improvements [#637](https://github.com/rust-bitcoin/rust-bitcoin/pull/637)
- PSBT improvements, including Taproot [#654](https://github.com/rust-bitcoin/rust-bitcoin/pull/654) [#681](https://github.com/rust-bitcoin/rust-bitcoin/pull/681) [#669](https://github.com/rust-bitcoin/rust-bitcoin/pull/669) [#774](https://github.com/rust-bitcoin/rust-bitcoin/pull/774) [#779](https://github.com/rust-bitcoin/rust-bitcoin/pull/779) [#752](https://github.com/rust-bitcoin/rust-bitcoin/pull/752) [#776](https://github.com/rust-bitcoin/rust-bitcoin/pull/776) [#790](https://github.com/rust-bitcoin/rust-bitcoin/pull/790) [#836](https://github.com/rust-bitcoin/rust-bitcoin/pull/836) [#847](https://github.com/rust-bitcoin/rust-bitcoin/pull/847) [#842](https://github.com/rust-bitcoin/rust-bitcoin/pull/842)
- serde improvements [#672](https://github.com/rust-bitcoin/rust-bitcoin/pull/672)
- Update rust-secp256k1 dependency [#694](https://github.com/rust-bitcoin/rust-bitcoin/pull/694) [#755](https://github.com/rust-bitcoin/rust-bitcoin/pull/755) [#875](https://github.com/rust-bitcoin/rust-bitcoin/pull/875)
- Change BIP32 to use rust-secp256k1 keys rather than rust-bitcoin ones (no compressedness flag) [#590](https://github.com/rust-bitcoin/rust-bitcoin/pull/590) [#591](https://github.com/rust-bitcoin/rust-bitcoin/pull/591)
- Rename inner key field in `PrivateKey` and `PublicKey` [#762](https://github.com/rust-bitcoin/rust-bitcoin/pull/762)
- Address and denomination related changes [#768](https://github.com/rust-bitcoin/rust-bitcoin/pull/768) [#784](https://github.com/rust-bitcoin/rust-bitcoin/pull/784)
- Don't allow hybrid EC keys [#829](https://github.com/rust-bitcoin/rust-bitcoin/pull/829)
- Change erroneous behavior for `SIGHASH_SINGLE` bug [#860](https://github.com/rust-bitcoin/rust-bitcoin/pull/860) [#897](https://github.com/rust-bitcoin/rust-bitcoin/pull/897)
- Delete the deprecated `contracthash` module [#871](https://github.com/rust-bitcoin/rust-bitcoin/pull/871); this functionality will migrate to ElementsProject/rust-elements
- Remove compilation-breaking feature-gating of enum variants" [#881](https://github.com/rust-bitcoin/rust-bitcoin/pull/881)

Additionally we made several minor API changes (renaming methods, etc.) to improve
compliance with modern Rust conventions. Where possible we left the existing methods
in place, marked as deprecated.

# 0.27 - 2021-07-21

- [Bigendian fixes and CI test](https://github.com/rust-bitcoin/rust-bitcoin/pull/627)
- [no_std support, keeping MSRV](https://github.com/rust-bitcoin/rust-bitcoin/pull/603)
- [Bech32m adoption](https://github.com/rust-bitcoin/rust-bitcoin/pull/601)
- [Use Amount type for dust value calculation](https://github.com/rust-bitcoin/rust-bitcoin/pull/616)
- [Errors enum improvements](https://github.com/rust-bitcoin/rust-bitcoin/pull/521)
- [std -> core](https://github.com/rust-bitcoin/rust-bitcoin/pull/614)

# 0.26.2 - 2021-06-08

- [Fix `Display` impl of `ChildNumber`](https://github.com/rust-bitcoin/rust-bitcoin/pull/611)

The previous release changed the behavior of `Display` for `ChildNumber`, assuming that any correct usage would not be
affected. [Issue 608](https://github.com/rust-bitcoin/rust-bitcoin/issues/608) goes into the details of why this isn't
the case and how we broke both `rust-miniscript` and BDK.

# 0.26.1 - 2021-06-06 (yanked, see explanation above)

- [Change Amount Debug impl to BTC with 8 decimals](https://github.com/rust-bitcoin/rust-bitcoin/pull/414)
- [Make uint types (un)serializable](https://github.com/rust-bitcoin/rust-bitcoin/pull/511)
- Add [more derives for key::Error](https://github.com/rust-bitcoin/rust-bitcoin/pull/551)
- [Fix optional amount serialization](https://github.com/rust-bitcoin/rust-bitcoin/pull/552)
- Add [PSBT base64 (de)serialization with Display & FromStr](https://github.com/rust-bitcoin/rust-bitcoin/pull/557)
- Add [non-API breaking derives for error & transaction types](https://github.com/rust-bitcoin/rust-bitcoin/pull/558)
- [Fix error derives](https://github.com/rust-bitcoin/rust-bitcoin/pull/559)
- [Add function to check RBF-ness of transactions](https://github.com/rust-bitcoin/rust-bitcoin/pull/565)
- [Add Script:dust_value() to get minimum output value for a spk](https://github.com/rust-bitcoin/rust-bitcoin/pull/566)
- [Improving bip32 ChildNumber display implementation](https://github.com/rust-bitcoin/rust-bitcoin/pull/567)
- [Make Script::fmt_asm a static method and add Script::str_asm ](https://github.com/rust-bitcoin/rust-bitcoin/pull/569)
- [Return BlockHash from BlockHeader::validate_pow](https://github.com/rust-bitcoin/rust-bitcoin/pull/572)
- [Add a method to error on non-standard hashtypes](https://github.com/rust-bitcoin/rust-bitcoin/pull/573)
- [Include proprietary key in deserialized PSBT](https://github.com/rust-bitcoin/rust-bitcoin/pull/577)
- [Fix Script::dust_value()'s calculation for non-P2*PKH script_pubkeys](https://github.com/rust-bitcoin/rust-bitcoin/pull/579)
- Add [Address to optimized QR string](https://github.com/rust-bitcoin/rust-bitcoin/pull/581) conversion
- [Correct Transaction struct encode_signing_data_to doc comment](https://github.com/rust-bitcoin/rust-bitcoin/pull/582)
- Fixing [CI if base image's apt db is outdated](https://github.com/rust-bitcoin/rust-bitcoin/pull/583)
- [Introduce some policy constants from Bitcoin Core](https://github.com/rust-bitcoin/rust-bitcoin/pull/584)
- [Fix warnings for sighashtype](https://github.com/rust-bitcoin/rust-bitcoin/pull/586)
- [Introduction of Schnorr keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/589)
- Adding [constructors for compressed and uncompressed ECDSA keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/592)
- [Count bytes read in encoding](https://github.com/rust-bitcoin/rust-bitcoin/pull/594)
- [Add verify_with_flags to Script and Transaction](https://github.com/rust-bitcoin/rust-bitcoin/pull/598)
- [Fixes documentation intra-links and enforce it](https://github.com/rust-bitcoin/rust-bitcoin/pull/600)
- [Fixing hashes core dependency and fuzz feature](https://github.com/rust-bitcoin/rust-bitcoin/pull/602)

# 0.26.0 - 2020-12-21

- Add [signet support](https://github.com/rust-bitcoin/rust-bitcoin/pull/291)
- Add [wtxidrelay message and `WTx` inv type](https://github.com/rust-bitcoin/rust-bitcoin/pull/446) for BIP 339
- Add [addrv2 support](https://github.com/rust-bitcoin/rust-bitcoin/pull/449)
- Distinguish [`FilterHeader` and `FilterHash`](https://github.com/rust-bitcoin/rust-bitcoin/pull/454)
- Add [hash preimage fields](https://github.com/rust-bitcoin/rust-bitcoin/pull/478) to PSBT
- Detect [write errors for `PublicKey::write_into`](https://github.com/rust-bitcoin/rust-bitcoin/pull/507)
- impl `Ord` and `PartialOrd` [for `Inventory`](https://github.com/rust-bitcoin/rust-bitcoin/pull/517)
- Add [binary encoding for BIP32 xkeys](https://github.com/rust-bitcoin/rust-bitcoin/pull/470)
- Add [Taproot Tagged Hashes](https://github.com/rust-bitcoin/rust-bitcoin/pull/259)
- Add [`message::MAX_INV_SIZE` constant](https://github.com/rust-bitcoin/rust-bitcoin/pull/516)
- impl [`ToSocketAddrs` for network addresses](https://github.com/rust-bitcoin/rust-bitcoin/pull/514)
- Add [new global fields to PSBT](https://github.com/rust-bitcoin/rust-bitcoin/pull/499)
- [Serde serialization of PSBT data](https://github.com/rust-bitcoin/rust-bitcoin/pull/497)
- [Make `Inventory` and `NetworkMessage` enums exhaustive](https://github.com/rust-bitcoin/rust-bitcoin/pull/496)
- [Add PSBT proprietary keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/471)
- [Add `PublicKey::read_from` method symmetric with `write_to`](https://github.com/rust-bitcoin/rust-bitcoin/pull/542)
- [Bump rust-secp to 0.20, turn off `recovery` feature by default](https://github.com/rust-bitcoin/rust-bitcoin/pull/545)
- [Change return value of `consensus_encode` to `io::Error`](https://github.com/rust-bitcoin/rust-bitcoin/pull/494)

# 0.25.1 - 2020-10-26

- Remove an incorrect `debug_assert` that can cause a panic when running using
  the dev profile.

# 0.25.1 - 2020-10-07

- [Expose methods on `Script`](https://github.com/rust-bitcoin/rust-bitcoin/pull/387) to generate various scriptpubkeys
- [Expose all cargo features of secp256k1](https://github.com/rust-bitcoin/rust-bitcoin/pull/486)
- Allow directly creating [various hash newtypes](https://github.com/rust-bitcoin/rust-bitcoin/pull/388)
- Add methods to `Block` [to get the coinbase tx and BIP34 height commitment](https://github.com/rust-bitcoin/rust-bitcoin/pull/444)
- [Add `extend` method](https://github.com/rust-bitcoin/rust-bitcoin/pull/459) to bip32::DerivationPath
- [Alias `(Fingerprint, DerivationPath)` as `KeySource`](https://github.com/rust-bitcoin/rust-bitcoin/pull/480)
- [Add serde implementation for PSBT data structs](https://github.com/rust-bitcoin/rust-bitcoin/pull/497)
- [Add FromStr/Display implementation for SigHashType](https://github.com/rust-bitcoin/rust-bitcoin/pull/497/commits/a4a7035a947998c8d0d69dab206e97253fd8e048)
- Expose [the raw sighash message](https://github.com/rust-bitcoin/rust-bitcoin/pull/485) from sighash computations
- Add [support for signmessage/verifymessage style message signatures](https://github.com/rust-bitcoin/rust-bitcoin/pull/413)

# 0.25.0 - 2020-09-10

- **Bump MSRV to 1.29.0**

# 0.24.0 - 2020-09-10

- [Remove](https://github.com/rust-bitcoin/rust-bitcoin/pull/385) the `BitcoinHash` trait
- [Introduce `SigHashCache` structure](https://github.com/rust-bitcoin/rust-bitcoin/pull/390) to replace `SighashComponents` and support all sighash modes
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/416) `Transaction::get_size` method
- [Export](https://github.com/rust-bitcoin/rust-bitcoin/pull/412) `amount::Denomination`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/417) `Block::get_size` and `Block::get_weight` methods
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/415) `MerkleBlock::from_header_txids`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/429) `BlockHeader::u256_from_compact_target`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/448) `feefilter` network message
- [Cleanup/replace](https://github.com/rust-bitcoin/rust-bitcoin/pull/397) `Script::Instructions` iterator API
- [Disallow uncompressed pubkeys in witness address generation](https://github.com/rust-bitcoin/rust-bitcoin/pull/428)
- [Deprecate](https://github.com/rust-bitcoin/rust-bitcoin/pull/451) `contracthash` module
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/435) modulo division operation for `Uint128` and `Uint256`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/436) `slice_to_u64_be` endian conversion method

# 0.23.0 - 2020-01-07

- Update `secp256k1` dependency to `0.17.1`.
- Update `bitcoinconsensus` dependency to `0.19.0-1`.
- Update `bech32` dependency to `0.7.2`.

# 0.22.0 - 2020-01-07

- Add `ServiceFlags` type.
- Add `NetworkMessage::command`.
- Add `key::Error`.
- Add newtypes for specific hashes:
    - `Txid`
    - `Wtxid`
    - `BlockHash`
    - `SigHash`
    - `PubkeyHash`
    - `ScriptHash`
    - `WPubkeyHash`
    - `WScriptHash`
    - `TxMerkleNode`
    - `WitnessMerkleNode`
    - `WitnessCommitment`
    - `XpubIdentifier`
    - `FilterHash`
- Refactor `CommandString`.
- Refactor `Reject` message.
- Rename `RejectReason` enum variants.
- Refactor `encode::Error`.
- Implement `Default` for `TxIn`.
- Implement `std::hash::Hash` for `Inventory`.
- Implement `Copy` for `InvType` enum.
- Use `psbt::Error` in `PartiallySignedTransaction::from_unsigned_tx`.
- Drop message decode max length to 4_000_000.
- Drop `hex` and `byteorder` dependencies.

# 0.21.0 - 2019-10-02

* Add [serde to `BlockHeader` and `Block`](https://github.com/rust-bitcoin/rust-bitcoin/pull/321)
* [Clean up `StreamReader` API](https://github.com/rust-bitcoin/rust-bitcoin/pull/318) (breaking change)
* Add [reject message](https://github.com/rust-bitcoin/rust-bitcoin/pull/323) to p2p messages

# 0.20.0 - 2019-08-23

* Update `secp256k1` 0.15 and `bitcoinconsensus` 0.17

# 0.19.0 - 2019-08-16

* Add `Amount` and `SignedAmount` types.
* Add BIP-158 support with `BlockFilter` and related types.
* Add `misc::signed_msg_hash()` for signing messages.
* Add `MerkleBlock` and `PartialMerkleTree` types.
* bip32: Support serde serializaton for types and add some utility methods:
    * `ChildNumber::increment`
    * `DerivationPath::children_from`
    * `DerivationPath::normal_children`
    * `DerivationPath::hardened_children`
* Add `blockdata::script::Builder::push_verify` to verify-ify an opcode.
* Add `sendheaders` network message.
* Add `OutPoint::new()` method and JSON-serialize as `<txid>:<vout>`.
* Refactor `Address` type:
    * Now supports segwit addresses with version >0.
    * Add `Address::from_script` constructor.
    * Add `Address::address_type` inspector.
    * Parsing now returns an `address::Error` instead of `encode::Error`.
    * Removed `bitcoin_bech32` dependency for bech32 payloads.
* bip143: Rename `witness_script` to `script_code`
* Rename `BlockHeader::spv_validate` to `validate_pow`
* Rename `OP_NOP2` and `OP_NOP3` to `OP_CLTV` and `OP_CSV`
* psbt: Use `BTreeMap` instead of `HashMap` to ensure serialization roundtrips.
* Drop `Decimal` type.
* Drop `LoneHeaders` type.
* Replace `strason` dependency with (optional) `serde_json`.
* Export the `dashcore_hashes` and `secp256k1` dependent crates.
* Updated `dashcore_hashes` dependency to v0.7.
* Removed `rand` and `serde_test` dependencies.
* Internal improvements to consensus encoding logic.

# 0.18.0 - 2019-03-21

* Update `bitcoin-bech32` version to 0.9
* add `to_bytes` method for `key` types
* add serde impls for `key` types
* contracthash: minor cleanups, use `key` types instead of `secp256k1` types

# 0.17.1 - 2019-03-04

* Add some trait impls to `PublicKey` for miniscript interoperability

# 0.17.0 - 2019-02-28 - ``The PSBT Release''

* **Update minimum rustc version to 1.22**.
* [Replace `rust-crypto` with `dashcore_hashes`; refactor hash types](https://github.com/rust-bitcoin/rust-bitcoin/pull/215)
* [Remove `Address::p2pk`](https://github.com/rust-bitcoin/rust-bitcoin/pull/222/)
* Remove misleading blanket `MerkleRoot` implementation; [it is now only defined for `Block`](https://github.com/rust-bitcoin/rust-bitcoin/pull/218)
* [Add BIP157](https://github.com/rust-bitcoin/rust-bitcoin/pull/215) (client-side block filtering messages)
* Allow network messages [to be deserialized even across multiple packets](https://github.com/rust-bitcoin/rust-bitcoin/pull/231)
* [Replace all key types](https://github.com/rust-bitcoin/rust-bitcoin/pull/183) to better match abstractions needed for PSBT
* [Clean up BIP32](https://github.com/rust-bitcoin/rust-bitcoin/pull/233) in preparation for PSBT; [use new native key types rather than `secp256k1` ones](https://github.com/rust-bitcoin/rust-bitcoin/pull/238/)
* Remove [apparently-used `Option` serialization](https://github.com/rust-bitcoin/rust-bitcoin/pull/236#event-2158116421) code
* Finally merge [PSBT](https://github.com/rust-bitcoin/rust-bitcoin/pull/103) after nearly nine months

# 0.16.0 - 2019-01-15

* Reorganize opcode types to eliminate unsafe code
* Un-expose some macros that were unintentionally exported
* Update rust-secp256k1 dependency to 0.12
* Remove `iter::Pair` type which does not belong in this library
* Minor bugfixes and optimizations

# 0.15.1 - 2018-11-08

* [Detect p2pk addresses with compressed keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/189)

# 0.15.0 - 2018-11-03

* [Significant API overhaul](https://github.com/rust-bitcoin/rust-bitcoin/pull/156):
    * Remove `nu_select` macro and low-level networking support
    * Move `network::consensus_params` to `consensus::params`
    * Move many other things into `consensus::params`
    * Move `BitcoinHash` from `network::serialize` to `hash`; remove impl for `Vec<u8>`
    * Rename/restructure error types
    * Rename `Consensus{De,En}coder` to `consensus::{De,En}coder`
    * Replace `Raw{De,En}coder` with blanket impls of `consensus::{De,En}coder` on `io::Read` and `io::Write`
    * make `serialize` and `serialize_hex` infallible
* Make 0-input transaction de/serialization [always use segwit](https://github.com/rust-bitcoin/rust-bitcoin/pull/153)
* Implement `FromStr` and `Display` for many more types

# 0.14.2 - 2018-09-11

* Add serde support for `Address`

# 0.14.1 - 2018-08-28

* Reject non-compact `VarInt`s on various types
* Expose many types at the top level of the crate
* Add `Ord`, `PartialOrd` impls for `Script`

# 0.14.0 - 2018-08-22

* Add [regtest network](https://github.com/rust-bitcoin/rust-bitcoin/pull/84) to `Network` enum
* Add [`Script::is_op_return()`](https://github.com/rust-bitcoin/rust-bitcoin/pull/101/) which is more specific than
  `Script::is_provably_unspendable()`
* Update to bech32 0.8.0; [add Regtest bech32 address support](https://github.com/rust-bitcoin/rust-bitcoin/pull/110)
* [Replace rustc-serialize dependency with hex](https://github.com/rust-bitcoin/rust-bitcoin/pull/107) as a stopgap
  toward eliminating any extra dependencies for this; clean up the many independent hex encoders and decoders
  throughout the codebase.
* [Add conversions between `ChildNumber` and `u32`](https://github.com/rust-bitcoin/rust-bitcoin/pull/126); make
  representation non-public; fix documentation
* [Add several derivation convenience](https://github.com/rust-bitcoin/rust-bitcoin/pull/129) to `bip32` extended keys
* Make `deserialize::deserialize()` [enforce no trailing bytes](https://github.com/rust-bitcoin/rust-bitcoin/pull/129)
* Replace `TxOutRef` with `OutPoint`; use it in `TxIn` struct.
* Use modern `as_` `to_` `into_` conventions for array-wrapping types; impl `Display` rather than `ToString` for most types
* Change `script::Instructions` iterator [to allow rejecting non-minimal pushes](https://github.com/rust-bitcoin/rust-bitcoin/pull/136);
  fix bug where errors would iterate forever.
* Overhaul `Error`; introduce `serialize::Error` [and use it for `SimpleDecoder` and `SimpleDecoder` rather
  than parameterizing these over their error type](https://github.com/rust-bitcoin/rust-bitcoin/pull/137).
* Overhaul `UDecimal` and `Decimal` serialization and parsing [and fix many lingering parsing bugs](https://github.com/rust-bitcoin/rust-bitcoin/pull/142)
* [Update to serde 1.0 and strason 0.4](https://github.com/rust-bitcoin/rust-bitcoin/pull/125)
* Update to secp256k1 0.11.0
* Many, many documentation and test improvements.

# 0.13.1

* Add `Display` trait to uints, `FromStr` trait to `Network` enum
* Add witness inv types to inv enum, constants for Bitcoin regtest network, `is_coin_base` accessor for tx inputs
* Expose `merkleroot(Vec<Sha256dHash>)`

# 0.13

* Move witnesses inside the `TxIn` structure
* Add `Transaction::get_weight()`
* Update bip143 `sighash_all` API to be more ergonomic

# 0.12

* The in-memory blockchain was moved into a dedicated project rust-bitcoin-chain.
* Removed old script interpreter
* A new optional feature "bitcoinconsensus" lets this library use Bitcoin Core's native
script verifier, wrappend into Rust by the rust-bitcoinconsenus project.
See `Transaction::verify` and `Script::verify` methods.
* Replaced Base58 traits with `encode_slice`, `check_encode_slice`, from and `from_check` functions in the base58 module.
* Un-reversed the Debug output for Sha256dHash
* Add bech32 support
* Support segwit address types

### 0.11

* Remove `num` dependency at Matt's request; agree this is obnoxious to require all
downstream users to also have a `num` dependency just so they can use `Uint256::from_u64`.

### Dashcore RPC

# 0.15.0

- bump bitcoin crate version to 0.28.0
- add `get_block_stats`
- add `add_node`
- add `remove_node`
- add `onetry_node`
- add `disconnect_node`
- add `disconnect_node_by_id`
- add `get_added_node_info`
- add `get_node_addresses`
- add `list_banned`
- add `clear_banned`
- add `add_ban`
- add `remove_ban`
- make `Auth::get_user_pass` public
- add `ScriptPubkeyType::witness_v1_taproot`

# 0.14.0

- add `wallet_conflicts` field in `WalletTxInfo`
- add `get_chain_tips`
- add `get_block_template`
- implement `From<u64>` and `From<Option<u64>>` for `ImportMultiRescanSince`
- bump rust-bitcoin dependency to 0.27
- bump json-rpc dependency to 0.12.0
- remove dependency on `hex`

# 0.13.0

- add `wallet_process_psbt`
- add `unlock_unspent_all`
- compatibility with Bitcoin Core v0.21
- bump rust-bitcoin dependency to 0.26
- implement Deserialize for ImportMultiRescanSince
- some fixes for some negative confirmation values

# 0.12.0

- bump `bitcoin` dependency to version `0.25`, increasing our MSRV to `1.29.0`
- test against `bitcoind` `0.20.0` and `0.20.1`
- add `get_balances`
- add `get_mempool_entry`
- add `list_since_block`
- add `get_mempool_entry`
- add `list_since_block`
- add `uptime`
- add `get_network_hash_ps`
- add `get_tx_out_set_info`
- add `get_net_totals`
- partially implement `scantxoutset`
- extend `create_wallet` and related APIs
- extend `GetWalletInfoResult`
- extend `WalletTxInfo`
- extend testsuite
- fix `GetPeerInfoResult`
- fix `GetNetworkInfoResult`
- fix `GetTransactionResultDetailCategory`
- fix `GetMempoolEntryResult` for bitcoind prior to `0.19.0`
- fix `GetBlockResult` and `GetBlockHeaderResult`

# 0.11.0

- fix `minimum_sum_amount` field name in `ListUnspentQueryOptions`
- add missing "orphan" variant for `GetTransactionResultDetailCategory`
- add `ImportMultiRescanSince` to support "now" for `importmulti`'s
  `timestamp` parameter
- rename logging target to `bitcoincore_rpc` instead of `bitcoincore_rpc::client`
- other logging improvements

# 0.10.0

- rename `dump_priv_key` -> `dump_private_key` + change return type
- rename `get_block_header_xxx` methods to conform with `get_block_xxx` methods
- rename `get_raw_transaction_xxx` methods to conform with `get_block_xxx` methods
- rename `GetBlockHeaderResult` fields
- rename `GetMiningInfoResult` fields
- represent difficulty values as `f64` instead of `BigUint`
- fix `get_peer_info`
- fix `get_transaction`
- fix `get_balance`
- fix `get_blockchain_info` and make compatible with both 0.18 and 0.19
- fix `get_address_info`
- fix `send_to_address`
- fix `estimate_smart_fee`
- fix `import_private_key`
- fix `list_received_by_address`
- fix `import_address`
- fix `finalize_psbt`
- fix `fund_raw_transaction`
- fix `test_mempool_accept`
- fix `stop`
- fix `rescan_blockchain`
- add `import_address_script`
- add `get_network_info`
- add `version`
- add `Error::UnexpectedStructure`
- add `GetTransactionResultDetailCategory::Immature`
- make `list_unspent` more ergonomic
- made all exported enum types implement `Copy`
- export `jsonrpc` dependency.
- remove `num_bigint` dependency

# v0.9.1

- Add `wallet_create_funded_psbt`
- Add `get_descriptor_info`
- Add `combine_psbt`
- Add `derive_addresses`
- Add `finalize_psbt`
- Add `rescan_blockchain`

# v0.7.0

- use `bitcoin::PublicKey` instead of `secp256k1::PublicKey`
- fix get_mining_info result issue
- fix test_mempool_accept issue
- fix get_transaction result issues
- fix bug in fund_raw_transaction
- add list_transactions
- add get_raw_mempool
- add reconsider_block
- add import_multi
- add import_public_key
- add set_label
- add lock_unspent
- add unlock_unspent
- add create_wallet
- add load_wallet
- add unload_wallet
- increased log level for requests to debug

# v0.6.0

- polish Auth to use owned Strings
- fix using Amount type and Address types where needed
- use references of sha256d::Hashes instead of owned/copied

# v0.5.1

- add get_tx_out_proof
- add import_address
- add list_received_by_address

# v0.5.0

- add support for cookie authentication
- add fund_raw_transaction command
- deprecate sign_raw_transaction
- use PrivateKey type for calls instead of string
- fix for sign_raw_transaction
- use 32-bit integers for confirmations, signed when needed

# v0.4.0

- add RawTx trait for commands that take raw transactions
- update jsonrpc dependency to v0.11.0
- fix for create_raw_transaction
- fix for send_to_address
- fix for get_new_address
- fix for get_tx_out
- fix for get_raw_transaction_verbose
- use `secp256k1::SecretKey` type in API

# v0.3.0

- removed the GetTransaction and GetScript traits
    (those methods are now directly implemented on types)
- introduce RpcApi trait
- use bitcoin_hashes library
- add signrawtransactionwithkey command
- add testmempoolaccept command
- add generate command
- improve hexadecimal byte value representation
- bugfix getrawtransaction (support coinbase txs)
- update rust-bitcoin dependency v0.16.0 -> v0.18.0
- add RetryClient example

# v0.2.0

- add send_to_address command
- add create_raw_transaction command
- Client methods take self without mut
