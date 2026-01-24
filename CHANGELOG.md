# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
