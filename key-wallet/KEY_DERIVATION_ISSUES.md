# Key Derivation Issues & Improvement Plan

Analysis of `src/derivation.rs` and `src/dip9.rs`.

---

## Issue 1 — Two parallel derivation systems

`derivation.rs` defines `HDWallet`, `AccountDerivation`, `DerivationPathBuilder`, and `DerivationStrategy`. The actual wallet derivation used by `ManagedCoreAccount` and `Wallet` goes through `AccountType::derivation_path()` + the `IndexConstPath` constants in `dip9.rs`. These two systems coexist without integration — `HDWallet` is never called from `ManagedCoreAccount` or `Wallet`. It is essentially dead infrastructure.

**Impact:** Maintenance burden. New derivation logic added to one system is invisible to the other.

**Fix:** Remove `HDWallet`, `AccountDerivation`, and `DerivationStrategy` or consolidate them onto `IndexConstPath`. `DerivationPathBuilder` can stay as a utility if it fixes the silent-error bugs below.

---

## Issue 2 — `for_network_and_type` silently ignores `account_type` (bug)

**File:** `src/derivation.rs:334`

```rust
pub fn for_network_and_type(
    self,
    network: Network,
    _account_type: AccountType,  // underscore — never read
    account_index: u32,
) -> Result<DerivationPath> {
    // Always derives BIP44, regardless of what account_type was passed
    self.purpose(44).coin_type(coin_type).account(account_index)...
}
```

Calling this with `AccountType::ProviderVotingKeys` silently returns a BIP44 path. No error, no warning. The function signature promises network/type-aware derivation but delivers BIP44 unconditionally.

**Fix:** Either delegate to `account_type.derivation_path(network)` or remove the method entirely.

---

## Issue 3 — `hardened()` and `normal()` silently swallow errors (bug)

**File:** `src/derivation.rs:249`

```rust
pub fn hardened(mut self, index: u32) -> Self {
    if let Ok(child) = ChildNumber::from_hardened_idx(index) {
        self.components.push(child);
    }
    // silently no-ops if index is out of range
    self
}
```

An invalid index produces a silently shorter path. The builder's `build()` then returns a valid `Result<DerivationPath>` over the wrong (truncated) path, so callers have no indication anything went wrong.

**Fix:** Either make `hardened()`/`normal()` return `Result<Self>` (breaking but correct), or change the terminal methods (`build()`, `bip44()`) to validate that all requested components were successfully added.

---

## Issue 4 — `Secp256k1::new()` allocated per operation (performance)

Three separate call sites create a new secp256k1 context on every invocation:

- `HDWallet::new()` — stores `Secp256k1<All>` in the struct
- `AccountDerivation::new()` — same
- `IndexConstPath::derive_priv_ecdsa_for_master_seed()` — `src/dip9.rs:96`

A secp256k1 context allocates and fills precomputed tables (~520 KB for `All`). Creating one per derivation call, or one per wallet instance that gets cloned, wastes significant time and memory.

**Fix:** Use a thread-local context:

```rust
thread_local! {
    static SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
}
```

Or accept `&Secp256k1<C>` as a parameter in all derivation functions and let the caller own one shared instance. The `IndexConstPath` methods already do this partially — `derive_priv_ecdsa_for_master_seed` is the outlier that creates its own.

---

## Issue 5 — String parsing per address derivation (performance)

**File:** `src/derivation.rs:176`

```rust
pub fn receive_address(&self, index: u32) -> Result<ExtendedPubKey> {
    let path = format!("m/0/{}", index)
        .parse::<DerivationPath>()  // heap alloc + parse on every call
        .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
```

Same pattern in `change_address()`. Every address derivation allocates a formatted string and runs the path parser. The `IndexConstPath::append()` pattern in `dip9.rs` shows the correct approach: build `DerivationPath` directly from `ChildNumber` values.

**Fix:**

```rust
pub fn receive_address(&self, index: u32) -> Result<ExtendedPubKey> {
    let path = DerivationPath::from(vec![
        ChildNumber::Normal { index: 0 },
        ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?,
    ]);
```

---

## Issue 6 — Private key used where public derivation suffices (security hygiene)

**File:** `src/derivation.rs:406`

```rust
pub fn scan_for_activity<C, F>(
    &self,
    key: &ExtendedPrivKey,   // accepts private key
    ...
    F: Fn(&ExtendedPubKey) -> bool,
) -> Result<Vec<u32>> {
    let derived = key.derive_priv(secp, &path)?;       // derives private child
    let pubkey = ExtendedPubKey::from_priv(secp, &derived);
    if check_fn(&pubkey) { ...                         // only needs pubkey
```

For non-hardened child paths (all external/internal address pool scanning), public key derivation is cryptographically sufficient. Deriving private keys here unnecessarily exposes private key material to the check function's closure scope and any future logging/error paths.

**Fix:** Accept `&ExtendedPubKey` and use `derive_pub`. Watch-only wallets can use this without any private key. Callers that have a private key can pass `ExtendedPubKey::from_priv(secp, &priv_key)` once at the call site.

---

## Issue 7 — Provider key paths have no named constants in `dip9.rs`

All other DIP9 paths are defined as `IndexConstPath` constants:

```
COINJOIN_PATH_MAINNET / TESTNET
IDENTITY_REGISTRATION_PATH_MAINNET / TESTNET
IDENTITY_TOPUP_PATH_MAINNET / TESTNET
IDENTITY_INVITATION_PATH_MAINNET / TESTNET
ASSET_LOCK_ADDRESS_TOPUP_PATH_MAINNET / TESTNET
ASSET_LOCK_SHIELDED_ADDRESS_TOPUP_PATH_MAINNET / TESTNET
DASHPAY_ROOT_PATH_MAINNET / TESTNET
PLATFORM_PAYMENT_ROOT_PATH_MAINNET / TESTNET
```

But provider key paths (`ProviderVotingKeys`, `ProviderOwnerKeys`, `ProviderOperatorKeys`, `ProviderPlatformKeys`) are assembled inline inside `AccountType::derivation_path()` using raw `ChildNumber::from_hardened_idx` calls with magic numbers. The DIP-3 paths are:

| Account type | Path |
|---|---|
| ProviderVotingKeys | `m/9'/coin_type'/3'/1'` |
| ProviderOwnerKeys | `m/9'/coin_type'/3'/2'` |
| ProviderOperatorKeys | `m/9'/coin_type'/3'/3'` |
| ProviderPlatformKeys | `m/9'/coin_type'/3'/4'` |

**Fix:** Add `PROVIDER_VOTING_PATH_MAINNET`, `PROVIDER_OWNER_PATH_MAINNET`, etc. as `IndexConstPath` constants, matching the pattern used for every other DIP9 path.

---

## Issue 8 — `DerivationPathReference` has no extension point

**File:** `src/dip9.rs:13`

```rust
pub enum DerivationPathReference {
    Unknown = 0,
    BIP32 = 1,
    // ... 16 more fixed variants
    Root = 255,
}
```

Plain integer enum, no room for application-defined values. When the `AccountTypeSpec` trait refactor lands (see `ACCOUNT_TYPE_REFACTOR.md`), external crates defining their own account types will need to tag their derivation paths with a reference discriminant that does not conflict with the built-in ones.

**Fix:** Add a `Custom(u32)` variant, or reserve a range (e.g. 128–254) for application use and document it. The `Custom` approach is cleanest:

```rust
pub enum DerivationPathReference {
    // ... existing variants
    Custom(u32),  // for application-defined paths outside the Dash standard set
}
```

This requires handling in the serde/bincode impls but is straightforward.

---

## Issue 9 — No caching of intermediate derived keys (performance)

Paths like `m/9'/5'/15'/0'` (DashPay root for account 0) are the shared parent of many contact-specific keys. Currently every derivation walks the full path from the master key. For a wallet with 50 DashPay contacts, the 3-component prefix `m/9'/5'/15'` is re-derived 50 times.

The same applies to any account type with many child keys: identity keys, provider keys, Platform payment keys.

**Impact:** Quadratic derivation cost relative to the number of keys per account. Noticeable during wallet restore/scan when hundreds of keys are checked.

**Fix:** Cache intermediate `ExtendedPrivKey` / `ExtendedPubKey` nodes at the account level. The natural place is `ManagedAccount`, which already holds the account-level xpub. Derivation below the account root should start from the cached account key, not re-derive from master.

The `address_pool` already receives an account key via `KeySource` — this is the correct boundary. The issue is that `IndexConstPath::derive_priv_ecdsa_for_master_seed` is sometimes called to re-derive the account key itself from seed on each use rather than caching it after the first derivation.

---

## Priority

| # | Issue | Type | Priority |
|---|---|---|---|
| 2 | `for_network_and_type` ignores `account_type` | Bug | High |
| 3 | `hardened()`/`normal()` swallow errors | Bug | High |
| 1 | Two parallel derivation systems | Architecture | Medium |
| 4 | `Secp256k1::new()` per operation | Performance | Medium |
| 5 | String parsing per address | Performance | Medium |
| 6 | Private key used where public suffices | Security hygiene | Medium |
| 7 | Provider paths have no named constants | Maintainability | Low |
| 8 | `DerivationPathReference` not extensible | Architecture | Low (blocks `AccountTypeSpec` refactor) |
| 9 | No intermediate key cache | Performance | Low |

Issues 2 and 3 are silent correctness bugs and should be fixed first regardless of any other refactoring. Issues 1 and 8 are blockers for the `AccountTypeSpec` extensibility refactor described in `ACCOUNT_TYPE_REFACTOR.md`.
