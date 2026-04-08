# AccountType Extensibility Refactor

## Problem Statement

`AccountType` (and its mirror `ManagedAccountType`) is a closed enum that lives in `key-wallet`. It currently encodes:

- Standard BIP44/BIP32 accounts ← universal wallet primitives
- CoinJoin accounts ← Dash Core-specific
- Identity registration/top-up/invitation ← Dash Platform application
- Asset lock accounts ← Dash Platform application
- Provider voting/owner/operator/platform keys ← masternode application
- DashPay receiving/external accounts ← DashPay social payment application
- Platform Payment (DIP-17) ← Dash Platform application

**This means `key-wallet` has compile-time coupling to Dash Platform, DashPay, and masternode logic.** Any upstream crate that uses `key-wallet` and wants to add a new account type must:

1. Add a variant to `AccountType` in `account/account_type.rs`
2. Mirror it in `ManagedAccountType` in `managed_account/managed_account_type.rs`
3. Add routing logic in `transaction_checking/transaction_router/mod.rs`
4. Add pool construction in `ManagedAccountType::from_account_type()`

This is 4-file shotgun surgery per new account type, and it requires modifying `key-wallet` itself regardless of which upstream application introduces the new type.

---

## Goal

**`key-wallet` should know only about universal HD wallet mechanics.** Application-specific account types (DashPay, Platform, Masternode) should be defined in their own crates and composed into an application-level `AccountType` enum there.

---

## Proposed Design

### 1. Define `AccountTypeSpec` trait in `key-wallet`

This trait encodes everything `key-wallet` needs to know about any account type to manage it:

```rust
/// Everything key-wallet needs to know about an account type.
/// Implement this for your application's account type enum.
pub trait AccountTypeSpec:
    Clone + Debug + PartialEq + Eq + Send + Sync + 'static
{
    /// Derivation path for this account type on the given network.
    fn derivation_path(&self, network: Network) -> Result<DerivationPath, Error>;

    /// The `DerivationPathReference` tag (used for logging and serialization context).
    fn derivation_path_reference(&self) -> DerivationPathReference;

    /// Primary account index, if this account type has one.
    fn index(&self) -> Option<u32>;

    /// Describe the address pools this account type needs.
    /// key-wallet creates pools from these descriptors — no match arms needed.
    fn address_pool_configs(&self) -> Vec<AddressPoolConfig>;

    /// Whether this account operates on the Core chain (true) or only on Platform (false).
    /// Core-chain accounts are candidates for transaction relevance checking.
    /// Platform-only accounts (e.g., DIP-17 PlatformPayment) should return false.
    fn is_core_chain_account(&self) -> bool {
        true
    }

    /// Which transaction types are potentially relevant to this account type.
    /// Used by `TransactionRouter` to skip irrelevant accounts efficiently.
    fn relevant_transaction_types(&self) -> &'static [TransactionType];
}
```

#### `AddressPoolConfig` — replaces manual `AddressPool::new()` call sites

```rust
/// Descriptor for a single address pool that key-wallet should create.
pub struct AddressPoolConfig {
    /// Pool role (External / Internal / Absent / AbsentHardened)
    pub pool_type: AddressPoolType,
    /// Gap limit for this pool
    pub gap_limit: u32,
    /// Derivation suffix appended to the account base path.
    /// e.g., `[Normal(0)]` for the external chain, `[Normal(1)]` for internal.
    /// Empty for single-pool account types.
    pub path_suffix: Vec<ChildNumber>,
}
```

This lets `ManagedAccountType::from_account_type()` become a single generic loop over `account_type.address_pool_configs()` — no more per-variant arms.

---

### 2. Define a `ManagedAccount<AT>` generic struct

Instead of the `ManagedAccountType` enum (which is a structural mirror of `AccountType`), use a single generic struct:

```rust
/// Managed (mutable) account state, generic over the application's account type.
pub struct ManagedAccount<AT: AccountTypeSpec> {
    /// The application-defined account type (carries derivation + pool config).
    pub account_type: AT,
    /// Address pools, created from `account_type.address_pool_configs()`.
    pub pools: Vec<AddressPool>,
    pub metadata: AccountMetadata,
    pub balance: WalletCoreBalance,
    pub transactions: BTreeMap<Txid, TransactionRecord>,
    pub utxos: BTreeMap<OutPoint, Utxo>,
    pub(crate) spent_outpoints: HashSet<OutPoint>,
}
```

`ManagedAccount::new(account_type, network, key_source)` constructs all pools by calling `account_type.address_pool_configs()`. No match arms. The current `to_account_type()` method on `ManagedAccountType` disappears because the original `AT` value is stored directly.

---

### 3. Make `Wallet` and `ManagedWalletInfo` generic

```rust
pub struct Wallet<AT: AccountTypeSpec> {
    pub wallet_id: [u8; 32],
    pub wallet_type: WalletType,
    pub accounts: BTreeMap<Network, AccountCollection<AT>>,
}

pub struct ManagedWalletInfo<AT: AccountTypeSpec> {
    pub accounts: Vec<ManagedAccount<AT>>,
    // ...
}
```

Callers that currently write `Wallet` write `Wallet<DashAccountType>` instead. `DashAccountType` is defined in whatever crate owns the application (e.g., `dash-spv` or a new `dash-account-types` crate).

---

### 4. Slim down `key-wallet`'s built-in enum

Keep only genuinely universal types in `key-wallet` itself:

```rust
/// Universal account types provided by key-wallet.
/// Application crates extend this by defining their own enum
/// that wraps or delegates to this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreAccountType {
    Standard { index: u32, standard_account_type: StandardAccountType },
    CoinJoin { index: u32 },
}

impl AccountTypeSpec for CoreAccountType { ... }
```

Every application-specific variant moves to the crate that owns it:

| Variant group | Moves to |
|---|---|
| `IdentityRegistration`, `IdentityTopUp`, `IdentityInvitation`, `AssetLock*`, `PlatformPayment` | `dash-platform` crate |
| `ProviderVotingKeys`, `ProviderOwnerKeys`, `ProviderOperatorKeys`, `ProviderPlatformKeys` | `dash-masternode` crate (or `dash-spv`) |
| `DashpayReceivingFunds`, `DashpayExternalAccount` | `dashpay` crate |

Each downstream crate defines its own enum and `impl AccountTypeSpec for MyAccountType`. The full Dash application assembles them:

```rust
// In e.g., dash-spv or a new dash-account-types crate
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DashAccountType {
    Core(CoreAccountType),
    Platform(PlatformAccountType),   // from dash-platform
    Masternode(MasternodeAccountType), // from dash-masternode
    DashPay(DashPayAccountType),     // from dashpay
}

impl AccountTypeSpec for DashAccountType {
    fn derivation_path(&self, network: Network) -> Result<DerivationPath, Error> {
        match self {
            Self::Core(at)       => at.derivation_path(network),
            Self::Platform(at)   => at.derivation_path(network),
            Self::Masternode(at) => at.derivation_path(network),
            Self::DashPay(at)    => at.derivation_path(network),
        }
    }
    // ... delegate all other methods similarly
}
```

Adding a new account type in any upstream crate now requires **zero changes to `key-wallet`**.

---

### 5. Transaction routing — remove `AccountTypeToCheck`

`AccountTypeToCheck` is a third parallel enum that duplicates `AccountType` variant names. It exists to avoid needing `ManagedAccountType` values in the router. It goes away:

- `AccountTypeSpec::relevant_transaction_types()` returns which `TransactionType` values this account cares about.
- `TransactionRouter::get_relevant_accounts(tx_type, accounts)` iterates the live account list and calls `account.relevant_transaction_types().contains(&tx_type)`.

No more separate `AccountTypeToCheck` enum. No more `TryFrom<ManagedAccountType> for AccountTypeToCheck`.

---

## Migration Strategy (incremental)

### Phase 1 — Introduce the trait, keep the enum

1. Define `AccountTypeSpec` trait in `key-wallet`.
2. `impl AccountTypeSpec for AccountType` — all 15 variants, exactly matching current behavior.
3. Add `AddressPoolConfig` and make `ManagedAccountType::from_account_type()` use it internally for new variants only.

**No breaking change yet.** Existing users keep using `AccountType` directly.

### Phase 2 — Generic structs, additive

1. Introduce `ManagedAccount<AT: AccountTypeSpec>` alongside the existing `ManagedCoreAccount` (the current concrete type).
2. Add `type ManagedCoreAccount = ManagedAccount<AccountType>` type alias so existing call sites compile unchanged.
3. Make `Wallet<AT>` generic; `type DashWallet = Wallet<AccountType>` alias for backwards compat.

### Phase 3 — Split the enum

1. Create `CoreAccountType` with only `Standard` and `CoinJoin`.
2. Move application-specific variants to their respective crates.
3. Create `DashAccountType` combining all of them.
4. Deprecate `AccountType` in favour of `DashAccountType` (or remove if all callers are internal).

### Phase 4 — Remove dead code

Drop `AccountTypeToCheck`, `ManagedAccountType` (the old enum), `TryFrom<ManagedAccountType>` impls, and the per-variant arms in `from_account_type()`.

---

## What key-wallet retains after the refactor

| Concept | Stays in key-wallet | Moves out |
|---|---|---|
| `AccountTypeSpec` trait | ✅ | — |
| `AddressPoolConfig` struct | ✅ | — |
| `CoreAccountType` enum | ✅ | — |
| `ManagedAccount<AT>` generic struct | ✅ | — |
| `Wallet<AT>` generic struct | ✅ | — |
| `AddressPool`, `GapLimitStage` | ✅ | — |
| BIP32/SLIP10 derivation | ✅ | — |
| Transaction checking infrastructure | ✅ | — |
| `TransactionRouter` enum/logic | ✅ (core types only) | — |
| Identity, Asset lock variants | — | dash-platform |
| Provider key variants | — | dash-masternode |
| DashPay variants | — | dashpay |
| `DashAccountType` composite enum | — | dash-spv or new crate |

---

## Serialization considerations

The `AT` type parameter must satisfy `Serialize + Deserialize` (serde) and `Encode + Decode` (bincode) under the respective features. Because `DashAccountType` is defined by the application crate, it controls its own serialization format. **Existing serialized wallet data that uses the old `AccountType` enum is unaffected** as long as the new `DashAccountType` serializes variant names identically — which it will if the migration keeps the same enum variant names at the `DashAccountType` level.

If wire/disk format stability is required during migration, Phase 2 can keep `AccountType` as the concrete serialized type and only introduce the generic `ManagedAccount<AT>` internally.

---

## Concrete "before / after" for adding a new account type

### Before (current)

Adding a hypothetical `VaultAccount` requires edits to:

1. `key-wallet/src/account/account_type.rs` — add `VaultAccount` variant, `derivation_path()` arm, `index()` arm, `derivation_path_reference()` arm, `TryFrom<AccountType> for AccountTypeToCheck` arm
2. `key-wallet/src/managed_account/managed_account_type.rs` — add `VaultAccount` variant, mirror all `match` arms (`index()`, `address_pools()`, `address_pools_mut()`, `to_account_type()`, `from_account_type()`)
3. `key-wallet/src/transaction_checking/transaction_router/mod.rs` — add `VaultAccount` to `AccountTypeToCheck`, add `TryFrom<ManagedAccountType>` arm, add routing arm in `get_relevant_account_types()`

**5–8 match arm additions across 3 files in key-wallet.**

### After (proposed)

Adding `VaultAccount` in `my-vault-crate`:

```rust
// my-vault-crate/src/account_type.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAccountType {
    pub index: u32,
}

impl AccountTypeSpec for VaultAccountType {
    fn derivation_path(&self, network: Network) -> Result<DerivationPath, Error> {
        // custom path
    }
    fn derivation_path_reference(&self) -> DerivationPathReference {
        DerivationPathReference::Custom(42)
    }
    fn index(&self) -> Option<u32> { Some(self.index) }
    fn address_pool_configs(&self) -> Vec<AddressPoolConfig> {
        vec![AddressPoolConfig::single(DEFAULT_EXTERNAL_GAP_LIMIT)]
    }
    fn relevant_transaction_types(&self) -> &'static [TransactionType] {
        &[TransactionType::Standard]
    }
}
```

Then extend the application-level composite enum:

```rust
pub enum AppAccountType {
    Dash(DashAccountType),
    Vault(VaultAccountType),  // ← one line
}
impl AccountTypeSpec for AppAccountType { /* delegate match */ }
```

**Zero changes to key-wallet. One new type + one match arm in the application crate.**
