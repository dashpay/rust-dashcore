# key-wallet

HD key derivation, accounts, address pools and transaction checking for Dash wallets. The root `AGENTS.md` applies here too. This file adds what is specific to this crate. Multi-wallet management lives in `key-wallet-manager`.

This crate handles key material. Correctness comes before performance, and private keys, seeds and mnemonics are never logged.

## Layout

- `wallet/`: `Wallet` and its construction, backup and restore. `wallet/managed_wallet_info/` holds `ManagedWalletInfo` plus coin selection, fees and transaction building.
- `account/`: `Account`, `AccountType` and `AccountCollection`, with the BLS and EdDSA variants.
- `managed_account/`: the mutable account state and `AddressPool`.
- `transaction_checking/`: `TransactionRouter` and the `WalletTransactionChecker` trait that decides which transactions belong to the wallet.
- `bip32.rs`, `dip9.rs`, `derivation*.rs`, `mnemonic.rs`, `seed.rs`: key derivation and the DIP-9 path constants.
- `gap_limit.rs`: the default gap limits and `MAX_GAP_LIMIT`.
- `src/tests/`: crate-level tests grouped by topic. `src/test_utils/`: helpers behind the `test-utils` feature.

## Invariants

- Keys and state are split. `Wallet` and `Account` hold identity only: wallet id, network, account type and extended public key. `ManagedWalletInfo` and the managed accounts hold everything that changes: address pools, transactions, UTXOs and balances. Don't put mutable state on `Wallet` or `Account`.
- Managed accounts come in three kinds. Standard, CoinJoin and DashPay accounts hold funds (`ManagedCoreFundsAccount`). Identity, asset-lock and provider accounts only derive keys (`ManagedCoreKeysAccount`). Platform payment accounts use `ManagedPlatformAccount`.
- A wallet, its accounts and its `ManagedWalletInfo` belong to one network. Mainnet uses coin type 5, every other network uses 1.
- Derivation paths come from `AccountType::derivation_path` and the `dip9` constants. Never change an existing path: wallets restored from the same seed would stop finding their funds. A new account type needs its own path, a `ManagedAccountType` variant and a route in `TransactionRouter`.
- `TransactionRouter::get_relevant_account_types` decides which accounts see a transaction type. An account type it does not list never matches, so update the router and its tests in `transaction_checking/transaction_router/tests/` together.
- An address pool derives up to `highest_used + gap_limit`, or `gap_limit` addresses while none is used. After marking addresses used, call `maintain_gap_limit` so the pool keeps watching ahead. `set_gap_limit` clamps to `MAX_GAP_LIMIT`.
- Add accounts to a live wallet with the `add_managed_*` methods of `ManagedAccountOperations`. They rewind the sync checkpoint so the new account's history gets scanned. Inserting into `ManagedWalletInfo::accounts` directly skips that.
- `Wallet::backup` and the `serde`/`bincode` encodings have no format version. Applications persist these bytes, so a change to a serialized type must keep existing data decodable.
- Library code never panics. Return `key_wallet::Error` through `Result`, including for malformed or untrusted input such as a corrupt backup.

## Features

`bls` and `eddsa` add BLS and Ed25519 accounts. `serde` and `bincode` add serialization, `bincode` is needed for backup and restore. `keep-finalized-transactions` keeps full records of ChainLocked transactions, which are otherwise reduced to their txids. Run `cargo test -p key-wallet --all-features` to cover every variant.
