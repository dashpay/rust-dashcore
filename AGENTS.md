# AGENTS.md

Conventions for anyone changing this repository, human or coding agent. It lists only what the code and the linters don't already tell you. Crates with their own rules carry a nested `AGENTS.md` (`dash-spv/`, `key-wallet/`).

## Repo map

Workspace members, as listed in the root `Cargo.toml` (package name in brackets where it differs):

- `dash/` (`dashcore`): protocol types, serialization, scripts, addresses, P2P messages, masternode lists.
- `crypto/` (`dashcore-crypto`): cryptographic primitives shared by the other crates.
- `dash-network/`: the `Network` enum and its parameters (magic bytes, ports, activation heights).
- `hashes/` (`dashcore_hashes`): Dash hash newtypes and the X11 engine over the hash functions of `bitcoin_hashes`.
- `internals/` (`dashcore-private`): internal macros and helpers.
- `key-wallet/`: HD keys, accounts, address pools and transaction checking.
- `key-wallet-manager/`: multi-wallet management, events and the `WalletInterface` that `dash-spv` drives.
- `dash-spv/`: the SPV client (network, storage, sync).
- `dash-network-seeds/`: masternode seed lists, refreshed weekly by CI.
- `masternode-seeds-fetcher/`: the tool that fetches those seed lists.
- `dash-spv-bench/`: sync benchmark harness for `dash-spv`.
- `git-state/`: proc macros exposing the git state at compile time.
- `rpc-client/` (`dashcore-rpc`), `rpc-json/` (`dashcore-rpc-json`), `rpc-integration-test/`: Dash Core JSON-RPC client, its types and its tests.
- `fuzz/` (`dash-fuzz`): honggfuzz targets.

Outside the workspace, `contrib/` holds scripts.

This library is not consensus code. It cannot replicate Dash Core's consensus behavior exactly.

## Commands

- `just` lists every recipe, including crate recipes such as `just dash-spv::test`. It needs just 1.47+, and PyYAML for `test` and `coverage`.
- `just check` is the gate before every commit and PR. It runs all pre-commit hooks including the push stage: rustfmt, typos, actionlint, file checks and clippy in three profiles with `-D warnings`. Without just: `pre-commit run --all-files --hook-stage pre-push`.
- `just doc` and `just msrv` run the documentation and MSRV checks CI runs.
- Targeted tests: `cargo test -p <crate> --lib <name>`. Drop `--lib` only when you need doc tests or `tests/` integration tests.
- `just test <group>` runs a CI test group from `.github/ci-groups.yml` (`core`, `spv`, `wallet`, `rpc`).

### dashd integration tests

`dash-spv` has integration tests against a real regtest `dashd`. They catch restart, resync and disconnect bugs that unit tests miss, so run them for every `dash-spv` change. Never set `SKIP_DASHD_TESTS=1`.

- `just dash-spv::test [args]` downloads `dashd` and the regtest chains (cached in `~/.rust-dashcore-test/`) and runs the `dash-spv` tests against them.
- To call cargo directly, load the environment first: `eval $(python3 contrib/setup-dashd.py)`.
- `DASHD_TEST_RETAIN_DIR=<dir>` keeps the data of failed tests. The just recipes default it to `target/dashd-test-logs`. Each test gets a directory with its SPV log at `spv/logs/run.log`.
- `DASHD_TEST_LOG=1` (with `--nocapture`) prints the logs, `DASHD_TEST_RETAIN_ALWAYS=1` also keeps passing tests. `just dash-spv::test-log` sets both.

## Branches and releases

- Branch from `dev` and open every PR against `dev`. This includes fixes and docs.
- `master` holds the latest release. Maintainers cut a `chore/release-vX.Y.Z` branch, merge it into `master` and tag `vX.Y.Z`. Don't target `master` or a release branch.
- `CHANGELOG.md` is written from the merged PR titles when a release is cut. Don't edit it in a feature PR: CI fails a PR that touches it unless it carries the `release` label.

## Rust code style

- Put every `use` at the top of its module. Only `mod` starts a new scope, so inside `#[cfg(test)] mod tests` the imports go at the top of `tests`. Never write a `use` inside a function, closure or block.
- Don't write a fully qualified path to avoid an import. Write `use std::ptr;` and `ptr::null()`, not `std::ptr::null()`. Calling a method on an imported type (`Foo::new()`) is fine.
- Delete dead code instead of adding `#[allow(dead_code)]`. Git history keeps it. When a lint must be silenced, use `#[expect(lint, reason = "...")]` over `#[allow]`.
- Give new items the most restrictive visibility that compiles: private, then `pub(super)` or `pub(crate)`, `pub` only when the item is public API.
- Write numeric literals without type suffixes (`[2; 20]`, not `[2u8; 20]`) unless the compiler needs one.
- No `unwrap`, `expect`, `panic!` or `unreachable!` in library code. Return an error, using the crate's `thiserror` error types. Tests may unwrap.
- `dash-spv` denies `std::sync::Mutex` and `std::sync::RwLock` (`dash-spv/clippy.toml`). Use `tokio::sync::Mutex` and `tokio::sync::RwLock`.
- Take network parameters from `dash-network` instead of hardcoding them. Never log private keys or seeds.
- Reuse before you add. Search for an existing function, type or test helper first, and extend it with a parameter rather than writing a near copy.
- Fix the root cause, not the symptom. Keep the diff to what the change needs, and put a refactor it depends on in its own commit.

## Comments and docs

- Default to no comment. Write one only for a *why* the code cannot show: a hidden constraint, a subtle invariant, a workaround, behavior that would surprise a reader. Never narrate *what* the code does.
- No history in code: no previous implementations, fixed bugs, issue or PR numbers, callers, or the current task. That belongs in the commit message and the PR.
- One line is normal, three is the ceiling. Before writing a block, try a clearer name or a smaller function instead. Make each point once, not on the struct, the field and the test.
- A doc comment starts with what the item does or returns ("Returns ...", "Whether ..."). The reason follows in its own sentence.
- Short sentences, one idea each, plain subject-verb-object order. Use real identifiers, not private shorthand or vague pronouns.
- When your change makes a nearby comment untrue, fix that comment. Don't remove unrelated comments.
- No new emojis, no capitals for emphasis, no line-number references, no "now returns" phrasing.

```rust
// Bad: dense, abstract, the point is buried.
/// Whether the diff not taken is wrong whatever our state: it contradicts
/// itself or the header that commits to it. Any other refusal can be a
/// gap or bug of ours, or depend on our own state, such as the base list
/// the diff is applied to or the network's activation heights.

// Good: the point first, then the reason, in plain sentences.
/// Whether the refusal proves the peer sent a bad diff. Only a diff that contradicts
/// itself or its block header does. Any other refusal can come from our side, such as
/// a stale base list or wrong activation heights.
```

## Tests

- Every fix comes with a regression test that fails without it.
- Before adding a `#[test]`, look for an existing test with the same setup and extend it.
- Test through the public API. Don't set internal fields or states by hand: a test that builds a state production never reaches proves nothing.
- Reuse the existing helpers before writing new ones. Each crate keeps them in `src/test_utils/` behind its `test-utils` feature (`dashcore`, `key-wallet`, `key-wallet-manager`, `dash-spv`).
- Never skip or delete a failing test. `#[ignore]` needs a comment linking the issue that tracks the failure.

## Commits and pull requests

- Use Conventional Commits for commit subjects and PR titles. CI (`.github/workflows/pr-title.yml`) allows `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor` and `test`. Add the crate as scope (`fix(dash-spv): ...`) and `!` for a breaking change (`feat(key-wallet)!: ...`).
- Keep a subject or title around 50 characters and never over 72, counting the `type(scope): ` prefix. Say the one thing the change does. The how and why go in the body.
- Put identifiers in backticks: ``fix(dash-spv): handle `None` in `process_block` ``.
- Don't hard-wrap commit body paragraphs. Write each as one line and separate them with blank lines.
- One concern per PR. Split an unrelated fix or refactor into its own PR.
- The PR title becomes the changelog entry, so it must describe the change for a reader of the release notes.
- The PR body (the `--body` of `gh pr create`) is a few plain sentences: what was wrong or missing, and what the PR changes. Link the issue it closes. Leave out review transcripts, tables of local runs, lists of commands you ran and the history of the session.
- Open a draft PR while work is unfinished.
