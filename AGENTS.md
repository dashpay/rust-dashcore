# Repository Guidelines

## Project Structure & Module Organization
- Workspace with crates: `dash`, `hashes`, `internals`, `dash-network`, `dash-spv`, `key-wallet`, `rpc-*`, utilities (`fuzz`, `test-utils`), and FFI crates (`*-ffi`).
- Each crate keeps sources in `src/`; unit tests live alongside code with `#[cfg(test)]`. Integration tests use `tests/` (e.g., `rpc-integration-test`).
- FFI bindings are in `*-ffi`. Shared helpers in `internals/` and `test-utils/`.

## Build, Test, and Development Commands
- MSRV: 1.89. Build all: `cargo build --workspace --all-features`
- Test all: `cargo test --workspace --all-features` or `./contrib/test.sh` (set `DO_COV=true`, `DO_LINT=true`, `DO_FMT=true` as needed)
- Targeted tests: `cargo test -p dash-spv --all-features`
- FFI iOS builds: `cd key-wallet-ffi && ./build-ios.sh`
- Lint/format: `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all`
- Docs: `cargo doc --workspace` (add `--open` locally)

## Coding Style & Naming Conventions
- Mixed editions (2021/2024); follow crate idioms. Prefer async via `tokio` where applicable.
- Format with `rustfmt` (see `rustfmt.toml`); run `cargo fmt --all` before commits.
- Lint with `clippy`; some crates deny warnings in CI. Avoid `unwrap()/expect()` in library code; use error types (e.g., `thiserror`).
- Naming: `snake_case` (funcs/vars), `UpperCamelCase` (types/traits), `SCREAMING_SNAKE_CASE` (consts). Keep modules focused.

## Testing Guidelines
- Unit tests near code; integration tests under `tests/`. Use descriptive names (e.g., `test_parse_address_mainnet`).
- Run targeted suites: `cargo test -p key-wallet --all-features`. Network‑dependent or long tests may be `#[ignore]`; run with `-- --ignored`.
- Cover critical parsing, networking, SPV, and wallet flows. Add regression tests for fixes; consider property tests (e.g., `proptest`) where valuable.

## Commit & Pull Request Guidelines
- Prefer Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`. Keep subject ≤72 chars with clear scope and rationale.
- Target branches: feature work to `v**-dev` (development), hotfixes/docs to `master` unless directed otherwise.
- Pre‑PR checks: `cargo fmt`, `cargo clippy`, `cargo test` (workspace). Update docs/CHANGELOG if user-facing.
- Include in PRs: description, linked issues, test evidence (commands/output), and notes on features/FFI impacts.

## Security & Configuration Tips
- Not for consensus‑critical validation; do not rely on exact Dash Core consensus behavior.
- Never commit secrets or real keys; avoid logging sensitive data. Keep test vectors deterministic.
- Mirror strict CI locally if helpful: `export RUSTFLAGS="-D warnings"`.

## References
- General workflow lives in `CONTRIBUTING.md`. For workspace specifics and current tooling, prefer this guide and `CLAUDE.md` when they differ.
