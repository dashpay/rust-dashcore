# Contributing to rust-dashcore

**Branching model (important)**

Feature work targets the active `v**-dev` branch (development). Submit hotfixes and documentation-only changes to `master` unless maintainers direct otherwise.

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to Rust Dash Core
implementation and other Rust Dash-related projects, which are hosted in the
[Rust Dash Core Community](https://github.com/rust-dashcore) on GitHub. These are
mostly guidelines, not rules. Use your best judgment, and feel free to propose
changes to this document in a pull request.

#### Table Of Contents

- [General](#general)
- [Communication channels](#communication-channels)
- [Asking questions](#asking-questions)
- [Contribution workflow](#contribution-workflow)
  * [Preparing PRs](#preparing-prs)
  * [Peer review](#peer-review)
  * [Repository maintainers](#repository-maintainers)
- [Coding conventions](#coding-conventions)
  * [Formatting](#formatting)
  * [MSRV](#msrv)
  * [Naming conventions](#naming-conventions)
  * [Unsafe code](#unsafe-code)
- [Security](#security)
- [Testing](#testing)
- [Going further](#going-further)


## General

We welcome contributions of all kinds: bug fixes, features, tests, docs, and reviews. This codebase powers Dash protocol libraries (networking, SPV, wallet, FFI). Changes must be reviewed with security and backward‑compatibility in mind.


## Communication

- Use GitHub Issues for bugs and feature requests.
- Use Pull Requests for code changes and design discussions.
- If enabled, GitHub Discussions can host broader design topics.


## Asking questions

Prefer opening a GitHub Discussion (if enabled) or a clearly labeled issue. Provide context, reproduction steps, and what you’ve tried.


## Contribution workflow

We use the standard fork-and-PR model:

1. Fork the repository and create a topic branch.
2. Make focused commits; keep diffs minimal and self‑contained.
3. Ensure each commit builds and tests pass to keep `git bisect` meaningful.
4. Cover new functionality with tests and docs where applicable.
5. Open a PR early for feedback; keep the description clear and scoped.

Commits should explain the why and the what. Conventional Commits are encouraged.


## Preparing PRs

Active development happens on `v**-dev` branches. Feature work should target the current `v**-dev`. The `master` branch is kept stable; submit hotfixes and documentation changes to `master` unless directed otherwise. All PRs must compile without errors (verified by GitHub CI).

Prerequisites that a PR must satisfy for merging into the `master` branch:
* each commit within a PR should compile and pass unit tests with no errors, with
  relevant feature combinations (including building fuzz tests where applicable);
* the tip of any PR branch must also compile and pass tests with no errors on
  MSRV (see README for current MSRV) and run fuzz tests where applicable;
* contain all necessary tests for the introduced functional (either as a part of
  commits, or, more preferably, as separate commits, so that it's easy to
  reorder them during review and check that the new tests fail without the new
  code);
* include inline docs for newly introduced APIs and pass doc tests;
* be based on the recent tip of the target branch in this repository.

Reviewers may run additional scripts; passing CI is necessary but may not be sufficient for merge. To mirror CI locally:
```bash
# Full suite with optional knobs
DO_COV=true DO_LINT=true DO_FMT=true ./contrib/test.sh

# Or workspace-wide checks
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --all-features
```

### Peer review

Anyone may review PRs. Start with design and correctness, then style. Maintain respectful, constructive feedback.

### Repository maintainers

Pull request merge requirements:
- All CI checks pass.
- At least one maintainer approval (more may be required for risky changes).
- No unresolved blocking reviews.


## Coding conventions

Follow idiomatic Rust and crate‑local patterns.

### Formatting & Linting

Run `cargo fmt --all` before submitting PRs. Use `cargo clippy --workspace --all-targets -- -D warnings` to catch issues early. Avoid large, unrelated reformatting to keep diffs focused and `git blame` useful.

You may check the [discussion on the formatting](https://github.com/rust-bitcoin/rust-bitcoin/issues/172)
and [how it is planned to coordinate it with crate refactoring](https://github.com/rust-bitcoin/rust-bitcoin/pull/525)

For the new code it is recommended to follow style of the existing codebase and
avoid any end-line space characters.

### MSRV

The Minimal Supported Rust Version (MSRV) is 1.89; it is enforced by CI. Crates use mixed editions (2021/2024); consult `Cargo.toml` and README for details.

### Naming conventions

Use Rust standards: `UpperCamelCase` for types/traits, `snake_case` for modules/functions/variables, `SCREAMING_SNAKE_CASE` for constants. Prefer descriptive names matching Dash domain concepts.

### Unsafe code

Minimize `unsafe`. When required (especially across FFI boundaries), encapsulate it, document invariants, add tests, and consider Miri/sanitizers.


## Security

This library is NOT suitable for consensus‑critical validation. Always validate inputs from untrusted sources and never log or store private keys. Report vulnerabilities privately via GitHub Security Advisories or by contacting the maintainers through a private channel.


## Testing

Testing is a priority. Keep unit tests close to code and use `tests/` for integration. Add fuzz targets under `fuzz/` when appropriate. Use deterministic test vectors and avoid network dependencies unless explicitly required (mark such tests `#[ignore]`).


## References

- See README for workspace overview and MSRV.
- See CLAUDE.md and AGENTS.md for repo‑specific commands and workflows.

Overall, have fun and build safely.
