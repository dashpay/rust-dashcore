# GitHub Actions recipes, run as `just gha::<recipe>`

import "../mod.just"

# `gh actions-lock` looks for `.github/workflows` under the current directory.
set working-directory := ".."

# Pin every action in `actions.lock` at a full version tag, which Dependabot then bumps.
# Use `taiki-e/install-action@v2` with `tool:`, not tags like `@just`. Those are recreated
# outside the branch history on every release, so their pins stop resolving.
lock:
    gh actions-lock --no-interactive

# Install or upgrade the `gh actions-lock` extension
setup:
    gh extension install github/gh-actions-lock --force

# Check that `actions.lock` covers every action and each pin resolves
verify:
    gh actions-lock --verify

# Check that every crate is in a CI test group and the matrix matches
verify-groups:
    {{ python }} .github/scripts/ci_config.py verify-groups
