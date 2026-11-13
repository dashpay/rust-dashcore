# dash-spv recipes, run as `just dash-spv::<recipe>`

import "../mod.just"

logs := root / "target" / "dashd-test-logs"
setup_dashd := quote(root / "contrib" / "setup-dashd.py")

export DASHD_TEST_RETAIN_DIR := env("DASHD_TEST_RETAIN_DIR", logs)

# Download dashd and the regtest chains, and print their env vars for `eval`
dashd:
    @{{ python }} {{ setup_dashd }}

# Run the tests against a regtest dashd, keeping failed tests' data
test *args:
    {{ python }} {{ setup_dashd }} -- cargo test -p dash-spv --all-features {{ args }}

# Run tests with dashd and SPV logs on the console, retaining every test's data
[env("DASHD_TEST_LOG", "1")]
[env("DASHD_TEST_RETAIN_ALWAYS", "1")]
[env("RUST_TEST_NOCAPTURE", "1")]
test-log *args:
    {{ python }} {{ setup_dashd }} -- cargo test -p dash-spv --all-features {{ args }}

# Print the retained tests' SPV log paths, newest first
logs:
    @{{ python }} -c "import pathlib, sys; [print(p) for p in sorted(pathlib.Path(sys.argv[1]).glob('*/spv/logs/run.log'), key=lambda p: p.stat().st_mtime, reverse=True)]" {{ quote(DASHD_TEST_RETAIN_DIR) }}

# Delete the retained test data
clean-logs:
    {{ python }} -c "import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" {{ quote(DASHD_TEST_RETAIN_DIR) }}
