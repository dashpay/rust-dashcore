#!/usr/bin/env python3

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
# Absolute, as cargo runs each crate's tests from that crate's directory
DASHD_TEST_RETAIN_DIR = ROOT / "target" / "dashd-test-logs"
DASHD_CRATES = {"dash-spv", "dashcore-rpc"}
WORKFLOW_FILE = ROOT / ".github" / "workflows" / "rust.yml"


def load_yaml(path: Path):
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        github_error(f"Configuration file not found: {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        github_error(f"Invalid YAML in {path}: {e}")
        sys.exit(1)


def github_error(msg: str):
    print(f"::error::{msg}")


def github_output(name: str, value: str):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def tested_crates(groups_file: Path):
    metadata = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=True,
    )
    crates = {pkg["name"] for pkg in json.loads(metadata.stdout)["packages"]}
    excluded = set(load_yaml(groups_file).get("excluded") or [])
    return sorted(crates - excluded)


def verify_groups(args):
    """Verify every tested crate has a path filter in rust.yml, and no filter is unknown."""
    expected = tested_crates(args.groups_file)
    steps = load_yaml(WORKFLOW_FILE)["jobs"]["changes"]["steps"]
    filters = next(step["with"]["filters"] for step in steps if step.get("id") == "crates")
    actual = sorted(yaml.safe_load(filters))

    if actual != expected:
        github_error(
            f"Crate filters {actual} in {WORKFLOW_FILE} do not match tested crates {expected}. "
            f"Add a filter for each crate, or exclude it in {args.groups_file}."
        )
        return 1

    print(f"Every tested crate has a path filter: {expected}")
    return 0


def dashd_env():
    path = ROOT / "contrib" / "setup-dashd.py"
    spec = importlib.util.spec_from_file_location("setup_dashd", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.setup()


def run_tests(args):
    """Run tests for the given crates, or for every tested crate."""
    selected = args.crates or tested_crates(args.groups_file)

    env = os.environ.copy()
    if DASHD_CRATES.intersection(selected):
        env.update(dashd_env())
        if not env.get("DASHD_TEST_RETAIN_DIR"):
            env["DASHD_TEST_RETAIN_DIR"] = str(DASHD_TEST_RETAIN_DIR)

    coverage = args.coverage
    if coverage:
        github_output("crate_flags", ",".join(selected))

    failed = []
    for crate in selected:
        print(f"::group::Testing {crate}", flush=True)
        try:
            if coverage:
                cmd = ["cargo", "llvm-cov", "--no-report", "-p", crate, "--all-features"]
            else:
                cmd = ["cargo", "test", "-p", crate, "--all-features"]
            result = subprocess.run(cmd, env=env)

            if result.returncode == 0 and not coverage and crate == "key-wallet-manager":
                result = subprocess.run(["cargo", "test", "-p", crate], env=env)

            if result.returncode != 0:
                failed.append(crate)
                github_error(f"Test failed for {crate} on {args.os}")
        finally:
            print("::endgroup::", flush=True)

    if failed:
        print("\n" + "=" * 40)
        print(f"FAILED TESTS on {args.os}:")
        for f in failed:
            print(f"  - {f}")
        print("=" * 40)
        return 1

    return 0


def main():
    parser = argparse.ArgumentParser(description="CI configuration management")
    parser.add_argument(
        "--groups-file",
        type=Path,
        default=Path(".github/ci-groups.yml"),
        help="Path to ci-groups.yml",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("verify-groups", help="Verify every tested crate has a path filter")

    test_parser = subparsers.add_parser("test", help="Run tests for some crates, or for all")
    test_parser.add_argument("crates", nargs="*", help="Crate names (default: all)")
    test_parser.add_argument(
        "--os", default=os.environ.get("CI_OS", "local"), help="OS name for error messages"
    )
    test_parser.add_argument(
        "--coverage",
        action="store_true",
        help="Use cargo-llvm-cov for coverage collection",
    )

    args = parser.parse_args()

    commands = {
        "verify-groups": verify_groups,
        "test": run_tests,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
