#!/usr/bin/env python3
"""CI configuration management script.

Used by GitHub Actions workflows for test management.

Subcommands:
    verify-groups    Check all workspace crates are assigned to test groups
    run-group        Run tests for all crates in a group
    run-no-std       Run no-std build checks
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml


def get_workspace_metadata():
    """Get workspace metadata from cargo."""
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def load_yaml(path: Path):
    """Load YAML file with error handling."""
    try:
        with open(path) as f:
            content = yaml.safe_load(f)
            return content if content is not None else {}
    except FileNotFoundError:
        github_error(f"Configuration file not found: {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        github_error(f"Invalid YAML in {path}: {e}")
        sys.exit(1)


def github_error(msg: str):
    """Print GitHub Actions error annotation."""
    print(f"::error::{msg}")


def github_notice(msg: str):
    """Print GitHub Actions notice annotation."""
    print(f"::notice::{msg}")


def github_group_start(name: str):
    """Start a GitHub Actions log group."""
    print(f"::group::{name}", flush=True)


def github_group_end():
    """End a GitHub Actions log group."""
    print("::endgroup::", flush=True)


def github_output(name: str, value: str):
    """Write a GitHub Actions output variable."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def verify_groups(args):
    """Verify all workspace crates are assigned to test groups."""
    metadata = get_workspace_metadata()
    workspace_crates = {pkg["name"] for pkg in metadata["packages"]}

    config = load_yaml(args.groups_file)
    groups = config.get("groups", {})

    assigned = set()
    for group_crates in groups.values():
        if group_crates:
            assigned.update(group_crates)
    assigned.update(config.get("excluded", []) or [])

    unassigned = workspace_crates - assigned
    if unassigned:
        github_error(
            f"Crates not assigned to any test group: {', '.join(sorted(unassigned))}"
        )
        print("\nPlease add them to a group or 'excluded' section in ci-groups.yml")
        return 1

    print(f"All {len(workspace_crates)} workspace crates are assigned to test groups")

    # Output groups for GitHub Actions matrix
    github_output("groups", json.dumps(list(groups.keys())))

    return 0


def run_no_std(args):
    """Run no-std build checks from ci-no-std.yml.

    Format: crate_name: [list of configs]
    Each config runs: cargo check -p crate --no-default-features --features <config>
    Special: 'bare' means just --no-default-features (no features)
    """
    config = load_yaml(args.no_std_file)

    failed = []

    for crate_name, entries in config.items():
        if not entries:
            continue

        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                continue

            entry_clean = entry.strip()

            # Build cargo flags
            if entry_clean == "bare":
                flags = ["--no-default-features"]
                display_name = "bare"
            elif entry_clean == "no-std":
                flags = ["--no-default-features", "--features", "no-std"]
                display_name = "no-std"
            elif " " in entry_clean:
                # Multiple features (space-separated)
                features = entry_clean.replace(" ", ",")
                flags = ["--no-default-features", "--features", features]
                display_name = entry_clean.replace(" ", "+")
            else:
                # Single feature
                flags = ["--no-default-features", "--features", entry_clean]
                display_name = entry_clean

            github_group_start(f"{crate_name} ({display_name})")

            cmd = ["cargo", "check", "-p", crate_name] + flags
            result = subprocess.run(cmd)

            github_group_end()

            if result.returncode != 0:
                failed.append(f"{crate_name} ({display_name})")
                github_error(f"No-std check failed: {crate_name} with {' '.join(flags)}")

    if failed:
        print("\n" + "=" * 40)
        print("FAILED NO-STD CHECKS:")
        for f in failed:
            print(f"  - {f}")
        print("=" * 40)
        return 1

    return 0


def run_group_tests(args):
    """Run tests for all crates in a group."""
    config = load_yaml(args.groups_file)
    groups = config.get("groups", {})

    if args.group not in groups:
        github_error(f"Unknown group: {args.group}")
        return 1

    crates = groups[args.group] or []
    failed = []

    for crate in crates:
        # Skip dash-fuzz on Windows
        if args.os == "windows-latest" and crate == "dash-fuzz":
            github_notice(f"Skipping {crate} on Windows (honggfuzz not supported)")
            continue

        github_group_start(f"Testing {crate}")

        cmd = ["cargo", "test", "-p", crate, "--all-features"]
        result = subprocess.run(cmd)

        github_group_end()

        if result.returncode != 0:
            failed.append(crate)
            github_error(f"Test failed for {crate} on {args.os}")

    if failed:
        print("\n" + "=" * 40)
        print(f"FAILED TESTS ({args.group} on {args.os}):")
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
    parser.add_argument(
        "--no-std-file",
        type=Path,
        default=Path(".github/ci-no-std.yml"),
        help="Path to ci-no-std.yml",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("verify-groups", help="Verify all crates assigned to groups")
    subparsers.add_parser("run-no-std", help="Run no-std checks")

    run_group_parser = subparsers.add_parser("run-group", help="Run tests for a group")
    run_group_parser.add_argument("group", help="Group name")
    run_group_parser.add_argument("--os", default="ubuntu-latest", help="OS name")

    args = parser.parse_args()

    commands = {
        "verify-groups": verify_groups,
        "run-no-std": run_no_std,
        "run-group": run_group_tests,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
