#!/usr/bin/env python3
"""Release automation for the `Release Check` and `Release` workflows.

Subcommands:
    version    Print the workspace version
    check      Check that the workspace version is ready to be released
    notes      Print the changelog section of a version
    bump       Start the next version on `dev` after a release
"""

import argparse
import os
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO_TOML = ROOT / "Cargo.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
# The `version` of `[workspace.package]`, which every crate inherits.
WORKSPACE_VERSION = re.compile(r'(^\[workspace\.package\]\n(?:(?!\[)[^\n]*\n)*?version = ")(\d+\.\d+\.\d+)(")', re.MULTILINE)
SECTION_START = re.compile(r"^## ", re.MULTILINE)
RELEASE_TAG = re.compile(r"v\d+\.\d+\.\d+")
# A changelog entry runs from its bullet to the next bullet, heading or blank line.
ENTRY_END = re.compile(r"\n(?=[ \t]*[-*] |#|\n)")
# The `(#123)` or `(#123, #124)` that ends an entry, before its authors. Any other `#123` in an
# entry mentions another PR, as a revert or a follow-up does.
OWN_PRS = re.compile(r"\((#\d+(?:, #\d+)*)\)\.?(?: @[\w-]+)*\s*$")


class ReleaseError(Exception):
    pass


def parse_version(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def next_version(version: str) -> str:
    major, minor, _ = parse_version(version)
    return f"{major}.{minor + 1}.0"


def workspace_version(cargo_toml: str) -> str:
    match = WORKSPACE_VERSION.search(cargo_toml)
    if not match:
        raise ReleaseError("Cargo.toml has no `version` in `[workspace.package]`")
    return match.group(2)


def set_workspace_version(cargo_toml: str, version: str) -> str:
    workspace_version(cargo_toml)
    return WORKSPACE_VERSION.sub(rf"\g<1>{version}\g<3>", cargo_toml, count=1)


def split_sections(changelog: str) -> list[str]:
    """Returns each `## ` section with its body."""
    starts = [match.start() for match in SECTION_START.finditer(changelog)]
    return [changelog[start:end] for start, end in zip(starts, starts[1:] + [len(changelog)])]


def release_section(changelog: str, version: str) -> str:
    """Returns the `## <version> - <date>` section, heading included."""
    heading = re.compile(rf"## {re.escape(version)} - (\S+)\n")
    for section in split_sections(changelog):
        match = heading.match(section)
        if not match:
            continue
        try:
            date.fromisoformat(match.group(1))
        except ValueError:
            raise ReleaseError(f"the `{version}` changelog heading has no YYYY-MM-DD date: {match.group(1)}")
        return section.strip() + "\n"
    raise ReleaseError(f"CHANGELOG.md has no `## {version} - YYYY-MM-DD` section")


def own_prs(text: str) -> set[int]:
    """Returns the PRs the entries in `text` are for."""
    groups = (match.group(1) for entry in ENTRY_END.split(text) if (match := OWN_PRS.search(entry)))
    return {int(number) for group in groups for number in re.findall(r"\d+", group)}


def format_prs(numbers: set[int]) -> str:
    return ", ".join(f"#{number}" for number in sorted(numbers))


def check(version: str, changelog: str, tags: list[str]):
    """Raises if `version` is not ready to be released."""
    section = release_section(changelog, version)
    if f"v{version}" in tags:
        raise ReleaseError(f"v{version} is already released, bump the workspace version")
    released = [parse_version(tag[1:]) for tag in tags]
    if released and parse_version(version) <= max(released):
        latest = ".".join(map(str, max(released)))
        raise ReleaseError(f"{version} is not above the latest release v{latest}")
    listed = own_prs(section)
    earlier = own_prs("".join(other for other in split_sections(changelog) if not other.startswith(f"## {version} ")))
    shipped = listed & earlier
    if shipped:
        raise ReleaseError(f"the {version} section lists PRs an earlier release already lists: {format_prs(shipped)}")


def bump(version: str, released: str) -> str | None:
    """Returns the version `dev` moves to after `released`, or `None` when `dev` keeps `version`.

    `dev` keeps its version when it is already past `released`, after a patch release.
    """
    if parse_version(version) < parse_version(released):
        raise ReleaseError(
            f"dev is on {version}, below the released {released}: merge the open version bump PR into dev, then rerun this job"
        )
    return next_version(released) if version == released else None


def bump_pr(released: str, new_version: str | None, repository: str, sha: str) -> tuple[str, str, str]:
    """Returns the branch, title and body of the PR that brings a release to `dev`."""
    release = f"[`v{released}`](https://github.com/{repository}/releases/tag/v{released})"
    footer = f"This PR goes into `dev` only. The release is the tag `v{released}` on {sha}.\n\nOpened by `.github/workflows/release.yml`."
    if new_version is None:
        body = (
            f"Copies `CHANGELOG.md` from `master` now that {release} is released. "
            f"`dev` is already past `{released}`, so its version stays.\n\n{footer}"
        )
        return f"chore/changelog-v{released}", f"chore: add the `{released}` changelog", body
    body = (
        f"Starts the `{new_version}` development cycle on `dev` now that {release} is released.\n\n"
        f"- Bump the workspace version to `{new_version}`.\n"
        f"- Copy `CHANGELOG.md` from `master`.\n\n{footer}"
    )
    return f"chore/bump-version-to-{new_version}", f"chore: bump version to `{new_version}`", body


def remote_tags() -> list[str]:
    output = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", "origin", "refs/tags/v*"],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    ).stdout
    names = (line.split("refs/tags/", 1)[1] for line in output.splitlines() if "refs/tags/" in line)
    return [name for name in names if RELEASE_TAG.fullmatch(name)]


def set_output(name: str, value: str):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as output:
            output.write(f"{name}<<RELEASE_OUTPUT\n{value}\nRELEASE_OUTPUT\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version")
    commands.add_parser("check")
    notes = commands.add_parser("notes")
    notes.add_argument("version")
    bump_parser = commands.add_parser("bump")
    bump_parser.add_argument("released")
    args = parser.parse_args()

    cargo_toml = CARGO_TOML.read_text()
    changelog = CHANGELOG.read_text()
    try:
        if args.command == "version":
            print(workspace_version(cargo_toml))
        elif args.command == "check":
            version = workspace_version(cargo_toml)
            check(version, changelog, remote_tags())
            print(f"{version} is ready to be released")
        elif args.command == "notes":
            print(release_section(changelog, args.version), end="")
        elif args.command == "bump":
            new_version = bump(workspace_version(cargo_toml), args.released)
            if new_version:
                CARGO_TOML.write_text(set_workspace_version(cargo_toml, new_version))
            branch, title, body = bump_pr(
                args.released,
                new_version,
                os.environ.get("GITHUB_REPOSITORY", ""),
                os.environ.get("GITHUB_SHA", ""),
            )
            print(title)
            set_output("branch", branch)
            set_output("title", title)
            set_output("body", body)
    except ReleaseError as error:
        print(f"::error::{error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
