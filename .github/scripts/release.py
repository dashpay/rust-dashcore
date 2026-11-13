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
SECTION_VERSION = re.compile(r"## (\d+\.\d+\.\d+) - ")
# `#123`, but not `rust-bitcoin#123`, a URL fragment or `[#123](...)`, which old entries use for
# upstream rust-bitcoin PRs.
PR_REFERENCE = re.compile(r"(?<![\w/\[])#(\d+)\b")
# `title (#123)` from a squash merge, `Merge pull request #123 from ...` from a merge commit.
MERGED_PR = re.compile(r"\(#(\d+)\)$|^Merge pull request #(\d+) ")
# Conventional Commit types that change the library for its users. Other PRs (`ci`, `docs`,
# `test`, `chore`, `build`) are usually left out of the changelog.
USER_FACING = re.compile(r"^(feat|fix|perf|refactor)(\([^)]*\))?!?: ")


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


def split_sections(changelog: str) -> tuple[str, list[str]]:
    """Returns the text before the first `## ` heading, and each `## ` section with its body."""
    starts = [match.start() for match in SECTION_START.finditer(changelog)]
    if not starts:
        return changelog, []
    ends = starts[1:] + [len(changelog)]
    return changelog[: starts[0]], [changelog[start:end] for start, end in zip(starts, ends)]


def release_section(changelog: str, version: str) -> str:
    """Returns the `## <version> - <date>` section, heading included."""
    heading = re.compile(rf"## {re.escape(version)} - (\S+)\n")
    for section in split_sections(changelog)[1]:
        match = heading.match(section)
        if not match:
            continue
        try:
            date.fromisoformat(match.group(1))
        except ValueError:
            raise ReleaseError(f"the `{version}` changelog heading has no YYYY-MM-DD date: {match.group(1)}")
        return section.strip() + "\n"
    raise ReleaseError(f"CHANGELOG.md has no `## {version} - YYYY-MM-DD` section")


def pr_references(text: str) -> set[int]:
    return {int(number) for number in PR_REFERENCE.findall(text)}


def merged_prs(subjects: list[str]) -> dict[int, str]:
    """Returns the commit subject of each merged PR, by PR number."""
    merged = {}
    for subject in subjects:
        match = MERGED_PR.search(subject)
        if match:
            merged[int(next(group for group in match.groups() if group))] = subject
    return merged


def format_prs(numbers: set[int]) -> str:
    return ", ".join(f"#{number}" for number in sorted(numbers))


def check(version: str, changelog: str, tags: list[str], merged: dict[int, str] | None) -> list[str]:
    """Raises if `version` is not ready to be released. Returns warnings that need a human look.

    `merged` holds the subjects of the PRs merged since the latest release, `None` when unknown.
    """
    section = release_section(changelog, version)
    if f"v{version}" in tags:
        raise ReleaseError(f"v{version} is already released, bump the workspace version")
    released = [parse_version(tag[1:]) for tag in tags]
    if released and parse_version(version) <= max(released):
        latest = ".".join(map(str, max(released)))
        raise ReleaseError(f"{version} is not above the latest release v{latest}")
    listed = pr_references(section)
    earlier = "".join(other for other in split_sections(changelog)[1] if not other.startswith(f"## {version} "))
    shipped = listed & pr_references(earlier)
    if shipped:
        raise ReleaseError(f"the {version} section lists PRs an earlier release already lists: {format_prs(shipped)}")
    if merged is None:
        return []
    warnings = []
    unmerged = listed - merged.keys()
    if unmerged:
        warnings.append(f"the {version} section lists PRs not merged since the latest release: {format_prs(unmerged)}")
    left_out = {number for number, subject in merged.items() if USER_FACING.match(subject)} - listed
    if left_out:
        warnings.append(f"the {version} section leaves out these merged PRs, check that each is meant to: {format_prs(left_out)}")
    return warnings


def bump(cargo_toml: str, changelog: str, released_changelog: str, released: str) -> tuple[str, str, str | None] | None:
    """Returns `Cargo.toml` and `CHANGELOG.md` for `dev` after `released`, and the new version.

    `dev` on `released` moves to the next minor version. `dev` already past it, after a patch
    release, only gains the released section and keeps its version (`None`). Returns `None` when
    `dev` needs neither.
    """
    header, sections = split_sections(changelog)
    versions = [match.group(1) if (match := SECTION_VERSION.match(section)) else None for section in sections]
    if None in versions:
        raise ReleaseError("CHANGELOG.md on dev has a section that is not a release, move its entries into one")
    version = workspace_version(cargo_toml)
    if parse_version(version) < parse_version(released):
        raise ReleaseError(f"dev is on {version}, below the released {released}")
    if released in versions and version != released:
        return None
    new_changelog = changelog
    if released not in versions:
        # Above the first older release, so a patch release lands below the newer sections.
        position = next(
            (index for index, other in enumerate(versions) if parse_version(other) < parse_version(released)),
            len(sections),
        )
        sections.insert(position, release_section(released_changelog, released))
        new_changelog = header + "\n\n".join(section.strip() for section in sections) + "\n"
    if version != released:
        return cargo_toml, new_changelog, None
    new_version = next_version(released)
    return set_workspace_version(cargo_toml, new_version), new_changelog, new_version


def bump_pr(released: str, new_version: str | None, repository: str, sha: str) -> tuple[str, str, str]:
    """Returns the branch, title and body of the PR that brings a release to `dev`."""
    release = f"[`v{released}`](https://github.com/{repository}/releases/tag/v{released})"
    tag = f"The release is the tag `v{released}` on {sha}"
    footer = "Opened by `.github/workflows/release.yml`."
    if new_version is None:
        body = (
            f"Adds the `{released}` changelog section to `dev` now that {release} is released from `master`. "
            f"`dev` is already past `{released}`, so its version stays.\n\n"
            f"This PR goes into `dev` only. {tag}.\n\n{footer}"
        )
        return f"chore/changelog-v{released}", f"chore: add the `{released}` changelog", body
    body = (
        f"Starts the `{new_version}` development cycle on `dev` now that {release} is released from `master`.\n\n"
        f"- Bump the workspace version to `{new_version}`.\n"
        f"- Add the `{released}` changelog section, identical to the one on `master`.\n\n"
        f"This PR goes into `dev` only. {tag}, where the workspace version stays `{released}`.\n\n{footer}"
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


def merged_since(tag: str) -> dict[int, str] | None:
    result = subprocess.run(["git", "log", "--format=%s", f"{tag}..HEAD"], capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        return None
    return merged_prs(result.stdout.splitlines())


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
    bump_parser.add_argument("--released-changelog", type=Path, required=True)
    args = parser.parse_args()

    cargo_toml = CARGO_TOML.read_text()
    changelog = CHANGELOG.read_text()
    try:
        if args.command == "version":
            print(workspace_version(cargo_toml))
        elif args.command == "check":
            version = workspace_version(cargo_toml)
            tags = remote_tags()
            latest = max(tags, key=lambda tag: parse_version(tag[1:]), default=None)
            merged = merged_since(latest) if latest else None
            if latest and merged is None:
                print(f"::warning::could not read the history since {latest}, so the merged PRs are not compared")
            for warning in check(version, changelog, tags, merged):
                print(f"::warning::{warning}")
            print(f"{version} is ready to be released")
        elif args.command == "notes":
            print(release_section(changelog, args.version), end="")
        elif args.command == "bump":
            result = bump(cargo_toml, changelog, args.released_changelog.read_text(), args.released)
            if result is None:
                print(f"::notice::dev already has the {args.released} changelog section")
                return
            new_cargo_toml, new_changelog, new_version = result
            CARGO_TOML.write_text(new_cargo_toml)
            CHANGELOG.write_text(new_changelog)
            branch, title, body = bump_pr(
                args.released, new_version, os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_SHA", "")
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
