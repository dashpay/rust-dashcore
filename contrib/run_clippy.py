#!/usr/bin/env python3
"""Run clippy."""

import subprocess
import sys

base = [
    "cargo", "clippy",
    "--workspace",
    "--target-dir", "target/clippy",
]

# Exclude dash-fuzz on Windows (honggfuzz doesn't support Windows)
if sys.platform == "win32":
    base.extend(["--exclude", "dash-fuzz"])

profiles = [
    ("all features + targets debug", ["--all-features", "--all-targets"]),
    ("all features + targets release", ["--all-features", "--all-targets", "--release"]),
    ("all targets debug", ["--all-targets"]),
    ("all targets release", ["--all-targets", "--release"]),
    ("default debug", []),
    ("default release", ["--release"]),
]

for label, extra in profiles:
    cmd = base + extra + ["--", "-D", "warnings"]
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"Clippy failed ({label}): {' '.join(cmd)}", file=sys.stderr)
        sys.exit(rc)
