#!/usr/bin/env python3
"""Run clippy."""

import subprocess
import sys

cmd = [
    "cargo", "clippy",
    "--workspace",
    "--all-features",
    "--all-targets",
]

# Exclude dash-fuzz on Windows (honggfuzz doesn't support Windows)
if sys.platform == "win32":
    cmd.extend(["--exclude", "dash-fuzz"])

cmd.extend(["--", "-D", "warnings"])

sys.exit(subprocess.call(cmd))
