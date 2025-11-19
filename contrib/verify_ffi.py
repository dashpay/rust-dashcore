#!/usr/bin/env python3
"""Verify that FFI headers and documentation are up to date."""

import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor


def build_ffi_crate(crate_dir: Path) -> tuple[str, int]:
    """Build crate to regenerate headers."""
    print(f"  Building {crate_dir.name}...")
    result = subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=crate_dir,
        capture_output=True,
        text=True
    )
    return crate_dir.name, result.returncode


def generate_ffi_docs(crate_dir: Path) -> tuple[str, int]:
    """Generate FFI documentation for a crate."""
    print(f"  Generating {crate_dir.name} docs...")
    result = subprocess.run(
        [sys.executable, "scripts/generate_ffi_docs.py"],
        cwd=crate_dir,
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                print(f"    {line}")
    return crate_dir.name, result.returncode


def main():
    repo_root = Path(__file__).parent.parent
    ffi_crates = [
        repo_root / "key-wallet-ffi",
        repo_root / "dash-spv-ffi"
    ]

    print("Regenerating FFI headers and documentation")

    # Build and generate docs for both crates in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        build_futures = [executor.submit(build_ffi_crate, crate) for crate in ffi_crates]
        doc_futures = [executor.submit(generate_ffi_docs, crate) for crate in ffi_crates]

        build_results = [f.result() for f in build_futures]
        doc_results = [f.result() for f in doc_futures]

    # Check if any builds failed
    for crate_name, returncode in build_results:
        if returncode != 0:
            print(f"Build failed for {crate_name}", file=sys.stderr)
            sys.exit(1)

    # Check if any doc generation failed
    for crate_name, returncode in doc_results:
        if returncode != 0:
            print(f"Documentation generation failed for {crate_name}", file=sys.stderr)
            sys.exit(1)

    print("  Generation complete, checking for changes...")

    # Check if headers changed
    headers_result = subprocess.run(
        ["git", "diff", "--exit-code", "--quiet", "--",
         "key-wallet-ffi/include/", "dash-spv-ffi/include/"],
        cwd=repo_root
    )

    # Check if docs changed
    docs_result = subprocess.run(
        ["git", "diff", "--exit-code", "--quiet", "--",
         "key-wallet-ffi/FFI_API.md", "dash-spv-ffi/FFI_API.md"],
        cwd=repo_root
    )

    headers_changed = headers_result.returncode != 0
    docs_changed = docs_result.returncode != 0

    if headers_changed or docs_changed:
        print()
        if headers_changed:
            print("FFI headers are out of date!\n")
            print("Header changes detected:")
            subprocess.run(
                ["git", "--no-pager", "diff", "--",
                 "key-wallet-ffi/include/", "dash-spv-ffi/include/"],
                cwd=repo_root
            )
            print()

        if docs_changed:
            print("FFI documentation is out of date!\n")
            print("Documentation changes detected:")
            subprocess.run(
                ["git", "--no-pager", "diff", "--",
                 "key-wallet-ffi/FFI_API.md", "dash-spv-ffi/FFI_API.md"],
                cwd=repo_root
            )
            print()

        sys.exit(1)

    print("FFI headers and documentation are up to date")


if __name__ == "__main__":
    main()
