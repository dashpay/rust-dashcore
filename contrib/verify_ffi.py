#!/usr/bin/env python3
"""Verify that FFI documentation is up to date."""

import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

FFI_CRATES = ["key-wallet-ffi", "dash-spv-ffi"]


def generate_ffi_docs(crate_dir: Path) -> tuple[str, int, str]:
    """Generate FFI documentation for a crate."""
    print(f"  Generating {crate_dir.name} docs...")
    result = subprocess.run(
        [sys.executable, "scripts/generate_ffi_docs.py"],
        cwd=crate_dir,
        capture_output=True,
        text=True
    )
    output = result.stdout
    if result.returncode != 0 and result.stderr:
        output = result.stderr
    return crate_dir.name, result.returncode, output


def main():
    repo_root = Path(__file__).parent.parent
    ffi_crate_dirs = [repo_root / crate for crate in FFI_CRATES]

    print("Regenerating FFI documentation")

    # Generate docs in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        doc_futures = [executor.submit(generate_ffi_docs, crate) for crate in ffi_crate_dirs]
        doc_results = [f.result() for f in doc_futures]

    # Check results and print output
    for crate_name, returncode, stdout in doc_results:
        if returncode != 0:
            print(f"Documentation generation failed for {crate_name}", file=sys.stderr)
            sys.exit(1)
        if stdout:
            for line in stdout.strip().split('\n'):
                print(f"    {line}")

    print("  Generation complete, checking for changes...")

    # Check if docs changed
    docs_result = subprocess.run(
        ["git", "diff", "--exit-code", "--quiet", "--",
         "key-wallet-ffi/FFI_API.md", "dash-spv-ffi/FFI_API.md"],
        cwd=repo_root
    )

    if docs_result.returncode != 0:
        print()
        print("FFI documentation is out of date!\n")
        print("Documentation changes detected:")
        subprocess.run(
            ["git", "--no-pager", "diff", "--",
             "key-wallet-ffi/FFI_API.md", "dash-spv-ffi/FFI_API.md"],
            cwd=repo_root
        )
        print()
        sys.exit(1)

    print("FFI documentation is up to date")


if __name__ == "__main__":
    main()
