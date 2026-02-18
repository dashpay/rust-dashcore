#!/usr/bin/env python3
"""Cross-platform setup script for dashd and test blockchain data.

Downloads the Dash Core binary and regtest test data for integration tests.
Outputs DASHD_PATH and DASHD_DATADIR lines suitable for appending to GITHUB_ENV
or evaluating in a shell.

Environment variables:
    DASHVERSION        - Dash Core version (default: 23.1.0)
    TEST_DATA_VERSION  - Test data release version (default: v0.0.2)
    TEST_DATA_REPO     - GitHub repo for test data (default: dashpay/regtest-blockchain)
    CACHE_DIR          - Cache directory (default: ~/.rust-dashcore-test)
"""

import os
import platform
import sys
import tarfile
import time
import urllib.request
import zipfile

# Keep these defaults in sync with .github/workflows/build-and-test.yml
DASHVERSION = os.environ.get("DASHVERSION", "23.1.0")
TEST_DATA_VERSION = os.environ.get("TEST_DATA_VERSION", "v0.0.2")
TEST_DATA_REPO = os.environ.get("TEST_DATA_REPO", "dashpay/regtest-blockchain")


def get_cache_dir():
    if "CACHE_DIR" in os.environ:
        return os.environ["CACHE_DIR"]
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if not home:
        sys.exit("Cannot determine home directory: neither HOME nor USERPROFILE is set")
    return os.path.join(home, ".rust-dashcore-test")


def get_asset_info():
    """Return the asset filename for the current platform."""
    system = platform.system()
    machine = platform.machine()

    if system == "Linux":
        linux_archs = {"aarch64": "aarch64", "arm64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}
        arch = linux_archs.get(machine)
        if not arch:
            sys.exit(f"Unsupported Linux architecture: {machine}")
        asset = f"dashcore-{DASHVERSION}-{arch}-linux-gnu.tar.gz"
    elif system == "Darwin":
        darwin_archs = {"arm64": "arm64", "x86_64": "x86_64"}
        arch = darwin_archs.get(machine)
        if not arch:
            sys.exit(f"Unsupported macOS architecture: {machine}")
        asset = f"dashcore-{DASHVERSION}-{arch}-apple-darwin.tar.gz"
    elif system == "Windows":
        asset = f"dashcore-{DASHVERSION}-win64.zip"
    else:
        sys.exit(f"Unsupported platform: {system}")

    return asset


def log(msg):
    print(msg, file=sys.stderr)


def download(url, dest, timeout=300, retries=3):
    for attempt in range(1, retries + 1):
        try:
            log(f"Downloading {url} (attempt {attempt}/{retries})...")
            with urllib.request.urlopen(url, timeout=timeout) as response:
                with open(dest, "wb") as f:
                    while chunk := response.read(8192):
                        f.write(chunk)
            return
        except Exception as e:
            log(f"Download failed: {e}")
            if attempt == retries:
                sys.exit(f"Failed to download {url} after {retries} attempts")
            time.sleep(5 * attempt)


def extract(archive_path, dest_dir):
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)
    else:
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(dest_dir, filter="data")


def setup_dashd(cache_dir):
    """Download and extract dashd binary. Returns the path to the dashd binary."""
    asset = get_asset_info()
    dashd_dir = os.path.join(cache_dir, f"dashcore-{DASHVERSION}")

    ext = ".exe" if platform.system() == "Windows" else ""
    dashd_bin = os.path.join(dashd_dir, "bin", f"dashd{ext}")

    if os.path.isfile(dashd_bin):
        log(f"dashd {DASHVERSION} already available")
        return dashd_bin

    log(f"Downloading dashd {DASHVERSION}...")
    archive_path = os.path.join(cache_dir, asset)
    url = f"https://github.com/dashpay/dash/releases/download/v{DASHVERSION}/{asset}"
    download(url, archive_path)
    extract(archive_path, cache_dir)
    os.remove(archive_path)
    log(f"Downloaded dashd to {dashd_dir}")

    if not os.path.isfile(dashd_bin):
        sys.exit(f"Expected binary not found after extraction: {dashd_bin}")

    return dashd_bin


def setup_test_data(cache_dir):
    """Download and extract test blockchain data. Returns the datadir path."""
    test_data_dir = os.path.join(
        cache_dir, f"regtest-blockchain-{TEST_DATA_VERSION}", "regtest-40000"
    )
    blocks_dir = os.path.join(test_data_dir, "regtest", "blocks")

    if os.path.isdir(blocks_dir):
        log(f"Test blockchain data {TEST_DATA_VERSION} already available")
        return test_data_dir

    log(f"Downloading test blockchain data {TEST_DATA_VERSION}...")
    parent_dir = os.path.join(cache_dir, f"regtest-blockchain-{TEST_DATA_VERSION}")
    os.makedirs(parent_dir, exist_ok=True)

    archive_path = os.path.join(cache_dir, "regtest-40000.tar.gz")
    url = f"https://github.com/{TEST_DATA_REPO}/releases/download/{TEST_DATA_VERSION}/regtest-40000.tar.gz"
    download(url, archive_path)
    extract(archive_path, parent_dir)
    os.remove(archive_path)

    if not os.path.isdir(blocks_dir):
        sys.exit(f"Expected blocks directory not found after extraction: {blocks_dir}")

    log(f"Downloaded test data to {test_data_dir}")

    return test_data_dir


def main():
    cache_dir = get_cache_dir()
    os.makedirs(cache_dir, exist_ok=True)

    dashd_path = setup_dashd(cache_dir)
    datadir = setup_test_data(cache_dir)

    # Output lines for GITHUB_ENV or shell eval
    print(f"DASHD_PATH={dashd_path}")
    print(f"DASHD_DATADIR={datadir}")


if __name__ == "__main__":
    main()
