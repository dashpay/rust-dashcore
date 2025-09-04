#!/usr/bin/env bash
set -ex

REPO_DIR=$(git rev-parse --show-toplevel)

# shellcheck source=./fuzz-util.sh
source "$REPO_DIR/fuzz/fuzz-util.sh"

# Check that input files are correct Windows file names
checkWindowsFiles

if [ "$1" == "" ]; then
  targetFiles="$(listTargetFiles)"
else
  # Accept either a direct path-like arg (e.g., hashes/cbor) or underscore form (hashes_cbor)
  if [ -f "fuzz_targets/$1.rs" ]; then
    targetFiles="fuzz_targets/$1.rs"
  else
    # Convert underscores to directory separators to match our layout
    converted="${1//_//}"
    if [ -f "fuzz_targets/$converted.rs" ]; then
      targetFiles="fuzz_targets/$converted.rs"
    else
      # Fallback to original behavior
      targetFiles="fuzz_targets/$1.rs"
    fi
  fi
fi

cargo --version
rustc --version

# Ensure we don't trigger ThinLTO/internalization issues with honggfuzz's link flags
export RUSTFLAGS="${RUSTFLAGS:-} -C lto=no"

# Testing
cargo install --force honggfuzz --no-default-features
for targetFile in $targetFiles; do
  targetName=$(targetFileToName "$targetFile")
  echo "Fuzzing target $targetName ($targetFile)"
  if [ -d "hfuzz_input/$targetName" ]; then
    HFUZZ_INPUT_ARGS="-f hfuzz_input/$targetName/input"
  else
    HFUZZ_INPUT_ARGS=""
  fi
  HFUZZ_RUN_ARGS="--run_time 30 --exit_upon_crash -v $HFUZZ_INPUT_ARGS" cargo hfuzz run "$targetName"

  checkReport "$targetName"
done
