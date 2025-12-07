#!/usr/bin/env bash

REPO_DIR=$(git rev-parse --show-toplevel)

listAllTargetFiles() {
  pushd "$REPO_DIR/fuzz" > /dev/null || exit 1
  # List dash targets first, then hashes
  find fuzz_targets/dash -type f -name "*.rs" 2>/dev/null
  find fuzz_targets/hashes -type f -name "*.rs" 2>/dev/null
  popd > /dev/null || exit 1
}

listTargetFiles() {
  # Exclude targets that don't work in CI
  listAllTargetFiles | grep -v 'deserialize_transaction\|deserialize_prefilled_transaction\|deserialize_psbt'
}

targetFileToName() {
  echo "$1" \
    | sed 's/^fuzz_targets\///' \
    | sed 's/\.rs$//' \
    | sed 's/\//_/g'
}

targetFileToHFuzzInputArg() {
  baseName=$(basename "$1")
  dirName="${baseName%.*}"
  if [ -d "hfuzz_input/$dirName" ]; then
    echo "HFUZZ_INPUT_ARGS=\"-f hfuzz_input/$dirName/input\""
  fi
}

listTargetNames() {
  for target in $(listTargetFiles); do
    targetFileToName "$target"
  done
}

# Utility function to avoid CI failures on Windows
checkWindowsFiles() {
  incorrectFilenames=$(find . -type f -name "*,*" -o -name "*:*" -o -name "*<*" -o -name "*>*" -o -name "*|*" -o -name "*\?*" -o -name "*\**" -o -name "*\"*" | wc -l)
  if [ "$incorrectFilenames" -gt 0 ]; then
    echo "Bailing early because there is a Windows-incompatible filename in the tree."
    exit 2
  fi
}

# Checks whether a fuzz case output some report, and dumps it in hex
checkReport() {
  reportFile="hfuzz_workspace/$1/HONGGFUZZ.REPORT.TXT"
  if [ -f "$reportFile" ]; then
    cat "$reportFile"
    for CASE in "hfuzz_workspace/$1/SIG"*; do
      xxd -p -c10000 < "$CASE"
    done
    if [ "${HFUZZ_FAIL_ON_CRASH:-}" = "1" ]; then
      exit 1
    else
      echo "[fuzz] Crash detected for $1, not failing (set HFUZZ_FAIL_ON_CRASH=1 to fail)"
    fi
  fi
}
