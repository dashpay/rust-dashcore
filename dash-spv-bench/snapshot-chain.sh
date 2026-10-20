#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN_DIR="${SCRIPT_DIR}/chain-data"
SUBDIR="testnet3"
DASH_VERSION="23.1.7"      # keep in sync with run.sh
IMAGE="dash-spv-bench/dashd:${DASH_VERSION}"

cd "${SCRIPT_DIR}"

: "${BENCH_HEIGHT:?BENCH_HEIGHT must be set — run.sh exports it from the scenario blocks}"
command -v docker >/dev/null 2>&1 || { echo "Error: docker is required to build the snapshot." >&2; exit 1; }

docker image inspect "${IMAGE}" >/dev/null 2>&1 \
  || { echo "==> building peer image"
       docker build --build-arg "DASHVERSION=${DASH_VERSION}" \
         -t "${IMAGE}" -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"; }

mkdir -p "${CHAIN_DIR}"

echo "==> extending snapshot to height ${BENCH_HEIGHT} via docker (downloads only the missing blocks)..."

docker run --rm --user "$(id -u):$(id -g)" -v "${CHAIN_DIR}:/data" "${IMAGE}" \
  dashd -testnet -datadir=/data -daemon=0 -server=1 \
  -blockfilterindex=1 -peerblockfilters=1 -stopatheight="${BENCH_HEIGHT}" \
  -txindex=0 -prune=0 -disablewallet=1

echo "==> done. Snapshot is at ${CHAIN_DIR}/${SUBDIR} (height ${BENCH_HEIGHT})."
