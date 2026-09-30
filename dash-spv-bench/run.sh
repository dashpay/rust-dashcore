#!/bin/bash
#
# dash-spv benchmark driver: builds the client, brings up local peers when the
# scenario has them, syncs inside the client container and archives the results.
#
# Usage: ./run.sh <scenario.yml|pattern>... [--flame] [--memory-snapshot] [--wallets <file>]
#
#   --flame             CPU flamegraph sampled by the client       -> flamegraph.svg
#   --memory-snapshot   live-heap flamegraph at the RSS peak        -> heap-peak.svg
#   --wallets <file>    one BIP39 mnemonic per line (default: wallets.txt)
#
# An argument that is not a file is a glob, tried against the current directory
# and then scenarios/. Every invocation writes results/<timestamp>/ with, per
# scenario, <name>.log, .run.log, .summary.txt and any flamegraph, plus
# results.tsv and report.md. RUST_LOG overrides the client's log filters.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SELF="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
INVOCATION_DIR="${PWD}"
IMAGE="dash-spv-bench/dashd:23.1.7"
CLIENT_IMAGE="dash-spv-bench/client:1"
RUST_CHANNEL="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "${REPO_ROOT}/rust-toolchain.toml" 2>/dev/null || true)"
RUST_IMAGE="rust:${RUST_CHANNEL:-1.89}-bookworm"
PROJECT="spv-bench"
STATE="${SCRIPT_DIR}/.clonedir"
CHAIN_DIR="${SCRIPT_DIR}/chain-data"

abspath() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "${INVOCATION_DIR%/}/$1" ;; esac; }
cd "${SCRIPT_DIR}"

FEATURES=""
FLAGS=()
SCN_ARGS=()
WALLETS_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --flame) FEATURES="${FEATURES} cpu-profile"; FLAGS+=("$1"); shift ;;
    --memory-snapshot) FEATURES="${FEATURES} heap-profile"; FLAGS+=("$1"); shift ;;
    --wallets) WALLETS_ARG="$(abspath "${2:?--wallets needs a file path}")"; FLAGS+=("$1" "${WALLETS_ARG}"); shift 2 ;;
    -h | --help) sed -n '3,/^set /p' "${SELF}" | sed '$d'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 1 ;;
    *) SCN_ARGS+=("$1"); shift ;;
  esac
done
[ "${#SCN_ARGS[@]}" -gt 0 ] || { echo "usage: $0 <scenario.yml|pattern>... [--flame] [--memory-snapshot] [--wallets <file>]" >&2; exit 1; }

SCN_FILES=()
add_matches() {
  local m
  while IFS= read -r m; do
    case "${m}" in /*) ;; *) m="$1/${m}" ;; esac
    if [ -f "${m}" ]; then SCN_FILES+=("${m}"); fi
  done < <(cd "$1" && compgen -G "$2")
}
for arg in "${SCN_ARGS[@]}"; do
  n="${#SCN_FILES[@]}"
  add_matches "${INVOCATION_DIR}" "${arg}"
  [ "${#SCN_FILES[@]}" -gt "${n}" ] || add_matches "${SCRIPT_DIR}/scenarios" "${arg}"
  [ "${#SCN_FILES[@]}" -gt "${n}" ] || { echo "Error: no scenario matched: ${arg}" >&2; exit 1; }
done

# Each scenario runs in a fresh invocation of this script, so one that fails
# cannot take the others with it.
if [ -z "${BENCH_BATCH:-}" ]; then
  RUN_TS="$(date +%Y%m%d-%H%M%S)"
  OUT_DIR="${SCRIPT_DIR}/results/${RUN_TS}"
  mkdir -p "${OUT_DIR}"
  TSV="${OUT_DIR}/results.tsv"
  REPORT="${OUT_DIR}/report.md"
  printf 'scenario\tcompleted\ttotal_ms\tblock_headers_ms\tfilter_headers_ms\tfilters_ms\ttransactions\tconfirmed_sat\tpeak_rss_mib\n' >"${TSV}"
  metric() { awk -F':[[:space:]]*' -v k="$2" '$1==k {gsub(/[[:space:]]+$/,"",$2); print $2; exit}' "$1"; }

  echo "==> ${#SCN_FILES[@]} scenario(s); results in ${OUT_DIR}"
  for f in "${SCN_FILES[@]}"; do
    name="$(basename "${f}" .yml)"
    log="${OUT_DIR}/${name}.log"
    echo "===== ${name} ====="
    BENCH_BATCH=1 BENCH_ARCHIVE_DIR="${OUT_DIR}" BENCH_ARCHIVE_NAME="${name}" \
      "${SELF}" "${f}" ${FLAGS[@]+"${FLAGS[@]}"} 2>&1 | tee "${log}" || true
    src="${OUT_DIR}/${name}.summary.txt"
    [ -s "${src}" ] || src="${log}"
    row="${name}"
    for key in completed total_ms block_headers_ms filter_headers_ms filters_ms transactions; do
      row+=$'\t'"$(metric "${src}" "${key}")"
    done
    row+=$'\t'"$(grep -m1 -o 'confirmed_sat=[0-9]*' "${src}" | cut -d= -f2 || true)"
    row+=$'\t'"$(metric "${src}" peak_rss_mib)"
    echo "${row}" >>"${TSV}"
  done

  {
    echo "# dash-spv bench — ${RUN_TS}"
    echo
    awk -F'\t' '{ line = "|"; for (i = 1; i <= NF; i++) line = line " " $i " |"; print line
                  if (NR == 1) { line = "|"; for (i = 1; i <= NF; i++) line = line "---|"; print line } }' "${TSV}"
  } >"${REPORT}"
  echo
  echo "==> report: ${REPORT}"
  cat "${REPORT}"
  exit 0
fi

SCN_FILE="${SCN_FILES[0]}"

if command -v yq >/dev/null 2>&1; then
  YQ=yq
else
  YQ="${SCRIPT_DIR}/.bin/yq"
  if [ ! -x "${YQ}" ]; then
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; *) arch="$(uname -m)" ;; esac
    echo "==> fetching yq into .bin/yq"
    mkdir -p "${SCRIPT_DIR}/.bin"
    curl -fsSL "https://github.com/mikefarah/yq/releases/download/v4.44.6/yq_${os}_${arch}" -o "${YQ}" \
      || { echo "Error: could not download yq; install it manually." >&2; exit 1; }
    chmod +x "${YQ}"
  fi
fi
scn() { "${YQ}" "$1" "${SCN_FILE}"; }

# `tc netem` arguments for the link described at yq path $1.
netem_args() {
  local lat jit loss rate corrupt reorder a=""
  read -r lat jit loss rate corrupt reorder <<<"$(scn "$1 | [.latency_ms // 0, .jitter_ms // 0, .loss_pct // 0, .rate_kbit // 0, .corrupt_pct // 0, .reorder_pct // 0] | @tsv")"
  [ "${lat}" != 0 ] && { a="delay ${lat}ms"; [ "${jit}" != 0 ] && a="${a} ${jit}ms"; }
  [ "${loss}" != 0 ] && a="${a} loss ${loss}%"
  [ "${rate}" != 0 ] && a="${a} rate ${rate}kbit"
  [ "${corrupt}" != 0 ] && a="${a} corrupt ${corrupt}%"
  [ "${reorder}" != 0 ] && a="${a} reorder ${reorder}%"
  echo "${a# }"
}

emit_compose() {
  local out="$1" groups g count n peer=0
  cat >"${out}" <<HEADER
# GENERATED for a bench scenario — do not edit; regenerated and deleted each run.
x-dashd-peer: &dashd-peer
  image: ${IMAGE}
HEADER
  cat >>"${out}" <<'ANCHOR'
  build:
    context: .
    dockerfile: Dockerfile
  cap_add: [NET_ADMIN]
  entrypoint: ["/bin/sh", "-ec"]
  command:
    - |
      if [ -n "$${NETEM_ARGS:-}" ]; then
        tc qdisc add dev eth0 root netem $${NETEM_ARGS} \
          && echo "netem: $${NETEM_ARGS}" || echo "WARNING: netem failed (NET_ADMIN/sch_netem?)"
      fi
      exec dashd -testnet -datadir=/data -port=19400 -rpcport=19500 -server=1 -daemon=0 \
        -connect=0 -bind=0.0.0.0 -listen=1 -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
        -whitelist=0.0.0.0/0 -disablewallet=1 -peerbloomfilters=1 \
        -dbcache=64 -fallbackfee=0.00001 -txindex=0 -addressindex=0 $${FILTER_FLAGS}

services:
ANCHOR
  # Only local scenarios bring their own peers; elsewhere `peers:` lists the
  # addresses of real ones.
  groups=0
  [ "${MODE}" != local ] || groups="$(scn '.peers | length')"
  case "${groups}" in '' | null | *[!0-9]*) groups=0 ;; esac
  for ((g = 0; g < groups; g++)); do
    count="$(scn ".peers[${g}].count // 0")"
    case "${count}" in '' | null | *[!0-9]*) count=0 ;; esac
    for ((n = 1; n <= count; n++)); do
      peer=$((peer + 1))
      cat >>"${out}" <<SERVICE
  dashd${peer}:
    <<: *dashd-peer
    container_name: spv-bench-dashd${peer}
    cpuset: "${BENCH_PEER_CPUS}"
    environment:
      NETEM_ARGS: "$(netem_args ".peers[${g}]")"
      FILTER_FLAGS: "-blockfilterindex=1 -peerblockfilters=1"
    volumes: ["\${CLONE_DIR}/peer${peer}:/data"]
SERVICE
    done
  done
  cat >>"${out}" <<SERVICE
  client:
    image: ${CLIENT_IMAGE}
    build:
      context: .
      dockerfile: Dockerfile.client
    container_name: spv-bench-client
    cap_add: [NET_ADMIN]${BENCH_CPUS:+
    cpuset: "${BENCH_CPUS}"}
    environment:
      NETEM_ARGS: "${CLIENT_NETEM}"
      INGRESS_RATE_KBIT: "${CLIENT_RATE_KBIT}"${RUST_LOG:+
      RUST_LOG: "${RUST_LOG}"}
      BENCH_MODE: "${MODE}"
      BENCH_PEERS: "\${BENCH_PEERS:-}"
      BENCH_MAX_PEERS: "\${BENCH_MAX_PEERS:-}"
      BENCH_HEIGHT: "\${BENCH_HEIGHT:-}"
      BENCH_START_HEIGHT: "\${BENCH_START_HEIGHT:-}"
      BENCH_STORAGE_DIR: "/out"
      BENCH_WALLET_FILE: "/wallets.txt"
    volumes:
      - "${BIN}:/usr/local/bin/dash-spv-bench:ro"
      - "${BENCH_STORAGE_DIR}:/out"
      - "${BENCH_WALLET_FILE}:/wallets.txt:ro"
    command:
      - |
        if [ -n "\$\${NETEM_ARGS:-}" ]; then
          tc qdisc add dev eth0 root netem \$\${NETEM_ARGS} \
            && echo "client netem (egress): \$\${NETEM_ARGS}" || echo "WARNING: client netem failed (NET_ADMIN/sch_netem?)"
        fi
        if [ "\$\${INGRESS_RATE_KBIT:-0}" != 0 ]; then
          ip link add ifb0 type ifb \
            && ip link set ifb0 up \
            && tc qdisc add dev eth0 handle ffff: ingress \
            && tc filter add dev eth0 parent ffff: protocol all prio 1 u32 \
                 match u32 0 0 action mirred egress redirect dev ifb0 \
            && tc qdisc add dev ifb0 root netem rate \$\${INGRESS_RATE_KBIT}kbit \
            || { echo "ERROR: cannot shape the client's downloads (no ifb in this kernel?)"; exit 1; }
          echo "client netem (ingress): rate \$\${INGRESS_RATE_KBIT}kbit via ifb0"
        fi
        exec /usr/local/bin/dash-spv-bench
SERVICE
}

MODE="$(scn '.mode // "local"')"
case "${MODE}" in local | testnet | mainnet) ;; *) echo "Error: mode must be 'local', 'testnet' or 'mainnet' (got '${MODE}')" >&2; exit 1 ;; esac
export CLONE_DIR="${CLONE_DIR:-/nonexistent}"

CLIENT_NETEM="$(netem_args .client)"
CLIENT_RATE_KBIT="$(scn '.client.rate_kbit // 0')"
case "${CLIENT_RATE_KBIT}" in
  '' | *[!0-9]*) echo "Error: client.rate_kbit must be a whole number of kbit (got '${CLIENT_RATE_KBIT}')" >&2; exit 1 ;;
esac
BENCH_CPUS="$(scn '.cpus // ""')"
BENCH_MAX_PEERS="$(scn '.max_peers // ""')"
export BENCH_MAX_PEERS
BENCH_WALLET_FILE="${WALLETS_ARG:-${SCRIPT_DIR}/wallets.txt}"
export BENCH_STORAGE_DIR="${SCRIPT_DIR}/bench-storage"

DESC="$(scn '.description // ""')"
[ -z "${DESC}" ] || echo "==> description: ${DESC}"

if [ "${MODE}" = local ]; then
  BENCH_HEIGHT="$(scn '.blocks // 1000000')"
  export BENCH_HEIGHT
  unset BENCH_START_HEIGHT
else
  BENCH_PEERS="$(scn '.peers // [] | join(",")')"
  export BENCH_PEERS
  start_height="$(scn '.start_height // ""')"
  [ -z "${start_height}" ] || export BENCH_START_HEIGHT="${start_height}"
fi

# The client gets BENCH_CPUS, docker peers get every other core.
BENCH_PEER_CPUS=""
if [ -n "${BENCH_CPUS}" ]; then
  ncpu="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 0)"
  bench_cores="$(IFS=,; for part in ${BENCH_CPUS}; do case "${part}" in *-*) seq "${part%-*}" "${part#*-}" ;; *) echo "${part}" ;; esac; done)"
  for ((i = 0; i < ncpu; i++)); do
    grep -qxF "${i}" <<<"${bench_cores}" || BENCH_PEER_CPUS="${BENCH_PEER_CPUS},${i}"
  done
  BENCH_PEER_CPUS="${BENCH_PEER_CPUS#,}"
  echo "==> pinning the client container to CPUs ${BENCH_CPUS}${BENCH_PEER_CPUS:+; docker peers to ${BENCH_PEER_CPUS}}"
fi

# Built in the Rust image so the binary links against the client image's glibc.
BIN="${REPO_ROOT}/target/bench/release/dash-spv-bench"
echo "==> building bench binary in ${RUST_IMAGE}"
docker run --rm -v "${REPO_ROOT}:/src" -w /src --user "$(id -u):$(id -g)" \
  -e CARGO_HOME=/src/target/bench/cargo-home -e CARGO_TARGET_DIR=/src/target/bench \
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true -e CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
  "${RUST_IMAGE}" cargo build --release -p dash-spv-bench ${FEATURES:+--features "${FEATURES# }"}
[ -x "${BIN}" ] || { echo "build produced no binary at ${BIN}" >&2; exit 1; }

COMPOSE_FILE="$(mktemp "${SCRIPT_DIR}/.scenario.XXXXXX")"
mv "${COMPOSE_FILE}" "${COMPOSE_FILE}.yml"
COMPOSE_FILE="${COMPOSE_FILE}.yml"
emit_compose "${COMPOSE_FILE}"
[ -z "${CLIENT_NETEM}" ] || echo "==> client link shaped: ${CLIENT_NETEM}"
compose() { docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" "$@"; }

teardown() {
  compose down --remove-orphans >/dev/null 2>&1 || true
  [ ! -f "${STATE}" ] || rm -rf "$(cat "${STATE}")" "${STATE}" 2>/dev/null || true
  rm -rf "${SCRIPT_DIR}"/.bench-clones.* 2>/dev/null || true
}
trap 'teardown; rm -f "${COMPOSE_FILE}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

wait_loaded() {
  local c logs all
  for _ in $(seq 1 400); do
    all=1
    for c in "$@"; do
      logs="$(docker logs "${c}" 2>&1)" || { all=0; break; }
      case "${logs}" in *"init message: Done loading"*) ;; *) all=0; break ;; esac
    done
    [ "${all}" -eq 0 ] || return 0
    echo -n "."; sleep 3
  done
  return 1
}

if [ "${MODE}" = local ]; then
  bash "${SCRIPT_DIR}/snapshot-chain.sh"   # builds ./chain-data to BENCH_HEIGHT via docker
  echo "==> ensuring a clean network"
  teardown
  docker image inspect "${IMAGE}" >/dev/null 2>&1 || { echo "==> building peer image"; compose build; }
  services="$(compose config --services | grep -v '^client$' || true)"
  npeers="$(echo ${services} | wc -w | tr -d ' ')"
  peers_summary="$(scn '[.peers[] | (.count | tostring) + "×" + ([to_entries[] | select(.key != "count") | .key + "=" + (.value | tostring)] | join(" "))] | join(", ")')"
  echo "==> scenario '$(basename "${SCN_FILE}" .yml)': ${npeers} peers [${peers_summary}], cpus=${BENCH_CPUS:-<none>}, blocks=${BENCH_HEIGHT}"
  echo "==> CoW-cloning ${CHAIN_DIR} for ${npeers} peers"
  clone_dir="$(mktemp -d "${SCRIPT_DIR}/.bench-clones.XXXXXX")"
  echo "${clone_dir}" >"${STATE}"
  for svc in ${services}; do
    dst="${clone_dir}/peer${svc#dashd}"
    cp -c -R "${CHAIN_DIR}" "${dst}" 2>/dev/null \
      || cp --reflink=auto -R "${CHAIN_DIR}" "${dst}" 2>/dev/null \
      || cp -R "${CHAIN_DIR}" "${dst}"
  done
  echo "==> starting ${npeers} peers in batches of 4"
  started=""
  count=0
  for svc in ${services}; do
    CLONE_DIR="${clone_dir}" compose up -d "${svc}" >/dev/null 2>&1
    started="${started} spv-bench-${svc}"
    count=$((count + 1))
    if [ $((count % 4)) -eq 0 ] || [ "${count}" -eq "${npeers}" ]; then
      echo -n "  loaded ${count}/${npeers} "
      wait_loaded ${started} || { echo " timeout loading batch" >&2; exit 1; }
      echo " ok"
    fi
  done
  # Container addresses, read back rather than pinned to a subnet that could
  # collide with whatever else the machine has up.
  csv=""
  for svc in ${services}; do
    ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "spv-bench-${svc}")"
    [ -n "${ip}" ] || { echo "Error: could not resolve address of spv-bench-${svc}" >&2; exit 1; }
    csv="${csv},${ip}:19400"
  done
  export BENCH_PEERS="${csv#,}"
  echo "==> ${npeers} peers started, reachable at ${BENCH_PEERS}"
else
  echo "==> ${MODE} mode, peers: ${BENCH_PEERS:-<DNS discovery>}"
fi

echo "==> running sync in the client container"
if { : >/dev/tty; } 2>/dev/null; then
  compose run --rm --build client >/dev/tty 2>&1
else
  compose run --rm --build client
fi

ARCHIVE_DIR="${BENCH_ARCHIVE_DIR:?BENCH_ARCHIVE_DIR is set by the batch wrapper}"
mkdir -p "${ARCHIVE_DIR}"
for out in run.log summary.txt flamegraph.svg heap-peak.svg; do
  [ -s "${BENCH_STORAGE_DIR}/${out}" ] || continue
  cp "${BENCH_STORAGE_DIR}/${out}" "${ARCHIVE_DIR}/${BENCH_ARCHIVE_NAME}.${out}"
done
echo "==> logs archived to ${ARCHIVE_DIR}"
