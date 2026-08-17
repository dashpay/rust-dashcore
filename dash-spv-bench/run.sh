#!/bin/bash
#
# dash-spv benchmark driver — runs ONE scenario end to end (build, bring up peers, sync, report).
#
# Usage:
#   ./run.sh <scenario.yml>            Run the scenario
#   ./run.sh <scenario.yml> --flame    Same, under the sampler (perf on Linux, sample on macOS)
#                                       -> profiles/flamegraph.svg
#   --wallets <file>                   Wallets for this run: a file with one BIP39 mnemonic per
#                                      line. No file => the run has no wallet.
#
# RUST_LOG can be set to tweak logging, e.g.  RUST_LOG=info ./run.sh scenarios/ideal-1-peer.yml
# It is the tracing filter for BOTH log sinks and overrides the defaults, which are
#   terminal = "warn,dash_spv_bench=info"  (kept light so the live bars stay readable)
#   file     = "warn,dash_spv=debug,dash_spv_bench=debug"  (debug, for offline analysis)
#
# Outputs land in bench-storage/ (gitignored, wiped at the start of each run):
#   run.log      full trace of the sync (debug by default) for offline analysis
#   summary.txt  metrics + per-wallet tx/balance fingerprint (also printed to stdout)
#   plus the SPV storage the run produced (block_headers/, filters/, ...)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE=""            # local mode generates one here; deleted on exit
DASH_VERSION="23.1.7"
IMAGE="dash-spv-bench/dashd:${DASH_VERSION}"
CLIENT_IMAGE="dash-spv-bench/client:1"
# Rust image for the Linux build, taken from the workspace's own pin so the two
# cannot drift: with a mismatched tag the image spends every run having rustup
# fetch the pinned toolchain before it can compile anything.
RUST_CHANNEL="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "${REPO_ROOT}/rust-toolchain.toml" 2>/dev/null || true)"
RUST_IMAGE="rust:${RUST_CHANNEL:-1.89}-bookworm"
# Separate from the host's `target/`: a different triple, and sharing one
# directory across both would make every switch a full rebuild.
LINUX_TARGET_DIR="target-linux"
PROJECT="spv-bench"
STATE="${SCRIPT_DIR}/.clonedir"
FLAME_SVG="${SCRIPT_DIR}/profiles/flamegraph.svg"
FLAMEGRAPH_DIR="${SCRIPT_DIR}/.flamegraph"   # FlameGraph tooling clone (gitignored, inside the package)
CHAIN_DIR="${SCRIPT_DIR}/chain-data"

INVOCATION_DIR="${PWD}"
abspath() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "${INVOCATION_DIR%/}/$1" ;; esac; }

cd "${SCRIPT_DIR}"

FLAME=0
SCN_FILE=""
WALLETS_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --flame) FLAME=1; shift ;;
    --wallets) WALLETS_ARG="${2:?--wallets needs a file path}"; shift 2 ;;
    -h | --help) sed -n '3,20p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 1 ;;
    *) SCN_FILE="$1"; shift ;;
  esac
done
[ -n "${SCN_FILE}" ] || { echo "usage: $0 <scenario.yml> [--flame] [--wallets <file>]" >&2; exit 1; }
SCN_FILE="$(abspath "${SCN_FILE}")"
[ -f "${SCN_FILE}" ] || { echo "Error: scenario file not found: ${SCN_FILE}" >&2; exit 1; }

YQ_VERSION="v4.44.6"
ensure_yq() {
  if command -v yq >/dev/null 2>&1; then YQ=yq; return 0; fi
  local bin="${SCRIPT_DIR}/.bin/yq"
  if [ ! -x "${bin}" ]; then
    mkdir -p "${SCRIPT_DIR}/.bin"
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"; arch="$(uname -m)"
    case "${arch}" in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; esac
    echo "==> fetching yq ${YQ_VERSION} (${os}/${arch}) into .bin/yq"
    curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_${os}_${arch}" \
      -o "${bin}" || { echo "Error: could not download yq; install it manually." >&2; exit 1; }
    chmod +x "${bin}"
  fi
  YQ="${bin}"
}
ensure_yq
scn() { "${YQ}" "$1" "${SCN_FILE}"; }   # evaluate a yq expression against the scenario file

_peer_group() {
  "${YQ}" ".peers[$1] | [.count, .latency_ms // 0, .jitter_ms // 0, .loss_pct // 0, .rate_kbit // 0, .corrupt_pct // 0, .reorder_pct // 0] | @tsv" "${SCN_FILE}"
}

build_netem() {
  local lat="$1" jit="$2" loss="$3" rate="$4" corrupt="$5" reorder="$6" a=""
  [ "${lat}" != 0 ] && { a="delay ${lat}ms"; [ "${jit}" != 0 ] && a="${a} ${jit}ms"; }
  [ "${loss}" != 0 ] && a="${a} loss ${loss}%"
  [ "${rate}" != 0 ] && a="${a} rate ${rate}kbit"
  [ "${corrupt}" != 0 ] && a="${a} corrupt ${corrupt}%"
  [ "${reorder}" != 0 ] && a="${a} reorder ${reorder}%"
  echo "${a# }"
}

# The measured client's own link shaping, if the scenario asks for one.
#
# `peers:` shapes each dashd's egress, which models distance to a peer but never
# the client's own pipe — with N peers at R kbit each the client still enjoys
# N*R. A `client:` section shapes the one link everything shares, which is what a
# phone or a home connection actually has, and it is the only shaping available
# at all in testnet/mainnet mode where there are no peer containers.
client_netem() {
  local lat jit loss rate corrupt reorder
  read -r lat jit loss rate corrupt reorder <<<"$("${YQ}" \
    '[.client.latency_ms // 0, .client.jitter_ms // 0, .client.loss_pct // 0, .client.rate_kbit // 0, .client.corrupt_pct // 0, .client.reorder_pct // 0] | @tsv' \
    "${SCN_FILE}")"
  build_netem "${lat}" "${jit}" "${loss}" "${rate}" "${corrupt}" "${reorder}"
}

peers_summary() {
  local ng g count lat jit loss rate corrupt reorder tag out=""
  ng="$(scn '.peers | length')"
  case "${ng}" in ''|null|*[!0-9]*) ng=0 ;; esac
  for ((g = 0; g < ng; g++)); do
    read -r count lat jit loss rate corrupt reorder <<<"$(_peer_group "${g}")"
    tag="${lat}ms"
    [ "${jit}" != 0 ] && tag="${tag}±${jit}"
    [ "${loss}" != 0 ] && tag="${tag}/${loss}%loss"
    [ "${rate}" != 0 ] && tag="${tag}/${rate}kbit"
    out="${out}, ${count}×${tag}"
  done
  echo "${out#, }"
}

emit_compose() {
  local out="$1" peer_cpus="$2"
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
  local ng g count lat jit loss rate corrupt reorder netem n peer=0
  # `null` when the scenario has no `peers:` at all, which is the normal shape
  # for testnet/mainnet: there the peers are the real network and the only
  # service to emit is the client.
  ng="$(scn '.peers | length')"
  # Arithmetic loops rather than `seq`: BSD seq (macOS) reads `seq 0 -1` as a
  # descending range and prints "0 -1", where GNU seq prints nothing. An empty
  # `peers:` — the normal shape for testnet/mainnet — hit exactly that and
  # emitted two garbage peer services.
  case "${ng}" in ''|null|*[!0-9]*) ng=0 ;; esac
  for ((g = 0; g < ng; g++)); do
    read -r count lat jit loss rate corrupt reorder <<<"$(_peer_group "${g}")"
    netem="$(build_netem "${lat}" "${jit}" "${loss}" "${rate}" "${corrupt}" "${reorder}")"
    case "${count}" in ''|null|*[!0-9]*) count=0 ;; esac
    for ((n = 1; n <= count; n++)); do
      peer=$((peer + 1))
      cat >>"${out}" <<SERVICE
  dashd${peer}:
    <<: *dashd-peer
    container_name: spv-bench-dashd${peer}
    cpuset: "${peer_cpus}"
    environment:
      NETEM_ARGS: "${netem}"
      FILTER_FLAGS: "-blockfilterindex=1 -peerblockfilters=1"
    volumes: ["\${CLONE_DIR}/peer${peer}:/data"]
    ports: ["127.0.0.1:$((19400 + peer)):19400"]
SERVICE
    done
  done
  emit_client_service "${out}"
  echo "${peer}"
}

# The measured client, as a container, so `tc netem` can shape ITS link.
#
# Only emitted when the scenario has a `client:` section: without one the client
# keeps running on the host exactly as before, so existing scenarios and the
# numbers they produced stay comparable.
emit_client_service() {
  local out="$1"
  [ -n "${CLIENT_NETEM}" ] || return 0
  cat >>"${out}" <<SERVICE
  client:
    image: ${CLIENT_IMAGE}
    build:
      context: .
      dockerfile: Dockerfile.client
    container_name: spv-bench-client
    cap_add: [NET_ADMIN]
    environment:
      NETEM_ARGS: "${CLIENT_NETEM}"
      RUST_LOG: "\${RUST_LOG:-}"
      BENCH_MODE: "${BENCH_MODE}"
      BENCH_PEERS: "\${BENCH_PEERS:-}"
      BENCH_MAX_PEERS: "\${BENCH_MAX_PEERS:-}"
      BENCH_HEIGHT: "\${BENCH_HEIGHT:-}"
      BENCH_START_HEIGHT: "\${BENCH_START_HEIGHT:-}"
      BENCH_STORAGE_DIR: "/out"
      BENCH_WALLET_FILE: "/wallets.txt"
    volumes:
      - "${SCRIPT_DIR}/${LINUX_TARGET_DIR}/release/dash-spv-bench:/usr/local/bin/dash-spv-bench:ro"
      - "${BENCH_STORAGE_DIR}:/out"
      - "${BENCH_WALLET_FILE}:/wallets.txt:ro"
    command:
      - |
        if [ -n "\$\${NETEM_ARGS:-}" ]; then
          tc qdisc add dev eth0 root netem \$\${NETEM_ARGS} \
            && echo "client netem: \$\${NETEM_ARGS}" || echo "WARNING: client netem failed (NET_ADMIN/sch_netem?)"
        fi
        exec /usr/local/bin/dash-spv-bench
SERVICE
}


MODE="$(scn '.mode // "local"')"
case "${MODE}" in local | testnet | mainnet) ;; *) echo "Error: mode must be 'local', 'testnet' or 'mainnet' (got '${MODE}')" >&2; exit 1 ;; esac
export BENCH_MODE="${MODE}"
export CLONE_DIR="${CLONE_DIR:-/nonexistent}"

CLIENT_NETEM="$(client_netem)"
BENCH_CPUS="$(scn '.cpus // ""')"
BENCH_MAX_PEERS="$(scn '.max_peers // ""')"   # only if set; else the ClientConfig default
export BENCH_MAX_PEERS

BENCH_WALLET_FILE="${SCRIPT_DIR}/wallets.txt"
[ -n "${WALLETS_ARG}" ] && BENCH_WALLET_FILE="$(abspath "${WALLETS_ARG}")"
export BENCH_WALLET_FILE
export BENCH_STORAGE_DIR="${SCRIPT_DIR}/bench-storage"

DESC="$(scn '.description // ""')"
[ -n "${DESC}" ] && echo "==> description: ${DESC}"

BLOCKS=""
if [ "${MODE}" = local ]; then
  BLOCKS="$(scn '.blocks // 1000000')"
  export BENCH_HEIGHT="${BLOCKS}"
  unset BENCH_START_HEIGHT   # local always syncs from genesis
else
  BENCH_PEERS="$(scn '.peers // [] | join(",")')"
  export BENCH_PEERS
  sh="$(scn '.start_height // ""')"; [ -n "${sh}" ] && export BENCH_START_HEIGHT="${sh}"
fi

expand_cpus() {
  local part lo hi
  local IFS=,
  for part in $1; do
    case "${part}" in
      *-*) lo="${part%-*}"; hi="${part#*-}"; seq "${lo}" "${hi}" ;;
      *)   echo "${part}" ;;
    esac
  done
}

CPU_PREFIX=()
if [ -n "${BENCH_CPUS}" ]; then
  ncpu="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 0)"
  bench_cores="$(expand_cpus "${BENCH_CPUS}" | sort -nu)"
  if [ "${ncpu}" -gt 0 ]; then
    peer_cores=""
    for i in $(seq 0 $((ncpu - 1))); do
      grep -qxF "${i}" <<<"${bench_cores}" || peer_cores="${peer_cores},${i}"
    done
    BENCH_PEER_CPUS="${peer_cores#,}"
  fi

  if command -v taskset >/dev/null 2>&1; then
    CPU_PREFIX=(taskset -c "${BENCH_CPUS}")
    echo "==> pinning the measured run to CPUs ${BENCH_CPUS}${BENCH_PEER_CPUS:+; docker peers to ${BENCH_PEER_CPUS}}"
  else
    echo "==> note: 'taskset' not found (e.g. macOS); running the measured binary UNPINNED${BENCH_PEER_CPUS:+ (docker peers still pinned to ${BENCH_PEER_CPUS})}" >&2
  fi
fi

# A compose file is needed for the peers (local mode) and for the client
# container (any mode with a `client:` section) — testnet/mainnet shape the
# client against the real network, with no peer services at all.
if [ "${MODE}" = local ] || [ -n "${CLIENT_NETEM}" ]; then
  COMPOSE_FILE="$(mktemp "${SCRIPT_DIR}/.scenario.XXXXXX")"
  mv "${COMPOSE_FILE}" "${COMPOSE_FILE}.yml"
  COMPOSE_FILE="${COMPOSE_FILE}.yml"
  npeers="$(emit_compose "${COMPOSE_FILE}" "${BENCH_PEER_CPUS:-}")"
  if [ "${MODE}" = local ]; then
    echo "==> scenario '$(basename "${SCN_FILE}" .yml)': ${npeers} peers [$(peers_summary)], cpus=${BENCH_CPUS:-<none>}, blocks=${BLOCKS}"
  fi
fi
[ -n "${CLIENT_NETEM}" ] && echo "==> client link shaped: ${CLIENT_NETEM}"

compose() { docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" "$@"; }

wait_loaded() {
  local c logs
  for _ in $(seq 1 400); do
    local all=1
    for c in "$@"; do
      logs="$(docker logs "${c}" 2>&1)" || { all=0; break; }
      case "${logs}" in *"init message: Done loading"*) ;; *) all=0; break ;; esac
    done
    [ "${all}" -eq 1 ] && return 0
    echo -n "."; sleep 3
  done
  return 1
}

teardown() {
  [ -n "${COMPOSE_FILE}" ] && compose down --remove-orphans >/dev/null 2>&1 || true
  [ -f "${STATE}" ] && { rm -rf "$(cat "${STATE}")" 2>/dev/null || true; rm -f "${STATE}"; }
  rm -rf "${SCRIPT_DIR}"/.bench-clones.* 2>/dev/null || true
}

arm_teardown() {
  # On exit: tear down, THEN delete the generated compose (down needs it to still exist).
  trap 'teardown; [ -n "${COMPOSE_FILE}" ] && rm -f "${COMPOSE_FILE}"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
}

bring_up() {
  echo "==> ensuring a clean network"
  teardown
  docker image inspect "${IMAGE}" >/dev/null 2>&1 || { echo "==> building peer image"; compose build; }

  # The client is in the same compose file but is not a peer: it must not be
  # counted, started here, or waited on for "Done loading".
  local services; services="$(compose config --services | grep -v '^client$' || true)"
  local n; n="$(echo ${services} | wc -w | tr -d ' ')"
  # BENCH_PEERS is derived from the generated peers (host ports 19401..).
  local peers_csv=""
  for svc in ${services}; do peers_csv="${peers_csv},127.0.0.1:$((19400 + ${svc#dashd}))"; done
  export BENCH_PEERS="${peers_csv#,}"

  echo "==> CoW-cloning ${CHAIN_DIR} for ${n} peers (instant)"
  local clone_dir; clone_dir="$(mktemp -d "${SCRIPT_DIR}/.bench-clones.XXXXXX")"
  echo "${clone_dir}" > "${STATE}"
  for svc in ${services}; do
    local dst="${clone_dir}/peer${svc#dashd}"
    cp -c -R "${CHAIN_DIR}" "${dst}" 2>/dev/null \
      || cp --reflink=auto -R "${CHAIN_DIR}" "${dst}" 2>/dev/null \
      || cp -R "${CHAIN_DIR}" "${dst}"
  done

  local batch=4
  echo "==> starting ${n} peers in batches of ${batch}"
  local started="" count=0
  for svc in ${services}; do
    CLONE_DIR="${clone_dir}" compose up -d "${svc}" >/dev/null 2>&1
    started="${started} spv-bench-${svc}"; count=$((count + 1))
    if [ $((count % batch)) -eq 0 ]; then
      echo -n "  loaded ${count}/${n} "
      wait_loaded ${started} || { echo " timeout loading batch" >&2; exit 1; }
      echo " ok"
    fi
  done
  if [ $((count % batch)) -ne 0 ]; then   # wait on the trailing partial batch too
    echo -n "  loaded ${count}/${n} "
    wait_loaded ${started} || { echo " timeout loading batch" >&2; exit 1; }
    echo " ok"
  fi

  echo "==> ${n} peers started"

  # A containerised client shares the compose network with the peers, so it must
  # reach them at their container addresses; the published host ports only exist
  # for a client running on the host. Read the addresses back from the running
  # containers rather than pinning a subnet in the compose file: a pinned subnet
  # is one more thing that can collide with whatever else the machine has up,
  # VPNs included, and it buys nothing a lookup does not.
  if [ -n "${CLIENT_NETEM}" ]; then
    local ip csv=""
    for svc in ${services}; do
      ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "spv-bench-${svc}")"
      [ -n "${ip}" ] || { echo "Error: could not resolve address of spv-bench-${svc}" >&2; exit 1; }
      csv="${csv},${ip}:19400"
    done
    export BENCH_PEERS="${csv#,}"
    echo "==> client will reach peers at ${BENCH_PEERS}"
  fi
}

build_bin() {
  if [ -n "${CLIENT_NETEM}" ]; then
    # The client runs in a Linux container, so the binary has to be a Linux
    # one; a host build is the wrong platform on macOS and cannot be mounted
    # in. Built by a throwaway container that bind-mounts the workspace and a
    # persistent Linux target dir, so this stays incremental — an image layer
    # build would replay the whole workspace on every source change, which
    # makes A/B runs unusable.
    echo "==> building bench binary for linux (${RUST_IMAGE}, target dir ${LINUX_TARGET_DIR}/)"
    mkdir -p "${SCRIPT_DIR}/${LINUX_TARGET_DIR}"
    docker run --rm \
      -v "${REPO_ROOT}:/src" \
      -v "${SCRIPT_DIR}/${LINUX_TARGET_DIR}:/target" \
      -v "spv-bench-cargo-registry:/usr/local/cargo/registry" \
      -v "spv-bench-rustup:/usr/local/rustup" \
      -w /src \
      -e CARGO_TARGET_DIR=/target \
      -e CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
      "${RUST_IMAGE}" \
      cargo build --release -p dash-spv-bench
    BIN="${SCRIPT_DIR}/${LINUX_TARGET_DIR}/release/dash-spv-bench"
    return 0
  fi
  echo "==> building bench binary (release + line-table symbols)"
  ( cd "${REPO_ROOT}" && CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
      cargo build --release -p dash-spv-bench )
  BIN="${REPO_ROOT}/target/release/dash-spv-bench"
}

FLAME_TOOL=""
if [ "${FLAME}" -eq 1 ]; then       # fail fast on missing profiler deps, before building
  if command -v perf >/dev/null; then FLAME_TOOL=perf                  # Linux
  elif command -v /usr/bin/sample >/dev/null; then FLAME_TOOL=sample   # macOS
  else echo "flame mode needs 'perf' (Linux) or '/usr/bin/sample' (macOS)" >&2; exit 1; fi
  [ -f "${FLAMEGRAPH_DIR}/flamegraph.pl" ] || \
    git clone --depth 1 https://github.com/brendangregg/FlameGraph "${FLAMEGRAPH_DIR}"
fi

build_bin

if [ "${MODE}" = local ]; then
  arm_teardown
  bash "${SCRIPT_DIR}/snapshot-chain.sh"   # builds ./chain-data to BENCH_HEIGHT via docker
  bring_up
else
  echo "==> testnet mode, peers: ${BENCH_PEERS:-<DNS discovery>}"
fi

if [ -n "${CLIENT_NETEM}" ]; then
  # `run` rather than `up`: it streams the client's own stdout and gives back
  # its exit code, which is what the report is read from. Profiling is not
  # wired through the container, so `--flame` is refused rather than silently
  # producing a graph of the host doing nothing.
  [ "${FLAME}" -eq 0 ] || { echo "Error: --flame is not supported with a containerised client" >&2; exit 1; }
  arm_teardown
  echo "==> running sync in the client container"
  compose run --rm --build client
elif [ "${FLAME}" -eq 0 ]; then
  echo "==> running sync"
  "${CPU_PREFIX[@]+"${CPU_PREFIX[@]}"}" "${BIN}"
elif [ "${FLAME_TOOL}" = perf ]; then
  echo "==> running sync under perf"
  mkdir -p "$(dirname "${FLAME_SVG}")"
  perf record -F 499 -g -o /tmp/bench-perf.data -- "${CPU_PREFIX[@]+"${CPU_PREFIX[@]}"}" "${BIN}"
  perf script -i /tmp/bench-perf.data \
    | "${FLAMEGRAPH_DIR}/stackcollapse-perf.pl" \
    | "${FLAMEGRAPH_DIR}/flamegraph.pl" --title "dash-spv sync" --colors hot > "${FLAME_SVG}"
  echo "==> wrote ${FLAME_SVG}"
else
  echo "==> running sync under the sampler"
  "${CPU_PREFIX[@]+"${CPU_PREFIX[@]}"}" "${BIN}" & bpid=$!
  sleep 3
  /usr/bin/sample "${bpid}" 2000 1 -file /tmp/bench.sample.txt -mayDie >/dev/null 2>&1 || true
  wait "${bpid}" 2>/dev/null || true
  mkdir -p "$(dirname "${FLAME_SVG}")"
  "${FLAMEGRAPH_DIR}/stackcollapse-sample.awk" /tmp/bench.sample.txt \
    | sed -E 's/^Thread_[^;]*;//' \
    | "${FLAMEGRAPH_DIR}/flamegraph.pl" --title "dash-spv sync" --colors hot > "${FLAME_SVG}"
  echo "==> wrote ${FLAME_SVG}"
fi
