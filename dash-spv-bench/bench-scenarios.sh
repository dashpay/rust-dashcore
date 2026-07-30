#!/bin/bash
#
# dash-spv-bench scenario matrix (LOCAL mode only).
#
#   ./bench-scenarios.sh [-d scenarios]
#
# Thin loop over scenario files: for each scenarios/*.yml it calls `run.sh scenario <file>`
# once per its `repeats:` count, captures the timings run.sh prints, and writes an organized
# Markdown report (median over repeats). All the real work — compose generation, bring-up,
# CPU pinning, teardown — lives in run.sh; this only orchestrates and aggregates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${SCRIPT_DIR}"

SCN_DIR="${SCRIPT_DIR}/scenarios"
RUN_CMD="${RUN_CMD:-${SCRIPT_DIR}/run.sh}"   # overridable for testing the loop without docker
while [ $# -gt 0 ]; do
  case "$1" in
    -d | --dir) SCN_DIR="$2"; shift 2 ;;
    -h | --help) sed -n '3,10p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

shopt -s nullglob
FILES=("${SCN_DIR}"/*.yml)
[ "${#FILES[@]}" -gt 0 ] || { echo "Error: no scenarios (*.yml) in ${SCN_DIR}" >&2; exit 1; }

RUN_TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${SCRIPT_DIR}/results/${RUN_TS}"
mkdir -p "${OUT_DIR}"
REPORT="${OUT_DIR}/report.md"
TSV="${OUT_DIR}/results.tsv"
: >"${TSV}"

metric() { awk -F':[[:space:]]*' -v k="$2" '$1==k {gsub(/[[:space:]]+$/,"",$2); print $2; exit}' "$1"; }
median() { sort -n | awk '{a[NR]=$1} END{if(NR==0){print"-";exit} print (NR%2)?a[(NR+1)/2]:int((a[NR/2]+a[NR/2+1])/2)}'; }

for f in "${FILES[@]}"; do
  name="$(basename "${f}" .yml)"
  repeats="$(awk '/^repeats:/{print $2; exit}' "${f}")"; repeats="${repeats:-1}"
  echo "===== scenario '${name}' × ${repeats} ====="
  for r in $(seq 1 "${repeats}"); do
    echo "-- ${name} repeat ${r}/${repeats}"
    log="${OUT_DIR}/${name}.r${r}.log"
    "${RUN_CMD}" "${f}" >"${log}" 2>&1 || echo "   (run.sh exited non-zero; see ${log})"

    # Scenario metadata comes straight from run.sh's own echo lines, so we never re-parse the YAML.
    meta="$(grep -m1 "==> scenario '" "${log}" || true)"
    cpus="$(sed -n "s/.*cpus=\([^,]*\),.*/\1/p" <<<"${meta}")"
    blocks="$(sed -n "s/.*blocks=\([0-9]*\).*/\1/p" <<<"${meta}")"
    peers="$(sed -n "s/.*\[\(.*\)\], cpus=.*/\1/p" <<<"${meta}")"
    desc="$(grep -m1 "==> description:" "${log}" | sed 's/.*==> description: //' || true)"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${name}" "${cpus}" "${blocks}" "${peers}" "${r}" \
      "$(metric "${log}" completed)" "$(metric "${log}" total_ms)" \
      "$(metric "${log}" block_headers_ms)" "$(metric "${log}" filter_headers_ms)" \
      "$(metric "${log}" filters_ms)" "$(metric "${log}" filter_hdr_lag_ms)" "${desc}" \
      >>"${TSV}"
  done
done

# --- report ---------------------------------------------------------------------------------
{
  echo "# dash-spv-bench scenario report"
  echo
  echo "- **Date:** $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "- **Host:** $(nproc) cores — $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //' || uname -m)"
  echo "- **git:** $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null)@$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null)"
  echo "- **Scenarios:** \`$(basename "${SCN_DIR}")/\` (${#FILES[@]} files)"
  echo
  echo "Timings are the **median** over each scenario's repeats (ms)."
  echo
  echo "| scenario | description | cpus | blocks | peers | completed | total | block_hdrs | filter_hdrs | filters | fh_lag |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|"
  for name in $(cut -f1 "${TSV}" | awk '!seen[$0]++'); do
    row() { awk -F'\t' -v n="${name}" '$1==n{print $'"$1"'; exit}' "${TSV}"; }
    med() { awk -F'\t' -v n="${name}" '$1==n && $'"$1"'!="" && $'"$1"'!="-"{print $'"$1"'}' "${TSV}" | median; }
    echo "| ${name} | $(row 12) | $(row 2) | $(row 3) | $(row 4) | $(row 6) | $(med 7) | $(med 8) | $(med 9) | $(med 10) | $(med 11) |"
  done
  echo
  echo "Raw per-repeat data: \`results.tsv\`; per-run logs alongside this report."
} >"${REPORT}"

echo "==> wrote ${REPORT}"
