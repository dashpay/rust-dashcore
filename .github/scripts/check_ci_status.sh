#!/usr/bin/env bash
# Evaluate CI check status for a PR, excluding the ready-for-review gate jobs.
# Usage: check_ci_status.sh <pr_number> <repo>
# Outputs one of: no_checks, all_passed, has_failures, pending

set -euo pipefail

PR_NUMBER="$1"
REPO="$2"

# gh pr checks exits 8 when any check is still pending and non-zero when any
# check fails, even with --json. Capture the JSON and ignore that exit status so
# the jq rollup below classifies the state instead of aborting the caller under
# set -e. Empty output means gh reported no checks at all.
CHECKS=$(gh pr checks "$PR_NUMBER" --repo "$REPO" --json name,bucket 2>/dev/null) || true

if [ -z "$CHECKS" ]; then
  echo "no_checks"
  exit 0
fi

echo "$CHECKS" | jq -r '
  [.[] | select(.name | test("^(validate-triggers|evaluate|ready-for-review-trigger)$") | not)] |
  if length == 0 then "no_checks"
  elif all(.bucket == "pass" or .bucket == "skipping") then "all_passed"
  elif any(.bucket == "fail") then "has_failures"
  else "pending"
  end
'
