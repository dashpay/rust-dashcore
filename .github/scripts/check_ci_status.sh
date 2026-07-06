#!/usr/bin/env bash
# Evaluate CI check status for a PR, excluding the ready-for-review gate jobs.
# Usage: check_ci_status.sh <pr_number> <repo>
# Outputs one of: no_checks, all_passed, has_failures, pending

set -euo pipefail

PR_NUMBER="$1"
REPO="$2"

# gh pr checks signals check state through its exit code: 0 when every check
# passed (and, with --json, also when some failed), 8 when checks are still
# pending. Any other code is gh itself failing (auth, rate limit, network,
# unknown PR); surface that instead of misreading it as an empty check set,
# which would silently strip the label and hide the error. Keep stderr visible.
set +e
CHECKS=$(gh pr checks "$PR_NUMBER" --repo "$REPO" --json name,bucket)
EXIT=$?
set -e

if [ "$EXIT" -ne 0 ] && [ "$EXIT" -ne 8 ]; then
  exit "$EXIT"
fi

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
