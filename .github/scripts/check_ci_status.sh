#!/usr/bin/env bash
# Evaluate CI check status for a PR, excluding the ready-for-review gate jobs.
# Usage: check_ci_status.sh <pr_number> <repo>
# Outputs one of: no_checks, all_passed, has_failures, pending

set -euo pipefail

PR_NUMBER="$1"
REPO="$2"

gh pr checks "$PR_NUMBER" --repo "$REPO" --json name,bucket --jq '
  [.[] | select(.name | test("^(validate-triggers|evaluate)$") | not)] |
  if length == 0 then "no_checks"
  elif all(.bucket == "pass" or .bucket == "skipping") then "all_passed"
  elif any(.bucket == "fail") then "has_failures"
  else "pending"
  end
'
