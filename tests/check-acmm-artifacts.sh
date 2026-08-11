#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

required=(
  .claude/session-summary.md
  .claude/settings.json
  .github/auto-qa-tuning.json
  .github/labeler.yml
  .github/workflows/ai-fix.yml
  .github/workflows/ci.yml
  .github/workflows/labeler.yml
  .github/workflows/nightly-compliance.yml
  docs/SECURITY-AI.md
  docs/metrics.md
  docs/quality.md
  docs/reflections/README.md
  docs/review-rubric.md
  docs/risk-tiers.md
)

for path in "${required[@]}"; do
  if [[ ! -s "$repo_root/$path" ]]; then
    echo "required quality-gate artifact is missing or empty: $path" >&2
    exit 1
  fi
done

jq -e '
  .permissions.deny as $deny
  | ($deny | type == "array")
    and ($deny | any(. == "Bash(fisherman:*)"))
    and ($deny | any(. == "Bash(sudo fisherman:*)"))
    and ($deny | any(. == "Bash(wipefs:*)"))
    and ($deny | any(. == "Bash(sudo wipefs:*)"))
' "$repo_root/.claude/settings.json" >/dev/null

jq -e '
  .schemaVersion == 1
  and (.coverage.floorPercent | type == "number")
  and .coverage.ratchet == "increase-only"
  and .guardrails.allowAutomaticThresholdReduction == false
  and .guardrails.requirePullRequest == true
  and .guardrails.requireInstallEvidenceForInstallerChanges == true
' "$repo_root/.github/auto-qa-tuning.json" >/dev/null

grep -q 'pull_request_target:' "$repo_root/.github/workflows/labeler.yml"
grep -q 'contents: read' "$repo_root/.github/workflows/labeler.yml"
grep -q 'pull-requests: write' "$repo_root/.github/workflows/labeler.yml"

if grep -qE 'pull_request_target:|pull_request:' "$repo_root/.github/workflows/ai-fix.yml"; then
  echo "AI fix handoff must not execute in an untrusted pull request context" >&2
  exit 1
fi
grep -q "ai-fix-requested" "$repo_root/.github/workflows/ai-fix.yml"
grep -q 'contents: read' "$repo_root/.github/workflows/ai-fix.yml"
grep -q 'issues: write' "$repo_root/.github/workflows/ai-fix.yml"

grep -q 'schedule:' "$repo_root/.github/workflows/nightly-compliance.yml"
grep -q 'tests/check-acmm-artifacts.sh' "$repo_root/.github/workflows/nightly-compliance.yml"
grep -q 'go test ./...' "$repo_root/.github/workflows/nightly-compliance.yml"

echo "ACMM quality-gate artifacts passed"
