#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

required=(
  .claude/session-summary.md
  .claude/settings.json
  .github/workflows/ci.yml
  docs/metrics.md
  docs/quality.md
  docs/review-rubric.md
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

echo "ACMM quality-gate artifacts passed"
