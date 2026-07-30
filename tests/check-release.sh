#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
goreleaser_bin=${GORELEASER:-goreleaser}
validate_workflow="$repo_root/.github/workflows/release-validate.yml"
goreleaser_action='goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94'
goreleaser_version='version: v2.17.1'
cd "$repo_root"

rm -rf dist
trap 'rm -rf "$repo_root/dist"' EXIT

grep -Fxq '    owner: frostyard' .goreleaser.yml || {
  echo "release owner must be frostyard" >&2
  exit 1
}
grep -Fxq '    name: fisherman' .goreleaser.yml || {
  echo "release repository must be fisherman" >&2
  exit 1
}
grep -Fxq '  draft: true' .goreleaser.yml || {
  echo "GoReleaser must stage a draft release" >&2
  exit 1
}
[[ -f "$validate_workflow" ]] || {
  echo "release validation workflow is missing" >&2
  exit 1
}
grep -Fq "uses: $goreleaser_action" "$validate_workflow" || {
  echo "release validation must pin goreleaser-action" >&2
  exit 1
}
grep -Fq "$goreleaser_version" "$validate_workflow" || {
  echo "release validation must pin GoReleaser v2.17.1" >&2
  exit 1
}
grep -Fq 'run: tests/check-release.sh' "$validate_workflow" || {
  echo "release validation must run the release contract" >&2
  exit 1
}

"$goreleaser_bin" check
"$goreleaser_bin" release --snapshot --clean

version=$(jq -er '
  [ .[]
    | select(.type == "Binary")
    | .name
    | select(startswith("fisherman_"))
    | capture("^fisherman_(?<version>.+)_linux_(amd64|arm64)$").version
  ]
  | unique
  | if length == 1 then .[0] else error("expected one snapshot version") end
' dist/artifacts.json)

raw_assets=(
  "fisherman_${version}_linux_amd64"
  "fisherman_${version}_linux_arm64"
)
archive_assets=(
  "fisherman_${version}_linux_amd64.tar.gz"
  "fisherman_${version}_linux_arm64.tar.gz"
)

for name in "${raw_assets[@]}" "${archive_assets[@]}" checksums.txt; do
  jq -e --arg name "$name" '[.[] | select(.name == $name)] | length == 1' \
    dist/artifacts.json >/dev/null || {
      echo "missing or duplicate snapshot artifact: $name" >&2
      exit 1
    }
done

for name in "${raw_assets[@]}"; do
  path=$(jq -er --arg name "$name" '.[] | select(.name == $name) | .path' \
    dist/artifacts.json)
  [[ -x "$path" ]] || {
    echo "raw artifact is not executable: $name" >&2
    exit 1
  }
done

for name in "${raw_assets[@]}" "${archive_assets[@]}"; do
  grep -Eq "^[0-9a-f]{64}  ${name}$" dist/checksums.txt || {
    echo "missing checksum entry: $name" >&2
    exit 1
  }
done

printf 'Validated release snapshot %s\n' "$version"
