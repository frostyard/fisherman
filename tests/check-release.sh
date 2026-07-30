#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
goreleaser_bin=${GORELEASER:-goreleaser}
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
