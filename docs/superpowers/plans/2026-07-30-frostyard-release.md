# Frostyard Fisherman Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish directly downloadable, checksum-pinned Linux amd64 and arm64 Fisherman binaries from versioned `frostyard/fisherman` GitHub Releases while retaining the existing archives.

**Architecture:** GoReleaser remains the single builder and produces both raw binaries and tar archives from each compiled target. Pull requests install the same pinned GoReleaser used by publication and validate a non-publishing snapshot; tagged publication uploads into a draft, verifies the complete remote asset set and checksum entries, then publishes the draft.

**Tech Stack:** Go, GoReleaser 2.17.1, GitHub Actions, Bash, `jq`, GitHub CLI.

## Global Constraints

- Release owner and repository are exactly `frostyard/fisherman`; never publish to `tuna-os/fisherman`.
- Version tags retain the exact `vMAJOR.MINOR.PATCH` convention and are cut from Frostyard `dev`.
- Raw assets are exactly `fisherman_<version>_linux_amd64` and `fisherman_<version>_linux_arm64`.
- Existing `fisherman_<version>_linux_amd64.tar.gz` and `fisherman_<version>_linux_arm64.tar.gz` assets remain available.
- `checksums.txt` contains lowercase SHA-256 entries for both raw binaries and both archives.
- Builds remain Linux-only and static with `CGO_ENABLED=0`; the contract rejects uploadable artifacts outside the exact four names plus `checksums.txt` and requires both raw assets to be static ELF executables.
- Pin GoReleaser to `v2.17.1` and `goreleaser/goreleaser-action` to commit `f06c13b6b1a9625abc9e6e439d9c05a8f2190e94` (`v7`).
- Publication stages a GitHub draft, verifies expected remote asset names and checksum-manifest entries (not recomputed remote bytes), and only then makes it public.
- `replace_existing_draft: true` replaces a prior draft for the same tag on retry; a post-publish API assertion can rarely fail after publication, requiring manual release-state inspection rather than a blind retry.
- Pull request validation never creates a tag or GitHub Release.
- Do not modify a consumer repository or cut a production release in this implementation plan; the first live cut/draft execution remains a deferred go-live gate.
- Never commit `dist/` or any generated release artifact.

---

### Task 1: GoReleaser Artifact Contract

**Files:**
- Create: `tests/check-release.sh`
- Modify: `.goreleaser.yml`

**Interfaces:**
- Consumes: GoReleaser `v2.17.1` available as `goreleaser`, or a path supplied through `GORELEASER`.
- Produces: a valid `.goreleaser.yml` and `tests/check-release.sh`, which builds and validates the complete local snapshot artifact contract.

- [ ] **Step 1: Write the failing release contract test**

Create `tests/check-release.sh` with executable mode and this content:

```bash
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
```

- [ ] **Step 2: Run the test and verify it fails for the current release configuration**

Install the pinned local test binary once, then run the test:

```bash
if [[ ! -x /tmp/opencode/goreleaser-2.17.1/goreleaser ]]; then
  mkdir -p /tmp/opencode/goreleaser-2.17.1
  gh release download v2.17.1 --repo goreleaser/goreleaser \
    --pattern goreleaser_Linux_x86_64.tar.gz \
    --dir /tmp/opencode/goreleaser-2.17.1
  tar -xzf /tmp/opencode/goreleaser-2.17.1/goreleaser_Linux_x86_64.tar.gz \
    -C /tmp/opencode/goreleaser-2.17.1
fi
chmod +x tests/check-release.sh
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
```

Expected: FAIL with `release owner must be frostyard`. If the owner assertion is temporarily bypassed for diagnosis, `goreleaser check` must also reject the current `before.dir` field.

- [ ] **Step 3: Replace the invalid hook and define raw plus archived artifacts**

Remove the entire current `before:` block from `.goreleaser.yml`; release builds must not mutate `go.mod` or `go.sum`. Replace the `archives:` and `release:` sections with:

```yaml
archives:
  - id: fisherman
    name_template: "fisherman_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    formats:
      - binary
      - tar.gz
    files:
      - README.md

release:
  github:
    owner: frostyard
    name: fisherman
  draft: true
  replace_existing_draft: true
  prerelease: auto
  header: |
    ## fisherman {{ .Tag }}

    A composefs-native bootc installer.
```

Keep the existing `builds:`, `checksum:`, and `changelog:` sections unchanged.

- [ ] **Step 4: Run the focused test and verify all four assets and checksum entries pass**

Run:

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
shellcheck tests/check-release.sh
git diff --check
```

Expected: `Validated release snapshot 0.2.1-SNAPSHOT-<commit>` followed by clean ShellCheck and whitespace checks. Confirm `git status --short` contains no `dist/` entry because the test trap removes it.

- [ ] **Step 5: Commit the local artifact contract**

```bash
git add .goreleaser.yml tests/check-release.sh
git commit -m "release: add raw Fisherman artifacts"
```

### Task 2: Pull Request Release Validation

**Files:**
- Create: `.github/workflows/release-validate.yml`
- Modify: `tests/check-release.sh`

**Interfaces:**
- Consumes: `tests/check-release.sh` from Task 1.
- Produces: a secretless, read-only PR job that installs GoReleaser `v2.17.1` and proves the snapshot contract.

- [ ] **Step 1: Extend the contract test to require CI wiring and watch it fail**

Insert these declarations after `goreleaser_bin=...` in `tests/check-release.sh`:

```bash
validate_workflow="$repo_root/.github/workflows/release-validate.yml"
goreleaser_action='goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94'
goreleaser_version='version: v2.17.1'
```

Insert these assertions before `"$goreleaser_bin" check`:

```bash
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
```

Run:

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
```

Expected: FAIL with `release validation workflow is missing`.

- [ ] **Step 2: Add the secretless validation workflow**

Create `.github/workflows/release-validate.yml`:

```yaml
name: Validate Release

on:
  pull_request:
    branches: [dev, prod]
    paths:
      - '.goreleaser.yml'
      - '.github/workflows/release-cut.yml'
      - '.github/workflows/release-publish.yml'
      - '.github/workflows/release-validate.yml'
      - 'tests/check-release.sh'

permissions:
  contents: read

jobs:
  release-contract:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version-file: fisherman/go.mod
          cache: true
          cache-dependency-path: fisherman/go.sum
      - name: Install pinned GoReleaser
        uses: goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7
        with:
          distribution: goreleaser
          version: v2.17.1
          install-only: true
      - name: Validate release contract
        run: tests/check-release.sh
```

- [ ] **Step 3: Verify the validation workflow and contract pass**

Run:

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
actionlint .github/workflows/release-validate.yml
shellcheck tests/check-release.sh
git diff --check
```

Expected: all commands PASS and the snapshot validator reports one version.

- [ ] **Step 4: Commit PR validation**

```bash
git add .github/workflows/release-validate.yml tests/check-release.sh
git commit -m "ci: validate release artifacts on pull requests"
```

### Task 3: Draft Verification And Publication

**Files:**
- Modify: `.github/workflows/release-publish.yml`
- Modify: `tests/check-release.sh`

**Interfaces:**
- Consumes: draft-producing `.goreleaser.yml` from Task 1 and the pinned action contract from Task 2.
- Produces: tag publication that verifies the remote draft asset names and checksum entries, but does not recompute remote asset bytes, before making the release public.

- [ ] **Step 1: Add failing static assertions for the publish workflow**

Add this declaration beside `validate_workflow` in `tests/check-release.sh`:

```bash
publish_workflow="$repo_root/.github/workflows/release-publish.yml"
```

After the validation-workflow assertions, add:

```bash
grep -Fq "uses: $goreleaser_action" "$publish_workflow" || {
  echo "release publication must pin goreleaser-action" >&2
  exit 1
}
grep -Fq "$goreleaser_version" "$publish_workflow" || {
  echo "release publication must pin GoReleaser v2.17.1" >&2
  exit 1
}
grep -Fq 'gh release download "$tag"' "$publish_workflow" || {
  echo "release publication must download and verify remote checksums" >&2
  exit 1
}
grep -Fq 'gh release edit "$tag" --repo "$repo" --draft=false' "$publish_workflow" || {
  echo "release publication must publish only the verified draft" >&2
  exit 1
}
```

Run:

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
```

Expected: FAIL with `release publication must pin goreleaser-action` because the current workflow uses `@v6` and `version: latest`.

- [ ] **Step 2: Pin publication and add remote draft verification**

Replace `.github/workflows/release-publish.yml` with:

```yaml
name: Publish Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  publish:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version-file: fisherman/go.mod
          cache: true
          cache-dependency-path: fisherman/go.sum
      - name: Run tests before publishing
        run: sudo go test -race ./...
        working-directory: fisherman
      - name: Validate GoReleaser configuration
        uses: goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7
        with:
          distribution: goreleaser
          version: v2.17.1
          args: check
      - name: Build and upload draft release
        uses: goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7
        with:
          distribution: goreleaser
          version: v2.17.1
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Verify and publish draft release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          tag=$GITHUB_REF_NAME
          version=${tag#v}
          repo=$GITHUB_REPOSITORY
          [[ $repo == frostyard/fisherman ]] || {
            echo "::error::unexpected release repository: $repo" >&2
            exit 1
          }

          release_json=$(gh release view "$tag" --repo "$repo" --json isDraft,assets)
          jq -e '.isDraft == true' <<<"$release_json" >/dev/null || {
            echo "::error::release is not a draft before verification" >&2
            exit 1
          }

          raw_assets=(
            "fisherman_${version}_linux_amd64"
            "fisherman_${version}_linux_arm64"
          )
          archive_assets=(
            "fisherman_${version}_linux_amd64.tar.gz"
            "fisherman_${version}_linux_arm64.tar.gz"
          )
          for name in "${raw_assets[@]}" "${archive_assets[@]}" checksums.txt; do
            jq -e --arg name "$name" '[.assets[] | select(.name == $name)] | length == 1' \
              <<<"$release_json" >/dev/null || {
                echo "::error::missing or duplicate remote release asset: $name" >&2
                exit 1
              }
          done

          tmpdir=$(mktemp -d)
          trap 'rm -rf "$tmpdir"' EXIT
          gh release download "$tag" --repo "$repo" --pattern checksums.txt --dir "$tmpdir"
          for name in "${raw_assets[@]}" "${archive_assets[@]}"; do
            grep -Eq "^[0-9a-f]{64}  ${name}$" "$tmpdir/checksums.txt" || {
              echo "::error::missing remote checksum entry: $name" >&2
              exit 1
            }
          done

          gh release edit "$tag" --repo "$repo" --draft=false
          gh release view "$tag" --repo "$repo" --json isDraft --jq \
            'if .isDraft then error("release remained a draft") else "published verified release" end'
```

Do not retain the obsolete `packages: read` permission; this workflow reads no package registry.

- [ ] **Step 3: Verify static publication contracts and snapshot behavior**

Run:

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
actionlint .github/workflows/release-publish.yml .github/workflows/release-validate.yml
shellcheck tests/check-release.sh
git diff --check
```

Expected: all commands PASS. This step deliberately does not push a tag or create a release; the first authorized live cut/draft execution remains a deferred go-live gate.

- [ ] **Step 4: Commit fail-closed publication**

```bash
git add .github/workflows/release-publish.yml tests/check-release.sh
git commit -m "release: verify draft assets before publication"
```

### Task 4: Release Cut Guard And Operator Documentation

**Files:**
- Modify: `.github/workflows/release-cut.yml`
- Modify: `tests/check-release.sh`
- Modify: `README.md`

**Interfaces:**
- Consumes: the tag-triggered publisher from Task 3.
- Produces: a release-cut workflow that refuses non-`dev` dispatches and documentation for immutable Frostyard release URLs.

- [ ] **Step 1: Add a failing source-branch contract**

Add this declaration with the workflow paths in `tests/check-release.sh`:

```bash
cut_workflow="$repo_root/.github/workflows/release-cut.yml"
```

Add this assertion before the GoReleaser commands:

```bash
grep -Fq '[[ $GITHUB_REF == refs/heads/dev ]]' "$cut_workflow" || {
  echo "release cut must refuse non-dev dispatches" >&2
  exit 1
}
```

Run:

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
```

Expected: FAIL with `release cut must refuse non-dev dispatches`.

- [ ] **Step 2: Fail closed when release-cut is dispatched from another ref**

Insert this step immediately after checkout in `.github/workflows/release-cut.yml`:

```yaml
      - name: Verify release source branch
        run: |
          [[ $GITHUB_REF == refs/heads/dev ]] || {
            echo "::error::Cut Release must be dispatched from dev, got $GITHUB_REF" >&2
            exit 1
          }
```

Keep the existing tag calculation, annotated tag push, and `dev` to `prod` PR behavior unchanged. Preserve `RELEASE_TOKEN || GITHUB_TOKEN`: without `RELEASE_TOKEN`, a tag can be pushed successfully but GitHub can suppress the publisher trigger, leaving an orphan tag. Operators must verify that the publisher starts; do not make the token mandatory.

- [ ] **Step 3: Document the Frostyard release contract**

Add a `## Releases` section to `README.md` before `## License`:

```markdown
## Releases

Frostyard releases are published from version tags at
[`frostyard/fisherman`](https://github.com/frostyard/fisherman/releases).
Run the `Cut Release` workflow from the `dev` branch with the intended semver
bump. The workflow uses `RELEASE_TOKEN || GITHUB_TOKEN`; without
`RELEASE_TOKEN`, a pushed tag can become an orphan because GitHub suppresses
the publisher trigger. Operators must verify that `Publish Release` starts.
The publisher verifies expected remote asset names and checksum-manifest
entries, not recomputed remote asset bytes; the consumer's independent digest
remains the trust boundary.

Each `vX.Y.Z` release provides directly executable Linux assets:

- `fisherman_X.Y.Z_linux_amd64`
- `fisherman_X.Y.Z_linux_arm64`

The matching `.tar.gz` archives remain available. `checksums.txt` covers both
raw binaries and both archives. Consumers must pin an exact versioned URL such
as
`https://github.com/frostyard/fisherman/releases/download/vX.Y.Z/fisherman_X.Y.Z_linux_amd64`
and independently record and verify its lowercase SHA-256; do not use GitHub's
mutable `/releases/latest/` discovery URL as an installation source.
```

- [ ] **Step 4: Run release and workflow verification**

Run:

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
actionlint .github/workflows/release-cut.yml .github/workflows/release-publish.yml .github/workflows/release-validate.yml
shellcheck tests/check-release.sh
git diff --check
```

Expected: all commands PASS and no generated `dist/` remains.

- [ ] **Step 5: Commit the release guard and documentation**

```bash
git add .github/workflows/release-cut.yml tests/check-release.sh README.md
git commit -m "docs: document Frostyard release process"
```

### Task 5: End-To-End Branch Verification

**Files:**
- Verify: `.goreleaser.yml`
- Verify: `.github/workflows/release-cut.yml`
- Verify: `.github/workflows/release-publish.yml`
- Verify: `.github/workflows/release-validate.yml`
- Verify: `tests/check-release.sh`
- Verify: `README.md`

**Interfaces:**
- Consumes: all release contract components from Tasks 1-4.
- Produces: a review-ready branch with local and PR evidence, but no tag or published release.

- [ ] **Step 1: Run the complete local verification suite**

```bash
GORELEASER=/tmp/opencode/goreleaser-2.17.1/goreleaser tests/check-release.sh
shellcheck tests/check-release.sh
actionlint .github/workflows/release-cut.yml .github/workflows/release-publish.yml .github/workflows/release-validate.yml
(cd fisherman && go test ./...)
(cd fisherman && go test -race ./...)
(cd fisherman && go vet ./...)
git diff --check origin/dev...HEAD
git status --short
```

Expected: every command PASS; `git status --short` is empty; no `dist/` directory remains.

- [ ] **Step 2: Review the complete branch diff**

```bash
git log --oneline origin/dev..HEAD
git diff --stat origin/dev...HEAD
git diff origin/dev...HEAD
```

Expected: only the design/plan commits and the release configuration, workflows, contract test, and README changes described above.

- [ ] **Step 3: Push and open a pull request to `dev`**

```bash
git push -u origin feat/frostyard-release
gh pr create --repo frostyard/fisherman --base dev --head feat/frostyard-release \
  --title "release: publish raw Frostyard Fisherman binaries" \
  --body $'## Summary\n- publish versioned raw Linux amd64 and arm64 Fisherman binaries alongside existing archives\n- validate the release contract in pull requests with pinned GoReleaser 2.17.1\n- stage, remotely verify, and then publish tagged GitHub Releases\n\n## Verification\n- `tests/check-release.sh`\n- `shellcheck tests/check-release.sh`\n- `actionlint .github/workflows/release-cut.yml .github/workflows/release-publish.yml .github/workflows/release-validate.yml`\n- `(cd fisherman && go test ./...)`\n- `(cd fisherman && go test -race ./...)`\n- `(cd fisherman && go vet ./...)`\n- `git diff --check origin/dev...HEAD`'
```

Expected: GitHub returns the new pull request URL.

- [ ] **Step 4: Require the release validation check before merge**

```bash
gh pr checks --repo frostyard/fisherman --watch --interval 20
```

Expected: when this release PR changes a configured path, `Validate Release / release-contract` passes. Do not configure it as a globally required branch-protection context: the workflow is path-filtered and would otherwise leave unrelated PRs pending. Do not dispatch `Cut Release`; the first live cut/draft execution remains the deferred go-live gate.
