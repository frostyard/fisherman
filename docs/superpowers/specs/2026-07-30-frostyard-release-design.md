# Frostyard Fisherman Release Design

## Goal

Publish immutable, versioned Fisherman executables from `frostyard/fisherman`
that external consumers can download directly and verify by SHA-256. Preserve
the existing semver tag flow and archive assets while adding raw Linux binaries
for consumers that cannot unpack an archive during image assembly.

## Scope

This change owns Fisherman's release contract only. It does not configure any
consumer repository, cut a production release, or change Fisherman's runtime
behavior. Consumer projects remain responsible for pinning an exact versioned
HTTPS asset URL and an independently configured SHA-256 value.

## Release Ownership And Versioning

GitHub Releases and assets are published under `frostyard/fisherman`, never
`tuna-os/fisherman`. Existing `vMAJOR.MINOR.PATCH` tags remain the versioning
authority. The manual release-cut workflow continues to calculate the next
semver from repository tags, create an annotated tag from the selected
Frostyard `dev` commit, and open the existing `dev` to `prod` release PR.

The publish workflow builds from the immutable tag commit. It must not publish
from a branch alias or create a mutable `latest` binary asset.

## Release Assets

Each release publishes these raw executables:

- `fisherman_<version>_linux_amd64`
- `fisherman_<version>_linux_arm64`

`<version>` is the release version without a mutable channel name. Existing
Linux amd64 and arm64 `.tar.gz` archives remain available for compatibility.
The release also publishes `checksums.txt`, containing SHA-256 entries for all
raw executables and archives.

The raw files are the GoReleaser-produced binaries, not copies extracted in a
separate workflow step. Both raw and archived forms therefore carry identical
compiled code and the same version, commit, and build-date linker metadata.
Builds remain static (`CGO_ENABLED=0`) and Linux-only.

## Publication Workflow

The tag-triggered publish job performs these stages in order:

1. Check out the complete tag history.
2. Install the Go version declared by `fisherman/go.mod`.
3. Run the full race-enabled Go test suite.
4. Validate the GoReleaser configuration.
5. Run a clean GoReleaser release using a specifically pinned GoReleaser
   version and the job-scoped GitHub token, creating a draft release.
6. Verify that the draft GitHub Release belongs to
   `frostyard/fisherman` and contains both raw binaries, both archives, and
   `checksums.txt`.
7. Publish the verified draft and report success.

The workflow retains only `contents: write`, plus read permissions needed by
checkout and dependency retrieval. It does not publish containers or require
long-lived release credentials. The existing optional `RELEASE_TOKEN` remains
limited to release-cut's cross-workflow tag trigger.

## Pull Request Validation

Pull requests that change `.goreleaser.yml` or either release workflow run a
release contract check that:

- validates GoReleaser configuration syntax;
- performs a non-publishing snapshot build;
- requires the exact amd64 and arm64 raw filenames;
- requires the existing amd64 and arm64 archives;
- requires `checksums.txt` to list every expected artifact;
- rejects a release target other than `frostyard/fisherman`; and
- rejects an unpinned `goreleaser-action` version such as `latest`.

This validation uses the same pinned GoReleaser version as publication. It
never creates a tag or GitHub Release.

## Failure Behavior

Release publication is fail-closed. Tests, configuration validation, build,
checksum generation, upload, or post-upload asset verification failures leave
the workflow failed. A failed run must not be represented as a usable release.
GoReleaser stages assets in a draft so partial uploads are not public. A failed
draft is deleted before retrying the same immutable tag; the tag itself is not
deleted, moved, or reused for different source. The workflow does not silently
overwrite an existing published version.

Consumers verify downloaded bytes against their separately configured SHA-256
before installation. `checksums.txt` is useful release metadata but is not a
substitute for the consumer's independent digest pin.

## Documentation

The Fisherman README documents the Frostyard release owner, immutable raw asset
naming, checksums, and the release-cut procedure. It explicitly distinguishes
raw versioned assets from mutable GitHub release discovery URLs.

## Acceptance Criteria

- A pull request snapshot proves both raw binaries, both archives, and their
  checksum entries without publishing anything.
- The release configuration names `frostyard/fisherman` as the GitHub owner.
- The publication workflow uses a pinned GoReleaser version, verifies a draft's
  final asset set, and only then publishes it.
- A test release or the first production release provides a directly
  downloadable executable at an exact URL shaped like
  `https://github.com/frostyard/fisherman/releases/download/vX.Y.Z/fisherman_X.Y.Z_linux_amd64`.
- A consumer can verify that executable using its independently recorded
  lowercase SHA-256 and execute it without archive extraction.
