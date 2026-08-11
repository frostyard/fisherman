# Contributing to Fisherman

Thank you for improving Fisherman. Because it partitions and formats disks,
changes must be tested in proportion to their impact and must never use a disk
that contains valuable data.

## Development setup

Fisherman's Go module lives in `fisherman/` within this repository and requires
Go 1.22 or newer. Clone the repository, create a branch from `dev`, and enter
the module before running the fast checks:

```sh
git clone https://github.com/frostyard/fisherman.git
cd fisherman
git switch dev
git switch -c <type>/<short-description>
cd fisherman
go build ./cmd/fisherman
go test ./...
go vet ./...
```

If `golangci-lint` is installed, also run it from the Go module:

```sh
golangci-lint run ./...
```

Use `gofmt` on changed Go files. Keep tests next to the package they exercise;
black-box command tests belong in `fisherman/tests/e2e/`. Repository-level VM
and install verification lives in `tests/`, `scripts/`, and the `justfile`.

## Making a change

1. Open or identify an issue that describes the problem and expected behavior.
2. Keep each branch focused on one independently reviewable change.
3. Add regression tests for changed behavior, including invalid and failure
   cases when applicable.
4. Run the fast checks above.
5. Commit using a concise Conventional Commit subject such as `fix:`, `feat:`,
   `test:`, `docs:`, or `ci:`.
6. Push the branch to `frostyard/fisherman` and open a pull request against
   `dev`, linking the issue.

Do not target the release branch directly. Releases are cut from tested `dev`
commits by the repository's release workflows.

## Install-path verification

Unit tests are not sufficient for changes to partition layouts, filesystems,
encryption, mounts, image installation, bootloaders, or post-install state.
Those changes require a complete install onto a disposable loop device, VM, or
lab disk followed by a successful boot verification.

The local Bootcrew recipes are documented in `justfile`. For example:

```sh
just bootcrew-vm <image> <filesystem> <composefs>
```

This workflow requires Linux host tooling, root privileges, virtualization,
and enough free disk space. Record the image reference, recipe, environment,
result, and relevant redacted logs in the pull request. Never paste encryption
passphrases, recovery keys, tokens, or credentials.

## Pull requests

A pull request should explain the user-visible outcome, link its issue, list
the exact verification performed, and call out compatibility or migration
effects. CI must pass before merge. Review feedback should be addressed with
new commits unless a maintainer asks for a history rewrite.

By contributing, you agree that your work is provided under the repository's
GPL-3.0-only license.
