# AGENTS.md — Fisherman agent guide

## Scope and priorities

This file applies to the entire repository. Fisherman is a destructive disk
installer: correctness and preservation of install invariants take precedence
over small diffs or passing mocked tests.

Read `README.md`, `CONTRIBUTING.md`, and relevant design documents before
changing behavior. Treat the current code, tests, recipes, and workflows as
authoritative when older prose disagrees.

## Repository map

- `fisherman/`: Go 1.22 CLI module and package tests.
- `fisherman/cmd/fisherman/`: command dispatch and installation pipeline.
- `fisherman/internal/disk/`: partition, format, mount, and finalize logic.
- `fisherman/internal/install/`: bootc, Podman, storage, and verification logic.
- `fisherman/internal/luks/`: LUKS and TPM enrollment.
- `fisherman/internal/post/`: installed-system configuration and cleanup.
- `fisherman/internal/recipe/`: JSON schema and validation.
- `fisherman/internal/secure/`: Snosi secure-install contract.
- `tests/`, `scripts/`, `justfile`: repository-level Bootcrew E2E tooling.
- `.github/workflows/`: CI, VM qualification, and release automation.

The Git repository root and Go module root are different. Run Go commands from
`fisherman/`, not from the repository root.

## Required workflow

1. Start from `origin/dev`; target pull requests to `dev`.
2. Inspect the working tree and preserve unrelated user changes.
3. Reproduce or characterize the issue before editing behavior.
4. Add focused tests for success, invalid input, and relevant failure paths.
5. Format changed Go files with `gofmt`.
6. Run verification proportional to the affected risk.
7. Use Conventional Commit subjects (`fix:`, `feat:`, `test:`, `docs:`, `ci:`).
8. In the PR, link the issue and record exact commands and install evidence.

## Verification

From `fisherman/`, run at minimum:

```sh
go build ./cmd/fisherman
go test ./...
go vet ./...
```

Run `golangci-lint run ./...` when available. For workflow changes, run
`actionlint` and any repository contract script relevant to the workflow.

Changes to partitioning, formatting, encryption, mounts, bootloaders, image
installation, or post-install state require a complete install on a disposable
loop device, VM, or lab disk and verification that the installed system boots.
The Bootcrew entry points are in `justfile`. Unit tests alone do not prove the
install path works.

## Safety invariants

- Never run Fisherman against a disk whose identity and disposability have not
  been explicitly established. Identify disks by model and serial, not only a
  mutable `/dev` name.
- Never expose recipe passphrases, recovery keys, tokens, key material, or
  unredacted logs in commits, issues, test output, or PRs.
- Validate all recipe input before the first destructive disk operation.
- Preserve cleanup behavior on every error path: mounts, mappers, loop devices,
  scratch storage, and temporary credentials must not leak.
- Keep secure-install verification fail-closed. Do not weaken digest pinning,
  signature policy, signed boot-chain checks, or credential file validation.
- Do not silently change partition sizes, GPT types, filesystem features,
  bootloader selection, target paths, or recipe compatibility.
- Keep subprocess arguments explicit and testable; do not invoke a shell for
  values derived from recipes or external state.

## Test design

Prefer deterministic package tests with injected command/filesystem functions.
Use black-box tests in `fisherman/tests/e2e/` for CLI boundaries. Keep real disk
and VM tests in the repository-level E2E harness. When an ambient filesystem,
tool, or firmware feature is required, skip with an explicit reason rather
than asserting assumptions about the runner.

Do not lower the coverage floor to land a change. A new behavior or validation
rule should include tests that demonstrate the intended contract.
