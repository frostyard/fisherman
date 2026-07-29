# Secure Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit, fail-closed schema-1 Snosi secure-install backend to Fisherman.

**Architecture:** `recipe.SecureInstall` explicitly enables the path and validates immutable recipe constraints. A new `internal/secure` package owns schema decoding, command construction, installed-artifact verification, TPM enrollment, MOK staging, provenance, and narrow repair actions. Generic installs retain their existing behavior.

**Tech Stack:** Go 1.22, JSON recipes, bootc, systemd-cryptenroll, cryptsetup, objcopy, sbverify.

## Global Constraints

- Require schema `1`, systemd bootloader, composefs, LUKS2 Btrfs, mapper `root`, and automatic layout.
- Require a 30 GiB target disk and 1 GiB ESP for the secure backend.
- Use `bootc install to-filesystem --composefs-backend --bootloader systemd --root-mount-spec ""` without `--karg` or `--skip-fetch-check`.
- Do not infer secure mode from image names or add compatibility aliases.
- Never emit or persist recovery passphrases, MOK passwords, or private keys.

---

### Task 1: Secure recipe and contract validation

**Files:**
- Modify: `fisherman/internal/recipe/recipe.go`
- Create: `fisherman/internal/secure/contract.go`
- Test: `fisherman/internal/recipe/recipe_test.go`, `fisherman/internal/secure/contract_test.go`

- [ ] Write failing tests for explicit secure opt-in, schema-1 contract fields, and required recipe constraints.
- [ ] Run `go test ./internal/recipe ./internal/secure` and observe failure.
- [ ] Implement strict JSON decoding and constraint validation.
- [ ] Re-run focused tests and observe pass.

### Task 2: Secure bootc and artifact verification

**Files:**
- Modify: `fisherman/internal/install/bootc.go`
- Create: `fisherman/internal/secure/verify.go`
- Test: `fisherman/internal/install/bootc_test.go`, `fisherman/internal/secure/verify_test.go`

- [ ] Write failing tests for exact secure bootc arguments and Type #2 BLS/UKI validation.
- [ ] Run focused tests and observe failure.
- [ ] Implement the secure argument builder and artifact verification.
- [ ] Re-run focused tests and observe pass.

### Task 3: Enrollment, recovery operations, integration, and documentation

**Files:**
- Create: `fisherman/internal/secure/enroll.go`, `fisherman/internal/secure/operations.go`
- Modify: `fisherman/cmd/fisherman/main.go`, `README.md`
- Test: `fisherman/internal/secure/enroll_test.go`, `fisherman/internal/secure/operations_test.go`

- [ ] Write failing tests for recovery-authenticated PCR-11 enrollment, redacted progress, MOK restage, ESP repair, and CLI dispatch.
- [ ] Run focused tests and observe failure.
- [ ] Implement the smallest secure pipeline integration and documented parent API.
- [ ] Run `gofmt -w`, `go test ./...`, `go test -race ./...`, `go vet ./...`, and available repository linting.
