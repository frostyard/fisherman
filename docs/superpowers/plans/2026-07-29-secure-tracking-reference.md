# Secure Tracking Reference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve an explicit, validated secure update-tracking tag while installing only a verified immutable source digest.

**Architecture:** Secure recipe validation owns the syntactic and same-repository constraints for `targetImgref`. The command entry point pins only `image`; installation uses that digest for every source operation and passes the retained tracking tag solely to bootc's `--target-imgref`; provenance records both references independently.

**Tech Stack:** Go, Go standard library, bootc, Podman, Skopeo.

## Global Constraints

- Modify only this Fisherman checkout; do not commit.
- Secure recipes require an explicit bare registry tag in `targetImgref`.
- The tracking tag must have the exact repository of the source image; it must not be a digest, transport-qualified, or local reference.
- `AcceptImage` verifies, capability-checks, and pins only the source image.
- All secure source pull/export/inspect/bootc operations consume only the pinned source digest.
- Secure bootc receives the tracking tag only through `--target-imgref`; never use `--skip-fetch-check`.
- Secure provenance records immutable `oci_ref` and mutable `tracking_ref` separately.
- Generic non-secure behavior remains unchanged.

---

### Task 1: Secure Recipe Tracking Reference Validation

**Files:**
- Modify: `fisherman/internal/recipe/recipe.go`
- Test: `fisherman/internal/recipe/recipe_test.go`

**Interfaces:**
- Produces: `Recipe.Validate()` rejects invalid secure `TargetImgref` values before any installation work.

- [ ] Add table-driven failing secure-recipe cases for a missing tag, digest, `docker://` transport, `containers-storage:` source, and repository mismatch, plus a valid same-repository tag.
- [ ] Run `go test ./internal/recipe -run TestSecureInstallRequiresExplicitCompatibleRecipe` and observe the invalid-target cases fail before implementation.
- [ ] Implement a small helper that parses registry repository plus tag and use it only in the secure validation branch.
- [ ] Re-run the focused recipe tests and observe PASS.

### Task 2: Pinned Source and Tracking-Tag Handoff

**Files:**
- Modify: `fisherman/cmd/fisherman/main.go`
- Modify: `fisherman/internal/install/bootc.go`
- Test: `fisherman/internal/install/bootc_test.go`
- Test: `fisherman/cmd/fisherman/main_test.go`

**Interfaces:**
- Consumes: a validated secure `Recipe.TargetImgref`.
- Produces: secure `Options.SourceImgref` is a digest and `Options.TargetImgref` is the supplied tag.

- [ ] Add failing tests that assert secure bootc arguments carry a digest-derived source and the original tracking tag, without `--skip-fetch-check` or a tag source fetch.
- [ ] Run focused package tests and observe the new assertions fail with the current digest-overwrite behavior.
- [ ] Change secure acceptance in `main.go` to assign only `r.Image = pinned`; retain `r.TargetImgref`.
- [ ] Ensure the secure install plumbing uses its source reference for pull, OCI export, composefs digest, and container execution, while `--target-imgref` remains the tracking tag.
- [ ] Re-run focused tests and observe PASS.

### Task 3: Separate Provenance and Public API Documentation

**Files:**
- Modify: `fisherman/internal/secure/secure.go`
- Modify: `fisherman/cmd/fisherman/main.go`
- Modify: `fisherman/internal/secure/durability_test.go`
- Modify: `docs/SECURE_INSTALL_API.md`
- Modify: `README.md`

**Interfaces:**
- Produces: `secure.Provenance` JSON containing `oci_ref` and `tracking_ref`.

- [ ] Add failing provenance tests requiring both references and verifying they differ when a digest is installed from a tracking tag.
- [ ] Run the secure package tests and observe failure for missing fields.
- [ ] Replace repository/digest provenance storage with the explicit immutable and tracking references, set from the pinned image and preserved tag.
- [ ] Document the required recipe field and the source-vs-tracking behavior.
- [ ] Re-run focused tests and observe PASS.

### Task 4: Formatting and Verification

**Files:**
- Verify the files changed in Tasks 1-3.

- [ ] Run `gofmt -w` on changed Go files.
- [ ] Run focused package tests, `go test ./...`, `go test -race ./...`, and `go vet ./...` from `fisherman/`.
- [ ] Inspect `git diff --check` and `git diff` to confirm only intended Fisherman files changed and no whitespace errors remain.
