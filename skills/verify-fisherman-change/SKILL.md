---
name: verify-fisherman-change
description: Verify Fisherman code, recipe, workflow, and documentation changes with checks proportional to disk-install risk. Use when reviewing or validating a Fisherman change, preparing a pull request, diagnosing CI failures, or deciding whether install-and-boot evidence is required.
---

# Verify Fisherman Change

Follow `AGENTS.md` as the authoritative repository guide.

## Classify the change

Treat changes to partitioning, formatting, encryption, mounts, image install,
bootloaders, secure verification, or post-install state as install-path changes.
Treat recipe schema or validation changes as install-path changes when they can
alter those behaviors. Documentation-only and isolated CI metadata changes are
lower risk unless they change release or qualification behavior.

## Inspect the contract

Read the linked issue, diff, callers, tests, and applicable design documents.
List the explicit behavior, invalid inputs, cleanup obligations, compatibility
constraints, and security invariants before judging completion. Confirm recipe
validation precedes destructive operations.

## Run proportional checks

Run from `fisherman/`:

```sh
gofmt -d <changed-go-files>
go build ./cmd/fisherman
go test ./...
go vet ./...
```

Run `golangci-lint run ./...` when available. Run `actionlint` and repository
contract scripts for workflow changes. Add targeted regression tests when the
existing suite does not prove the changed behavior.

For install-path changes, require a complete install on an explicitly
disposable loop device, VM, or lab disk and verify the installed system boots.
Do not accept mocked unit tests as complete install evidence.

## Report the result

Return findings first, ordered by severity and linked to exact files. Then list
commands and results, install evidence, and remaining unverified risks. Redact
passphrases, recovery keys, tokens, key material, and sensitive logs.
