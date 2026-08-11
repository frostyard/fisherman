# GitHub Copilot instructions

Use `AGENTS.md` for repository architecture, invariants, tests, and safety
requirements. Use `CONTRIBUTING.md` for branch and pull-request conventions.

- Work in the nested `fisherman/` Go module and require Go 1.22 or newer.
- Format Go changes with `gofmt`; run `go build ./cmd/fisherman`, `go test
  ./...`, and `go vet ./...` from that module.
- Add tests with every behavior or recipe-validation change.
- Preserve fail-closed secure-install checks and cleanup on all error paths.
- Never print or commit passphrases, recovery keys, tokens, or key material.
- Do not suggest running destructive installation commands unless the target is
  an explicitly identified disposable loop device, VM disk, or lab disk.
- Changes affecting the install path require complete install and boot evidence.
- Target pull requests to `dev` and use Conventional Commit subjects.
