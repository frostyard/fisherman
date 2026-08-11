# Claude instructions

Follow [`AGENTS.md`](AGENTS.md) as the authoritative repository guide and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the contribution workflow.

- The Go module is in `fisherman/`; run Go commands there.
- Base work on `origin/dev` and target pull requests to `dev`.
- Treat disk, encryption, boot, install, and post-install changes as high risk.
- Never expose credentials or run destructive commands without an explicitly
  identified disposable target.
- Require full install-and-boot evidence for install-path changes; mocked unit
  tests are necessary but not sufficient.
