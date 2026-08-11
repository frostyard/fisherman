# Change risk tiers

Classify every pull request by its highest-impact change. The tier determines
the minimum evidence; it never relaxes the invariants in `AGENTS.md`.

| Tier | Typical scope | Required evidence |
| --- | --- | --- |
| 1 — Low | Documentation, comments, non-executable metadata | Relevant contract or link checks; reviewer confirms claims match current behavior |
| 2 — Standard | Deterministic application logic that cannot mutate disks or trust state | Build, full unit tests, vet, focused success and failure tests |
| 3 — Elevated | Workflows, release logic, subprocess construction, recipe validation, cleanup | Tier 2 plus relevant contract scripts, `actionlint` for workflows, and explicit failure-path review |
| 4 — Critical | Partitioning, formatting, encryption, mounts, bootloaders, image installation, secure-install trust, or installed-system state | Tier 3 plus a complete install on an identified disposable target and successful boot verification |

If a change spans tiers, use the highest tier. Missing ambient tooling may
explain why evidence is pending, but does not lower the tier or make the
evidence optional. Tier 4 evidence must identify the disposable device or VM
by stable characteristics and redact credentials and key material.
