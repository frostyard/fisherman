---
description: Review and verify a Fisherman change according to its install risk
agent: agent
---

Review the current Fisherman change against `AGENTS.md` and its linked issue.

1. Identify the affected recipe, disk, encryption, install, boot, post-install,
   CI, or documentation contracts.
2. Inspect the diff and relevant callers; do not infer safety from diff size.
3. Confirm validation precedes destructive operations and cleanup remains
   correct on failure paths.
4. Check that tests prove the changed behavior and important invalid cases.
5. Run required Go checks from `fisherman/` and relevant workflow checks.
6. If the install path changes, require complete disposable-disk or VM install
   evidence followed by a successful boot; report its absence as unverified.
7. Return findings first, ordered by severity, followed by verification results
   and remaining risk. Do not expose secrets from recipes or logs.
