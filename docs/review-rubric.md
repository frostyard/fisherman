# Pull request review rubric

Reviewers should apply this rubric together with `AGENTS.md`. Findings are
ordered by risk: data loss or weakened secure-install verification, functional
correctness, missing verification, and maintainability.

## Required review

1. **Scope and traceability:** The PR links its issue, matches the requested
   behavior, targets `dev`, and calls out compatibility or migration effects.
2. **Installer safety:** Recipe input is validated before destructive work.
   Disk identity is not trusted from a mutable device name alone. Error paths
   clean up mounts, mappers, loop devices, scratch storage, and credentials.
3. **Secure installation:** Digest pinning, signature policy, boot-chain checks,
   and credential validation remain fail-closed. Logs and fixtures contain no
   passphrases, keys, tokens, or unredacted credentials.
4. **Subprocesses:** Arguments are explicit and testable; recipe or external
   values are not evaluated by a shell.
5. **Tests:** Changed behavior has focused success, invalid-input, and relevant
   failure-path coverage. Tests are deterministic or skip ambient requirements
   with an explicit reason.
6. **Evidence:** Go build, tests, and vet pass. Workflow changes pass actionlint
   and repository contract scripts. Install-path changes include a complete
   disposable-disk or VM install and successful boot result.
7. **Operations:** Partition sizes, GPT types, filesystem features, bootloader,
   target paths, and recipe compatibility do not change silently.

A reviewer should request changes when a required item is contradicted or lacks
evidence. “Not applicable” is acceptable only with a reason. Approval means the
reviewer found no unresolved correctness or safety issue at the evidence level
appropriate to the change; it is not a guarantee that the installer is safe on
an unidentified disk.
