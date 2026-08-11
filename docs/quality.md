# Quality status

Fisherman's quality signals are intentionally split by risk. The GitHub Actions
run for a commit is the current dashboard; this page explains what each signal
proves and what it does not prove.

| Signal | Scope | Required interpretation |
| --- | --- | --- |
| CI matrix | Build, unit tests, and vet on minimum Go 1.22 and current stable Go | Compatibility and deterministic package behavior |
| Coverage gate | Repository statement coverage is at least 42% | A floor only; it does not prove install correctness |
| Bootcrew required canaries | Full install and boot of required matrix entries | Install-path evidence for represented recipes and images |
| Bootcrew advisory jobs | Broader image compatibility | Diagnostic; failures need triage before promotion |
| Release validation | Release workflow and artifact contract | Packaging integrity before a release is cut |
| Nightly compliance | Policy contracts plus build, test, and vet | Detects drift outside the pull-request feedback loop |

For every pull request, reviewers should use the rubric in
[`review-rubric.md`](review-rubric.md) and require exact verification commands
in the PR description. Red checks are never waived without explaining whether
the failure is caused by the change. Green package tests cannot substitute for
a disposable-disk or VM install and successful boot when partitioning,
formatting, encryption, mounts, bootloaders, image installation, or installed
state changes.

The acceptance metrics in [`metrics.md`](metrics.md) provide the longer-term
feedback loop. Maintainers should open an issue for a downward trend, escaped
defect, repeatedly flaky required gate, or a mismatch between documented and
enforced branch protection.

Classify changes using [`risk-tiers.md`](risk-tiers.md). The Auto-QA policy in
`.github/auto-qa-tuning.json` may ratchet coverage upward with headroom through
a reviewed pull request, but may never lower a threshold automatically or
substitute package coverage for required install-and-boot evidence.
