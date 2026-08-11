# AI-assisted development security policy

AI tools are untrusted contributors. A maintainer remains responsible for every
change, command, credential boundary, and claim they produce.

## Allowed use

AI may inspect repository content, propose patches, add deterministic tests,
and summarize redacted results. It must follow `AGENTS.md`, classify changes
with `risk-tiers.md`, preserve unrelated work, and use the same pull-request,
review, and branch-protection path as human-authored changes.

## Prohibited use

- Do not provide passphrases, recovery keys, signing keys, tokens, private
  images, credential files, or unredacted logs to a model or commit them.
- Do not let generated input select an unidentified disk or invoke recipe data
  through a shell.
- Do not run Fisherman against a disk unless its model, serial, and
  disposability have been explicitly established.
- Do not grant workflows triggered by untrusted pull-request content access to
  secrets or broad repository write permissions.
- Do not weaken digest pinning, signature policy, signed boot-chain checks,
  credential validation, cleanup, or required verification to accept a patch.

## Review and incident handling

Generated changes receive the risk-tier evidence and human review required for
their behavior. Treat fabricated test output, unsafe commands, secret exposure,
or an unexplained invariant change as a security incident: stop execution,
revoke exposed credentials, preserve redacted evidence, notify maintainers via
the repository's private security-reporting channel, and correct any durable
learning artifact that encouraged the failure.
