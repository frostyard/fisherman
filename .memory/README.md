# Correction memory

`corrections.jsonl` records durable repository-specific corrections discovered
during reviews, CI failures, or agent sessions. Each line is one JSON object:

- `date`: discovery date in `YYYY-MM-DD` form.
- `scope`: short affected area.
- `incorrect`: the disproven assumption or action.
- `correct`: the behavior future contributors should follow.
- `evidence`: repository path, issue, PR, or test that proves the correction.

Record only reusable technical lessons. Never store prompts, personal data,
credentials, recovery material, tokens, or unredacted logs. Update `AGENTS.md`
when a correction establishes a repository-wide invariant.
