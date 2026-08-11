# Pull request acceptance metrics

Fisherman uses pull request outcomes to check whether its development process
is producing changes that reviewers can accept safely. Review these metrics
quarterly using GitHub pull request and Actions data. Report the date range and
exclude automated dependency updates so that comparisons use the same cohort.

| Metric | Definition | Desired signal |
| --- | --- | --- |
| First-pass acceptance | Merged PRs with no request-changes review divided by all merged PRs | Stable or increasing |
| Review rework | Median number of request-changes review rounds on merged PRs | Stable or decreasing |
| Gate reliability | PR required-check runs that succeed on their first attempt divided by all PR required-check runs | Stable or increasing |
| Time to acceptance | Median time from ready-for-review to approval on merged PRs | Tracked, not optimized at the expense of safety |
| Escaped defects | Regressions linked to a merged PR and reported within 30 days | Zero |

Record the numerator, denominator, and links to the underlying pull requests
when publishing a result. A small sample must be reported as such rather than
presented as a trend. Reverted PRs and escaped defects require a short review of
the missing test, review check, or install evidence; do not use these metrics to
reward smaller review counts or faster merges.
