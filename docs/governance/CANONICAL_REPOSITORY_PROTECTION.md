# CANONICAL REPOSITORY PROTECTION

- Baseline: `CANONICAL_REPOSITORY_PROTECTION_BASELINE_V1`
- Scope: `James3014/nexus-core`, `James3014/nexus-learning`, `James3014/nexus-open-swe-runtime`
- Target Branch: `refs/heads/main`
- Mechanism: GitHub Repository Ruleset (ID: `22367671`, Name: `"Canonical Main Protection v1"`)
- Enforcement: `active`

## Policy Baseline Specification

| Rule | Specification | Configuration |
|---|---|---|
| Target | `refs/heads/main` | `include: ["refs/heads/main"]` |
| Direct Push | Blocked | Enforcement active |
| Pull Request | Required | `required_approving_review_count: 0`<br>`require_last_push_approval: false`<br>`dismiss_stale_reviews_on_push: false`<br>`require_code_owner_review: false` |
| Conversations | Required | `required_review_thread_resolution: true` |
| Force Push | Blocked | `non_fast_forward` enabled |
| Branch Deletion | Blocked | `deletion` enabled |
| Status Checks | Strict | `strict_required_status_checks_policy: true`<br>`required_status_checks: [{"context": "test"}, {"context": "Nexus Core issue completion"}]` |
| Bypass Actors | None | Empty bypass actors list |
| Merge Queue | Required (#288) | `merge_queue`: `merge_method: SQUASH`, `grouping_strategy: ALLGREEN`, `max_entries_to_build: 5`, `min_entries_to_merge: 1`, `max_entries_to_merge: 5`, `min_entries_to_merge_wait_minutes: 0`, `check_response_timeout_minutes: 60` |

## Repository Required Checks

- Repository: `James3014/nexus-core`
- Required Status Check Contexts (both enforced on `main`):
  - `test` — GitHub Actions workflow `ci.yml` job `test` (tests, static analysis and packaging)
  - `Nexus Core issue completion` — GitHub Actions workflow `nexus-core-issue-completion.yml` job `verify` (signed Issue-bound verification receipt)

## Merge Queue (#288)

`main` is merged through a GitHub merge queue. GitHub tests each queued pull request on a
merge group commit built on top of the latest `main` (plus the PRs ahead of it), and merges
only when every required check passes on that commit. A branch therefore never needs to be
brought up to date by hand.

- Workflows that report a required check also trigger on `merge_group`: `ci.yml` (`test`) and
  `sibling-merge-checks.yml`. The two required commit statuses are published on the PR head by
  the trusted `pull_request_target` path; on a merge group commit the `merge-group` job copies
  the latest status of each from the queued PR's head (missing, non-success or
  non-`github-actions[bot]` copies as failure). GitHub admits a PR to the queue only after its
  head passed them, so the copy keeps the queue moving and is not a separate trust boundary.
  Pinned by `tests/architecture/test_merge_queue_triggers.py`.
- Agent merge flow: `gh pr merge <PR> --repo James3014/nexus-core --squash --match-head-commit <head>`
  **adds the PR to the queue** (the queue's `merge_method` decides the final method), and
  `gh pr merge --auto` enqueues once the PR checks are green. Then wait for `state: MERGED`
  (`gh pr view <PR> --json state,mergeCommit`). A push to a queued PR removes it from the
  queue. Do not merge `main` into a branch only to catch up.

## Server-Side Verification

Ruleset verified via GitHub REST API:
```bash
gh api repos/James3014/nexus-core/rulesets/22367671
gh api repos/James3014/nexus-core/branches/main --jq '{protected: .protected}'
```
Expected output:
```json
{
  "protected": true
}
```
