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
| Status Checks | Required, not strict | `strict_required_status_checks_policy: false`<br>`required_status_checks: [{"context": "test"}, {"context": "Review record present (advisory)"}, {"context": "Bindings preflight (default branch)"}]` (the last two with `integration_id: 15368`, GitHub Actions) |
| Bypass Actors | None | Empty bypass actors list |
| Up-to-date Branch | Not required | `strict_required_status_checks_policy: false`; no merge queue (unavailable for this user-owned repository, #288) |

## Repository Required Checks

- Repository: `James3014/nexus-core`
- Required Status Check Contexts (all enforced on `main`, since 2026-10-16):
  - `test` — GitHub Actions workflow `ci.yml` job `test` (tests, static analysis and packaging)
  - `Review record present (advisory)` — commit status published by `sibling-merge-checks.yml` (Nexus-new reusable workflow, #2385)
  - `Bindings preflight (default branch)` — commit status published by `sibling-merge-checks.yml` (Nexus-new reusable workflow, #2385)
- `Nexus Core issue completion` (`nexus-core-issue-completion.yml` job `verify`) still runs on every pull request into `main` but is no longer required.

## Merge Flow (#288)

There is **no merge queue** and the branch does **not** need to be up to date with `main`.
GitHub merge queue is only available to organization-owned repositories (public, or private on
GitHub Enterprise Cloud); `James3014/nexus-core` is owned by a personal account, and the
ruleset API rejects a `merge_queue` rule here (`422 Invalid rule 'merge_queue'`, 2026-10-17).

- Authors self-merge once the required checks pass and the review record names the current head:
  `gh pr merge <PR> --repo James3014/nexus-core --squash --match-head-commit <head>` (a standalone
  command). `--match-head-commit` makes the merge fail if the head moved after review.
- Merge `main` into a branch only when it conflicts with `main`, or when `main` changed the same
  files; then post a short review record for the new head.
- Backstop: `ci.yml` runs `test` on every push to `main`. What this gives up compared with an
  up-to-date requirement or a queue: two PRs that are green separately can still break `main`
  together (a semantic conflict without a textual one). Such a break shows up in the post-merge
  `main` run and is fixed forward.
- Dormant: `ci.yml` and `sibling-merge-checks.yml` still trigger on `merge_group`, and
  `sibling-merge-checks.yml` has a `merge-group` job that copies the PR-head statuses to a merge
  group commit (#292, pinned by `tests/architecture/test_merge_queue_triggers.py`). These events
  never fire in this repository; the code is kept, tested, so the queue can be enabled without a
  workflow change if the repository moves to an organization.

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
