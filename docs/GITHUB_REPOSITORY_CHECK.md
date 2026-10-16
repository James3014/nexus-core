# GitHub Repository Gate

## Checklist for a new repository

1. Run `nexus-certify init`, add a version 2 `[isolation]` section with a digest-pinned container `image`, and merge `.nexus-core/config.toml` into the base branch.
2. Run `nexus-certify markers` and paste the `NEXUS_CORE_EVIDENCE_UNIVERSE` line into the Issue body (check it with `nexus-certify markers --issue <number> --check`; see [Core-ready Issues](#core-ready-issues-and-failure-remediation)).
3. Copy [`examples/github-repository-check.yml`](examples/github-repository-check.yml) to `.github/workflows/`, set `expected-identity` to that workflow file on `refs/heads/main`, and pin both actions and `nexus-certify-ref` to one full 40-hex commit.
4. Merge the workflow into the base branch (the gate runs from the base ref).
5. Require the status check `Nexus Core issue completion` in the branch protection or ruleset, and set fork pull request workflows to require approval.
6. Open a pull request whose body contains `<!-- NEXUS_CORE_ISSUE: <number> -->` (run `nexus-certify markers --issue <number>`), and confirm both jobs go green.

Nexus Core provides a reusable composite action, `.github/actions/issue-gate`,
that gates a pull request on an Issue-bound `nexus-certify issue-check`. It runs
the verifier configured in the base ref's `.nexus-core/config.toml`, derives facts
from the physical checked-out Git repository, and writes the same durable local
verification receipt, which is uploaded as a workflow artifact.

A successful result is `VERIFIED (not CERTIFIED)`: the base-ref verification
contract passed inside the configured isolation against this exact tree. It is not
approval, Candidate acceptance, merge authority, release authority, semantic proof
that the Issue is complete, or a production claim.

## Core-ready Issues and failure remediation

Every Issue the gate binds needs one exact `NEXUS_CORE_EVIDENCE_UNIVERSE` line.
Start new Issues from this body (for example in `.github/ISSUE_TEMPLATE/`), with
the placeholder replaced by the line `nexus-certify markers` prints on an
up-to-date base branch:

```markdown
## Problem

## Acceptance

<!-- Paste the line printed by `nexus-certify markers` (do not edit it by hand): -->
<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: sha256:<64 hex from nexus-certify markers> -->
```

The hash changes whenever `.nexus-core/config.toml` changes on the base branch, so
a template cannot carry a fixed value. Check a live Issue read-only with:

```bash
nexus-certify markers --issue <number> --check   # exit 0 = marker matches, 1 = fix needed
```

It reads the Issue body with the same GitHub reader as `issue-init`, prints the
expected line, and writes nothing. When the gate fails, `nexus-certify` and both
actions print one remediation line (and append it to the job summary) next to the
unchanged fail-closed reason codes:

| Remediation code | Meaning and fix |
| --- | --- |
| `BASE_REF_NOT_ANCESTOR` | HEAD shares no single merge-base with the base tip (unrelated or criss-cross history); the line names the base SHA and the rebase command (`git fetch origin && git rebase origin/<base>`). |
| `ISSUE_MISSING_EVIDENCE_UNIVERSE` | The Issue has no marker (`UNVERIFIABLE`); the line contains the exact marker to add. |
| `ISSUE_EVIDENCE_UNIVERSE_STALE` | The config changed since the marker was written; the line contains the replacement marker. |
| `ISSUE_EVIDENCE_UNIVERSE_BINDING_MALFORMED` | More than one or a malformed marker; keep exactly the printed line. |
| `PR_MISSING_CORE_ISSUE_BINDING` | The PR body (or the receipt) names no Issue; add `<!-- NEXUS_CORE_ISSUE: N -->`. When the body has no marker but names exactly one same-repository Issue through `Refs`/`Closes`/`Fixes`/`Resolves #N`, the line prints that marker with N filled in (a hint only; the binding is never inferred and the gate still fails closed). |
| `RECEIPT_ISSUE_BINDING_MISMATCH` | The receipt is bound to a different Issue than the PR. |
| `REPOSITORY_VERIFICATION_NOT_VERIFIED` | The verifier itself did not pass; see the receipt / "Diagnose Core verifier failure" step. |

These lines are diagnostics only; the marker must still match exactly. Since #243
(Owner decision) HEAD need only descend from a commit on the base branch: a branch
one merge behind passes, its subject diff is `merge-base..HEAD`, and the trusted
config is still read from the current base tip.

### Opt-in: trusted-config evidence universe (no Issue marker)

The default is fail closed: an Issue without the exact `NEXUS_CORE_EVIDENCE_UNIVERSE`
line is `UNVERIFIABLE`, and a stale or malformed line fails. A repository can opt in to a
second mode in which the evidence universe is derived from the `.nexus-core/config.toml` committed on the base ref
instead, so Issues need no hand-written marker:

```bash
nexus-certify issue-init  --issue <number> --evidence-universe trusted-config
nexus-certify issue-check --issue <number> --evidence-universe trusted-config --require-trusted-config
```

In the `issue-gate` action, set the input `evidence-universe: trusted-config` (default
`issue-marker`); both commands receive it through `env:`. Use the same mode for init and
check: a binding created in one mode is refused (`ISSUE_EVIDENCE_UNIVERSE_MODE_MISMATCH`) by the other.

The mode requires trusted config: `issue-init` refuses (`CONFIG_UNTRUSTED`) unless the effective
config is committed on the base ref (a plain branch name; a worktree-only config or a revision
expression such as `HEAD~1` is refused), and `issue-check` fails closed with
`EVIDENCE_UNIVERSE_REQUIRES_TRUSTED_CONFIG` unless `--require-trusted-config` is given (it is
not forced silently). Receipts claiming `trusted-base-config` are rejected by `receipt-verify`
unless their `config_source.kind` is `base-ref`. A legacy schema-1 Issue binding carries no
evidence-sufficiency binding, so in this mode it stays UNBOUND and its Issue is UNVERIFIABLE.

In this mode the universe is bound to the verification contract hash of that base-ref config
(recorded with `source = "trusted-base-config"`), so the Issue status follows the repository
verification: `VERIFIED` exactly when the repository check is `VERIFIED`. A marker that is
present but stale or malformed only prints a warning on stderr and is ignored. Receipts
record `issue_verification.evidence_universe_source`; receipts without the key (every
default-mode receipt) stay valid.

What it gives up: in the default mode the Issue author (often an agent) must re-acknowledge
the current verification contract by pasting a fresh marker whenever the base config changes.
Trusted-config mode removes that step, so a base-config change is no longer re-acknowledged
per Issue. The trust moves entirely to the base branch config and its review. Keep the
default unless that trade is intended.

## Two jobs: run and verify

The gate is two jobs, so that the required status check never rests on a bare
exit code:

- **`run`** (`Nexus Core issue run`) runs `issue-gate`. After `issue-check` it
  signs the newest receipt, success or failure, with Sigstore keyless signing
  (`sigstore sign`, OIDC workflow identity) and uploads the receipt and its
  `<receipt>.sigstore.json` bundle as one artifact. This job must grant
  `id-token: write`. Outputs: `artifact-name`, `artifact-id`, `issue-number`,
  and the action outputs `receipt-file`, `bundle-file`, `receipt-sha256`. The
  artifact name is `nexus-core-receipts-<head-sha>-run<run-id>-attempt<run-attempt>`:
  a rerun keeps earlier attempts' artifacts in the same workflow run, so the name
  binds the producing attempt.
- **`verify`** (`Nexus Core issue completion`, `needs: run`, `if: always()`) is
  the required check. It runs `receipt-verify` with only `contents: read`,
  `actions: read` and `pull-requests: read` (the last only for the
  `PR_ALREADY_CLOSED_SKIPPED` live PR read): it requires the artifact name to bind this head, this
  workflow run and an attempt not after the current one (a verifier-only rerun
  keeps the producer's attempt from `needs.run.outputs`), resolves it through the
  GitHub API to exactly one unexpired artifact of this run (and to `artifact-id`
  when given), failing closed on a missing, ambiguous or mismatched artifact,
  downloads exactly that artifact by id, requires exactly one receipt and
  one bundle, runs `sigstore verify github`, resolves the expected head tree with
  a shallow fetch of the PR head sha, and runs `nexus-certify receipt-check` with
  every expectation.

The required status now means: **a receipt signed by this repository's
main-branch workflow identity describes exactly this head, this base config, this
Issue, and says VERIFIED.**

"Says VERIFIED" includes the Issue-level verdict: the receipt's
`issue_verification.status` must be `VERIFIED`, which requires the Issue's evidence
universe marker to be present and equal to the current verification contract. A
repository-level `outcome.status` of `VERIFIED` with an unbound or stale marker is
`UNVERIFIABLE` at the Issue level and fails `--expect-issue` and `--expect-status`
(see Issue #134, a false green found in nexus-runtime PRs #89 and #91).

### Runs that start after the PR closed (`PR_ALREADY_CLOSED_SKIPPED`)

A queued or retried run often starts after its PR merged and auto-closed the
Issue. Before binding the Issue, `issue-gate` reads the **live pull request**
(`nexus-certify pr-state --mode gate`):

- PR open: the gate runs as above. A closed Issue on an open PR still fails
  `ISSUE_NOT_OPEN`; an Issue being closed is never success by itself.
- PR merged or closed: the gate evaluates nothing, produces no receipt and
  outputs `outcome: PR_ALREADY_CLOSED_SKIPPED` with the observed PR state in the
  log and job summary. This is a neutral result, never a pass of the evidence.
- PR state unreadable (API error, malformed payload): the gate fails closed.

`receipt-verify` takes the gate's `outcome` as `gate-outcome`. For
`PR_ALREADY_CLOSED_SKIPPED` it does not trust the claim: it re-reads the live PR
(`nexus-certify pr-state --mode verify-skip`) and passes only when the PR is
merged **and** its head equals `head-sha`. Its `verified` output stays `false`
and its `outcome` output is `PR_ALREADY_CLOSED_SKIPPED`. A closed-unmerged PR,
an open PR, a merge at another head, or an API failure fails the check.
Consumers that do not pass `gate-outcome` get the old behaviour (a skipped run
has no receipt, so the check fails closed).

A skip pass binds this **head** to a **merged PR**; it does not bind the base
ref, the base config or the Issue, and it is not completion evidence. Whatever
governed the merge itself was the gate result that existed when the PR merged.
The `verify` job needs `pull-requests: read` for the live PR read; without it the
read fails (403/404 in private repositories) and the check fails closed.

The signing identity is the workflow file on the default branch:

```text
https://github.com/<owner>/<repo>/.github/workflows/<workflow-file>.yml@refs/heads/main
```

For Nexus Core itself this is
`https://github.com/James3014/nexus-core/.github/workflows/nexus-core-issue-completion.yml@refs/heads/main`.
Because the workflow runs under `pull_request_target`, the certificate identity
is the base-branch workflow, not the PR branch.

## Early run on repository_dispatch (Issue #255)

The heavy check takes 30 to 60 minutes. A consumer may run it earlier, when an
agent reports completion, by sending a `repository_dispatch` event. The pull
request still runs its own full check; a dispatch run does not stand in for it.

**Status: opt-in for consumers; not used by Nexus Core's own gate.** Nexus
Core's `.github/workflows/nexus-core-issue-completion.yml` keeps the two-job
layout above (an `issue-gate` with no `head-sha` under a pull request event behaves
exactly as before). Consumers adopt the early run by copying
[`examples/nexus-core-issue-completion.consumer.yml`](examples/nexus-core-issue-completion.consumer.yml)
to `.github/workflows/nexus-core-issue-completion.yml` and adapting it as its header
says: replace `OWNER/REPO` in `expected-identity` and replace every `0000...0000`
placeholder with the same pinned 40-hex nexus-core commit. Then send
`repository_dispatch` events of type `nexus-core-precheck` from the agent
completion hook.

- **Dispatch mode.** `issue-gate` also runs under `repository_dispatch` (the
  example uses event type `nexus-core-precheck`, `client_payload`:
  `{"head_sha": "<40-hex>", "issue_number": <N>}`). It requires a 40-hex
  `head-sha` and a positive `issue-number` input, requires
  `github.ref == refs/heads/<default branch>`, and takes the base from the run's
  own commit (`github.sha`, the default-branch tip) and the base ref from
  `github.ref_name`. Under `pull_request`/`pull_request_target` the `head-sha`
  input must be empty or equal the PR head; any other event fails closed.
  `repository_dispatch` needs only `contents: write` to send (an agent identity
  with `actions: read` cannot use `workflow_dispatch`), and GitHub always runs
  the default-branch workflow file for it. The dispatch run's `verify` job runs
  `receipt-verify` with `base-sha = github.sha`.
  The dispatched head must be the tip of a branch of this repository
  (`git ls-remote --heads`); a commit reachable only through `refs/pull/*`, such
  as a fork pull request head, is refused
  (`NEXUS_CORE_GATE_DISPATCH_HEAD_NOT_A_BRANCH_TIP`), so dispatch never runs code
  that the fork guard keeps off the runner.
- **Required check.** `run` executes on dispatch or on a pull request. `verify`
  (the required check) passes only when `receipt-verify` succeeded with
  `verified == 'true'`, or (pull requests only) `receipt-verify` succeeded with
  outcome `PR_ALREADY_CLOSED_SKIPPED` (#250: the live PR was merged at this head
  before the gate ran; neutral, not evidence). A dispatch run never passes on a
  skip: it has no pull request, so the skip check fails closed.

## Consumer workflow

Copy [`examples/github-repository-check.yml`](examples/github-repository-check.yml)
to `.github/workflows/`, set `expected-identity` to your own workflow file on
`refs/heads/main`, and pin both actions and `nexus-certify-ref` to the same full
40-hex nexus-core commit sha:

```yaml
jobs:
  run:
    name: Nexus Core issue run
    permissions:
      contents: read
      issues: read
      pull-requests: read
      id-token: write
    outputs:
      artifact-name: ${{ steps.gate.outputs.artifact-name }}
      artifact-id: ${{ steps.gate.outputs.artifact-id }}
      issue-number: ${{ steps.gate.outputs.issue-number }}
      outcome: ${{ steps.gate.outputs.outcome }}
    steps:
      - id: gate
        uses: James3014/nexus-core/.github/actions/issue-gate@<40-hex-sha>
        with:
          nexus-certify-ref: "<40-hex-sha>"
  verify:
    name: Nexus Core issue completion
    needs: run
    if: always()
    permissions:
      contents: read
      actions: read
      pull-requests: read  # PR_ALREADY_CLOSED_SKIPPED re-reads the live PR
    steps:
      - uses: James3014/nexus-core/.github/actions/receipt-verify@<40-hex-sha>
        with:
          artifact-name: ${{ needs.run.outputs.artifact-name }}
          artifact-id: ${{ needs.run.outputs.artifact-id }}
          expected-identity: https://github.com/<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/main
          github-repository: ${{ github.repository }}
          head-sha: ${{ github.event.pull_request.head.sha }}
          base-sha: ${{ github.event.pull_request.base.sha }}
          issue-number: ${{ needs.run.outputs.issue-number }}
          gate-outcome: ${{ needs.run.outputs.outcome }}
          nexus-certify-ref: "<40-hex-sha>"
```

(The example file also carries the `pull_request_target` trigger, the source
`if:` on `run` and the fail-closed guard step in `verify`; both are required.) The PR body must contain exactly one
`<!-- NEXUS_CORE_ISSUE: <number> -->` marker, or you pass `issue-number`
explicitly. Otherwise the gate fails closed. Other inputs: `python-version`
(default `3.11`), `candidate-path` (default `candidate`), and for
`receipt-verify`, `sigstore-version` (default: the pinned release). Nexus Core's
own repository uses `nexus-certify-source: path` to install the tool from the
trusted base checkout instead of a pinned ref.

## What runs where

1. **Runner, trusted stage.** The action validates inputs, resolves the Issue
   number, installs `uv`, and installs `nexus-certify` from the pinned ref into a
   runner-private tool directory (`$RUNNER_TEMP`). No candidate code exists on disk
   yet.
2. **Runner, candidate fetch.** The candidate head is checked out into
   `./candidate` (full history, no persisted credentials) and the base is pinned to
   `pull_request.base.sha`. Core takes the single merge-base of that tip and head as
   the source revision (the PR diff); head with no single merge-base is reported as
   `BASE_REF_NOT_ANCESTOR`. Config trust stays on the base tip.
3. **Core.** `issue-init` and `issue-check --require-trusted-config` run with
   `GITHUB_TOKEN` available only to read the Issue. The configuration is read from
   the base ref; an untracked or base-missing config fails with `CONFIG_UNTRUSTED`.
4. **Verifier, isolated.** The verifier command (including any `uv sync`,
   `uv build`, or tests) runs in a detached clone with an allowlisted environment,
   inside the container configured by `[isolation]`. The runner never runs
   candidate `uv sync`, `uv build`, `pip install`, or scripts.
5. **Signing and artifacts.** The newest receipt is signed (even on failure) and
   `candidate/.nexus-core/receipts/` is uploaded with the bundle; a failing run
   prints a diagnostic of the latest receipt.
6. **Verify job.** A separate job with no candidate code checks the signature
   and the receipt expectations (see above).

## Runner support

GitHub-hosted runners are supported when container isolation is configured in the
committed config:

```toml
[isolation]
mode = "container"
image = "ghcr.io/astral-sh/uv:python3.11-bookworm@sha256:<digest>"
network = "bridge"
```

The image must be pinned by digest and only the sandbox parent directory is mounted
(at `/sandbox`). If `docker` is missing, the run fails closed with
`ISOLATION_UNAVAILABLE`; the image is pulled before the verifier timeout starts and a
pull failure is `ISOLATION_IMAGE_UNAVAILABLE`. See [`LOCAL_GOLDEN_PATH.md`](LOCAL_GOLDEN_PATH.md)
for the isolation modes and trusted config source.

## Candidate acquisition

The `run` job acquires the candidate with plain Git (`git init`, a token-on-the-command-line fetch of the exact head and base shas, `git checkout --detach`), not with `actions/checkout`. Nothing is written to `.git/config`, submodules and gitlinks are never initialised (repositories that carry gitlink entries without `.gitmodules` URLs need no extra step), and the base ref is force-updated to the event's base sha so a moved base does not reject a non-fast-forward.

## Why fork pull requests are excluded

`pull_request_target` runs with the base repository's token and permissions. The
job guard (`head.repo.full_name == github.repository`) skips fork PRs, because
verifying untrusted fork code is a different
trust problem that this gate does not claim to solve. Do not add a
`head.repo.fork == false` clause: when the repository is itself a GitHub fork that
clause is true for every branch, the jobs are skipped, and a skipped required check
counts as passing. Also keep the repository's
fork-PR workflow approval set to require approval for external contributors.
Same-repository branches, the normal agent path, are covered by the container
isolation and the trusted config source.

In consumer workflows the required `verify` job must not be skipped either: a
skipped required check counts as success, so a job-level `if:` on the source
would let fork or cross-repository PRs through. `verify` therefore keeps only
`if: always()` and its first step fails closed with
`NEXUS_CORE_UNTRUSTED_PR_SOURCE` (head repository differs from
`github.repository`) or `NEXUS_CORE_ISSUER_NOT_SUCCESSFUL` (`needs.run.result`
is not `success`). Only the `run` job keeps the source `if:` (skipping it is
safe because `verify` then fails). See
`docs/examples/nexus-core-issue-completion.consumer.yml`.

## Trusted-input evolution

The workflow file comes from the base ref by `pull_request_target` semantics, and
the config comes from the base ref by Core construction. A PR that changes the
gate, the action pin, or `.nexus-core/config.toml` is verified under generation N
and takes effect as generation N+1 after an ordinary reviewed merge. There is no
byte-compare "protect inputs" step and no manual ruleset bypass.

Keep the `verify` job name `Nexus Core issue completion` stable if it is a
required status check.

## Verify a receipt yourself

Anyone can check a CI receipt without trusting the runner. Download the
`nexus-core-receipts-<head-sha>-run<run-id>-attempt<run-attempt>` artifact of the producing attempt (it holds `<receipt>.json` and
`<receipt>.json.sigstore.json`), then:

```bash
uvx --from "sigstore==4.5.0" sigstore verify github \
  --cert-identity "https://github.com/James3014/nexus-core/.github/workflows/nexus-core-issue-completion.yml@refs/heads/main" \
  --repository James3014/nexus-core \
  --bundle <receipt>.json.sigstore.json \
  <receipt>.json

TREE=$(git rev-parse '<head-sha>^{tree}')
nexus-certify receipt-check --receipt <receipt>.json \
  --expect-status VERIFIED \
  --expect-subject-head <head-sha> \
  --expect-target-tree "$TREE" \
  --expect-config-commit <base-sha> \
  --expect-issue <N> \
  --expect-github-repository James3014/nexus-core \
  --require-clean-subject \
  --require-trusted-config
```

### Receipt summary (display only)

`nexus-certify receipt-summary --receipt <receipt>.json [--format markdown|notice]
[--receipt-sha256 <hex>]` prints a one-screen coverage summary: status, reason
codes, claim ceiling, Issue, evidence universe, one row per coverage entry,
changed/deleted/protected paths and any owner-signature advisory. `notice` emits a
single `::notice title=Nexus Core receipt::...` workflow command (escaped so a
receipt value cannot start another command). Both the issue-gate and
receipt-verify actions run it in a `continue-on-error` step (markdown to the job
summary, notice as a check-run annotation), including when the run is red. It
exits 0 for any readable JSON and 2 otherwise, never reads or changes
enforcement, and is not evidence: Core remains an evidence notary.

Flipping one byte of the receipt makes `sigstore verify` fail. A mismatch in
`receipt-check` exits 2 with `STATUS_MISMATCH`, `SUBJECT_HEAD_MISMATCH`,
`TARGET_TREE_MISMATCH`, `CONFIG_SOURCE_MISMATCH`, `ISSUE_BINDING_MISMATCH`,
`SUBJECT_NOT_CLEAN` or `CONFIG_UNTRUSTED`. The signature proves which workflow
identity produced the bytes (and logs it in the public Rekor transparency log);
it does not prove the verifier command is sufficient or that the Issue is
semantically complete.

## Legacy request-file mode

The older request-file mode remains available for existing consumers:

```bash
python -m product.clients.github_action \
  --request-file request.json \
  --token-file /protected/path/token \
  --service-url http://127.0.0.1:8767
```

That mode retains its self-hosted-runner requirement, loopback service URL
requirement, protected token read, and canonical HTTP behavior. The two modes are
mutually exclusive.
