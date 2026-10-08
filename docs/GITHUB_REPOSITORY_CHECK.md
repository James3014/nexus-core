# GitHub Repository Gate

## Checklist for a new repository

1. Run `nexus-certify init`, add a version 2 `[isolation]` section with a digest-pinned container `image`, and merge `.nexus-core/config.toml` into the base branch.
2. Run `nexus-certify markers` and paste the `NEXUS_CORE_EVIDENCE_UNIVERSE` line into the Issue body.
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

## Two jobs: run and verify

The gate is two jobs, so that the required status check never rests on a bare
exit code:

- **`run`** (`Nexus Core issue run`) runs `issue-gate`. After `issue-check` it
  signs the newest receipt, success or failure, with Sigstore keyless signing
  (`sigstore sign`, OIDC workflow identity) and uploads the receipt and its
  `<receipt>.sigstore.json` bundle as one artifact. This job must grant
  `id-token: write`. Outputs: `artifact-name`, `issue-number`, and the action
  outputs `receipt-file`, `bundle-file`, `receipt-sha256`.
- **`verify`** (`Nexus Core issue completion`, `needs: run`, `if: always()`) is
  the required check. It runs `receipt-verify` with only `contents: read` and
  `actions: read`: it downloads the artifact, requires exactly one receipt and
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

The signing identity is the workflow file on the default branch:

```text
https://github.com/<owner>/<repo>/.github/workflows/<workflow-file>.yml@refs/heads/main
```

For Nexus Core itself this is
`https://github.com/James3014/nexus-core/.github/workflows/nexus-core-issue-completion.yml@refs/heads/main`.
Because the workflow runs under `pull_request_target`, the certificate identity
is the base-branch workflow, not the PR branch.

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
      issue-number: ${{ steps.gate.outputs.issue-number }}
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
    steps:
      - uses: James3014/nexus-core/.github/actions/receipt-verify@<40-hex-sha>
        with:
          artifact-name: ${{ needs.run.outputs.artifact-name }}
          expected-identity: https://github.com/<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/main
          github-repository: ${{ github.repository }}
          head-sha: ${{ github.event.pull_request.head.sha }}
          base-sha: ${{ github.event.pull_request.base.sha }}
          issue-number: ${{ needs.run.outputs.issue-number }}
          nexus-certify-ref: "<40-hex-sha>"
```

(The example file also carries the `pull_request_target` trigger and the fork
guard on both jobs; both are required.) The PR body must contain exactly one
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
   `pull_request.base.sha`. A base that is not an ancestor of head is reported by
   Core as `BASE_REF_NOT_ANCESTOR`.
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
`nexus-core-receipts-<head-sha>` artifact (it holds `<receipt>.json` and
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
