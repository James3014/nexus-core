# GitHub Repository Gate

Nexus Core provides a reusable composite action, `.github/actions/issue-gate`,
that gates a pull request on an Issue-bound `nexus-certify issue-check`. It runs
the verifier configured in the base ref's `.nexus-core/config.toml`, derives facts
from the physical checked-out Git repository, and writes the same durable local
verification receipt, which is uploaded as a workflow artifact.

A successful result is `VERIFIED (not CERTIFIED)`: the base-ref verification
contract passed inside the configured isolation against this exact tree. It is not
approval, Candidate acceptance, merge authority, release authority, semantic proof
that the Issue is complete, or a production claim.

## Consumer workflow

Copy [`examples/github-repository-check.yml`](examples/github-repository-check.yml)
to `.github/workflows/` and pin both the action and `nexus-certify-ref` to a full
40-hex nexus-core commit sha:

```yaml
on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited]
permissions:
  contents: read
  issues: read
  pull-requests: read
jobs:
  nexus-core-issue-completion:
    name: Nexus Core issue completion
    if: >-
      github.event.pull_request.head.repo.full_name == github.repository &&
      github.event.pull_request.head.repo.fork == false
    runs-on: ubuntu-latest
    steps:
      - uses: James3014/nexus-core/.github/actions/issue-gate@<40-hex-sha>
        with:
          nexus-certify-ref: "<40-hex-sha>"
```

The PR body must contain exactly one `<!-- NEXUS_CORE_ISSUE: <number> -->` marker,
or you pass `issue-number` explicitly. Otherwise the gate fails closed. Other
inputs: `python-version` (default `3.11`) and `candidate-path` (default
`candidate`). Nexus Core's own repository uses `nexus-certify-source: path` to
install the tool from the trusted base checkout instead of a pinned ref.

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
5. **Artifacts.** `candidate/.nexus-core/receipts/` is uploaded even on failure,
   and a failing run prints a diagnostic of the latest receipt.

## Runner support

GitHub-hosted runners are supported when container isolation is configured in the
committed config:

```toml
[isolation]
mode = "container"
image = "ghcr.io/astral-sh/uv:python3.11-bookworm@sha256:<digest>"
network = "bridge"
```

The image must be pinned by digest. If `docker` is missing, the run fails closed
with `ISOLATION_UNAVAILABLE`. See [`LOCAL_GOLDEN_PATH.md`](LOCAL_GOLDEN_PATH.md)
for the isolation modes and trusted config source.

## Why fork pull requests are excluded

`pull_request_target` runs with the base repository's token and permissions. The
job guard (`head.repo.full_name == github.repository` and `head.repo.fork ==
false`) skips fork PRs, because verifying untrusted fork code is a different
trust problem that this gate does not claim to solve. Also keep the repository's
fork-PR workflow approval set to require approval for external contributors.
Same-repository branches, the normal agent path, are covered by the container
isolation and the trusted config source.

## Trusted-input evolution

The workflow file comes from the base ref by `pull_request_target` semantics, and
the config comes from the base ref by Core construction. A PR that changes the
gate, the action pin, or `.nexus-core/config.toml` is verified under generation N
and takes effect as generation N+1 after an ordinary reviewed merge. There is no
byte-compare "protect inputs" step and no manual ruleset bypass.

Keep the job name `Nexus Core issue completion` stable if it is a required status
check.

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
