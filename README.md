# Nexus Core

**Language:** [English](https://github.com/James3014/nexus-core/blob/main/README.md) | [繁體中文](https://github.com/James3014/nexus-core/blob/main/README.zh-TW.md)

[![PyPI version](https://img.shields.io/pypi/v/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![Python versions](https://img.shields.io/pypi/pyversions/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![CI](https://github.com/James3014/nexus-core/actions/workflows/ci.yml/badge.svg)](https://github.com/James3014/nexus-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/James3014/nexus-core/blob/main/LICENSE)

**An agent's change counts as done only when the acceptance checks you declared in advance pass against the exact tree, and the receipt can be verified by anyone.**

The tool is a Python package named **`nexus-certify`**. It works in an ordinary Git repository. The local commands need no account, no API key and no network service.

## Contents

- [Install](#install)
- [Start in 5 minutes (local)](#start-in-5-minutes-local)
- [Govern an agent's pull request](#govern-an-agents-pull-request)
- [Config reference](#config-reference)
- [Receipts](#receipts)
- [What VERIFIED means](#what-verified-means)
- [Security model](#security-model)
- [Development](#development)
- [License](#license)

## Install

You need Python 3.11 or newer and Git. A virtual environment is recommended.

```bash
python -m venv .venv
source .venv/bin/activate    # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install nexus-certify
nexus-certify --help
```

The Golden Path commands (`init`, `doctor`, `check`, `receipt-check`, `issue-init`, `issue-check`, `markers`) need no third-party packages. The HTTP service, MCP and legacy request commands need the optional extra: `pip install 'nexus-certify[runtime]'`.

PyPI: https://pypi.org/project/nexus-certify/

PyPI has `0.1.3`. The `main` branch contains the newer trusted-config, isolation and signed-receipt features described below. A release will follow. Until then, install from a pinned commit if you need them:

```bash
python -m pip install "git+https://github.com/James3014/nexus-core.git@c293dc944fe99652ae8856d732a35b5191f52a5e"
```

## Start in 5 minutes (local)

Run these in the Git repository you want to check. Make your change on a branch first. `check` compares your work against the base branch, and it reports a failure when nothing changed.

```bash
nexus-certify init \
  --base-ref main \
  --allow 'src/**' \
  --allow 'tests/**' \
  --verifier python -m pytest -q

nexus-certify doctor
nexus-certify check
```

- `init` writes `.nexus-core/config.toml`. Change the `--allow` patterns to fit your repository. `--verifier` must be the last option on the line.
- `doctor` only reads. It tells you if something is missing.
- `check` runs your verifier on a clean copy of the exact tree and writes a receipt under `.nexus-core/receipts/`.

A good run prints:

```text
verification: VERIFIED (not CERTIFIED)
config: untrusted (not committed on main)
receipt: .nexus-core/receipts/...
```

`config: untrusted` is expected until you commit `.nexus-core/config.toml` on the base branch. The next section explains why that matters.

`check` fails, and does not print `VERIFIED`, when for example:

- the config is missing or invalid;
- the base ref cannot be found;
- there is no change relative to the base;
- a changed path is outside your `--allow` patterns;
- a file was deleted and deletions are forbidden (the default);
- the verifier is missing, times out or exits non-zero;
- the files change while the verifier runs.

Your verifier is real code. It runs with your permissions, started directly without a shell. Only configure commands you trust.

## Govern an agent's pull request

This is the main use: a pull request from an agent (or a person) cannot merge until a check proves the change passes the acceptance checks that were fixed before the work started.

### 1. Commit the config on main

Merge `.nexus-core/config.toml` into your base branch first. In CI the config is read from the base branch, never from the pull request. An agent cannot loosen the checks by editing the config in its own branch.

### 2. Open an Issue with a marker

The Issue is the contract for the work. It must contain one line that names the exact config:

```bash
nexus-certify markers
```

```text
Issue body: <!-- NEXUS_CORE_EVIDENCE_UNIVERSE: sha256:<config hash> -->
```

Paste that marker line into the Issue body. The command is read-only. It prints a warning on stderr if the config is not yet committed on the base branch, because the hash changes once it is.

If the work advances a pinned `[[materials]]` identity (for example a dependency commit), also authorize that change in the Issue:

```bash
nexus-certify markers --material-transition nexus-runtime=git-commit:<new sha>
```

```text
Issue body: <!-- NEXUS_CORE_MATERIAL_TRANSITION: nexus-runtime git-commit:<old sha> -> git-commit:<new sha> -->
```

`<old sha>` is read from the committed config. The pull request must then change `.nexus-core/config.toml` by exactly those `expected_identity` values and nothing else. See [Issue-authorized material transitions](docs/MULTI_EVIDENCE_GOLDEN_PATH.md#issue-authorized-material-transitions).

### 3. Open the pull request with a marker

The pull request body must contain exactly one marker that names the Issue:

```bash
nexus-certify markers --issue 42
```

```text
Issue body: <!-- NEXUS_CORE_EVIDENCE_UNIVERSE: sha256:<config hash> -->
PR body:    <!-- NEXUS_CORE_ISSUE: 42 -->
```

Paste the `PR body` line into the pull request description. Add `--json` for machine-readable output with the keys `config_hash`, `config_source`, `issue_marker` and `pr_marker`.

You can also try the Issue binding locally:

```bash
nexus-certify issue-init --issue 42
nexus-certify issue-check --issue 42 --require-trusted-config
```

`issue-init` freezes the open Issue text. If the Issue has no evidence marker, it prints a hint that points back to `nexus-certify markers`. `issue-check` re-reads the Issue and fails if the text has changed since you bound it.

### 4. Add the two-job workflow

Copy [`docs/examples/github-repository-check.yml`](docs/examples/github-repository-check.yml) to `.github/workflows/`. Replace `OWNER/REPO` in `expected-identity` with your repository and keep the workflow file name in sync. The example pins both actions to this commit:

```text
c293dc944fe99652ae8856d732a35b5191f52a5e
```

Always pin to a full 40-character commit, never a tag or branch.

The workflow has two jobs:

- **`run`** uses `James3014/nexus-core/.github/actions/issue-gate@<sha>`. It installs the pinned tool, then runs the verifier from the base-branch config inside a container. Then it signs the receipt with Sigstore keyless signing and uploads it. It needs `id-token: write`.
- **`verify`** uses `James3014/nexus-core/.github/actions/receipt-verify@<sha>`. It has no write access and sees no pull request code. It checks the signature, then checks that the receipt matches this exact head, this base config and this Issue.

The workflow must run on `pull_request_target`, and it skips pull requests from forks. Full details: [`docs/GITHUB_REPOSITORY_CHECK.md`](docs/GITHUB_REPOSITORY_CHECK.md).

Your config needs container isolation for GitHub-hosted runners. See [Config reference](#config-reference).

### 5. Require the check

In your branch protection or ruleset, require the status check named **`Nexus Core issue completion`** (the `verify` job). It means:

> A receipt signed by this repository's main-branch workflow identity describes exactly this head, this base config, this Issue, and says VERIFIED.

A change to the workflow, the action pin or the config is checked under the old rules. It takes effect only after an ordinary reviewed merge.

## Config reference

`nexus-certify init` writes a version 1 config. It is enough for local use:

```toml
version = 1
base_ref = "main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
verifier_command = ["python", "-m", "pytest", "-q"]
timeout_seconds = 300
```

| Field | Meaning |
| --- | --- |
| `base_ref` | The branch your change is compared with. The trusted config is read from here. |
| `allowed_patterns` | Paths a change may touch. Anything else fails the check. |
| `deletion_policy` | `FORBID` (default) or `ALLOW`. |
| `verifier_command` | The command to run, as a list. It is not passed through a shell. Exit code 0 means pass. |
| `timeout_seconds` | The verifier is killed after this time. |

### Version 2: several named checks

Version 2 lets you require several separate pieces of evidence, set the environment and run in a container. You write it by hand:

```toml
version = 2
base_ref = "main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
universe_generation = 1
materials = []
env_passthrough = ["MY_TEST_FLAG"]

[[verifiers]]
id = "tests"
command = ["uv", "run", "pytest", "-q"]
timeout_seconds = 300
logical_subject_id = "app/tests"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"

[isolation]
mode = "container"
image = "ghcr.io/astral-sh/uv:python3.11-bookworm@sha256:<64 hex digits>"
network = "bridge"
```

- **`[[verifiers]]`**: each entry is one required check with its own id and result. A missing or failed required check means no `VERIFIED`.
- **`materials`**: optional commands that record the exact identity of an outside dependency, such as a resolved revision. See [`docs/MULTI_EVIDENCE_GOLDEN_PATH.md`](docs/MULTI_EVIDENCE_GOLDEN_PATH.md).
- **`universe_generation`**: a number you raise when you change the list of required checks.
- **`env_passthrough`**: names of environment variables the verifier may see. By default it sees only `PATH`, `LANG`/`LC_ALL`, `PYTHONDONTWRITEBYTECODE`, `PYTEST_ADDOPTS` and a private `HOME` and `TMPDIR`. Tokens and cloud credentials are hidden unless you list them. Only the names, never the values, go into the receipt.
- **`[isolation]`**:
  - `mode`: `process` (default) or `container`. Use `container` for agents you do not fully trust. It needs `docker`. If `docker` is missing, the run fails with `ISOLATION_UNAVAILABLE`.
  - `image`: must be pinned by digest (`@sha256:...`). Only the sandbox directory is mounted into the container.
  - `network`: `bridge` (default) or `none`.

### Trusted config source

`check` and `issue-check` read the worktree config only to learn `base_ref`. They then use the config committed on that base ref. The output tells you which one was used:

```text
config: trusted (main@<commit>)
config: untrusted (not committed on main)
```

To refuse the untrusted case, add `--require-trusted-config` (or set `NEXUS_CERTIFY_REQUIRE_TRUSTED_CONFIG=1`). The run then fails with `CONFIG_UNTRUSTED`.

```bash
nexus-certify check --require-trusted-config
```

More: [`docs/LOCAL_GOLDEN_PATH.md`](docs/LOCAL_GOLDEN_PATH.md) ([繁體中文](docs/LOCAL_GOLDEN_PATH.zh-TW.md)).

## Receipts

Every run writes a JSON receipt under `.nexus-core/receipts/`. It records the tool version, the base and head commits, the file manifest, the config and where it came from, each verifier command with its exit code and output, the result, and a hash over all of it. Revalidating a receipt detects edits.

Fields that tie a receipt to one exact subject:

| Field | Meaning |
| --- | --- |
| `subject_head` | The commit that was checked (`git-commit:<sha>`). |
| `subject_head_tree` | That commit's tree (`git-tree:<sha>`). |
| `subject_clean` | True when the checked tree equals the commit's tree, so nothing uncommitted was included. |
| `config_source` | Where the config came from: `base-ref` with the commit and blob, or `worktree`. |

Check a receipt without running the verifier again:

```bash
nexus-certify receipt-check --receipt .nexus-core/receipts/<receipt>.json
```

Add expectations to make it strict. A mismatch exits with code 2 and names the reason:

| Flag | Reason code on mismatch |
| --- | --- |
| `--expect-status VERIFIED` | `STATUS_MISMATCH` |
| `--expect-subject-head <40-hex>` | `SUBJECT_HEAD_MISMATCH` |
| `--expect-target-tree <40-hex>` | `TARGET_TREE_MISMATCH` |
| `--expect-config-commit <40-hex>` | `CONFIG_SOURCE_MISMATCH` |
| `--expect-issue <N>` | `ISSUE_BINDING_MISMATCH` |
| `--expect-github-repository owner/name` | `ISSUE_BINDING_MISMATCH` |
| `--require-clean-subject` | `SUBJECT_NOT_CLEAN` |
| `--require-trusted-config` | `CONFIG_UNTRUSTED` |

A receipt on disk can be replaced by anyone with file access. Receipts made in CI are signed with Sigstore keyless signing (`sigstore==4.5.0`) by the workflow identity:

```text
https://github.com/OWNER/REPO/.github/workflows/<file>.yml@refs/heads/main
```

To verify one by hand, download the `nexus-core-receipts-<head-sha>` artifact from the workflow run. It holds `<receipt>.json` and `<receipt>.json.sigstore.json`. Then:

```bash
uvx --from "sigstore==4.5.0" sigstore verify github \
  --cert-identity "https://github.com/OWNER/REPO/.github/workflows/<file>.yml@refs/heads/main" \
  --repository OWNER/REPO \
  --bundle <receipt>.json.sigstore.json \
  <receipt>.json

TREE=$(git rev-parse '<head-sha>^{tree}')
nexus-certify receipt-check --receipt <receipt>.json \
  --expect-status VERIFIED \
  --expect-subject-head <head-sha> \
  --expect-target-tree "$TREE" \
  --expect-config-commit <base-sha> \
  --expect-issue <N> \
  --expect-github-repository OWNER/REPO \
  --require-clean-subject \
  --require-trusted-config
```

Changing a single byte of the receipt makes `sigstore verify` fail. The signature is also logged in the public Rekor transparency log.

## What VERIFIED means

`VERIFIED` means: the checks declared in the base-branch config passed, inside the configured isolation, against this exact tree. The output always says `(not CERTIFIED)` on purpose.

It does not mean:

- the Issue is truly finished (a green test suite proves only what the tests check);
- the code is correct, secure or free of vulnerabilities;
- the change is approved, merged, released or deployed;
- the verifier ran in a perfect sandbox;
- the dependencies are safe.

You still review the change and decide to merge. `VERIFIED` is evidence for that decision, not the decision.

## Security model

- The verifier is executable code. In `process` mode it has your user's permissions and is not an OS sandbox. Use `container` mode for agents you do not trust.
- The verifier runs in a detached clone with no remote, so it cannot reach back into your repository through Git.
- In CI the config comes from the base branch, the tool is installed before any pull request code is on the runner, and the runner never installs or builds pull request code outside the container.
- Fork pull requests are not covered by the gate.
- Local commands upload nothing.

Threat model, trust boundaries and how to report a vulnerability: [`SECURITY.md`](SECURITY.md).

## Development

```bash
uv sync
uv run pytest -q tests/product
uv run ruff check product tests
uv run pyright product
uv run nexus-certify --help
```

Other documents:

- [`docs/GITHUB_REPOSITORY_CHECK.md`](docs/GITHUB_REPOSITORY_CHECK.md): the pull request gate in full, with a six-step checklist for a new repository.
- [`docs/RUNTIME_HANDOFF.md`](docs/RUNTIME_HANDOFF.md): checking that code runs in a live runtime (`handoff-init`, `handoff-check`, `handoff-status`).
- [`docs/COEXISTENCE.md`](docs/COEXISTENCE.md): using this package next to `nexus-legacy`.

## License

Apache License 2.0. See the [LICENSE](https://github.com/James3014/nexus-core/blob/main/LICENSE). Both the wheel and the source distribution include the full license file.
