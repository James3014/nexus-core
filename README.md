# nexus-certify

[![PyPI version](https://img.shields.io/pypi/v/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![Python versions](https://img.shields.io/pypi/pyversions/nexus-certify.svg)](https://pypi.org/project/nexus-certify/)
[![CI](https://github.com/James3014/nexus-core/actions/workflows/ci.yml/badge.svg)](https://github.com/James3014/nexus-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/James3014/nexus-core/blob/main/LICENSE)

**`nexus-certify` verifies whether a code change is backed by real, current evidence before you trust a “done” claim from a human or AI agent.**

The standalone package is **`nexus-certify`**. For the local Golden Path, it works inside an ordinary Git repository and does **not** require Nexus-new, DevSpace, another Nexus service, a model provider, or an API token.

### Naming and affiliation

`nexus-certify` is the public Python distribution. **Nexus Core** is this project's repository and architecture name. This is an independent project and is not affiliated with or endorsed by Sonatype, Inc., Sonatype Nexus Repository, or other software projects that use the name “Nexus Core”.

## Why use it

AI coding agents and humans can both say that a change is complete. `nexus-certify` checks the physical repository state instead of trusting that statement.

For a local repository, `nexus-certify check`:

1. reads the real Git source and current worktree state;
2. enforces the paths and deletion policy you configured;
3. runs your real verifier command, such as `python -m pytest -q`;
4. binds the verifier evidence to the exact Git state that was checked;
5. asks the canonical Core verifier for the factual result; and
6. writes a durable receipt that can be re-checked later.

A successful local result is:

```text
VERIFIED (not CERTIFIED)
```

That wording is intentional. `VERIFIED` does **not** mean approved, merged, released, deployed, production-ready, or `CERTIFIED`.

## Install

### Requirements

- Python **3.11+**
- Git
- the verifier you want Nexus Core to run (for example, `pytest`)

Using a virtual environment is recommended.

```bash
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install nexus-certify
nexus-certify --help
```

For a reproducible install of the currently published release:

```bash
python -m pip install nexus-certify==0.1.1
```

If you use the pytest example below, make sure pytest is installed in the same environment:

```bash
python -m pip install pytest
```

PyPI: https://pypi.org/project/nexus-certify/

## 2-minute quick start

Run these commands from the Git repository you want to verify:

```bash
nexus-certify init \
  --base-ref main \
  --allow 'src/**' \
  --allow 'tests/**' \
  --verifier python -m pytest -q

nexus-certify doctor
nexus-certify check
```

Adjust the `--allow` patterns for your repository. The `--verifier` option and its arguments must be the final `init` option.

Typical healthy output looks like:

```text
doctor: OK
verification: VERIFIED (not CERTIFIED)
receipt: .nexus-core/receipts/...
```

### What gets written to your repository

- `nexus-certify init` creates `.nexus-core/config.toml`.
- `nexus-certify doctor` is read-only.
- `nexus-certify check` writes a verification receipt under `.nexus-core/receipts/`.

`nexus-certify` materializes the target Git state with an isolated temporary index. Its acquisition path does not commit, checkout, stage into your normal index, merge, or rewrite your source files.

Your configured verifier is still real executable code and runs with the permissions of your shell. `nexus-certify` invokes the configured argv directly rather than through a shell, but you should only configure verifier commands you trust.

## Security and privacy

For the local Golden Path (`init`, `doctor`, `check`):

- no Nexus account, API key, bearer token, or remote Nexus service is required;
- the local verification path does not upload your repository contents or verification receipt to a Nexus service;
- `doctor` is read-only;
- Git acquisition uses an isolated temporary index rather than staging into your normal index;
- `check` writes only its receipt directory in addition to whatever your configured verifier itself may write.

The verifier command is deliberately under your control. It executes locally with your user permissions, so review verifier commands before running them, just as you would review any test or build command.

`nexus-certify` is open source under Apache-2.0. The package dependencies are declared in [`pyproject.toml`](https://github.com/James3014/nexus-core/blob/main/pyproject.toml), and CI builds the wheel/sdist and performs a clean-environment wheel-install smoke test.

### Optional install verification

After installation:

```bash
python -m pip show nexus-certify
python -m pip check
nexus-certify --help
```

These commands let you confirm the installed package identity, dependency consistency, and CLI entry point before using it on a repository.

## What nexus-certify checks

The local path fails closed rather than returning `VERIFIED` when it encounters conditions such as:

- a missing or invalid configuration;
- a base ref that cannot be resolved or is not an ancestor of the current HEAD;
- a changed path outside the configured allow-list;
- a deletion when deletions are forbidden;
- a verifier that is unavailable, times out, or exits non-zero;
- the target state changing while verification is running;
- malformed, stale, mismatched, or tampered verification inputs or receipts.

The receipt binds the installed Nexus Core version, Git source/target identity, manifest, verifier evidence, canonical request, Core response, and integrity hashes.

See the [Local Golden Path Contract](https://github.com/James3014/nexus-core/blob/main/docs/LOCAL_GOLDEN_PATH.md) for the exact behavior and negative controls.

## Why you can evaluate it independently

`nexus-certify` is designed so that trust does not depend on the author of the code change saying “it passed”.

- **Physical Git binding** — verification is tied to real Git commits/trees and a deterministic manifest.
- **Real verifier evidence** — the configured verifier actually runs.
- **Freshness checks** — evidence that no longer applies to the final content is rejected.
- **Tamper detection** — receipts and canonical inputs are hash-bound and re-checkable.
- **Fail-closed behavior** — missing or contradictory evidence does not become a green result.
- **Authority separation** — verification does not silently become approval, merge, release, or deployment authority.

The initial public `nexus-certify==0.1.0` artifact was installed from PyPI in a fresh environment and exercised against an ordinary external repository, including fail-closed negative cases. Version `0.1.1` is a packaging, licensing, and documentation synchronization release; runtime verification semantics are unchanged. The acceptance record is preserved in [Issue #36](https://github.com/James3014/nexus-core/issues/36).

## Current maturity

- **Public package:** `nexus-certify`
- **Version in this source:** `0.1.1`
- **Local Golden Path:** published-artifact external-repository canary passed
- **License:** Apache-2.0
- **Python:** 3.11+
- **Generic HTTP ChangeSet interface:** experimental
- **Public protocol Stable:** not claimed

The local Golden Path is the simplest supported entry point for external users. The HTTP/protocol surfaces below are for advanced integrations and remain experimental unless stated otherwise.

## Architecture scope

Nexus Core owns two truth authorities:

- **Evidence Trust Core** — ingestion, normalization, verification, freshness, and tamper detection of execution evidence.
- **Completion Core** — ChangeSet certification, deterministic verification reduction, evidence applicability, and disposition enforcement.

Carrying layers such as acquisition, runtime, clients, ledger, adapters, and benchmark instrumentation do not become additional truth authorities.

Nexus Core does not own agent execution, model routing, Workforce admission, merge approval, release approval, deployment, or production authority.

## Generic ChangeSet Verification (experimental)

The loopback HTTP runtime exposes a transport-neutral, non-GitHub verification seam for bounded consumers such as DevSpace or Open SWE:

- `GET /v1/protocol/generic-verification` — authenticated protocol descriptor, JSON schemas, canonicalization rules, schema-bundle hash, and cross-language conformance vectors.
- `POST /v1/changesets/verify` — deterministic `AcceptanceContract + ChangeSet + VerificationPlan + EvidenceBundle` verification. Certification is optional and occurs only when the caller supplies explicit policy facts.

Generic revision identities are typed as `git-commit:<40-lowercase-hex>` or `git-tree:<40-lowercase-hex>`. An uncommitted managed change may therefore be verified against a deterministic Git tree without creating a commit first. The generic `diff_hash` binds a canonical source-tree-to-target-tree manifest instead of pretty-patch formatting.

`verification=VERIFIED` does not imply `CERTIFIED`, Candidate acceptance, merge authorization, release, deployment, or production readiness. This interface does not select execution lanes, workers, models, routes, or workspaces.

## Completion Evidence Applicability and Freshness Contract

`product.completion` binds a completion claim to the exact source/artifact state it claims, then decides whether verification evidence actually applies to that final state. It is deterministic, model-independent, and advisory: the completion claim's `asserted_by` identity never confers authority, and certification remains with `product.kernel.certify`.

It derives three explicit semantic states:

- `CLAIMS_COMPLETE` — a completion claim is revision-bound to the change set's `target_revision` and covers every changed non-deleted path with a claimed final content hash.
- `VERIFICATION_APPLIES` — every required verifier has an evidence observation bound to a changed path, observes the claimed final content hash, and reports `PASS`.
- `CLAIMS_VERIFIED` — the conjunction of the two states above with the existing deterministic `verify()` reduction.

Per-verifier `EvidenceDisposition` values (`ACCEPTED`, `REJECTED_STALE`, `REJECTED_IRRELEVANT`, `REJECTED_MISSING`, `REJECTED_CONTRADICTORY`, `REJECTED_FAILED`) explain which evidence was accepted or rejected.

```python
from product.completion import analyze_completion_evidence, validate_completion_evidence_analysis

analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
assert analysis.claims_verified
assert validate_completion_evidence_analysis(analysis, claim, contract, change_set, plan, evidence)
```

Freshness is derived from content-hash comparison rather than wall-clock timestamps. See `tests/product/test_completion_evidence_applicability.py` for the `modify -> test PASS -> modify again` and irrelevant-verification regressions.

## GitHub repository integration

For trusted same-repository GitHub `push` and `pull_request` events on self-hosted runners, see the [GitHub Repository Golden Path](https://github.com/James3014/nexus-core/blob/main/docs/GITHUB_REPOSITORY_CHECK.md).

Fork PRs and GitHub-hosted runners are explicitly unsupported by that path.

## Development

```bash
uv sync
uv run pytest -q tests/product
uv run pytest -q tests/benchmark
uv run ruff check product tests
uv run pyright product
uv run nexus-certify --help
```

## Compatibility and coexistence

`nexus-core` and the current `nexus-legacy` package in `Nexus-new` have distinct package and console-script ownership:

- Nexus Core is distributed as `nexus-certify` while continuing to own the internal `product` Python package and `nexus-certify` console script.
- `nexus-legacy` owns the `nexus` and `scripts` packages and the `nexus` console script.

Use separate virtual environments for normal development and testing because the repositories have different dependency sets and operational roles.

## License

Nexus Core, including the `nexus-certify` distribution, is licensed under the Apache License, Version 2.0. See the [Apache-2.0 LICENSE](https://github.com/James3014/nexus-core/blob/main/LICENSE).

The published `0.1.0` package metadata declared Apache-2.0. Starting with `0.1.1`, CI requires the full `LICENSE` and `THIRD_PARTY_NOTICES.md` files to be physically present in both wheel and source-distribution artifacts.
