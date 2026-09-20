# Nexus Core

Nexus Core is the standalone Evidence-to-Claim Completion Certification implementation extracted from Nexus-new.

Its truth authorities are Evidence Trust Core and Completion Core.

## Scope

- **Evidence Trust Core**: Ingestion, normalization, verification, and tamper detection of execution evidence.
- **Completion Core**: ChangeSet certification, deterministic verification reduction, and disposition enforcement.

It provides the standalone `nexus-certify` CLI and HTTP/deterministic runtime interfaces.

## Local Golden Path

An external Python Git repository can verify a committed or dirty change without
running the HTTP service or hand-authoring protocol JSON:

The public distribution identity is `nexus-certify`. Until the release gate
publishes a versioned artifact, install the candidate source or locally built wheel
in a development environment. After an authorized public release, the supported
registry install command is `python -m pip install nexus-certify`.

```bash
nexus-certify init --base-ref main --allow 'src/**' --allow 'tests/**' \
  --verifier python -m pytest -q
nexus-certify doctor
nexus-certify check
```

The local shell derives real Git object identities and the canonical manifest,
runs the configured verifier, delegates the verdict to the existing generic Core
adapter, and persists a verification receipt under `.nexus-core/receipts/`.
`VERIFIED` remains distinct from `CERTIFIED`; the local receipt is not a
Certification receipt or merge/release authority.

See [Local Golden Path Contract](docs/LOCAL_GOLDEN_PATH.md) for the exact config,
negative controls, receipt validation contract, and the not-yet-executed G4
fresh-environment canary contract.

For trusted same-repository GitHub `push` and `pull_request` events on self-hosted
runners, see the [G2 GitHub Repository Golden Path](docs/GITHUB_REPOSITORY_CHECK.md).
Fork PRs and GitHub-hosted runners are explicitly unsupported by that path.

## Generic ChangeSet Verification (experimental)

The loopback HTTP runtime also exposes a transport-neutral, non-GitHub verification seam for bounded consumers such as DevSpace or Open SWE:

- `GET /v1/protocol/generic-verification` — authenticated protocol descriptor, JSON schemas, canonicalization rules, schema-bundle hash, and cross-language conformance vectors.
- `POST /v1/changesets/verify` — deterministic `AcceptanceContract + ChangeSet + VerificationPlan + EvidenceBundle` verification. Certification is optional and occurs only when the caller supplies explicit policy facts.

Generic revision identities are typed as `git-commit:<40-lowercase-hex>` or `git-tree:<40-lowercase-hex>`. An uncommitted managed change may therefore be verified against a deterministic Git tree without creating a commit first. The generic `diff_hash` binds a canonical source-tree-to-target-tree manifest instead of pretty-patch formatting.

`verification=VERIFIED` does not imply `CERTIFIED`, Candidate acceptance, merge authorization, release, deployment, or production readiness. This interface does not select execution lanes, workers, models, routes, or workspaces.

## Completion Evidence Applicability and Freshness Contract

`product.completion` is an additive Completion Core capability that binds a
completion claim to the exact source/artifact state it claims, then decides
whether verification evidence actually applies to that final state. It is
deterministic, model-independent, and advisory: the completion claim's
`asserted_by` identity never confers authority, and certification remains with
`product.kernel.certify`.

It derives three explicit semantic states:

- `CLAIMS_COMPLETE` — a completion claim is present, revision-bound to the
  change set's `target_revision`, and covers every changed non-deleted path
  with a claimed final content hash.
- `VERIFICATION_APPLIES` — every required verifier has an evidence observation
  that is bound to a changed path, observes the claimed final content hash
  (freshness by content-hash comparison), and reports `PASS`.
- `CLAIMS_VERIFIED` — the conjunction of the two states above with the existing
  deterministic `verify()` reduction. A claim assertion can never substitute
  for a physical observation.

Per-verifier `EvidenceDisposition` values (`ACCEPTED`, `REJECTED_STALE`,
`REJECTED_IRRELEVANT`, `REJECTED_MISSING`, `REJECTED_CONTRADICTORY`,
`REJECTED_FAILED`) let Completion Core explain exactly which evidence was
accepted, rejected, stale, missing, or contradictory. Original API:

```python
from product.completion import analyze_completion_evidence, validate_completion_evidence_analysis

analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
assert analysis.claims_verified         # all three states
assert validate_completion_evidence_analysis(analysis, claim, contract, change_set, plan, evidence)
```

Freshness and execution ordering are derived from content hash comparison
rather than wall-clock timestamps: an observation whose artifact content hash
differs from the claimed final content hash predates a later mutation and is
stale unless the hashes are equal (equivalence proven by the trusted hash
machinery). See `tests/product/test_completion_evidence_applicability.py` for
the `modify -> test PASS -> modify again` and irrelevant-verification
regressions.

## Development

```bash
uv sync
uv run pytest -q tests/product
uv run pytest -q tests/benchmark
uv run ruff check product tests
uv run nexus-certify --help
```

## Compatibility and Coexistence Boundary

`nexus-core` and the current `nexus-legacy` package in `Nexus-new` have distinct package and console-script ownership:

- Nexus Core is distributed as `nexus-certify` while continuing to own the
  internal `product` Python package and `nexus-certify` console script.
- `nexus-legacy` owns the `nexus` and `scripts` packages and the `nexus` console script.

The current package definitions therefore no longer have the historical `product` namespace / `nexus-certify` console-script collision described by the previous README.

Use separate virtual environments for normal development and testing because the repositories have different dependency sets and operational roles. That isolation is development hygiene, not a requirement caused by the retired namespace/script collision.
