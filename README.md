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

Until G3 proves a public, versioned distribution, install the candidate source in
a development environment (for example, `python -m pip install /path/to/nexus-core`).
The target G3 public install command is `python -m pip install nexus-core`; this
G0/G1 implementation does not claim that public path is available yet.

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

## Generic ChangeSet Verification (experimental)

The loopback HTTP runtime also exposes a transport-neutral, non-GitHub verification seam for bounded consumers such as DevSpace or Open SWE:

- `GET /v1/protocol/generic-verification` — authenticated protocol descriptor, JSON schemas, canonicalization rules, schema-bundle hash, and cross-language conformance vectors.
- `POST /v1/changesets/verify` — deterministic `AcceptanceContract + ChangeSet + VerificationPlan + EvidenceBundle` verification. Certification is optional and occurs only when the caller supplies explicit policy facts.

Generic revision identities are typed as `git-commit:<40-lowercase-hex>` or `git-tree:<40-lowercase-hex>`. An uncommitted managed change may therefore be verified against a deterministic Git tree without creating a commit first. The generic `diff_hash` binds a canonical source-tree-to-target-tree manifest instead of pretty-patch formatting.

`verification=VERIFIED` does not imply `CERTIFIED`, Candidate acceptance, merge authorization, release, deployment, or production readiness. This interface does not select execution lanes, workers, models, routes, or workspaces.

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

- `nexus-core` owns the `product` package and `nexus-certify` console script.
- `nexus-legacy` owns the `nexus` and `scripts` packages and the `nexus` console script.

The current package definitions therefore no longer have the historical `product` namespace / `nexus-certify` console-script collision described by the previous README.

Use separate virtual environments for normal development and testing because the repositories have different dependency sets and operational roles. That isolation is development hygiene, not a requirement caused by the retired namespace/script collision.
