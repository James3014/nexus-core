# Nexus Core

Nexus Core is the standalone Evidence-to-Claim Completion Certification implementation extracted from Nexus-new.

Its truth authorities are Evidence Trust Core and Completion Core.

## Scope

- **Evidence Trust Core**: Ingestion, normalization, verification, and tamper detection of execution evidence.
- **Completion Core**: ChangeSet certification, deterministic verification reduction, and disposition enforcement.

It provides the standalone `nexus-certify` CLI and HTTP/deterministic runtime interfaces.

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

Do not install `nexus-core` and `nexus-legacy` into the same Python environment until the legacy product namespace / console script is removed from `Nexus-new`.

`nexus-core` packages the standalone `product` namespace and exposes the `nexus-certify` console script. Developing or testing `nexus-core` requires an isolated virtual environment to prevent shadowing or collision with legacy `product` artifacts.
