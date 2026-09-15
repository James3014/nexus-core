# Nexus Core

Nexus Core is the standalone Evidence-to-Claim Completion Certification implementation extracted from Nexus-new.

Its truth authorities are Evidence Trust Core and Completion Core.

## Scope

- **Evidence Trust Core**: Ingestion, normalization, verification, and tamper detection of execution evidence.
- **Completion Core**: ChangeSet certification, deterministic verification reduction, and disposition enforcement.

It provides the standalone `nexus-certify` CLI and HTTP/deterministic runtime interfaces.

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
