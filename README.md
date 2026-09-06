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

Do not install `nexus-core` and `nexus-legacy` into the same Python environment until the legacy product namespace / console script is removed from `Nexus-new`.

`nexus-core` packages the standalone `product` namespace and exposes the `nexus-certify` console script. Developing or testing `nexus-core` requires an isolated virtual environment to prevent shadowing or collision with legacy `product` artifacts.
