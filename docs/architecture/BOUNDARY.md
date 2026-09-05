# Nexus Core Architecture Boundary

## Canonical Truth Authorities
1. **Evidence Trust Core**: Handles evidence verification, hashing, normalization, and condition reduction.
2. **Completion Core**: Handles ChangeSet certification, policy application, and disposition.

## Non-authorities / Carrying Layers
- Acquisition (GitHub / file-based)
- Local runtime and execution runners
- Ledger storage
- Conformance & benchmark gates

## Prohibition
This repository must never import or depend on:
- `nexus.*`
- `scripts.*`
- `runtimes.*`
