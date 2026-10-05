# Nexus Core Agent Guidelines

nexus-core owns exactly:

1. Evidence Trust Core
2. Completion Core

It may also contain carrying layers required for the standalone
Completion Certification product:
- protocol
- acquisition
- deterministic runner interfaces
- local runtime
- clients
- ledger
- adapters
- benchmark instrumentation

Those carrying layers are NOT additional truth authorities.

nexus-core does NOT own:
- general Agent execution
- Open SWE internals
- model routing
- Workforce admission
- Learning adaptation
- automatic remediation
- merge/release authority

Ordinary bounded engineering does not require Task Cards.

Escalate only on:
- public protocol change
- security boundary change
- persistent schema / migration
- authority semantic change
- cross-repo breaking contract
- irreversible external side effect
- release
- production/public claim


## Nexus Core issue-bound completion evidence

- This repository is enrolled in the standalone `nexus-certify` Golden Path through `.nexus-core/config.toml`.
- For mutation work tracked by a repository-local GitHub Issue, run `nexus-certify issue-init --issue <N>` before relying on Issue-bound completion evidence, and run `nexus-certify issue-check --issue <N>` before claiming engineering completion.
- This binding is Evidence Trust + Completion only. It does not select the execution lane, route, worker/model, Candidate acceptance, merge, release, deployment, or production authority.
- DIRECT work remains transport-neutral. A Core mutation session is not required solely because repository files are being changed.
