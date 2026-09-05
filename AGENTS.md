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
