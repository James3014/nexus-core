# Runtime and manual handoff levels

Moved from the README. Content unchanged.

## The Three Governance Levels

Nexus Core separates code verification from runtime manual handoff readiness:

1. **Level 1: `VERIFIED`** — The repository code changes pass automated verification against a clean tree.
2. **Level 2: `HANDOFF_READY`** — The exact code (`target_commit` / `target_tree`) is verified running in a live runtime whose endpoints and process identities are bound, and handoff verifier succeeded.
3. **Level 3: `RELEASE / DEPLOY`** — Human owner and production pipeline authority (never automated by Core).

`VERIFIED` never automatically promotes to `HANDOFF_READY`, and `HANDOFF_READY` never implies production release or deployment.

The CLI commands for Level 2 are `nexus-certify handoff-init`, `handoff-check` and `handoff-status`. See [`LOCAL_GOLDEN_PATH.md`](LOCAL_GOLDEN_PATH.md) for the full hierarchy.
