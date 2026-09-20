# Local Golden Path Contract (G0/G1)

This is the frozen external-user contract for an ordinary Python Git repository.
The user installs only the Nexus Core distribution, `nexus-certify`. Nexus-new, DevSpace, nexus-runtime,
nexus-learning, nexus-open-swe-runtime, model routing, and any particular human or
agent author are not part of this flow.

The product shell acquires physical Git facts and verifier output, then constructs
the existing canonical `AcceptanceContract`, `ChangeSet`, `VerificationPlan`, and
`EvidenceBundle`. The existing generic verification adapter is the only factual
verification authority. The shell does not create another verifier, policy,
receipt, execution, routing, merge, or certification authority.

## Exact first-use journey

The distribution identity is `nexus-certify`. Until an authorized G3 public
release exists, install from the candidate source or a locally built wheel in a
development environment. After publication, the supported registry install command
is `python -m pip install nexus-certify`. This source integration does not claim
that the public artifact has been released. From the external repository, the
otherwise-frozen first-use product journey is:

```bash
nexus-certify init \
  --base-ref main \
  --allow 'src/**' \
  --allow 'tests/**' \
  --verifier python -m pytest -q
nexus-certify doctor
nexus-certify check
```

Commit `.nexus-core/config.toml` if the repository wants a shared policy. Ignore
`.nexus-core/receipts/` if local verification records should not be committed.
`init` refuses to replace an existing config; `--force` is the explicit override.
Because verifier arguments may begin with `-`, `--verifier` and its argv must be
the final `init` option.

`doctor` is read-only. It diagnoses Git repository access, config validity, base-ref
resolution and ancestry of current `HEAD`, Python/verifier availability, repository
cleanliness, and whether Git can discover changes. It never materializes a tree or
runs the verifier.

`check` needs no local HTTP service, bearer token, or ledger. It:

1. resolves the configured base to a commit, requires it to be an ancestor of
   current `HEAD`, and resolves its tree;
2. uses an isolated temporary Git index to materialize the current physical
   worktree state, including committed, staged, unstaged, and untracked changes,
   without changing the caller's HEAD, normal index, or worktree;
3. derives the source-tree-to-target-tree manifest from real Git objects;
4. projects allowed path globs to the exact changed paths placed in the canonical
   `AcceptanceContract`;
5. executes the configured argv directly (never through a shell), captures its
   exit code and output hashes, and binds the artifact hash into the canonical
   `EvidenceBundle`;
6. invokes the existing generic Core adapter and writes a local verification
   receipt under `.nexus-core/receipts/`.

The human verdict always says `VERIFIED (not CERTIFIED)` or
`FAILED_VERIFICATION (not CERTIFIED)`. A local verification receipt is a durable,
recomputable record of inputs and Core response. It is not a Completion
Certification receipt, Candidate acceptance, merge approval, release approval, or
production claim.

## Minimal deterministic config

```toml
version = 1
base_ref = "main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
verifier_command = ["python", "-m", "pytest", "-q"]
timeout_seconds = 300
```

There is intentionally no executor, worker, model, route, approval, merge, or
certification identity. The config hash binds this normalized config. Path patterns
are product-shell acquisition policy only; on an admitted run they are projected
to the exact changed paths supplied to the existing canonical contract.

## Fail-closed negative controls

`check` produces no `VERIFIED` result for any of these conditions:

- not a Git repository, missing/invalid config, an unresolved base ref, or a base
  commit outside current `HEAD` ancestry;
- no change relative to the base;
- a changed path outside every allowed pattern;
- a deletion while `deletion_policy = "FORBID"`;
- unavailable verifier, launch failure, timeout, or non-zero verifier exit;
- target state changing while the verifier runs;
- malformed, cross-bound, stale, mismatched, or tampered canonical input;
- any canonical Core result other than `VERIFIED`.

A normal verifier's result contract is deliberately small: process launch must
succeed, completion must occur before the timeout, and exit code zero means `PASS`.
Stdout/stderr are evidence bytes, not a second result protocol to parse. Non-zero
exit is canonical `FAILED_VERIFICATION`, not a transport error.

## Durable receipt contract

The repository-local receipt contains the installed product version and receipt
schema version; UTC timestamp; exact source commit/tree and target tree; normalized
config and config hash; physical manifest and manifest hash; verifier argv,
exit code, captured output and hashes, and artifact hash; the complete canonical
request; and the complete Core response. Its envelope hash covers all fields except
the envelope hash itself.

The preserved request can be independently passed back through the generic adapter.
Receipt validation recomputes the config, manifest, verifier artifact, envelope,
and Core response, and can compare the preserved manifest with the referenced Git
objects still present in the repository.

## G4 fresh-environment canary contract (not executed in G0/G1)

G4 may claim the fresh-environment canary only when all of these are observed in a
new temporary environment with no Nexus sibling repositories or pre-existing Nexus
service state:

1. create an ordinary Python Git repository with a base commit and a feature
   change;
2. create a new virtual environment and install only the candidate
   `nexus-certify` wheel plus the external repository's declared verifier
   dependencies;
3. assert imports and executable paths resolve from that environment, not a source
   checkout or sibling repository;
4. run `init`, `doctor`, and `check` exactly as documented;
5. observe a real verifier execute and a canonical `VERIFIED`, non-certified Core
   response;
6. reread the persisted receipt in a fresh process and recompute all preserved
   hashes, the Core response, and physical Git manifest;
7. run negative canaries for forbidden path, forbidden deletion, verifier failure,
   and tampered receipt, each failing closed with the documented typed reason;
8. confirm HEAD, the normal index, and pre-existing worktree bytes are unchanged by
   acquisition and receipt validation.

This section freezes the future canary acceptance contract; it does not claim G4
has run or passed.
