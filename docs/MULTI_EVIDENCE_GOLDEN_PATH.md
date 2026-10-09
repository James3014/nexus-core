# Multi-Evidence Golden Path Contract

Issue: #104

This document freezes the repository-facing contract for Local / Issue-bound Golden Path config version 2. It extends the product shell over the existing Core `AcceptanceContract`, `VerificationPlan`, `EvidenceBundle`, `ExpectedEvidenceSubject`, and coverage reducer. It does not create another verifier, Completion reducer, CI orchestrator, or semantic-correctness authority.

## Compatibility

Config version 1 remains the default produced by `nexus-certify init` and preserves the existing single `verifier_command` behavior and receipt schema 1.

Config version 2 is an explicit trusted-policy opt-in. It uses receipt schema 2 and declares a versioned evidence universe.

## Named required evidence

Example:

```toml
version = 2
base_ref = "main"
allowed_patterns = ["src/**", "tests/**"]
deletion_policy = "FORBID"
universe_generation = 3
materials = []

[[verifiers]]
id = "targeted-negative-control"
command = ["python", "-m", "pytest", "-q", "tests/test_retry.py::test_budget_unavailable"]
timeout_seconds = 300
logical_subject_id = "retry/budget-unavailable"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"

[[verifiers]]
id = "full-suite"
command = ["python", "-m", "pytest", "-q", "tests"]
timeout_seconds = 1800
logical_subject_id = "runtime/full-installed-suite"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
```

Each applicable producer executes against the same exact target tree and emits a separately attributable artifact and canonical observation. Required producer IDs are projected into the existing `VerificationPlan`. All declared logical subjects are projected into the existing `AcceptanceContract.expected_subjects`.

Missing required evidence, failed evidence, and unresolved coverage therefore reduce through the existing canonical Core semantics.

## Exact external material identity

A cross-repository or external dependency can be declared as a material evidence producer:

```toml
[[materials]]
id = "learning-revision"
observe_command = ["python", "-c", "import nexus_learning; print(nexus_learning.__revision__)"]
timeout_seconds = 30
logical_subject_id = "dependency/nexus-learning"
evidence_kind = "resolved-dependency"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
expected_identity = "git-commit:0123456789abcdef0123456789abcdef01234567"

[[verifiers]]
id = "full-suite"
command = ["python", "-m", "pytest", "-q", "tests"]
timeout_seconds = 1800
logical_subject_id = "runtime/full-installed-suite"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
required_material_ids = ["learning-revision"]
```

The observe command must physically read the resolved identity from the verification environment. Core never copies the expected value into the observed value.

A material observation is PASS only when:

1. the observe command exits zero; and
2. normalized stdout exactly equals `expected_identity`.

A verifier that declares `required_material_ids` is not executed unless those material observations are PASS. The receipt binds this declared material-to-verifier relationship as `evidence_links`.

This proves that the trusted verifier contract required the exact observed material identity before that verifier was admitted to run. It does not prove semantic runtime use of the dependency inside every code path; that remains outside the Core claim ceiling.

Core does not become a dependency resolver or package manager. The consumer chooses how to acquire the dependency and how to read back its exact identity; Core binds and reduces the resulting evidence.

## Issue-authorized material transitions

Under `--require-trusted-config` a material is compared with the `expected_identity` committed on the base ref, so a pull request that advances a pinned dependency would otherwise observe a new identity and fail. The Issue contract can pre-authorize that change with one marker per material (at most one per material id), written exactly as:

```text
<!-- NEXUS_CORE_MATERIAL_TRANSITION: <material_id> <from_identity> -> <to_identity> -->
```

Generate it with `nexus-certify markers --material-transition <material_id>=<to_identity>` (repeatable); `<from_identity>` is read from the trusted config. The marker is frozen with the rest of the Issue contract by `issue-init`, and `issue-check` applies it:

- `<from_identity>` must equal the trusted `expected_identity` (`MATERIAL_TRANSITION_STALE` otherwise); an unknown id is `MATERIAL_TRANSITION_UNKNOWN_MATERIAL`; a malformed or duplicate marker is `ISSUE_MATERIAL_TRANSITION_MALFORMED`. Transitions need a committed base-ref config (`MATERIAL_TRANSITION_REQUIRES_TRUSTED_CONFIG`).
- The effective expectation for that material becomes `<to_identity>`; it passes only if the observed identity equals it. Artifacts record `expected_identity` (effective), `trusted_expected_identity` and `transition`.
- Exact-delta rule: the pull request's working-tree `config.toml` must equal the trusted config with exactly those `expected_identity` values replaced. Any other difference fails closed with `CONFIG_DRIFT_BEYOND_AUTHORIZED_TRANSITION`, so merging the pull request leaves the base-ref config consistent with the new pins.
- All of these checks run before any verifier and leave a receipt. The receipt records `inputs.material_transitions` and `issue_verification.material_transitions`; `receipt-check` recomputes producers with the transitions applied and rejects a receipt that applies a transition without an Issue binding (`MATERIAL_TRANSITION_UNBOUND`).

Without the marker, a pin bump fails exactly as before. The evidence-universe marker is unchanged and still hashes the trusted base-ref config.

## Applicability

Version 2 reuses the existing evidence coverage model:

- `REQUIRED + APPLICABLE`: evidence must be observed and PASS.
- `CONDITIONALLY_REQUIRED + APPLICABLE`: the logical subject remains part of the evidence universe and must be covered.
- `CONDITIONALLY_REQUIRED + NOT_APPLICABLE`: recorded as conditionally not applicable.
- `CONDITIONALLY_REQUIRED + UNRESOLVED`: result remains `UNVERIFIABLE`.
- `NOT_APPLICABLE`: must use `NOT_APPLICABLE` applicability.

Core does not infer applicability from Issue prose, filenames, test names, or model judgment.

## Issue-bound semantics

Issue binding and evidence coverage are separate identities.

`issue-init` / `issue-check` continue to bind the exact current Issue contract into the `AcceptanceContract.requirements_hash`. Config version 2 separately binds the machine-readable evidence universe and its `universe_generation`.

Therefore:

```text
Issue contract freshness
        !=
evidence-universe coverage
        !=
verifier semantic adequacy
```

A current Issue hash does not by itself prove that every acceptance requirement has a witness. The repository-owned trusted config must declare the evidence obligations Core is expected to enforce.

## Trusted verifier-contract evolution

A repository may protect `.nexus-core/config.toml` and the Core workflow as trusted inputs. That protection must not be disabled merely because a feature Candidate needs stronger evidence.

The supported governance shape is:

```text
trusted config generation N
        |
        | separately reviewed trusted-input change
        v
trusted config generation N+1 on base branch
        |
        | feature Candidate rebases onto accepted base
        v
check / issue-check under generation N+1
```

The Candidate being evaluated must not silently weaken or replace its own verification contract.

The version-2 config hash, `universe_generation`, projected expected subjects, required producer IDs, evidence links, and produced artifacts are bound into the receipt. The consumer repository remains responsible for authorizing the trusted-input transition. Nexus Core does not acquire merge, approval, route, Learning, release, or deployment authority.

## Claim boundary

Complete declared evidence coverage proves only that the trusted machine-readable evidence contract was satisfied for the bound physical subject.

It does not prove:

- verifier semantic adequacy;
- semantic runtime use of every declared material inside every code path;
- program correctness;
- security correctness;
- Candidate acceptance;
- merge or release approval;
- deployment or production readiness.
