# Nexus Certify Security Policy

## Overview

Nexus Certify provides deterministic verification, Git-bound evidence handling, and tamper-evident receipts. Its security claims are deliberately narrower than software correctness, sandboxing, release approval, or production safety.

Because Nexus Certify can execute caller-configured verifier commands, it crosses several trust and execution boundaries. This document states those boundaries and the reporting policy for security defects.

---

## Threat Model & Trust Boundaries

| Surface / Component | Trust Level | Execution Boundary | Security Invariants |
| :--- | :--- | :--- | :--- |
| **Local Repository & Working Tree** | Untrusted / Caller-Supplied | Local filesystem + Git plumbing | Local acquisition does not change `HEAD`, the normal Git index, or working-tree files. It uses a temporary Git index; Git plumbing may write Git objects while materializing the target tree. The worktree `.nexus-core/config.toml` is not authoritative (see Governance config source). |
| **Git Binary & Metadata** | Trusted Host Dependency | Subprocess execution | Nexus relies on the host `git` executable and uses Git object IDs as content-addressed identities. Git object IDs are not treated as a universal proof of collision-free or trustworthy content. |
| **Configured Verifier Command** | **Executable Code** | **Detached clone; optional container** | Deliberately executed as specified by the base-ref configuration, in a detached clone with no remote and no alternates, inside a process group that is killed on timeout. In `process` mode it still runs with the caller's OS user permissions and is NOT an OS sandbox; use `container` mode for adversarial agents. |
| **Verifier environment** | Allowlisted | Verifier process / container | Only `PATH`, `LANG`/`LC_ALL`, `PYTHONDONTWRITEBYTECODE`, `PYTEST_ADDOPTS`, and sandbox-private `HOME`/`TMPDIR` are passed. `GITHUB_TOKEN`, `GH_TOKEN` and cloud credentials are not visible unless named in `env_passthrough`; the names (never values) are recorded in the receipt. |
| **Verifier sandbox** | Detached Clone | `isolated_detached_clone` | The sandbox is cloned with `--no-hardlinks`, the `origin` remote is removed and `objects/info/alternates` must be absent, so the verifier cannot reach back into the original repository through Git. The verifier runs in its own session/process group and the whole group is killed on timeout. Container mode (`[isolation] mode = "container"`, digest-pinned image, only the sandbox parent directory mounted at `/sandbox`) is the recommended setting for adversarial agents; it requires `docker` and fails closed with `ISOLATION_UNAVAILABLE`. The image is pulled before the verifier timeout starts; a pull failure is `ISOLATION_IMAGE_UNAVAILABLE`. A nonce round-trip through the mount proves the sandbox is visible inside the container (`ISOLATION_MOUNT_UNAVAILABLE` otherwise), and the image is pulled before the verifier timeout (`ISOLATION_IMAGE_UNAVAILABLE` on failure). The sandbox root is `NEXUS_CERTIFY_SANDBOX_ROOT` or, on macOS, `~/.cache/nexus-certify/sandbox`. |
| **Ignored residue** | Sandbox-Only Policy | `residue_policy = "sandbox-only"` | Ignored files in the original repository (`.venv`, `__pycache__`, caches) do not block `check`: the verifier only sees the detached clone built from repository objects. Verifier mutation of tracked/non-ignored bytes inside the sandbox and any change to the original target tree during the run still fail closed. `doctor` reports the ignored-path count as informational only. |
| **Governance config source** | Base-Ref Authoritative | `git show <base_ref>:.nexus-core/config.toml` | The config committed on the base ref is the effective config; a differing `base_ref` fails with `CONFIG_BASE_REF_MISMATCH`. `base_ref` must name an existing branch, remote-tracking ref or tag; a revision expression such as `HEAD~1` or a commit SHA, which a candidate commit can point at its own history, never yields `base-ref` trust. A named ref is only advisory locally, because any process with write access to the repository can create a ref; an unpinned base ref is reported as `config: base-ref, unpinned`. For enforcement pass `--expect-config-commit <40-hex>` (on `check`, `issue-check` and `receipt-check`; CI pins `BASE_SHA`) with a commit obtained outside the candidate's control; any other config source fails closed with `CONFIG_SOURCE_MISMATCH`. A worktree-only config is reported as `config: untrusted` and `--require-trusted-config` (or `NEXUS_CERTIFY_REQUIRE_TRUSTED_CONFIG=1`) fails closed with `CONFIG_UNTRUSTED`. The receipt records `config_source` and `config_drift`. |
| **Python Runtime & Package Dependencies** | Environment-Resolved Dependencies | Python interpreter | Published dependencies are version-constrained, not cryptographically pinned for every end-user install. Repository development/test resolution is locked by `uv.lock`; GitHub Actions dependencies are separately pinned to immutable identities. |
| **Local Receipt Files** | Caller-Writable Evidence Files | `.nexus-core/receipts/` | Each receipt is self-hashed and can be recomputed/validated. Local receipt files are not append-only, are not hash-chained to prior receipts, and can be deleted or replaced by a principal with filesystem access. Local receipts are unsigned and advisory; the CI receipt (next row) is the authority. |
| **CI receipts** | Sigstore-Signed Workflow Evidence | `issue-gate` (sign), `receipt-verify` (verify), Sigstore/Rekor | The `run` job signs the newest receipt, including failure receipts, with Sigstore keyless signing: a short-lived certificate bound to the workflow's OIDC identity (`https://github.com/<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/main`), with a public Rekor transparency-log entry. The `verify` job (the required check) runs `sigstore verify github --cert-identity ... --repository ...` and `nexus-certify receipt-check` with `--expect-status/--expect-subject-head/--expect-target-tree/--expect-config-commit/--expect-issue/--expect-github-repository/--require-clean-subject/--require-trusted-config`. This proves the receipt bytes were produced by that workflow identity and describe the exact PR head, head tree, base config and Issue. It does not prove the verifier is sufficient, the Issue is semantically complete, the receipt is the only one produced, or that the Rekor entry is private. Anyone can re-verify an artifact offline with the commands in `docs/GITHUB_REPOSITORY_CHECK.md`. Nexus Verify (`verify_code_change_evidence`, `evidence-check`) applies the same signature check before trusting a receipt (#231). |
| **GitHub Acquisition Adapter** | Untrusted Remote Snapshot | Controller-injected read port | `product.acquisition.github` contains no network client or credential parameter. It validates the supplied snapshot schema, identities, hashes, paths, pagination completion, and convergence across two reads; authentication/network transport are owned outside this module. |
| **Loopback HTTP Runtime** | Local Service | `127.0.0.1` | Local bearer token authentication; does not expose external network interfaces by default. |
| **GitHub Actions / CI Surface** | Ephemeral Runner | CI Runner Environment | Actions dependencies pinned to immutable commit SHAs; advisory-only claim ceilings for external intelligence. |
| **PR gate** | Trusted Base + Untrusted Candidate | `pull_request_target`, composite action `issue-gate` | Same-repository branches only (fork guard). The workflow and action come from the base ref; the pinned tool is installed into a runner-private directory before any candidate code exists, and the runner never runs candidate `uv sync`/`uv build`/scripts. In `issue-gate` the token reaches only the plain-Git candidate fetch (as `FETCH_TOKEN`, passed to that one `git fetch` through an environment-scoped `http.extraheader` and never written to `.git/config`) the live PR-state preflight (as `GITHUB_TOKEN`, to read the pull request), and the `issue-init`/`issue-check` steps (as `GITHUB_TOKEN`, to read the Issue); the verifier's allowlisted environment does not receive it. In `receipt-verify` it is used only to resolve the receipt artifact, fetch the head tree and, for a declared `PR_ALREADY_CLOSED_SKIPPED`, re-read the live PR (the skip passes only for a PR merged at this exact head and is never `VERIFIED`). In `receipt-reuse` it is used only to list prior runs and their artifacts, fetch commits into a bare repository (`FETCH_TOKEN` via the same env-scoped `http.extraheader`), read the Issue state and download the artifact by id. Dispatch mode and reuse (#255) are opt-in for consumers through `docs/examples/nexus-core-issue-completion.consumer.yml`; Nexus Core's own gate workflow does not use them yet. Dispatch mode: `issue-gate` also runs under `repository_dispatch` on the default branch only (`github.ref` must be `refs/heads/<default>`), with an explicit 40-hex head that must be the tip of a branch of this repository and an Issue number, and the default-branch tip (`github.sha`) as the trusted base; any other event fails closed. Reuse: a pull request that targets the default branch may pass on a receipt from such a run only when `receipt-reuse` proves its producing commit R is an ancestor of the PR base, `.nexus-core/config.toml`, the workflow file and any listed paths are identical at R and at the base, the Sigstore identity/trigger/commit match, `receipt-check` passes every expectation with config commit R, and the Issue is open and unchanged since the producing run was created (`updated_at` <= run `created_at`, else `REUSE_ISSUE_CHANGED_AFTER_PRECHECK`); otherwise the full run decides. This widens #249 (config commit must be the current base tip) to an older tip with byte-identical trust files. Receipts are uploaded as a workflow artifact. Changes to the gate or config are verified under the old generation and take effect after an ordinary reviewed merge. |

---

## Intended Execution Behavior

### The Verifier is Real Executable Code
- Verifier commands configured in `.nexus-core/config.toml` or another supported verifier configuration surface are **intentionally executed**.
- Verifier processes run locally with the **exact permissions of the invoking user or service account**.
- In the local Golden Path, Nexus invokes the configured argv directly rather than through an intermediate shell. This reduces shell-expansion exposure but **does not** make an untrusted verifier safe.
- Users must review and audit verifier command definitions just as they would any arbitrary build or test script. Running untrusted verifier configurations against untrusted repositories is unsafe.
- A `VERIFIED` result means the base-ref verification contract passed inside the configured isolation against this exact tree; it does not prove semantic completion of the Issue.
- Expected command execution according to user configuration is an intended feature and is not considered a vulnerability.

---

## Security Claim Boundaries: What `VERIFIED` Means

`VERIFIED` is a factual result inside the exact evidence and policy contract that was evaluated. It does **not** mean the software is generally correct or secure.

### What a valid `VERIFIED` result establishes within the applicable path
1. **Bound subject identity**: the verification request/evidence is bound to the exact ChangeSet/Git identities represented by that path.
2. **Evidence integrity checks**: Nexus recomputes the hashes and cross-bindings that its protocol requires and fails closed on modeled mismatch/tamper conditions.
3. **Verifier outcome binding**: the recorded verifier outcome is bound to the verifier artifact/evidence supplied to the canonical verification path.
4. **Deterministic reduction**: the canonical verifier reduces the admitted evidence and explicit policy facts deterministically.

The local Golden Path additionally checks that the materialized target Git tree has not changed while the configured verifier runs.

A receipt's SHA-256 field makes that receipt **tamper-evident when revalidated**. It is not an authenticated signature, an append-only log, or proof that a filesystem principal could not replace both a receipt and other local files.

### What `VERIFIED` Does NOT Guarantee:
- **No Vulnerability-Free Guarantee**: `VERIFIED` does not mean the code is secure, free of vulnerabilities, or resistant to exploit.
- **No Oracle Adequacy**: A green test suite only proves what the test suite checks. It does not prove the test suite is adequate, exhaustive, or bug-free.
- **No Dependency Trust**: It does not prove third-party upstream dependencies are safe or uncompromised.
- **No Execution Containment**: It does not prove the verifier or repository was sandboxed or unable to perform side effects outside Nexus's observed evidence. Detached-clone and container isolation reduce, but do not eliminate, this exposure (kernel or container-runtime escapes, and network access under `bridge`, are out of scope).
- **No Deployment or Release Authority**: A receipt is evidence; it does not authorize git merge, branch promotion, release, or production deployment.
- **No Execution Safety**: It does not guarantee that the repository code is safe to execute or install.
- **Repository `VERIFIED` Is Not Issue `VERIFIED`**: `outcome.status` reflects the repository check only. For Issue-bound receipts the Issue-level verdict lives in `issue_verification`; since Issue #134 `receipt-check --expect-issue` and `--expect-status VERIFIED` require it to be `VERIFIED`, so an unbound or stale evidence universe can no longer pass the gate. Receipts without `issue_verification` never satisfy `--expect-issue`.
- **Nexus Verify Trusts Only Sigstore-Authenticated Receipts**: since #231, `verify_code_change_evidence` (and `nexus-certify evidence-check`) report `APPLIES`/`VERIFIED` only when the receipt arrives with its CI Sigstore bundle. That bundle must verify for the exact receipt bytes, with issuer GitHub Actions, the subject repository's `nexus-core-issue-completion.yml@refs/heads/main` identity (a host may configure another workflow file of the same repository; a tool caller cannot) and the same workflow repository. A receipt that is only self-consistent (unkeyed SHA-256), for example one edited and re-hashed to name the current base, is `UNVERIFIABLE` with `RECEIPT_NOT_AUTHENTICATED`. When the optional `sigstore` package (`pip install 'sigstore>=4.5,<5'`; not a core dependency) or its trust root is unavailable, the result is `UNVERIFIABLE` with `RECEIPT_AUTHENTICATION_UNAVAILABLE`, never `VERIFIED`. Authentication proves which workflow identity produced the bytes; it is only as strong as control over that workflow on the default branch, and it does not prove the verifier is sufficient.
- **Runtime Receipt Verification Is Not Provenance**: `POST /v1/receipts/verify` `status` checks receipt hash and recomputation consistency only, so a CERTIFIED receipt minted offline for a PR the runtime never ran still returns `VALID`. Every 200 response now carries `provenance`: `RECORDED` (this runtime's ledger holds that `receipt_hash`), `NOT_RECORDED`, or `LEDGER_UNAVAILABLE` (ledger read failed; fail closed). Callers who need provenance must require `provenance == "RECORDED"`; no signature is checked and the policy facts remain placeholders (James3014/Nexus-new#1750). See `docs/architecture/LEDGER_TRUST_MODEL.md` (#233).

---

## Vulnerability Reporting

If you discover a security vulnerability in Nexus Certify, please disclose it responsibly. **Do not open public GitHub issues or discussions for sensitive security disclosures.**

### Reporting Route
Preferred when GitHub Private Vulnerability Reporting is available:
- [Submit a Security Advisory Report](https://github.com/James3014/nexus-core/security/advisories/new)

If Private Vulnerability Reporting is unavailable, please contact the repository owner privately via email:
- `james.chen.dev@gmail.com`

### Required Information
To help us triage and investigate effectively, please provide:
1. **Exact Package Version / Commit**: e.g. `nexus-certify==0.1.1` or the specific git commit SHA on `main`.
2. **Affected Surface**: CLI (`product.clients.cli`), HTTP service (`product.runtime`), Evidence Trust Core, or GitHub acquisition.
3. **Reproduction Steps**: A minimal, self-contained reproduction script, config, or scenario.
4. **Impact Assessment**: Explanation of how the boundary is bypassed or compromised.

### Response & Handling Policy
- We aim to acknowledge receipt within **3 business days**. This is a response target, not an SLA.
- We will collaborate with the reporter to assess impact, develop a fix, and coordinate a release.
- Coordinated disclosure will follow once a patched release is available on PyPI.

---

## Supported Versions

Security fixes are currently targeted at the latest `0.1.x` release line and `main`:

| Version Series | Security Support Status |
| :--- | :--- |
| **Current (`0.1.x`) / `main`** | **Supported while this early-release policy remains current** |
| `< 0.1.0` | **Unsupported** |

Nexus Certify is currently in early release (`0.1.x`). Long-Term Support (LTS) agreements are not currently provided.
