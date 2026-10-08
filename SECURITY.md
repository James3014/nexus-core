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
| **Verifier sandbox** | Detached Clone | `isolated_detached_clone` | The sandbox is cloned with `--no-hardlinks`, the `origin` remote is removed and `objects/info/alternates` must be absent, so the verifier cannot reach back into the original repository through Git. The verifier runs in its own session/process group and the whole group is killed on timeout. Container mode (`[isolation] mode = "container"`, digest-pinned image, sandbox as sole mount) is the recommended setting for adversarial agents; it requires `docker` and fails closed with `ISOLATION_UNAVAILABLE`. |
| **Governance config source** | Base-Ref Authoritative | `git show <base_ref>:.nexus-core/config.toml` | The config committed on the base ref is the effective config; a differing `base_ref` fails with `CONFIG_BASE_REF_MISMATCH`. A worktree-only config is reported as `config: untrusted` and `--require-trusted-config` (or `NEXUS_CERTIFY_REQUIRE_TRUSTED_CONFIG=1`) fails closed with `CONFIG_UNTRUSTED`. The receipt records `config_source` and `config_drift`. |
| **Python Runtime & Package Dependencies** | Environment-Resolved Dependencies | Python interpreter | Published dependencies are version-constrained, not cryptographically pinned for every end-user install. Repository development/test resolution is locked by `uv.lock`; GitHub Actions dependencies are separately pinned to immutable identities. |
| **Local Receipt Files** | Caller-Writable Evidence Files | `.nexus-core/receipts/` | Each receipt is self-hashed and can be recomputed/validated. Local receipt files are not append-only, are not hash-chained to prior receipts, and can be deleted or replaced by a principal with filesystem access. |
| **GitHub Acquisition Adapter** | Untrusted Remote Snapshot | Controller-injected read port | `product.acquisition.github` contains no network client or credential parameter. It validates the supplied snapshot schema, identities, hashes, paths, pagination completion, and convergence across two reads; authentication/network transport are owned outside this module. |
| **Loopback HTTP Runtime** | Local Service | `127.0.0.1` | Local bearer token authentication; does not expose external network interfaces by default. |
| **GitHub Actions / CI Surface** | Ephemeral Runner | CI Runner Environment | Actions dependencies pinned to immutable commit SHAs; advisory-only claim ceilings for external intelligence. |
| **PR gate** | Trusted Base + Untrusted Candidate | `pull_request_target`, composite action `issue-gate` | Same-repository branches only (fork guard). The workflow and action come from the base ref; the pinned tool is installed into a runner-private directory before any candidate code exists, and the runner never runs candidate `uv sync`/`uv build`/scripts. `GITHUB_TOKEN` is set only on the `issue-init`/`issue-check` steps, and receipts are uploaded as a workflow artifact. Changes to the gate or config are verified under the old generation and take effect after an ordinary reviewed merge. |

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
