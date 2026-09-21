# Nexus Certify Security Policy

## Overview

Nexus Certify provides deterministic code verification, Git-bound evidence collection, and tamper-evident receipt certification.

Because Nexus Certify coordinates and executes test commands, it operates across distinct trust and execution boundaries. This document outlines the threat model, intended execution behavior, security claim ceilings, and vulnerability reporting procedures.

---

## Threat Model & Trust Boundaries

| Surface / Component | Trust Level | Execution Boundary | Security Invariants |
| :--- | :--- | :--- | :--- |
| **Local Repository & Working Tree** | Untrusted / Caller-Supplied | Local filesystem | Read-only during acquisition; uses an isolated temporary Git index; does not dirty or alter unstaged user files. |
| **Git Binary & Metadata** | Trusted (Host Environment) | Subprocess execution | Relies on the host `git` executable. Commit SHAs and tree hashes are treated as authoritative Git cryptographic roots. |
| **Configured Verifier Command** | **Executable Code** | **Caller's OS User Permissions** | Deliberately executed as specified by configuration. Nexus does NOT sandbox or isolate OS capabilities. |
| **Python & Dependencies** | Pinned / Packaged | Python interpreter | Package dependencies (`aiohttp`, `PyGithub`) are pinned; external GitHub Actions are pinned to immutable commit SHAs. |
| **Local Receipt Storage** | Durable Evidence | `.nexus-core/receipts/` | Append-only local storage; verified via cryptographic hash chain and schema validation. |
| **GitHub Acquisition Path** | Untrusted Remote Input | Network HTTPS (PyGithub) | PR diffs, commits, and comments are sanitized and validated against schemas before ingestion. |
| **Loopback HTTP Runtime** | Local Service | `127.0.0.1` | Local bearer token authentication; does not expose external network interfaces by default. |
| **GitHub Actions / CI Surface** | Ephemeral Runner | CI Runner Environment | Actions dependencies pinned to immutable commit SHAs; advisory-only claim ceilings for external intelligence. |

---

## Intended Execution Behavior

### The Verifier is Real Executable Code
- Verifier commands configured in `.nexus-core/config.json` or passed via CLI/API (e.g. `pytest`, `cargo test`, `npm test`) are **intentionally executed**.
- Verifier processes run locally with the **exact permissions of the invoking user or service account**.
- While Nexus Certify invokes commands directly via `execve`/`subprocess` without an intermediate shell wrapper (mitigating shell-injection metacharacter expansion), **this invocation mechanism does not constitute a sandbox**.
- Users must review and audit verifier command definitions just as they would any arbitrary build or test script. Running untrusted verifier configurations against untrusted repositories is unsafe.
- Expected command execution according to user configuration is an intended feature and is not considered a vulnerability.

---

## Security Claim Boundaries: What `VERIFIED` Means

A receipt status of `VERIFIED` provides strict mathematical and deterministic guarantees within its claim ceiling, but does **not** provide holistic software safety guarantees.

### What `VERIFIED` Guarantees:
1. **Cryptographic State Binding**: Every claimed change in the ChangeSet is bound by content hash and Git tree state to the exact evidence observations.
2. **Freshness & Applicability**: Evidence observations were produced against the exact final content of the modified paths (not stale or superseded mutations).
3. **Deterministic Policy Reduction**: The configured verification plan was evaluated against explicit, machine-checked acceptance criteria without human bypass.
4. **Tamper-Evident Receipts**: The resulting receipt is sealed with a canonical SHA-256 digest covering all input parameters and observation digests.

### What `VERIFIED` Does NOT Guarantee:
- **No Vulnerability-Free Guarantee**: `VERIFIED` does not mean the code is secure, free of vulnerabilities, or resistant to exploit.
- **No Oracle Adequacy**: A green test suite only proves what the test suite checks. It does not prove the test suite is adequate, exhaustive, or bug-free.
- **No Dependency Trust**: It does not prove third-party upstream dependencies are safe or uncompromised.
- **No Deployment or Release Authority**: A receipt is evidence; it does not authorize git merge, branch promotion, or production deployment.
- **No Execution Safety**: It does not guarantee that the repository code is safe to execute or install.

---

## Vulnerability Reporting

If you discover a security vulnerability in Nexus Certify, please disclose it responsibly. **Do not open public GitHub issues or discussions for sensitive security disclosures.**

### Reporting Route
Please report vulnerabilities using **GitHub Private Vulnerability Reporting**:
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
- We aim to acknowledge receipt within **3 business days**.
- We will collaborate with the reporter to assess impact, develop a fix, and coordinate a release.
- Coordinated disclosure will follow once a patched release is available on PyPI.

---

## Supported Versions

Security fixes are delivered as point releases on top of the latest release series:

| Version Series | Security Support Status |
| :--- | :--- |
| **Current (`0.1.x`) / `main`** | **Supported** (Active fixes and releases) |
| `< 0.1.0` | **Unsupported** |

Nexus Certify is currently in early release (`0.1.x`). Long-Term Support (LTS) agreements are not currently provided.
