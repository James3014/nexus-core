# GitHub Actions Workflow Dependency Policy

## Overview

Nexus Core verification and release workflows require that every external GitHub Action reference is pinned to an **immutable full 40-character commit SHA**. This prevents supply chain poisoning via mutable tags or branch heads (e.g. `@v4`, `@main`).

## Workflow Dependency Inventory

| Workflow File | Action | Pinned Commit SHA | Human Version / Upstream Ref | Role |
| :--- | :--- | :--- | :--- | :--- |
| `.github/workflows/ci.yml` | `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | `v4.2.2` | Checkout repository source |
| `.github/workflows/ci.yml` | `astral-sh/setup-uv` | `d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86` | `v5.4.1` | Install uv binary |
| `.github/workflows/publish.yml` | `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | `v4` | Checkout tagged source |
| `.github/workflows/publish.yml` | `astral-sh/setup-uv` | `d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86` | `v5` | Install pinned uv binary |
| `.github/workflows/repository-intelligence.yml` | `James3014/repository-intelligence-engine` | `cb081c20549ce5105e557794d01055bff6728f6c` | `v0.1.1` | Collect PR intelligence |
| `.github/workflows/repository-intelligence.yml` | `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `v4.6.1` | Upload intelligence report |
| `.github/workflows/repository-intelligence.yml` | `James3014/repository-intelligence-engine/terminal` | `7d7a0e375f0b7be7b57d96653a4064fd379231eb` | `main` | Observe terminal checks |
| `.github/workflows/repository-intelligence.yml` | `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `v4.6.1` | Upload terminal evidence |

## Enforcement & Anti-Regression Guard

The repository enforces this policy via machine-checked test:
- `tests/architecture/test_workflow_dependency_pinning.py`

This test:
1. Deterministically parses all `.github/workflows/*.yml` files.
2. Permits explicitly local actions (`./...`) and docker actions.
3. Rejects any external action whose ref is not a 40-character hexadecimal SHA.
4. Includes negative controls to ensure movable tags or branch names fail CI.

## Update Mechanics

When upgrading an action dependency:
1. **Resolve Commit SHA**: Resolve the targeted upstream release tag to its immutable git commit SHA via GitHub API:
   ```bash
   gh api repos/<owner>/<repo>/git/refs/tags/<tag> -q .object.sha
   ```
2. **Update Workflow File**: Replace the SHA in the workflow, keeping the version comment:
   ```yaml
   uses: <owner>/<repo>@<new-sha>  # <version>
   ```
3. **Verify Locally**:
   ```bash
   uv run pytest -q tests/architecture
   ```
4. **Open Pull Request**: The PR diff clearly displays the old SHA, new SHA, and upstream version. Normal CI executes against the updated SHA before merge.
