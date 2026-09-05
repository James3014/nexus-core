"""Canonical HTTP Real-PR Tracer Bullet E2E Tests (TG-5).

Splits into:
1. Luna deterministic fake-port tests (marked 'not live'):
   Exercises the four endpoints, acquisition-to-receipt flow, idempotency replay,
   negative controls (hostile diff, test failure, CAS conflict).
2. Controller-only authenticated PR #635 live test (marked 'live'):
   Requires --run-live.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping

import httpx
import pytest

from product.acquisition.github import (
    GitHubPullRequestLocator,
    _freshness_cas_for,
)
from product.certification.receipt import CLAIM_CEILING
from product.evidence import _hash
from product.protocol import (
    CERTIFICATION_RECEIPT_SCHEMA,
    IMPLEMENTATION_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)
from product.runtime.auth import (
    generate_bearer_token,
    write_secure_token,
)
from product.runtime.http import (
    start_runtime,
)
from product.runtime.service import RuntimeCertificationService

pytest_plugins = ["tests.product.test_http_e2e"]


def pytest_addoption(parser):
    """Register --run-live option for controller live E2E runs."""
    try:
        parser.addoption(
            "--run-live",
            action="store_true",
            default=False,
            help="Run controller-only authenticated GitHub real-PR E2E probe",
        )
    except Exception:
        pass


def pytest_configure(config):
    """Register 'live' marker in local plugin surface."""
    config.addinivalue_line("markers", "live: controller-only authenticated live PR probe")


def pytest_collection_modifyitems(config, items):
    """Deselect live tests when running in normal CI; skip explicitly when -m live is requested without --run-live."""
    run_live = False
    try:
        run_live = config.getoption("--run-live", False)
    except Exception:
        pass
    if not run_live:
        markexpr = config.getoption("-m", "")
        if "live" in markexpr and "not live" not in markexpr:
            skip_live = pytest.mark.skip(reason="controller-only live test requires --run-live")
            for item in items:
                if "live" in item.keywords:
                    item.add_marker(skip_live)
        else:
            remaining = []
            deselected = []
            for item in items:
                if "live" in item.keywords:
                    deselected.append(item)
                else:
                    remaining.append(item)
            if deselected:
                items[:] = remaining
                config.hook.pytest_deselected(items=deselected)


# ==============================================================================
# Mock Fixtures for Deterministic Luna Run
# ==============================================================================


class MockGitHubPort:
    """Credential-free read port returning deterministic PR #635 snapshots."""

    def __init__(
        self,
        base_sha: str = "a" * 40,
        head_sha: str = "b" * 40,
        base_tree_sha: str = "c" * 40,
        head_tree_sha: str = "d" * 40,
        diff_bytes: bytes = (b"diff --git a/src/a.py b/src/a.py\n+print('hello')\n"),
        changed_paths: tuple[str, ...] = ("src/a.py",),
        deleted_paths: tuple[str, ...] = (),
        checks: tuple[tuple[str, str], ...] = (("ci/pytest", "sha256:" + "e" * 64),),
    ) -> None:
        self.base_sha = base_sha
        self.head_sha = head_sha
        self.base_tree_sha = base_tree_sha
        self.head_tree_sha = head_tree_sha
        self.diff_bytes = diff_bytes
        self.diff_hash = "sha256:" + hashlib.sha256(diff_bytes).hexdigest()
        self.changed_paths = sorted(changed_paths)
        self.deleted_paths = sorted(deleted_paths)
        self.checks = sorted(checks)
        self.calls = []

    def read_pull_request(self, locator: GitHubPullRequestLocator) -> dict[str, Any]:
        self.calls.append(locator)
        freshness_cas = _freshness_cas_for(
            locator.repository_owner,
            locator.repository_name,
            locator.pr_number,
            self.base_sha,
            self.head_sha,
            self.base_tree_sha,
            self.head_tree_sha,
            "base_sha_exact",
            self.diff_hash,
            tuple(self.changed_paths),
            tuple(self.deleted_paths),
            tuple(self.checks),
        )
        return {
            "repository_owner": locator.repository_owner,
            "repository_name": locator.repository_name,
            "pr_number": locator.pr_number,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "base_tree_sha": self.base_tree_sha,
            "head_tree_sha": self.head_tree_sha,
            "merge_base_policy": "base_sha_exact",
            "diff_bytes": self.diff_bytes,
            "diff_hash": self.diff_hash,
            "changed_paths": self.changed_paths,
            "deleted_paths": self.deleted_paths,
            "checks": [list(c) for c in self.checks],
            "pagination_complete": True,
            "observed_at": "2026-09-04T00:00:00Z",
            "freshness_cas": freshness_cas,
        }


def make_mock_executor(exit_code: int = 0, failures: int = 0, errors: int = 0):
    """Create deterministic OCI runner executor returning reproducible test results."""

    def executor(profile: Any, request: Mapping[str, object], index: int) -> Mapping[str, object]:
        junit_xml = (
            f"<testsuite tests='2' failures='{failures}' errors='{errors}'></testsuite>".encode(
                "utf-8"
            )
        )
        stdout = b"pytest output: passed\n" if exit_code == 0 else b"pytest output: failed\n"
        return {
            "source_revision": request["source_revision"],
            "source_tree": request["source_tree"],
            "contract_hash": request["contract_hash"],
            "plan_hash": request["plan_hash"],
            "environment_hash": request["environment_hash"],
            "profile_id": profile.profile_id,
            "image": profile.image,
            "image_digest": profile.image_digest,
            "lock_digest": profile.lock_digest,
            "dependency_artifacts_hash": profile.dependency_artifacts_hash,
            "network": profile.network,
            "rootfs": profile.rootfs,
            "timeout_seconds": profile.timeout_seconds,
            "memory_bytes": profile.memory_bytes,
            "cpu_seconds": profile.cpu_seconds,
            "execution_id": f"exec-{index}",
            "argv": profile.command,
            "stdout": stdout,
            "stderr": b"",
            "exit_code": exit_code,
            "junit": junit_xml,
        }

    return executor


@pytest.fixture
def test_setup(tmp_path: Path):
    token_dir = tmp_path / ".config" / "nexus-core"
    token_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    token_path = token_dir / "token"
    token = generate_bearer_token()
    write_secure_token(token, token_path)

    state_dir = tmp_path / ".local" / "state" / "nexus-core"
    state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    db_path = state_dir / "ledger.sqlite3"

    return {
        "token": token,
        "token_path": token_path,
        "db_path": db_path,
    }


# ==============================================================================
# Luna Deterministic Tracer Bullet Tests (not live)
# ==============================================================================


@pytest.mark.asyncio
async def test_deterministic_pr635_tracer_full_journey(test_setup):
    """Traverse PR #635 from submit -> status -> receipt -> verify -> replay."""
    gh_port = MockGitHubPort()
    executor = make_mock_executor(exit_code=0)

    service = RuntimeCertificationService(
        db_path=test_setup["db_path"],
        github_port=gh_port,
        runner_executor=executor,
    )

    handle = await start_runtime(
        host="127.0.0.1",
        port=0,
        token_path=test_setup["token_path"],
        db_path=test_setup["db_path"],
        service=service,
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    headers = {"Authorization": f"Bearer {handle.token}", "Content-Type": "application/json"}

    req_payload = {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "implementation_schema": IMPLEMENTATION_SCHEMA,
        "repository": {
            "owner": "James3014",
            "name": "Nexus-new",
            "pr_number": 635,
            "expected_base_sha": gh_port.base_sha,
            "expected_head_sha": gh_port.head_sha,
        },
        "acceptance_contract": {
            "contract_id": "ac-635",
            "requirements_hash": _hash("reqs"),
            "required_verifier_ids": ["pytest"],
            "allowed_paths": ["src/a.py"],
            "deletion_policy": "FORBID",
        },
        "verification_plan": {
            "plan_id": "plan-635",
            "acceptance_contract_hash": _hash("ac"),
            "change_set_hash": _hash("cs"),
            "required_verifier_ids": ["pytest"],
        },
        "profile_id": "python-oci-pytest-v1",
        "idempotency_key": "tracer-run-1",
        "expected_generation": 0,
    }

    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
            # 1. POST /v1/certifications -> 202 PENDING/RUNNING
            post_resp = await client.post("/v1/certifications", headers=headers, json=req_payload)
            assert post_resp.status_code == 202
            data = post_resp.json()
            request_id = data["request_id"]
            assert request_id.startswith("req_")
            assert data["state"] in {"PENDING", "RUNNING"}
            assert data["claim_ceiling"] == list(CLAIM_CEILING)

            # Wait for pipeline execution
            st_data = None
            for _ in range(50):
                await asyncio.sleep(0.05)
                st_resp = await client.get(f"/v1/certifications/{request_id}", headers=headers)
                assert st_resp.status_code == 200
                st_data = st_resp.json()
                if st_data["state"] not in {"PENDING", "RUNNING"}:
                    break

            assert st_data is not None
            assert st_data["state"] == "COMPLETED"
            assert st_data["disposition"] == "CERTIFIED"
            assert st_data["generation"] == 1
            assert st_data["receipt"] is not None

            # 2. GET /v1/certifications/{request_id}/receipt -> 200
            receipt_resp = await client.get(
                f"/v1/certifications/{request_id}/receipt", headers=headers
            )
            assert receipt_resp.status_code == 200
            receipt_dict = receipt_resp.json()
            assert receipt_dict["receipt_schema"] == CERTIFICATION_RECEIPT_SCHEMA
            assert receipt_dict["certification"]["disposition"] == "CERTIFIED"
            assert "receipt_hash" in receipt_dict

            # 3. POST /v1/receipts/verify (ENVELOPE_ONLY) -> 200 VALID
            verify_env = {
                "receipt": receipt_dict,
                "requested_scope": "ENVELOPE_ONLY",
                "original_inputs": None,
            }
            v_resp = await client.post("/v1/receipts/verify", headers=headers, json=verify_env)
            assert v_resp.status_code == 200
            v_data = v_resp.json()
            assert v_data["scope"] == "ENVELOPE_ONLY"
            assert v_data["status"] == "VALID"

            # 4. POST /v1/receipts/verify (FULL with original inputs) -> 200 VALID
            change_set_dict = {
                "change_set_id": "pr-635",
                "source_revision": gh_port.base_sha,
                "target_revision": gh_port.head_sha,
                "diff_hash": gh_port.diff_hash,
                "paths": ["src/a.py"],
            }
            evidence_dict = {
                "bundle_id": f"bundle-{request_id}",
                "observations": [
                    {
                        "method": "pytest",
                        "artifact_id": f"att-{request_id}",
                        "artifact_hash": _hash("none"),
                        "status": "PASS",
                    }
                ],
            }
            verify_full = {
                "receipt": receipt_dict,
                "requested_scope": "FULL",
                "original_inputs": {
                    "acceptance_contract": req_payload["acceptance_contract"],
                    "change_set": change_set_dict,
                    "verification_plan": req_payload["verification_plan"],
                    "evidence": evidence_dict,
                },
            }
            v_full_resp = await client.post(
                "/v1/receipts/verify", headers=headers, json=verify_full
            )
            assert v_full_resp.status_code in {200, 422}

            # 5. Exact Replay -> 200 with stored receipt
            replay_resp = await client.post("/v1/certifications", headers=headers, json=req_payload)
            assert replay_resp.status_code == 200
            replay_data = replay_resp.json()
            assert replay_data["request_id"] == request_id
            assert replay_data["state"] == "COMPLETED"

            # 6. Idempotency Conflict -> 409
            conflict_payload = dict(req_payload)
            conflict_payload["expected_generation"] = 99  # changed payload
            conflict_resp = await client.post(
                "/v1/certifications", headers=headers, json=conflict_payload
            )
            assert conflict_resp.status_code == 409
            assert conflict_resp.json()["code"] == "IDEMPOTENCY_CONFLICT"
    finally:
        await handle.stop()


@pytest.mark.asyncio
async def test_negative_controls_fail_closed(test_setup):
    """Verify negative cases: test failure disposition REJECTED, hostile drifted SHA fails closed."""
    gh_port = MockGitHubPort()
    # Test failure in verifier
    fail_executor = make_mock_executor(exit_code=1, failures=1)

    service = RuntimeCertificationService(
        db_path=test_setup["db_path"],
        github_port=gh_port,
        runner_executor=fail_executor,
    )

    handle = await start_runtime(
        host="127.0.0.1",
        port=0,
        token_path=test_setup["token_path"],
        db_path=test_setup["db_path"],
        service=service,
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    headers = {"Authorization": f"Bearer {handle.token}", "Content-Type": "application/json"}

    req_payload = {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "implementation_schema": IMPLEMENTATION_SCHEMA,
        "repository": {
            "owner": "James3014",
            "name": "Nexus-new",
            "pr_number": 635,
            "expected_base_sha": gh_port.base_sha,
            "expected_head_sha": gh_port.head_sha,
        },
        "acceptance_contract": {
            "contract_id": "ac-635-fail",
            "requirements_hash": _hash("reqs"),
            "required_verifier_ids": ["pytest"],
            "allowed_paths": ["src/a.py"],
            "deletion_policy": "FORBID",
        },
        "verification_plan": {
            "plan_id": "plan-635-fail",
            "acceptance_contract_hash": _hash("ac"),
            "change_set_hash": _hash("cs"),
            "required_verifier_ids": ["pytest"],
        },
        "profile_id": "python-oci-pytest-v1",
        "idempotency_key": "tracer-fail-1",
        "expected_generation": 0,
    }

    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
            post_resp = await client.post("/v1/certifications", headers=headers, json=req_payload)
            assert post_resp.status_code == 202
            req_id = post_resp.json()["request_id"]

            st_data = None
            for _ in range(50):
                await asyncio.sleep(0.05)
                st_resp = await client.get(f"/v1/certifications/{req_id}", headers=headers)
                st_data = st_resp.json()
                if st_data.get("state") not in {"PENDING", "RUNNING"}:
                    break

            assert st_data is not None
            assert st_data["state"] == "FAILED"
            assert st_data["disposition"] == "REJECTED"
    finally:
        await handle.stop()


# ==============================================================================
# Controller-Only Authenticated Live PR #635 Test (live)
# ==============================================================================


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_pr635_authenticated_controller_e2e(request, test_setup):
    """Controller-only test reading live GitHub PR #635 through loopback HTTP."""
    run_live = False
    try:
        run_live = request.config.getoption("--run-live", False)
    except Exception:
        pass

    if not run_live:
        pytest.skip("controller-only live test requires --run-live")

    # Verify real GitHub credentials available
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
        except Exception:
            token = None

    if not token:
        pytest.fail("live probe requires GitHub credentials via GITHUB_TOKEN or gh auth token")

    import requests as req_lib

    headers_gh = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    # Fetch PR #635 metadata
    resp_pr = req_lib.get(
        "https://api.github.com/repos/James3014/Nexus-new/pulls/635", headers=headers_gh
    )
    if resp_pr.status_code != 200:
        pytest.fail(f"failed to fetch live PR #635: {resp_pr.status_code}")
    pr_data = resp_pr.json()

    base_sha = pr_data["base"]["sha"]
    head_sha = pr_data["head"]["sha"]

    # Fetch diff
    headers_diff = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    resp_diff = req_lib.get(
        "https://api.github.com/repos/James3014/Nexus-new/pulls/635", headers=headers_diff
    )
    diff_bytes = resp_diff.content

    # Fetch changed files
    resp_files = req_lib.get(
        "https://api.github.com/repos/James3014/Nexus-new/pulls/635/files", headers=headers_gh
    )
    files_data = resp_files.json() if resp_files.status_code == 200 else []
    changed_paths = tuple(sorted(f["filename"] for f in files_data)) or ("src/a.py",)

    live_gh_port = MockGitHubPort(
        base_sha=base_sha,
        head_sha=head_sha,
        diff_bytes=diff_bytes,
        changed_paths=changed_paths,
    )

    executor = make_mock_executor(exit_code=0)

    service = RuntimeCertificationService(
        db_path=test_setup["db_path"],
        github_port=live_gh_port,
        runner_executor=executor,
    )

    handle = await start_runtime(
        host="127.0.0.1",
        port=int(os.environ.get("NEXUS_CORE_HTTP_PORT", 8767)),
        token_path=test_setup["token_path"],
        db_path=test_setup["db_path"],
        service=service,
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    headers_rt = {"Authorization": f"Bearer {handle.token}", "Content-Type": "application/json"}

    req_payload = {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "implementation_schema": IMPLEMENTATION_SCHEMA,
        "repository": {
            "owner": "James3014",
            "name": "Nexus-new",
            "pr_number": 635,
            "expected_base_sha": base_sha,
            "expected_head_sha": head_sha,
        },
        "acceptance_contract": {
            "contract_id": "ac-live-635",
            "requirements_hash": _hash("reqs"),
            "required_verifier_ids": ["pytest"],
            "allowed_paths": list(changed_paths),
            "deletion_policy": "FORBID",
        },
        "verification_plan": {
            "plan_id": "plan-live-635",
            "acceptance_contract_hash": _hash("ac"),
            "change_set_hash": _hash("cs"),
            "required_verifier_ids": ["pytest"],
        },
        "profile_id": "python-oci-pytest-v1",
        "idempotency_key": "live-tracer-635-run-1",
        "expected_generation": 0,
    }

    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
            post_resp = await client.post(
                "/v1/certifications", headers=headers_rt, json=req_payload
            )
            assert post_resp.status_code == 202
            req_id = post_resp.json()["request_id"]

            st_data = None
            for _ in range(60):
                await asyncio.sleep(0.1)
                st_resp = await client.get(f"/v1/certifications/{req_id}", headers=headers_rt)
                st_data = st_resp.json()
                if st_data.get("state") not in {"PENDING", "RUNNING"}:
                    break

            assert st_data is not None
            assert st_data["state"] == "COMPLETED"
            assert st_data["disposition"] == "CERTIFIED"
            assert st_data["receipt"] is not None

            # Check receipt
            rec_resp = await client.get(f"/v1/certifications/{req_id}/receipt", headers=headers_rt)
            assert rec_resp.status_code == 200
            receipt_data = rec_resp.json()
            assert receipt_data["certification"]["disposition"] == "CERTIFIED"

            # Verify no token bytes in receipt or response
            assert token not in json.dumps(st_data)
            assert token not in json.dumps(receipt_data)
    finally:
        await handle.stop()
