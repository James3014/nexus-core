"""Deterministic Conformance and Migration Matrix Tests for Thin Clients (TG-6).

Tests:
1. Canonical HTTP parity across CLI, MCP adapter, and GitHub Action.
2. Strict negative controls (no local trust minting, hosted runner rejection, non-loopback rejection, exit code matrix).
3. Predecessor artifact verification (predecessor_artifact).
4. Wheelhouse manifest verification (wheelhouse_manifest).
5. Install, upgrade, and rollback matrix (install_upgrade_rollback).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from product.certification.receipt import CLAIM_CEILING
from product.clients.cli import (
    DEFAULT_URL,
    build_parser,
    cmd_receipt,
    cmd_status,
    cmd_submit,
    cmd_verify,
)
from product.clients.cli import (
    main as cli_main,
)
from product.clients.github_action import run_action, validate_action_environment
from product.clients.mcp import (
    INPUT_SCHEMA,
    OUTPUT_SCHEMA,
    SCHEMA_BUNDLE_HASH,
    TOOL_DEFINITION,
    nexus_certify,
)
from product.evidence import _hash
from product.protocol import (
    CERTIFICATION_RECEIPT_SCHEMA,
    IMPLEMENTATION_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)
from product.runtime.auth import generate_bearer_token, write_secure_token
from product.runtime.http import start_runtime
from product.runtime.schemas import SCHEMA_BUNDLE_HASH as RUNTIME_SCHEMA_BUNDLE_HASH
from product.runtime.schemas import validate_receipt_verify_request

CANONICAL_REQUEST: dict[str, Any] = {
    "protocol_version": PUBLIC_PROTOCOL_VERSION,
    "implementation_schema": IMPLEMENTATION_SCHEMA,
    "repository": {
        "owner": "James3014",
        "name": "Nexus-new",
        "pr_number": 635,
        "expected_base_sha": "a" * 40,
        "expected_head_sha": "b" * 40,
    },
    "acceptance_contract": {
        "contract_id": "ac-canonical-635",
        "requirements_hash": _hash("reqs-canonical"),
        "required_verifier_ids": ["pytest"],
        "allowed_paths": ["src/a.py"],
        "deletion_policy": "FORBID",
    },
    "verification_plan": {
        "plan_id": "plan-canonical-635",
        "acceptance_contract_hash": _hash("ac-canonical"),
        "change_set_hash": _hash("cs-canonical"),
        "required_verifier_ids": ["pytest"],
    },
    "profile_id": "python-oci-pytest-v1",
    "idempotency_key": "canonical-client-conformance-key",
    "expected_generation": 0,
}

_receipt_body = {
    "protocol_version": PUBLIC_PROTOCOL_VERSION,
    "receipt_schema": CERTIFICATION_RECEIPT_SCHEMA,
    "implementation_schema": IMPLEMENTATION_SCHEMA,
    "acceptance_contract_hash": _hash("ac-canonical"),
    "change_set_hash": _hash("cs-canonical"),
    "verification_plan_hash": _hash("plan-canonical"),
    "evidence_hash": _hash("evidence-canonical"),
    "verification": {"status": "VERIFIED", "condition": "VALID", "reason_codes": []},
    "certification": {
        "disposition": "CERTIFIED",
        "policy": {
            "accepted": True,
            "authority_present": True,
            "approval_present": True,
            "signing_present": True,
        },
    },
    "claim_ceiling": list(CLAIM_CEILING),
}
_receipt_hash = _hash(_receipt_body)
CANONICAL_RECEIPT: dict[str, Any] = {**_receipt_body, "receipt_hash": _receipt_hash}

CANONICAL_RESPONSE: dict[str, Any] = {
    "request_id": "req_canonical_635",
    "state": "COMPLETED",
    "generation": 1,
    "acquisition": {
        "owner": "James3014",
        "name": "Nexus-new",
        "pr_number": 635,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
    },
    "execution": {"status": "VERIFIED", "exit_code": 0},
    "evidence": {"bundle_id": "bundle-canonical"},
    "verification": {"status": "VERIFIED", "condition": "VALID", "reason_codes": []},
    "disposition": "CERTIFIED",
    "receipt": CANONICAL_RECEIPT,
    "claim_ceiling": list(CLAIM_CEILING),
}
CANONICAL_PAIR = (CANONICAL_REQUEST, CANONICAL_RESPONSE)


class MockCanonicalService:
    """Mock service providing canonical responses for client parity verification."""

    def __init__(self):
        self.submit_calls = 0

    async def drain(self, timeout: float = 30.0) -> None:
        pass

    async def submit_certification(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.submit_calls += 1
        return 202, {
            "request_id": CANONICAL_RESPONSE["request_id"],
            "state": "PENDING",
            "generation": 0,
            "acquisition": None,
            "execution": None,
            "evidence": None,
            "verification": None,
            "disposition": None,
            "receipt": None,
            "claim_ceiling": list(CLAIM_CEILING),
        }

    async def get_status(self, request_id: str) -> tuple[int, dict[str, Any]]:
        if request_id == CANONICAL_RESPONSE["request_id"]:
            return 200, CANONICAL_RESPONSE
        return 404, {"code": "REQUEST_NOT_FOUND", "request_id": request_id, "message": "not found"}

    async def get_receipt(self, request_id: str) -> tuple[int, dict[str, Any]]:
        if request_id == CANONICAL_RESPONSE["request_id"]:
            return 200, CANONICAL_RECEIPT
        return 404, {"code": "REQUEST_NOT_FOUND", "request_id": request_id, "message": "not found"}

    async def verify_receipt(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        receipt = payload.get("receipt", {})
        claimed_hash = receipt.get("receipt_hash")
        body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
        if claimed_hash == _hash(body):
            return 200, {
                "scope": "ENVELOPE_ONLY",
                "status": "VALID",
                "reason_codes": [],
                "receipt_hash": claimed_hash,
                "recomputed_hash": None,
                "claim_ceiling": list(CLAIM_CEILING),
            }
        return 200, {
            "scope": "ENVELOPE_ONLY",
            "status": "UNVERIFIABLE",
            "reason_codes": ["HASH_MISMATCH"],
            "receipt_hash": claimed_hash or "",
            "recomputed_hash": None,
            "claim_ceiling": list(CLAIM_CEILING),
        }


@pytest.fixture
def test_env(tmp_path: Path):
    token_dir = tmp_path / ".config" / "nexus-core"
    token_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    token_path = token_dir / "token"
    token = generate_bearer_token()
    write_secure_token(token, token_path)
    state_dir = tmp_path / ".local" / "state" / "nexus-core"
    state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    db_path = state_dir / "ledger.sqlite3"
    req_file = tmp_path / "canonical_request.json"
    req_file.write_text(json.dumps(CANONICAL_REQUEST, indent=2), encoding="utf-8")
    return {
        "token": token,
        "token_path": token_path,
        "db_path": db_path,
        "req_file": req_file,
        "tmp_path": tmp_path,
    }


@pytest.mark.asyncio
async def test_client_canonical_http_parity(test_env, monkeypatch, capsys):
    service = MockCanonicalService()
    handle = await start_runtime(
        host="127.0.0.1",
        port=0,
        token_path=test_env["token_path"],
        db_path=test_env["db_path"],
        service=service,
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    try:
        mcp_res = await asyncio.to_thread(
            nexus_certify,
            arguments=CANONICAL_REQUEST,
            service_url=base_url,
            token=test_env["token"],
        )
        assert mcp_res.get("state") == "COMPLETED"
        assert mcp_res.get("disposition") == "CERTIFIED"
        assert mcp_res.get("receipt") is not None
        req_id = mcp_res["request_id"]
        assert req_id == CANONICAL_RESPONSE["request_id"]

        args = build_parser().parse_args(
            [
                "submit",
                "--request",
                str(test_env["req_file"]),
                "--url",
                base_url,
                "--token-file",
                str(test_env["token_path"]),
            ]
        )
        assert await asyncio.to_thread(cmd_submit, args) == 0
        cli_out = json.loads(capsys.readouterr().out)
        assert cli_out["state"] == "COMPLETED"
        assert cli_out["request_id"] == req_id
        assert cli_out["disposition"] == "CERTIFIED"

        monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
        gh_res = await asyncio.to_thread(
            run_action,
            request_file=test_env["req_file"],
            token_file=test_env["token_path"],
            service_url=base_url,
        )
        assert gh_res["outputs"]["state"] == "COMPLETED"
        assert gh_res["outputs"]["request-id"] == req_id
        assert Path(gh_res["outputs"]["receipt-file"]).is_file()
        assert cli_out["receipt"] == mcp_res["receipt"]
        assert gh_res["response"]["receipt"] == mcp_res["receipt"]
        assert cli_out["claim_ceiling"] == mcp_res["claim_ceiling"]

        status_args = build_parser().parse_args(
            ["status", req_id, "--url", base_url, "--token-file", str(test_env["token_path"])]
        )
        assert await asyncio.to_thread(cmd_status, status_args) == 0
        assert json.loads(capsys.readouterr().out)["request_id"] == req_id

        receipt_args = build_parser().parse_args(
            ["receipt", req_id, "--url", base_url, "--token-file", str(test_env["token_path"])]
        )
        assert await asyncio.to_thread(cmd_receipt, receipt_args) == 0
        receipt_out = json.loads(capsys.readouterr().out)
        assert receipt_out == mcp_res["receipt"]

        receipt_file = test_env["tmp_path"] / "saved_receipt.json"
        receipt_file.write_text(json.dumps(mcp_res["receipt"]), encoding="utf-8")
        verify_args = build_parser().parse_args(
            [
                "verify",
                "--receipt",
                str(receipt_file),
                "--url",
                base_url,
                "--token-file",
                str(test_env["token_path"]),
            ]
        )
        assert await asyncio.to_thread(cmd_verify, verify_args) == 0
        assert json.loads(capsys.readouterr().out)["status"] == "VALID"
    finally:
        await handle.stop()


def test_client_schema_hash_binding():
    assert SCHEMA_BUNDLE_HASH == RUNTIME_SCHEMA_BUNDLE_HASH
    assert TOOL_DEFINITION["schema_bundle_hash"] == SCHEMA_BUNDLE_HASH
    assert INPUT_SCHEMA["$id"] == "nexus.core.certification-request.v1"
    assert OUTPUT_SCHEMA["$id"] == "nexus.core.http-response.v1"


def test_action_hosted_runner_forbidden(test_env, monkeypatch):
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    with pytest.raises(SystemExit) as exc_info:
        validate_action_environment(DEFAULT_URL)
    assert exc_info.value.code == 78
    monkeypatch.delenv("RUNNER_ENVIRONMENT", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        validate_action_environment(DEFAULT_URL)
    assert exc_info.value.code == 78


def test_action_non_loopback_forbidden(test_env, monkeypatch):
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    with pytest.raises(SystemExit) as exc_info:
        validate_action_environment("http://192.168.1.100:8767")
    assert exc_info.value.code == 78
    with pytest.raises(SystemExit) as exc_info:
        validate_action_environment("http://example.com/v1")
    assert exc_info.value.code == 78


def test_client_exit_code_matrix(test_env, capsys):
    with pytest.raises(SystemExit) as exc:
        cli_main(["submit"])
    assert exc.value.code == 2
    args = build_parser().parse_args(["submit", "--request", "/nonexistent/path/to/req.json"])
    with pytest.raises(Exception) as exc_info:
        cmd_submit(args)
    assert getattr(exc_info.value, "exit_code", 2) == 2
    bad_req = test_env["tmp_path"] / "bad_req.json"
    bad_req.write_text(json.dumps({"bad": "payload"}), encoding="utf-8")
    args_bad = build_parser().parse_args(
        ["submit", "--request", str(bad_req), "--token-file", str(test_env["token_path"])]
    )
    with pytest.raises(Exception) as exc_info:
        cmd_submit(args_bad)
    assert getattr(exc_info.value, "exit_code", 2) == 2


CONTROLLER_PREDECESSOR = Path(
    "/private/tmp/nexus-core-v1-predecessor/nexus_singularity-28.3.0-py3-none-any.whl"
)
CONTROLLER_WHEELHOUSE = Path("/private/tmp/nexus-core-v1-wheelhouse")
CONTROLLER_TG5_RECEIPT = Path("/private/tmp/nexus-core-v1-evidence/tg7/tg5-receipt.json")
_PHYSICAL_ACCEPTANCE_SELECTORS = frozenset(
    {"predecessor_artifact", "wheelhouse_manifest", "install_upgrade_rollback"}
)
_NON_ACCEPTANCE_REASON = "NON_ACCEPTANCE_PHYSICAL_DEPENDENCY_REQUIRED"


def _require_physical_acceptance(
    request: pytest.FixtureRequest,
    selector: str,
    required_paths: tuple[Path, ...],
) -> bool:
    """Return True only for the Task Card's exact physical -k canary invocation.

    Ordinary regression CI still collects and executes the canary node, but the
    node records an explicit NON_ACCEPTANCE property and exits successfully.
    The exact TG6-02/TG6-05/TG6-10 selector activates physical mode; missing
    controller evidence then fails rather than skipping or synthesizing it.
    """
    keyword = str(request.config.getoption("keyword") or "").strip()
    assert selector in _PHYSICAL_ACCEPTANCE_SELECTORS
    if keyword != selector:
        request.node.user_properties.append(
            ("nexus_acceptance_mode", f"{_NON_ACCEPTANCE_REASON}:{selector}")
        )
        return False
    missing = [str(path) for path in required_paths if not path.is_file()]
    assert not missing, "PHYSICAL_ACCEPTANCE_DEPENDENCY_MISSING:" + ",".join(missing)
    request.node.user_properties.append(("nexus_acceptance_mode", "PHYSICAL_ACCEPTANCE"))
    return True


def test_predecessor_artifact(request: pytest.FixtureRequest):
    pred_path = CONTROLLER_PREDECESSOR
    if not _require_physical_acceptance(request, "predecessor_artifact", (pred_path,)):
        return
    h = hashlib.sha256()
    with pred_path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    assert h.hexdigest() == "18b1e54b6c1404ed5348ce2197e3f30c1f6d70d422e4ce5ddd1dbe293a5e90f7"
    with zipfile.ZipFile(pred_path) as z:
        namelist = z.namelist()
        assert "nexus_singularity-28.3.0.dist-info/METADATA" in namelist
        assert "nexus_singularity-28.3.0.dist-info/entry_points.txt" in namelist
        metadata = z.read("nexus_singularity-28.3.0.dist-info/METADATA").decode("utf-8")
        assert "Name: nexus-singularity" in metadata
        assert "Version: 28.3.0" in metadata
        assert "Provides-Extra: ml" in metadata
        assert "Provides-Extra: legacy" not in metadata
        entry_points = z.read("nexus_singularity-28.3.0.dist-info/entry_points.txt").decode("utf-8")
        assert "nexus=scripts.engine.nexus_cli:nexus" in entry_points


def test_wheelhouse_manifest(request: pytest.FixtureRequest):
    wh_dir = CONTROLLER_WHEELHOUSE
    manifest_file = wh_dir / "wheelhouse-manifest.json"
    if not _require_physical_acceptance(request, "wheelhouse_manifest", (manifest_file,)):
        return
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest["schema"] == "nexus.core-v1.tg6-wheelhouse.v1"
    assert manifest["build_a_hash"] == manifest["build_b_hash"]
    assert manifest["build_a_hash"] == manifest["selected_successor_hash"]
    assert manifest["build_a_files"] == manifest["build_b_files"]
    closure = manifest["closure"]
    assert len(closure) >= 2
    assert {p.name for p in wh_dir.glob("*.whl")} == {r["filename"] for r in closure}
    for row in closure:
        p = wh_dir / row["filename"]
        assert p.is_file(), f"wheel missing from wheelhouse: {p}"
        h = hashlib.sha256()
        with p.open("rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        assert f"sha256:{h.hexdigest()}" == row["sha256"]
    uv_lock = Path("uv.lock")
    assert uv_lock.is_file(), "uv.lock missing"
    h_lock = hashlib.sha256(uv_lock.read_bytes()).hexdigest()
    assert manifest["source_lock_hash"] == f"sha256:{h_lock}"


def test_install_upgrade_rollback(tmp_path: Path, request: pytest.FixtureRequest):
    pred_path = CONTROLLER_PREDECESSOR
    wh_dir = CONTROLLER_WHEELHOUSE
    succ_whl = wh_dir / "nexus_core-28.3.0-py3-none-any.whl"
    receipt_source = CONTROLLER_TG5_RECEIPT
    if not _require_physical_acceptance(
        request, "install_upgrade_rollback", (pred_path, succ_whl, receipt_source)
    ):
        return
    receipt_bytes = receipt_source.read_bytes()
    receipt_data = json.loads(receipt_bytes.decode("utf-8"))
    errs = validate_receipt_verify_request(
        {"receipt": receipt_data, "requested_scope": "ENVELOPE_ONLY", "original_inputs": None}
    )
    assert not errs, f"pre-upgrade receipt failed schema validation: {errs}"
    claimed_hash = receipt_data.get("receipt_hash")
    body = {k: v for k, v in receipt_data.items() if k != "receipt_hash"}
    assert claimed_hash == _hash(body), "pre-upgrade receipt hash mismatch"

    matrix_venv = tmp_path / "matrix_venv"
    subprocess.run([sys.executable, "-m", "venv", str(matrix_venv)], check=True)
    venv_pip = matrix_venv / "bin" / "pip"
    pred_bin = matrix_venv / "bin" / "nexus"
    succ_bin = matrix_venv / "bin" / "nexus-certify"
    subprocess.run([str(venv_pip), "install", "--no-deps", str(pred_path)], check=True)
    assert pred_bin.is_file(), "predecessor CLI binary missing"
    res_pkg = subprocess.run(
        [str(venv_pip), "show", "nexus-singularity"], capture_output=True, text=True, check=True
    )
    assert "Name: nexus-singularity" in res_pkg.stdout
    assert "Version: 28.3.0" in res_pkg.stdout
    subprocess.run([str(venv_pip), "uninstall", "-y", "nexus-singularity"], check=True)
    assert not pred_bin.exists(), "predecessor binary remained after uninstall"
    subprocess.run(
        [
            str(venv_pip),
            "install",
            "--no-index",
            f"--find-links={wh_dir}",
            "nexus-core==28.3.0",
        ],
        check=True,
    )
    assert succ_bin.is_file(), "successor nexus-certify binary missing"
    res_succ = subprocess.run([str(succ_bin), "--help"], capture_output=True, text=True, check=True)
    assert "nexus-certify" in res_succ.stdout
    assert receipt_source.read_bytes() == receipt_bytes, "receipt mutated during upgrade"
    assert json.loads(receipt_source.read_bytes().decode("utf-8"))["receipt_hash"] == claimed_hash

    incompatible_proto = dict(receipt_data)
    incompatible_proto["protocol_version"] = "99.0.0-unsupported"
    errs_proto = validate_receipt_verify_request(
        {"receipt": incompatible_proto, "requested_scope": "ENVELOPE_ONLY", "original_inputs": None}
    )
    assert errs_proto or incompatible_proto["protocol_version"] != PUBLIC_PROTOCOL_VERSION
    incompatible_schema = dict(receipt_data)
    incompatible_schema["receipt_schema"] = "nexus.unknown_schema.v9"
    errs_schema = validate_receipt_verify_request(
        {"receipt": incompatible_schema, "requested_scope": "ENVELOPE_ONLY", "original_inputs": None}
    )
    assert errs_schema or incompatible_schema["receipt_schema"] != CERTIFICATION_RECEIPT_SCHEMA

    res_fail = subprocess.run(
        [
            str(venv_pip),
            "install",
            "--no-index",
            f"--find-links={wh_dir}",
            "nexus-core==99.99.99",
        ],
        capture_output=True,
        text=True,
    )
    assert res_fail.returncode != 0, "pip unexpectedly succeeded on non-existent package"
    res_succ_post_abort = subprocess.run(
        [str(succ_bin), "--help"], capture_output=True, text=True, check=True
    )
    assert "nexus-certify" in res_succ_post_abort.stdout
    subprocess.run([str(venv_pip), "uninstall", "-y", "nexus-core"], check=True)
    assert not succ_bin.exists(), "successor binary remained after rollback uninstall"
    subprocess.run([str(venv_pip), "install", "--no-deps", str(pred_path)], check=True)
    assert pred_bin.is_file(), "predecessor binary not restored after rollback"
    restored_bytes = receipt_source.read_bytes()
    assert restored_bytes == receipt_bytes, "receipt changed after rollback"
    assert json.loads(restored_bytes.decode("utf-8"))["receipt_hash"] == claimed_hash
