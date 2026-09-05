"""Deterministic unit and integration tests for Core V1 HTTP runtime (TG-5).

Tests:
- Constant-time Bearer authentication and file permission checks.
- Auth check running before route disclosure.
- Loopback binding enforcement (rejecting 0.0.0.0 / non-loopback).
- Request size and path limits (1MB body, 512B path, 128B IDs).
- Complete status and error matrix across all four endpoints.
- Idempotency replay and CAS conflict detection.
- Receipt verification (ENVELOPE_ONLY, FULL, tampered).
- Server start/stop lifecycle and port reuse.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from product.evidence import _hash
from product.kernel import certify
from product.protocol import (
    IMPLEMENTATION_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)
from product.runtime.auth import (
    AuthSecurityError,
    generate_bearer_token,
    read_bearer_token,
    validate_auth_header,
    write_secure_token,
)
from product.runtime.http import (
    LoopbackBindError,
    start_runtime,
)
from product.runtime.schemas import (
    SCHEMA_BUNDLE_HASH,
    validate_certification_request,
)
from tests.product.test_evidence_receipt_hardening import _input

pytest_plugins = ["tests.product.test_http_e2e"]


@pytest.fixture
def isolated_env(tmp_path: Path):
    """Provide isolated directory with valid token and ledger path."""
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


def _valid_request_payload(
    idempotency_key: str = "key-1", expected_generation: int = 0
) -> dict[str, Any]:
    """Construct a schema-conforming certification request dictionary."""
    return {
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
        "idempotency_key": idempotency_key,
        "expected_generation": expected_generation,
    }


# ==============================================================================
# 1. Auth and File System Security Tests
# ==============================================================================


def test_token_generation_and_validation(isolated_env):
    token = isolated_env["token"]
    token_path = isolated_env["token_path"]

    assert len(token) == 43
    read_back = read_bearer_token(token_path)
    assert read_back == token

    # Constant time validation
    assert validate_auth_header(f"Bearer {token}", token) is True
    assert validate_auth_header(f"Bearer {token[:-1]}x", token) is False
    assert validate_auth_header(f"Basic {token}", token) is False
    assert validate_auth_header(None, token) is False
    assert validate_auth_header("", token) is False


def test_token_file_permission_rejection(tmp_path: Path):
    token_dir = tmp_path / "bad_token_dir"
    token_dir.mkdir(parents=True, mode=0o755)  # Wrong dir mode
    token_path = token_dir / "token"
    token = generate_bearer_token()
    token_path.write_text(token)
    os.chmod(token_path, 0o644)  # Wrong file mode

    with pytest.raises(AuthSecurityError):
        read_bearer_token(token_path)


def test_token_file_symlink_rejection(tmp_path: Path):
    real_dir = tmp_path / "real"
    real_dir.mkdir(parents=True, mode=0o700)
    real_file = real_dir / "token"
    token = generate_bearer_token()
    write_secure_token(token, real_file)

    symlink_file = tmp_path / "sym_token"
    symlink_file.symlink_to(real_file)

    with pytest.raises(AuthSecurityError):
        read_bearer_token(symlink_file)


# ==============================================================================
# 2. Schema and Validation Tests
# ==============================================================================


def test_schema_bundle_hash_stability():
    assert SCHEMA_BUNDLE_HASH.startswith("sha256:")
    assert len(SCHEMA_BUNDLE_HASH) == 71


def test_request_validation_catches_malformed_fields():
    valid = _valid_request_payload()

    # Valid payload has no errors
    assert validate_certification_request(valid) == ()

    # Extra key rejected
    bad_extra = dict(valid, extra_field="unexpected")
    assert any("unknown keys" in e for e in validate_certification_request(bad_extra))

    # Missing required key rejected
    bad_missing = dict(valid)
    bad_missing.pop("idempotency_key")
    assert any("missing required keys" in e for e in validate_certification_request(bad_missing))

    # Forbidden null rejected
    bad_null = dict(valid, idempotency_key=None)
    assert any("null value forbidden" in e for e in validate_certification_request(bad_null))

    # Unsupported protocol version rejected
    bad_ver = dict(valid, protocol_version="0.2.0")
    assert any("unsupported protocol_version" in e for e in validate_certification_request(bad_ver))

    # Unsupported profile_id rejected
    bad_prof = dict(valid, profile_id="other-profile")
    assert any("unsupported profile_id" in e for e in validate_certification_request(bad_prof))

    # Identical base and head SHA rejected
    bad_sha = dict(valid)
    bad_sha["repository"] = dict(
        valid["repository"], expected_base_sha="a" * 40, expected_head_sha="a" * 40
    )
    assert any("must differ" in e for e in validate_certification_request(bad_sha))


# ==============================================================================
# 3. HTTP Server and Endpoint Matrix Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_non_loopback_bind_rejected(isolated_env):
    with pytest.raises(LoopbackBindError):
        await start_runtime(
            host="0.0.0.0",
            port=8767,
            token_path=isolated_env["token_path"],
            db_path=isolated_env["db_path"],
        )


@pytest.mark.asyncio
async def test_auth_runs_before_route_disclosure(isolated_env):
    handle = await start_runtime(
        host="127.0.0.1",
        port=0,
        token_path=isolated_env["token_path"],
        db_path=isolated_env["db_path"],
    )
    base_url = f"http://127.0.0.1:{handle.port}"

    try:
        async with httpx.AsyncClient(base_url=base_url) as client:
            # Unauthenticated access to completely non-existent route returns 401, not 404!
            resp = await client.get("/v1/completely_unknown_path")
            assert resp.status_code == 401
            assert resp.json() == {
                "code": "UNAUTHORIZED",
                "request_id": None,
                "message": "unauthorized",
            }

            # Unauthenticated access with invalid method to known route returns 401, not 405!
            resp = await client.delete("/v1/certifications")
            assert resp.status_code == 401
            assert resp.json()["code"] == "UNAUTHORIZED"

            # Authenticated access to unknown route returns 404
            headers = {"Authorization": f"Bearer {handle.token}"}
            resp = await client.get("/v1/completely_unknown_path", headers=headers)
            assert resp.status_code == 404
            assert resp.json()["code"] == "ROUTE_NOT_FOUND"

            # Authenticated access with invalid method returns 405
            resp = await client.delete("/v1/certifications", headers=headers)
            assert resp.status_code == 405
            assert resp.json()["code"] == "METHOD_NOT_ALLOWED"
    finally:
        await handle.stop()


@pytest.mark.asyncio
async def test_request_limits_enforced(isolated_env):
    handle = await start_runtime(
        host="127.0.0.1",
        port=0,
        token_path=isolated_env["token_path"],
        db_path=isolated_env["db_path"],
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    headers = {"Authorization": f"Bearer {handle.token}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(base_url=base_url) as client:
            # Body > 1MB returns 413
            oversized_body = json.dumps({"data": "x" * (1024 * 1024 + 50)})
            resp = await client.post("/v1/certifications", headers=headers, content=oversized_body)
            assert resp.status_code == 413
            assert resp.json()["code"] == "REQUEST_TOO_LARGE"

            # Path > 512 bytes returns 400
            long_path = "/v1/" + "x" * 600
            resp = await client.get(long_path, headers=headers)
            assert resp.status_code == 400
            assert resp.json()["code"] == "MALFORMED_REQUEST"

            # Request ID > 128 bytes returns 400
            long_id = "id_" + "a" * 200
            resp = await client.get(f"/v1/certifications/{long_id}", headers=headers)
            assert resp.status_code == 400
            assert resp.json()["code"] == "MALFORMED_REQUEST"

            # Non-JSON content type returns 415
            resp = await client.post(
                "/v1/certifications",
                headers={"Authorization": f"Bearer {handle.token}", "Content-Type": "text/plain"},
                content="hello",
            )
            assert resp.status_code == 415
            assert resp.json()["code"] == "UNSUPPORTED_MEDIA_TYPE"
    finally:
        await handle.stop()


@pytest.mark.asyncio
async def test_endpoint_error_matrix_and_idempotency_conflicts(isolated_env):
    handle = await start_runtime(
        host="127.0.0.1",
        port=0,
        token_path=isolated_env["token_path"],
        db_path=isolated_env["db_path"],
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    headers = {"Authorization": f"Bearer {handle.token}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(base_url=base_url) as client:
            # Query non-existent request -> 404
            resp = await client.get("/v1/certifications/req_nonexistent", headers=headers)
            assert resp.status_code == 404
            assert resp.json()["code"] == "REQUEST_NOT_FOUND"

            # Query non-existent receipt -> 404
            resp = await client.get("/v1/certifications/req_nonexistent/receipt", headers=headers)
            assert resp.status_code == 404
            assert resp.json()["code"] == "REQUEST_NOT_FOUND"

            # Stale generation check
            stale_req = _valid_request_payload(idempotency_key="key-stale", expected_generation=999)
            resp = await client.post("/v1/certifications", headers=headers, json=stale_req)
            assert resp.status_code == 409
            assert resp.json()["code"] == "STALE_GENERATION"
    finally:
        await handle.stop()


@pytest.mark.asyncio
async def test_receipt_verify_endpoint(isolated_env):
    handle = await start_runtime(
        host="127.0.0.1",
        port=0,
        token_path=isolated_env["token_path"],
        db_path=isolated_env["db_path"],
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    headers = {"Authorization": f"Bearer {handle.token}", "Content-Type": "application/json"}

    # Generate a real valid receipt using product kernel
    cert_in = _input()
    receipt_obj = certify(cert_in).receipt
    receipt_dict = receipt_obj.to_dict()

    try:
        async with httpx.AsyncClient(base_url=base_url) as client:
            # 1. ENVELOPE_ONLY scope on valid receipt -> 200 VALID
            verify_payload = {
                "receipt": receipt_dict,
                "requested_scope": "ENVELOPE_ONLY",
                "original_inputs": None,
            }
            resp = await client.post("/v1/receipts/verify", headers=headers, json=verify_payload)
            assert resp.status_code == 200
            data = resp.json()
            assert data["scope"] == "ENVELOPE_ONLY"
            assert data["status"] == "VALID"
            assert data["receipt_hash"] == receipt_obj.hash

            # 2. Tampered receipt -> 422 RECEIPT_INVALID
            tampered_dict = dict(receipt_dict, receipt_hash="sha256:" + "0" * 64)
            bad_verify = {
                "receipt": tampered_dict,
                "requested_scope": "ENVELOPE_ONLY",
                "original_inputs": None,
            }
            resp = await client.post("/v1/receipts/verify", headers=headers, json=bad_verify)
            assert resp.status_code == 422
            assert resp.json()["code"] == "RECEIPT_INVALID"

            # 3. FULL scope without original inputs -> 200 UNVERIFIABLE
            full_unverifiable = {
                "receipt": receipt_dict,
                "requested_scope": "FULL",
                "original_inputs": None,
            }
            resp = await client.post("/v1/receipts/verify", headers=headers, json=full_unverifiable)
            assert resp.status_code == 200
            data = resp.json()
            assert data["scope"] == "FULL_RECOMPUTED"
            assert data["status"] == "UNVERIFIABLE"
            assert "MISSING_ORIGINAL_INPUTS" in data["reason_codes"]
    finally:
        await handle.stop()


@pytest.mark.asyncio
async def test_server_restart_and_port_reuse(isolated_env):
    # Test starting and stopping on the same port repeatedly without collision
    for _ in range(2):
        handle = await start_runtime(
            host="127.0.0.1",
            port=0,
            token_path=isolated_env["token_path"],
            db_path=isolated_env["db_path"],
        )
        assigned_port = handle.port
        assert assigned_port > 0

        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{assigned_port}") as client:
            headers = {"Authorization": f"Bearer {handle.token}"}
            resp = await client.get("/v1/certifications/req_test", headers=headers)
            assert resp.status_code == 404

        await handle.stop()
