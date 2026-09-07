"""Regression coverage for fail-closed runtime replay of corrupt durable payloads."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from product.evidence import _hash
from product.evidence.ingestion import IDENTITY_ENVELOPE_SCHEMA
from product.kernel import certify
from product.ledger import LedgerAppendRequest, LedgerAppendStatus, append_or_replay
from product.protocol import IMPLEMENTATION_SCHEMA, PUBLIC_PROTOCOL_VERSION
from product.runtime.service import RuntimeCertificationService
from tests.product.test_evidence_receipt_hardening import _input


def _request_payload() -> dict[str, object]:
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
            "contract_id": "ac-corrupt-replay",
            "requirements_hash": _hash("reqs"),
            "required_verifier_ids": ["pytest"],
            "allowed_paths": ["src/a.py"],
            "deletion_policy": "FORBID",
        },
        "verification_plan": {
            "plan_id": "plan-corrupt-replay",
            "acceptance_contract_hash": _hash("ac"),
            "change_set_hash": _hash("cs"),
            "required_verifier_ids": ["pytest"],
        },
        "profile_id": "python-oci-pytest-v1",
        "idempotency_key": "corrupt-replay",
        "expected_generation": 0,
    }


def _append_valid_row(tmp_path: Path) -> tuple[Path, dict[str, object], str]:
    db_path = tmp_path / "nexus-core" / "ledger.sqlite3"
    payload = _request_payload()
    receipt = certify(_input()).receipt
    receipt_bytes = json.dumps(receipt.to_dict(), sort_keys=True).encode("utf-8")
    envelope_bytes = json.dumps(
        {
            "schema": IDENTITY_ENVELOPE_SCHEMA,
            "identity_hash": _hash("corrupt-replay-envelope"),
        },
        sort_keys=True,
    ).encode("utf-8")
    result = append_or_replay(
        LedgerAppendRequest(
            ledger_id="nexus-core-ledger-v1",
            request_id="req_corrupt_replay",
            idempotency_key=str(payload["idempotency_key"]),
            expected_generation=0,
            attempt=1,
            canonical_request=payload,
            identity_envelope_bytes=envelope_bytes,
            completion_receipt_bytes=receipt_bytes,
            source_snapshot_hash=_hash("snapshot"),
        ),
        db_path=db_path,
    )
    assert result.status == LedgerAppendStatus.APPENDED
    assert result.entry is not None
    return db_path, payload, result.entry.factual_disposition


def _corrupt_column(db_path: Path, column: str, value: bytes) -> None:
    assert column in {"receipt_bytes", "envelope_bytes"}
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("DROP TRIGGER prevent_ledger_update")
        conn.execute(
            f"UPDATE ledger_entries SET {column} = ? WHERE idempotency_key = ?",
            (value, "corrupt-replay"),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("column", ["receipt_bytes", "envelope_bytes"])
async def test_submit_replay_fails_closed_when_carried_payload_is_corrupt(
    tmp_path: Path, column: str
) -> None:
    db_path, payload, disposition = _append_valid_row(tmp_path)
    assert disposition == "CERTIFIED"
    _corrupt_column(db_path, column, b"not-json")

    service = RuntimeCertificationService(db_path=db_path)
    status, body = await service.submit_certification(payload)

    assert status == 503
    assert body["code"] == "SERVICE_UNAVAILABLE"
    assert "state" not in body
    assert "disposition" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("column", ["receipt_bytes", "envelope_bytes"])
async def test_status_replay_fails_closed_when_carried_payload_is_corrupt(
    tmp_path: Path, column: str
) -> None:
    db_path, _payload, disposition = _append_valid_row(tmp_path)
    assert disposition == "CERTIFIED"
    _corrupt_column(db_path, column, b"not-json")

    service = RuntimeCertificationService(db_path=db_path)
    status, body = await service.get_status("req_corrupt_replay")

    assert status == 503
    assert body["code"] == "SERVICE_UNAVAILABLE"
    assert "state" not in body
    assert "disposition" not in body
