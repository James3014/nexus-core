"""Regression coverage for receipt-body integrity in the durable ledger."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from product.kernel import certify
from product.ledger import LedgerAppendRequest, LedgerAppendStatus, append_or_replay, verify_chain
from tests.product.test_evidence_receipt_hardening import _input
from tests.product.test_trusted_evidence_serialization import (
    _accepted_tg1_tg2_fixture,
    _Verifier,
)


def _canonical_payloads() -> tuple[bytes, bytes, str]:
    context, ingestion, snapshot, runner, verification, reference, payload, make = (
        _accepted_tg1_tg2_fixture()
    )
    envelope = make(
        context,
        ingestion,
        acquisition_snapshot=snapshot,
        runner_result=runner,
        verification_receipt=verification,
        trust_reference=reference,
        verifier=_Verifier(),
        payload=payload,
        signature=b"s" * 64,
        observed_at="2026-08-29T12:00:00+00:00",
        external_receipt_hashes=(verification.external_receipt_hash,),
    )
    envelope_bytes = json.dumps(envelope.to_dict(), sort_keys=True).encode("utf-8")

    receipt = certify(_input()).receipt
    receipt_bytes = json.dumps(receipt.to_dict(), sort_keys=True).encode("utf-8")
    return envelope_bytes, receipt_bytes, snapshot.locator_hash


def test_append_rejects_tampered_receipt_body_with_preserved_hash(tmp_path: Path) -> None:
    """Admission must reject a receipt whose body no longer matches its embedded hash."""
    db_path = tmp_path / "nexus-core" / "ledger.sqlite3"
    envelope_bytes, receipt_bytes, snapshot_hash = _canonical_payloads()
    receipt = json.loads(receipt_bytes.decode("utf-8"))
    original_hash = receipt["receipt_hash"]
    receipt["tampered_marker"] = True
    assert receipt["receipt_hash"] == original_hash
    tampered_bytes = json.dumps(receipt, sort_keys=True).encode("utf-8")

    request = LedgerAppendRequest(
        ledger_id="ledger-receipt-admission",
        request_id="req-receipt-admission",
        idempotency_key="idem-receipt-admission",
        expected_generation=0,
        attempt=1,
        canonical_request={"operation": "certify", "target": "receipt-admission"},
        identity_envelope_bytes=envelope_bytes,
        completion_receipt_bytes=tampered_bytes,
        source_snapshot_hash=snapshot_hash,
    )

    with pytest.raises(ValueError, match="completion receipt hash mismatch"):
        append_or_replay(request, db_path=db_path)

    assert not db_path.exists()


def test_verify_chain_rejects_tampered_receipt_body_with_preserved_hash(tmp_path: Path) -> None:
    """Changing receipt bytes must fail even when the old receipt_hash is retained."""
    db_path = tmp_path / "nexus-core" / "ledger.sqlite3"
    envelope_bytes, receipt_bytes, snapshot_hash = _canonical_payloads()
    request = LedgerAppendRequest(
        ledger_id="ledger-receipt-integrity",
        request_id="req-receipt-integrity",
        idempotency_key="idem-receipt-integrity",
        expected_generation=0,
        attempt=1,
        canonical_request={"operation": "certify", "target": "receipt-integrity"},
        identity_envelope_bytes=envelope_bytes,
        completion_receipt_bytes=receipt_bytes,
        source_snapshot_hash=snapshot_hash,
    )

    append_result = append_or_replay(request, db_path=db_path)
    assert append_result.status is LedgerAppendStatus.APPENDED
    control = verify_chain(db_path=db_path, expected_ledger_id="ledger-receipt-integrity")
    assert control.valid
    assert control.status == "VALID"

    receipt = json.loads(receipt_bytes.decode("utf-8"))
    original_hash = receipt["receipt_hash"]
    receipt["tampered_marker"] = True
    assert receipt["receipt_hash"] == original_hash
    tampered_bytes = json.dumps(receipt, sort_keys=True).encode("utf-8")

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("DROP TRIGGER prevent_ledger_update;")
        conn.execute(
            "UPDATE ledger_entries SET receipt_bytes = ? WHERE request_id = ?;",
            (tampered_bytes, request.request_id),
        )
        conn.commit()
    finally:
        conn.close()

    verification = verify_chain(db_path=db_path, expected_ledger_id="ledger-receipt-integrity")
    assert not verification.valid
    assert verification.status == "RECEIPT_TAMPERED"
