"""Unit and integration tests for product/ledger.py (TG-4).

Verifies:
- Append-only WAL/full-sync SQLite ledger.
- Idempotent replay and generation CAS.
- Hash chaining and corruption fail-closed inspection.
- SQLite triggers preventing UPDATE / DELETE.
- Failpoints and crash reconciliation.
- External signer port and external head-anchor port.
- Carried TG-3 envelope and Completion receipts.
- Multiprocess concurrency / locking.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from product.evidence import canonical_json
from product.kernel import certify
from product.ledger import (
    GENESIS_PREVIOUS_HASH,
    LEDGER_SCHEMA_VERSION,
    LedgerAppendRequest,
    LedgerAppendStatus,
    UnknownEffectError,
    append_or_replay,
    get_by_request_id,
    resolve_ledger_path,
    verify_chain,
    verify_external_anchor,
)
from tests.product.test_evidence_receipt_hardening import _input
from tests.product.test_trusted_evidence_serialization import (
    _accepted_tg1_tg2_fixture,
    _Verifier,
)


@pytest.fixture
def test_db_path(tmp_path: Path) -> Path:
    """Fixture providing an isolated ledger database path."""
    return tmp_path / "nexus-core" / "ledger.sqlite3"


@pytest.fixture
def sample_payloads() -> tuple[bytes, bytes, str]:
    """Provide valid serialized TG-3 envelope, Completion receipt, and source snapshot hash."""
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

    cert_in = _input()
    receipt = certify(cert_in).receipt
    receipt_bytes = json.dumps(receipt.to_dict(), sort_keys=True).encode("utf-8")

    source_snapshot_hash = snapshot.locator_hash
    return envelope_bytes, receipt_bytes, source_snapshot_hash


class MockSigner:
    """Mock external Ed25519 signer."""

    def __init__(self, key_id: str = "key-ed25519-1"):
        self.key_id = key_id
        self.public_metadata = {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key_hex": "aa" * 32,
        }
        self.signed_digests: list[bytes] = []

    def sign_entry(self, digest: bytes) -> tuple[str, str, dict[str, object], bytes]:
        self.signed_digests.append(digest)
        signature = b"sig:" + digest[:16]
        return "Ed25519", self.key_id, self.public_metadata, signature


class MockAnchorVerifier:
    """Mock external head anchor verifier."""

    def __init__(self, expected_payload: bytes | None = None, return_status: str = "VERIFIED"):
        self.expected_payload = expected_payload
        self.return_status = return_status
        self.received_payloads: list[bytes] = []

    def verify_head_anchor(self, anchor: object, payload: bytes) -> str:
        self.received_payloads.append(payload)
        if self.expected_payload is not None and payload != self.expected_payload:
            return "UNVERIFIABLE"
        return self.return_status


def test_resolve_ledger_path_defaults_and_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Path resolution honors override, XDG_STATE_HOME, and ~/.local fallback."""
    explicit = tmp_path / "custom" / "ledger.sqlite3"
    assert resolve_ledger_path(explicit) == explicit.resolve()

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    xdg_resolved = resolve_ledger_path()
    assert xdg_resolved == (tmp_path / "xdg" / "nexus-core" / "ledger.sqlite3").resolve()

    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    fallback = resolve_ledger_path()
    assert str(fallback).endswith(".local/state/nexus-core/ledger.sqlite3")


def test_filesystem_security_directory_and_file_modes(test_db_path: Path, sample_payloads):
    """Ensure directory is created mode 0700, db and sidecars are mode 0600."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    req = LedgerAppendRequest(
        ledger_id="test-ledger",
        request_id="req-1",
        idempotency_key="key-1",
        expected_generation=0,
        attempt=1,
        canonical_request={"action": "test"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )

    res = append_or_replay(req, db_path=test_db_path)
    assert res.status is LedgerAppendStatus.APPENDED

    parent_stat = test_db_path.parent.stat()
    assert stat.S_IMODE(parent_stat.st_mode) == 0o700

    db_stat = test_db_path.stat()
    assert stat.S_IMODE(db_stat.st_mode) == 0o600
    assert db_stat.st_uid == os.getuid()

    # Check WAL sidecar permissions if present
    wal_path = Path(str(test_db_path) + "-wal")
    if wal_path.exists():
        wal_stat = wal_path.stat()
        assert stat.S_IMODE(wal_stat.st_mode) == 0o600


def test_filesystem_security_rejects_symlinks(tmp_path: Path, sample_payloads):
    """Reject symlinked database files for security."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    real_db = tmp_path / "real.sqlite3"
    real_db.touch(mode=0o600)
    symlink_db = tmp_path / "symlink.sqlite3"
    symlink_db.symlink_to(real_db)

    req = LedgerAppendRequest(
        ledger_id="test-ledger",
        request_id="req-1",
        idempotency_key="key-1",
        expected_generation=0,
        attempt=1,
        canonical_request={"action": "test"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )

    with pytest.raises(Exception, match="(symlink|SecurityError)"):
        append_or_replay(req, db_path=symlink_db)


def test_basic_append_and_get_by_request_id(test_db_path: Path, sample_payloads):
    """First entry append increments sequence to 1, generation to 1, genesis previous hash."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    req = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-100",
        idempotency_key="idem-100",
        expected_generation=0,
        attempt=1,
        canonical_request={"operation": "certify", "target": "PR#767"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )

    res = append_or_replay(req, db_path=test_db_path)
    assert res.status is LedgerAppendStatus.APPENDED
    assert not res.is_replay
    assert res.generation == 1
    assert res.entry is not None
    assert res.entry.sequence == 1
    assert res.entry.committed_generation == 1
    assert res.entry.expected_generation == 0
    assert res.entry.previous_entry_hash == GENESIS_PREVIOUS_HASH
    assert res.entry.factual_disposition == "CERTIFIED"

    # Verify retrieval
    read_res = get_by_request_id("req-100", db_path=test_db_path)
    assert read_res.found
    assert read_res.entry == res.entry

    # Non-existent
    missing = get_by_request_id("req-non-existent", db_path=test_db_path)
    assert not missing.found


def test_idempotent_replay_success(test_db_path: Path, sample_payloads):
    """Same idempotency key with identical canonical request returns replay."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    req = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-200",
        idempotency_key="idem-200",
        expected_generation=0,
        attempt=1,
        canonical_request={"foo": "bar"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )

    first = append_or_replay(req, db_path=test_db_path)
    assert first.status is LedgerAppendStatus.APPENDED
    assert not first.is_replay

    # Replay with same key and request (even if expected_generation changed)
    req_replay = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-200",
        idempotency_key="idem-200",
        expected_generation=999,  # Should be ignored for replay
        attempt=2,
        canonical_request={"foo": "bar"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )

    second = append_or_replay(req_replay, db_path=test_db_path)
    assert second.status is LedgerAppendStatus.REPLAYED
    assert second.is_replay
    assert second.generation == first.generation
    assert second.entry == first.entry


def test_idempotency_conflict_different_request(test_db_path: Path, sample_payloads):
    """Reusing idempotency key with different request returns IDEMPOTENCY_CONFLICT."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    req1 = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-301",
        idempotency_key="idem-shared",
        expected_generation=0,
        attempt=1,
        canonical_request={"version": 1},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res1 = append_or_replay(req1, db_path=test_db_path)
    assert res1.status is LedgerAppendStatus.APPENDED

    req2 = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-302",
        idempotency_key="idem-shared",
        expected_generation=1,
        attempt=1,
        canonical_request={"version": 2},  # Different!
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res2 = append_or_replay(req2, db_path=test_db_path)
    assert res2.status is LedgerAppendStatus.IDEMPOTENCY_CONFLICT
    assert res2.entry is None


def test_generation_cas_enforcement(test_db_path: Path, sample_payloads):
    """Stale or future expected generation is rejected and writes nothing."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    req1 = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-401",
        idempotency_key="idem-401",
        expected_generation=0,
        attempt=1,
        canonical_request={"num": 1},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res1 = append_or_replay(req1, db_path=test_db_path)
    assert res1.status is LedgerAppendStatus.APPENDED
    assert res1.generation == 1

    # Attempt with stale generation 0 (current is 1)
    req_stale = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-402",
        idempotency_key="idem-402",
        expected_generation=0,  # Stale!
        attempt=1,
        canonical_request={"num": 2},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res_stale = append_or_replay(req_stale, db_path=test_db_path)
    assert res_stale.status is LedgerAppendStatus.STALE_GENERATION
    assert res_stale.generation == 1

    # Attempt with future generation 5 (current is 1)
    req_future = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-403",
        idempotency_key="idem-403",
        expected_generation=5,  # Future!
        attempt=1,
        canonical_request={"num": 3},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res_future = append_or_replay(req_future, db_path=test_db_path)
    assert res_future.status is LedgerAppendStatus.STALE_GENERATION

    # Proper generation 1 succeeds and moves to 2
    req_valid = LedgerAppendRequest(
        ledger_id="ledger-01",
        request_id="req-404",
        idempotency_key="idem-404",
        expected_generation=1,
        attempt=1,
        canonical_request={"num": 4},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res_valid = append_or_replay(req_valid, db_path=test_db_path)
    assert res_valid.status is LedgerAppendStatus.APPENDED
    assert res_valid.generation == 2


def test_chain_verification_and_hash_links(test_db_path: Path, sample_payloads):
    """Verify hash links, sequence, and verification of multiple entries."""
    env_bytes, rec_bytes, snap_hash = sample_payloads

    # Empty chain
    empty_ver = verify_chain(db_path=test_db_path)
    assert empty_ver.valid
    assert empty_ver.status == "EMPTY"

    # Append 3 entries sequentially
    for i in range(3):
        req = LedgerAppendRequest(
            ledger_id="ledger-chain",
            request_id=f"req-chain-{i}",
            idempotency_key=f"idem-chain-{i}",
            expected_generation=i,
            attempt=1,
            canonical_request={"seq": i},
            identity_envelope_bytes=env_bytes,
            completion_receipt_bytes=rec_bytes,
            source_snapshot_hash=snap_hash,
        )
        res = append_or_replay(req, db_path=test_db_path)
        assert res.status is LedgerAppendStatus.APPENDED

    # Verify complete chain
    ver = verify_chain(db_path=test_db_path, expected_ledger_id="ledger-chain")
    assert ver.valid
    assert ver.status == "VALID"
    assert ver.entries_count == 3
    assert ver.head_sequence == 3
    assert ver.head_generation == 3
    assert ver.head_hash is not None


def test_sqlite_triggers_prevent_update_and_delete(test_db_path: Path, sample_payloads):
    """Database-level triggers reject direct UPDATE and DELETE operations."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    req = LedgerAppendRequest(
        ledger_id="ledger-immutable",
        request_id="req-imm",
        idempotency_key="idem-imm",
        expected_generation=0,
        attempt=1,
        canonical_request={"test": True},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res = append_or_replay(req, db_path=test_db_path)
    assert res.status is LedgerAppendStatus.APPENDED

    conn = sqlite3.connect(str(test_db_path))
    try:
        with pytest.raises(sqlite3.IntegrityError, match="LEDGER_IMMUTABLE: updates forbidden"):
            conn.execute(
                "UPDATE ledger_entries SET factual_disposition = 'TAMPERED' WHERE sequence = 1;"
            )

        with pytest.raises(sqlite3.IntegrityError, match="LEDGER_IMMUTABLE: deletions forbidden"):
            conn.execute("DELETE FROM ledger_entries WHERE sequence = 1;")
    finally:
        conn.close()


def test_chain_tamper_detection_on_corrupted_storage(test_db_path: Path, sample_payloads):
    """When triggers are dropped and data modified, verify_chain fails closed."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    for i in range(2):
        req = LedgerAppendRequest(
            ledger_id="ledger-tamper",
            request_id=f"req-t-{i}",
            idempotency_key=f"idem-t-{i}",
            expected_generation=i,
            attempt=1,
            canonical_request={"idx": i},
            identity_envelope_bytes=env_bytes,
            completion_receipt_bytes=rec_bytes,
            source_snapshot_hash=snap_hash,
        )
        append_or_replay(req, db_path=test_db_path)

    conn = sqlite3.connect(str(test_db_path))
    try:
        conn.execute("DROP TRIGGER prevent_ledger_update;")
        conn.execute(
            "UPDATE ledger_entries SET envelope_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE sequence = 1;"
        )
        conn.commit()
    finally:
        conn.close()

    ver = verify_chain(db_path=test_db_path)
    assert not ver.valid
    assert ver.status in {"ENVELOPE_TAMPERED", "ENTRY_HASH_MISMATCH"}


def test_failpoints_and_reconciliation(test_db_path: Path, sample_payloads):
    """Test before_write, before_commit, and before_response failpoints."""
    env_bytes, rec_bytes, snap_hash = sample_payloads

    # 1. Before write -> raises, zero rows
    req_bw = LedgerAppendRequest(
        ledger_id="ledger-failpoints",
        request_id="req-bw",
        idempotency_key="idem-bw",
        expected_generation=0,
        attempt=1,
        canonical_request={"fp": "before_write"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
        _failpoint="before_write",
    )
    with pytest.raises(RuntimeError, match="Failpoint: before_write"):
        append_or_replay(req_bw, db_path=test_db_path)
    assert not get_by_request_id("req-bw", db_path=test_db_path).found

    # 2. Before commit -> rolls back, zero rows
    req_bc = LedgerAppendRequest(
        ledger_id="ledger-failpoints",
        request_id="req-bc",
        idempotency_key="idem-bc",
        expected_generation=0,
        attempt=1,
        canonical_request={"fp": "before_commit"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
        _failpoint="before_commit",
    )
    with pytest.raises(RuntimeError, match="Failpoint: before_commit"):
        append_or_replay(req_bc, db_path=test_db_path)
    assert not get_by_request_id("req-bc", db_path=test_db_path).found

    # 3. Before response -> commits row, raises UnknownEffectError
    req_br = LedgerAppendRequest(
        ledger_id="ledger-failpoints",
        request_id="req-br",
        idempotency_key="idem-br",
        expected_generation=0,
        attempt=1,
        canonical_request={"fp": "before_response"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
        _failpoint="before_response",
    )
    with pytest.raises(UnknownEffectError, match="UNKNOWN_EFFECT_RECONCILIATION_REQUIRED"):
        append_or_replay(req_br, db_path=test_db_path)

    # Verification: row WAS committed
    read = get_by_request_id("req-br", db_path=test_db_path)
    assert read.found
    assert read.entry is not None

    # Retry with same idempotency key reconciles as replay without rerun or duplicate!
    retry_req = LedgerAppendRequest(
        ledger_id="ledger-failpoints",
        request_id="req-br",
        idempotency_key="idem-br",
        expected_generation=0,
        attempt=2,
        canonical_request={"fp": "before_response"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    retry_res = append_or_replay(retry_req, db_path=test_db_path)
    assert retry_res.status is LedgerAppendStatus.REPLAYED
    assert retry_res.is_replay
    assert retry_res.entry == read.entry


def test_carried_failed_verification_receipt_preserved(test_db_path: Path, sample_payloads):
    """Carried FAILED_VERIFICATION receipt remains byte-identical and retains disposition."""
    env_bytes, _, snap_hash = sample_payloads
    from product.certification import CertificationDisposition
    from product.evidence import Observation, ObservationStatus, _hash

    # Construct input with failing observation
    failed_obs = (Observation("unit", "failed_art", _hash("fail"), ObservationStatus.FAIL),)
    cin = _input(observations=failed_obs)
    failed_receipt = certify(cin).receipt
    assert failed_receipt.disposition is CertificationDisposition.REJECTED

    failed_receipt_bytes = json.dumps(failed_receipt.to_dict(), sort_keys=True).encode("utf-8")

    req = LedgerAppendRequest(
        ledger_id="ledger-carried",
        request_id="req-fail",
        idempotency_key="idem-fail",
        expected_generation=0,
        attempt=1,
        canonical_request={"status": "failed"},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=failed_receipt_bytes,
        source_snapshot_hash=snap_hash,
    )

    res = append_or_replay(req, db_path=test_db_path)
    assert res.status is LedgerAppendStatus.APPENDED
    assert res.entry is not None
    assert res.entry.receipt_bytes == failed_receipt_bytes
    assert res.entry.factual_disposition == "REJECTED"
    assert res.entry.claim_ceiling == tuple(failed_receipt.claim_ceiling)

    # Verify chain retains it
    ver = verify_chain(db_path=test_db_path)
    assert ver.valid
    assert ver.status == "VALID"


def test_external_signer_port_attestation(test_db_path: Path, sample_payloads):
    """External signer receives canonical digest, returns public metadata and signature."""
    env_bytes, rec_bytes, snap_hash = sample_payloads
    signer = MockSigner(key_id="ed25519-signer-beta")

    req = LedgerAppendRequest(
        ledger_id="ledger-signed",
        request_id="req-sign-1",
        idempotency_key="idem-sign-1",
        expected_generation=0,
        attempt=1,
        canonical_request={"signed": True},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
        signer=signer,
    )

    res = append_or_replay(req, db_path=test_db_path)
    assert res.status is LedgerAppendStatus.APPENDED
    assert res.entry is not None
    assert res.entry.signer_algorithm == "Ed25519"
    assert res.entry.signer_key_id == "ed25519-signer-beta"
    assert res.entry.signer_public_metadata == signer.public_metadata
    assert res.entry.signature is not None
    assert len(signer.signed_digests) == 1

    # Verify chain with signature present
    ver = verify_chain(db_path=test_db_path)
    assert ver.valid
    assert ver.status == "VALID"


def test_external_head_anchor_verification(test_db_path: Path, sample_payloads):
    """External head anchor verification contracts."""
    env_bytes, rec_bytes, snap_hash = sample_payloads

    # Empty ledger returns ANCHOR_UNAVAILABLE
    empty_res = verify_external_anchor(
        MockAnchorVerifier(), anchor={"sig": "abc"}, db_path=test_db_path
    )
    assert empty_res.status == "ANCHOR_UNAVAILABLE"

    # Missing verifier or anchor returns ANCHOR_UNAVAILABLE
    no_ver = verify_external_anchor(None, anchor={"sig": "abc"}, db_path=test_db_path)
    assert no_ver.status == "ANCHOR_UNAVAILABLE"

    req = LedgerAppendRequest(
        ledger_id="ledger-anchor",
        request_id="req-anchor-1",
        idempotency_key="idem-anchor-1",
        expected_generation=0,
        attempt=1,
        canonical_request={"anchor": 1},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res = append_or_replay(req, db_path=test_db_path)
    assert res.status is LedgerAppendStatus.APPENDED
    head_hash = res.entry.entry_hash

    # Valid anchor returns VERIFIED
    expected_payload = canonical_json((
        "nexus.ledger-head-anchor.v1",
        "ledger-anchor",
        LEDGER_SCHEMA_VERSION,
        1,
        1,
        head_hash,
    )).encode("utf-8")

    verifier_ok = MockAnchorVerifier(expected_payload=expected_payload, return_status="VERIFIED")
    verified_res = verify_external_anchor(
        verifier_ok, anchor={"proof": "anchor-ok"}, db_path=test_db_path
    )
    assert verified_res.status == "VERIFIED"
    assert verified_res.head_hash == head_hash

    # Tampered anchor returns UNVERIFIABLE
    verifier_bad = MockAnchorVerifier(
        expected_payload=b"mismatched-payload", return_status="VERIFIED"
    )
    unverifiable_res = verify_external_anchor(
        verifier_bad, anchor={"proof": "stale"}, db_path=test_db_path
    )
    assert unverifiable_res.status == "UNVERIFIABLE"


def _worker_concurrent_append(db_path_str: str, ikey: str, req_id: str, payload_tuple):
    """Worker function for multiprocess test."""
    env_bytes, rec_bytes, snap_hash = payload_tuple
    req = LedgerAppendRequest(
        ledger_id="ledger-mp",
        request_id=req_id,
        idempotency_key=ikey,
        expected_generation=0,
        attempt=1,
        canonical_request={"mp": True},
        identity_envelope_bytes=env_bytes,
        completion_receipt_bytes=rec_bytes,
        source_snapshot_hash=snap_hash,
    )
    res = append_or_replay(req, db_path=Path(db_path_str))
    return res.status.value, res.is_replay, res.generation


def test_multiprocess_concurrency_fencing(test_db_path: Path, sample_payloads):
    """Two concurrent processes with same idempotency key produce exactly one row."""
    from product.ledger import _connect_ledger

    # Pre-initialize db and tables so workers test transaction contention
    _connect_ledger(test_db_path).close()

    payload_tuple = sample_payloads
    ikey = "concurrent-idempotency-key"

    with multiprocessing.Pool(processes=2) as pool:
        results = pool.starmap(
            _worker_concurrent_append,
            [
                (str(test_db_path), ikey, "req-worker-1", payload_tuple),
                (str(test_db_path), ikey, "req-worker-2", payload_tuple),
            ],
        )

    statuses = [r[0] for r in results]
    assert "APPENDED" in statuses
    # Exactly one must append (or both succeeded via replay), and no duplicates exist
    conn = sqlite3.connect(str(test_db_path))
    try:
        count = conn.execute("SELECT COUNT(*) FROM ledger_entries;").fetchone()[0]
        assert count == 1
    finally:
        conn.close()

    ver = verify_chain(db_path=test_db_path)
    assert ver.valid
    assert ver.entries_count == 1
