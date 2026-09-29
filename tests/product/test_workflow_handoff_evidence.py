"""Issue #59: verify session-handoff evidence without orchestration authority."""

from __future__ import annotations

import json

import pytest

from product.evidence import IntegrityStatus, _hash
from product.evidence.handoff import (
    HANDOFF_CLAIM_CEILING,
    HANDOFF_SCHEMA,
    HandoffIdentity,
    HandoffVerdict,
    HandoffVerification,
    build_handoff_envelope,
    identity_binding,
    is_trustworthy,
    project_workflow_checkpoint_envelope,
    verify_handoff_evidence,
)

# Exact output of nexus_runtime.workflow_checkpoint.WorkflowCheckpoint.to_dict()
# for a real runtime attempt. Used as the compatibility fixture for the
# nexus-runtime handoff contract.
RUNTIME_CHECKPOINT_FIXTURE = {
    "attempt_id": "attempt-handoff-1",
    "blocked_reason": "",
    "checkpoint_hash": "c201aa7e838b255587273f73b4afd02e67cc2bf1cef2aac9a5ab01eb2b2d9904",
    "claim_ceiling": "RUNTIME_SESSION_CHECKPOINT_EXECUTION_STATE_ONLY",
    "completed_effects": [
        {"effect_hash": "abc123", "effect_key": "merge:pr-43", "receipt_ref": "receipt:merge-43"},
    ],
    "evidence_refs": ["receipt:ci-1"],
    "external_operation_ids": {},
    "identity": {
        "repository": "James3014/nexus-runtime",
        "runtime_identity": "runtime-sha:0000000000000000",
        "source_revision": "git-commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "target_revision": "git-commit:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
    "leases": [],
    "next_gate": "pr-open",
    "operation_id": "op-handoff-1",
    "pending_steps": ["open-pr"],
    "phase": "TEST",
    "retry_history": ["retry:1:flake"],
    "revision": 4,
    "schema": "nexus.runtime.workflow_checkpoint.v1",
    "status": "RUNNING",
    "task_id": "task-handoff-1",
}


def _current() -> HandoffIdentity:
    return HandoffIdentity(
        repository="James3014/nexus-runtime",
        source_revision="git-commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        runtime_identity="runtime-sha:0000000000000000",
    )


def _envelope(**kwargs):
    return project_workflow_checkpoint_envelope(
        RUNTIME_CHECKPOINT_FIXTURE,
        producer_identity="agent:session-a",
        observed_identity="agent:session-a",
        **kwargs,
    )


def test_runtime_handoff_fixture_verifies_valid():
    envelope = _envelope()
    assert envelope["schema"] == HANDOFF_SCHEMA
    result = verify_handoff_evidence(envelope, current_identity=_current())
    assert result.verdict is HandoffVerdict.VALID
    assert result.trustworthy is True
    assert is_trustworthy(result.verdict)
    assert result.integrity is IntegrityStatus.VALID
    assert result.claim_ceiling == HANDOFF_CLAIM_CEILING
    assert isinstance(result, HandoffVerification)


def test_projected_receipts_include_completed_effects():
    envelope = _envelope()
    assert "receipt:ci-1" in envelope["receipt_refs"]
    assert "receipt:merge-43" in envelope["receipt_refs"]
    assert envelope["asserted_phase"] == "TEST"
    assert envelope["asserted_terminal"] is False


def test_freshness_is_identity_bound_not_timestamped():
    envelope = _envelope()
    # Injecting a chat/wall-clock timestamp must not change the verdict.
    stamped = dict(envelope)
    stamped["generated_at"] = "1970-01-01T00:00:00Z"
    stamped["envelope_hash"] = _hash({k: v for k, v in stamped.items() if k != "envelope_hash"})
    assert (
        verify_handoff_evidence(stamped, current_identity=_current()).verdict
        is HandoffVerdict.VALID
    )
    drift = HandoffIdentity(
        repository="James3014/nexus-runtime",
        source_revision="git-commit:" + "c" * 40,
        runtime_identity="runtime-sha:0000000000000000",
    )
    result = verify_handoff_evidence(stamped, current_identity=drift)
    assert result.verdict is HandoffVerdict.STALE
    assert any("source_revision" in code for code in result.reason_codes)


def test_source_and_runtime_drift_are_stale():
    envelope = _envelope()
    for drift in (
        HandoffIdentity(
            repository="James3014/nexus-runtime",
            source_revision="git-commit:" + "d" * 40,
            runtime_identity="runtime-sha:0000000000000000",
        ),
        HandoffIdentity(
            repository="James3014/nexus-runtime",
            source_revision="git-commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            runtime_identity="runtime-sha:ffffffffffffffff",
        ),
        HandoffIdentity(
            repository="other/repo",
            source_revision="git-commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    ):
        result = verify_handoff_evidence(envelope, current_identity=drift)
        assert result.verdict is HandoffVerdict.STALE
        assert result.trustworthy is False


def test_tampered_envelope_fails_closed():
    envelope = _envelope()
    for key, value in (
        ("asserted_phase", "DONE"),
        ("attempt_id", "attempt-handoff-2"),
        ("asserted_terminal", True),
    ):
        tampered = dict(envelope)
        tampered[key] = value
        result = verify_handoff_evidence(tampered, current_identity=_current())
        assert result.verdict is HandoffVerdict.TAMPERED
        assert result.integrity is IntegrityStatus.TAMPERED


def test_tampered_identity_binding_hash_is_tampered():
    envelope = _envelope()
    tampered = dict(envelope)
    tampered["identity_binding_hash"] = "sha256:" + "0" * 64
    assert (
        verify_handoff_evidence(tampered, current_identity=_current()).verdict
        is HandoffVerdict.TAMPERED
    )


def test_checkpoint_hash_must_bind_the_body():
    envelope = _envelope()
    tampered = dict(envelope)
    tampered["checkpoint"] = dict(envelope["checkpoint"])
    tampered["checkpoint"]["content_hash"] = "sha256:" + "f" * 64
    tampered["envelope_hash"] = _hash({k: v for k, v in tampered.items() if k != "envelope_hash"})
    result = verify_handoff_evidence(tampered, current_identity=_current())
    assert result.verdict is HandoffVerdict.MISMATCHED
    assert any("checkpoint_content_hash" in code for code in result.reason_codes)


def test_expected_configuration_cannot_fill_observed_identity():
    envelope = project_workflow_checkpoint_envelope(
        RUNTIME_CHECKPOINT_FIXTURE, producer_identity="agent:session-a"
    )
    result = verify_handoff_evidence(envelope, current_identity=_current())
    assert result.verdict is HandoffVerdict.MISMATCHED
    assert any("observed_identity_missing" in code for code in result.reason_codes)


def test_malformed_and_ceiling_escalation_fail_closed():
    assert (
        verify_handoff_evidence("not-an-object", current_identity=_current()).verdict
        is HandoffVerdict.INVALID
    )
    bad_schema = _envelope()
    bad_schema["schema"] = "nexus.core.workflow_handoff.v9"
    assert (
        verify_handoff_evidence(bad_schema, current_identity=_current()).verdict
        is HandoffVerdict.INVALID
    )
    escalated = _envelope()
    escalated["claim_ceiling"] = "MERGE_AUTHORITY"
    result = verify_handoff_evidence(escalated, current_identity=_current())
    assert result.verdict is HandoffVerdict.INVALID
    assert any("claim_ceiling" in code for code in result.reason_codes)


def test_terminal_claim_without_status_is_mismatched():
    envelope = build_handoff_envelope(
        operation_id="op",
        attempt_id="attempt",
        identity=_current(),
        checkpoint_content_hash="sha256:" + "a" * 64,
        asserted_terminal=True,
        checkpoint_status="",
    )
    result = verify_handoff_evidence(envelope, current_identity=_current())
    assert result.verdict is HandoffVerdict.MISMATCHED


def test_result_is_sealed_and_deterministic():
    envelope = _envelope()
    first = verify_handoff_evidence(envelope, current_identity=_current())
    second = verify_handoff_evidence(envelope, current_identity=_current())
    assert first.hash == second.hash
    assert first.input_binding_hash == second.input_binding_hash
    assert first.input_binding_hash.startswith("sha256:")
    assert len(first.input_binding_hash) == 71
    drifted = verify_handoff_evidence(
        envelope,
        current_identity=HandoffIdentity(
            repository="James3014/nexus-runtime",
            source_revision="git-commit:" + "e" * 40,
        ),
    )
    assert drifted.input_binding_hash != first.input_binding_hash
    body = first.to_dict()
    assert body["trustworthy"] is True
    assert body["authority_note"] == (
        "verification_is_not_resume_merge_release_or_deploy_authority"
    )
    assert json.dumps(body, sort_keys=True)


def test_verification_explicitly_is_not_resume_or_merge_authority():
    result = verify_handoff_evidence(_envelope(), current_identity=_current())
    note = result.to_dict()["authority_note"]
    for forbidden in ("resume", "merge", "release", "deploy"):
        assert forbidden in note
        assert "not_" in note
    # Sealed construction rejects an escalated ceiling outright.
    with pytest.raises(ValueError):
        HandoffVerification(
            verdict=HandoffVerdict.VALID,
            reason_codes=("VALID:x",),
            integrity=IntegrityStatus.VALID,
            input_binding_hash=first_input_binding(),
            schema=HANDOFF_SCHEMA,
            claim_ceiling="MERGE_AUTHORITY",
        )


def first_input_binding() -> str:
    return "sha256:" + "1" * 64


def test_no_second_orchestration_state_machine_is_exported():
    import product.evidence.handoff as module

    exported = set(getattr(module, "__all__", ()))
    forbidden = {
        "advance",
        "transition",
        "resume",
        "next_status",
        "run",
        "dispatch",
        "route",
        "approve",
        "merge",
        "checkpoint_store",
        "WorkflowCheckpointStore",
        "WorkflowCheckpoint",
        "CHECKPOINT_STATUSES",
    }
    assert exported & forbidden == set()
    assert is_trustworthy(HandoffVerdict.INVALID) is False
    assert is_trustworthy(HandoffVerdict.VALID) is True
    assert identity_binding(_current()).to_dict() == _current().to_dict()
