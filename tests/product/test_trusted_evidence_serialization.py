"""Restart and external-verifier witnesses for the TG3 trust boundary."""

import json
import subprocess
import sys
from dataclasses import replace

import pytest

payload = b"payload"


def _unsafe_replace(value, **changes):
    candidate = object.__new__(type(value))
    for name in value.__dataclass_fields__:
        object.__setattr__(candidate, name, changes.get(name, getattr(value, name)))
    return candidate


def test_identity_envelope_round_trips_and_recomputes_after_fresh_import():
    from product.evidence.ingestion import (
        load_identity_envelope,
        serialize_identity_envelope,
    )

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
    payload = serialize_identity_envelope(envelope)
    assert load_identity_envelope(json.loads(json.dumps(payload))) == envelope
    code = (
        "import json,sys; from product.evidence.ingestion import load_identity_envelope; "
        "x=load_identity_envelope(json.loads(sys.stdin.read())); print(x.identity_hash)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == envelope.identity_hash


def test_identity_envelope_rejects_tampering_and_cross_bound_payload():
    from product.evidence.ingestion import load_identity_envelope

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
    data = envelope.to_dict()
    data["context_hash"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="identity_hash"):
        load_identity_envelope(data)
    data = envelope.to_dict()
    data["external_receipt_hashes"] = ["sha256:" + "c" * 64]
    with pytest.raises(ValueError, match="identity_hash"):
        load_identity_envelope(data)


class _Verifier:
    def __init__(self, result=True, key_id="key-1", signature=b"s" * 64):
        self.result = result
        self.key_id = key_id
        self.signature = signature
        self.calls = []

    def verify(self, **kwargs):
        self.calls.append(kwargs)
        return (
            self.result
            and kwargs["key_id"] == self.key_id
            and kwargs["signature"] == self.signature
        )


def _accepted_tg1_tg2_fixture(*, seed=0, observed_at="2026-08-29T12:00:00+00:00"):
    from product.acquisition.github import GitHubAcquisitionSnapshot, _freshness_cas_for
    from product.evidence.ingestion import (
        GitHubAcquisitionReceipt,
        PythonRunnerReceipt,
        make_identity_envelope,
    )
    from product.execution.python_runner import ExecutionAttempt, RunnerResult, RunnerStatus
    from tests.product.test_trusted_evidence_ingestion import _fixture

    api, context, submission, _ = _fixture()
    chars = ("a", "b", "c", "d") if seed == 0 else ("5", "6", "7", "8")
    source, target, source_tree, target_tree = (char * 40 for char in chars)
    diff = b"diff"
    diff_hash = "sha256:" + __import__("hashlib").sha256(diff).hexdigest()
    change = replace(
        context.change_set, source_revision=source, target_revision=target, diff_hash=diff_hash
    )
    plan = replace(context.plan, change_set_hash=change.hash)
    provenance = replace(
        submission.provenance,
        repository_id="James3014/Nexus-new",
        source_revision=source,
        source_tree=source_tree,
        target_revision=target,
        target_tree=target_tree,
        change_set_hash=change.hash,
        diff_hash=diff_hash,
    )
    submission = replace(submission, provenance=provenance)
    requirement = replace(context.requirements[0], provenance_hash=provenance.hash)
    payload = b"payload"
    external_hash = "sha256:" + __import__("hashlib").sha256(b"receipt").hexdigest()
    context = replace(
        context,
        change_set=change,
        plan=plan,
        source_tree=source_tree,
        target_tree=target_tree,
        observed_at=observed_at,
        repository_id="James3014/Nexus-new",
        requirements=(requirement,),
        prerequisite_payload_hashes=((api.TrustRole.AUTHORITY, external_hash),),
    )
    ingestion = api.ingest_evidence(context, (submission,))
    snapshot_values = dict(
        repository_owner="James3014",
        repository_name="Nexus-new",
        pr_number=767,
        base_sha=source,
        head_sha=target,
        base_tree_sha=source_tree,
        head_tree_sha=target_tree,
        merge_base_policy="base_sha_exact",
        diff_bytes=diff,
        diff_hash=diff_hash,
        changed_paths=("src/a.py",),
        deleted_paths=(),
        checks=(("ci", "sha256:" + "e" * 64),),
        pagination_complete=True,
        observed_at="2026-08-29T12:00:00Z",
    )
    snapshot_values["freshness_cas"] = _freshness_cas_for(
        snapshot_values["repository_owner"],
        snapshot_values["repository_name"],
        snapshot_values["pr_number"],
        source,
        target,
        source_tree,
        target_tree,
        "base_sha_exact",
        diff_hash,
        snapshot_values["changed_paths"],
        (),
        snapshot_values["checks"],
    )
    from product.acquisition.github import GitHubPullRequestLocator

    snapshot_values["locator_hash"] = GitHubPullRequestLocator(
        "James3014", "Nexus-new", 767
    ).locator_hash
    snapshot = GitHubAcquisitionSnapshot(**snapshot_values)
    junit = b"<testsuite tests='1' failures='0' errors='0'></testsuite>"
    import json

    from product.execution import python_runner as pr

    command = pr.PythonOCIProfile().command
    identity = (
        json.dumps(
            {
                "source_revision": target,
                "source_tree": target_tree,
                "contract_hash": context.contract.hash,
                "plan_hash": context.plan.hash,
                "environment_hash": requirement.environment_hash,
                "profile_id": pr.PROFILE_ID,
                "image": pr.IMAGE,
                "image_digest": pr.IMAGE_DIGEST,
                "lock_digest": pr.LOCK_DIGEST,
                "network": "none",
                "rootfs": "read-only",
                "timeout_seconds": 300,
                "memory_bytes": 1073741824,
                "cpu_seconds": 60,
                "argv": list(command),
                "junit": [1, 0, 0],
                "exit_code": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + pr.DEPENDENCY_ARTIFACTS_HASH.encode()
    )
    artifact = (
        "sha256:"
        + __import__("hashlib").sha256(b"\0".join((identity, b"", b"", junit))).hexdigest()
    )
    normalized = pr.PythonOCIRunner._normalized_junit(junit)
    outcome = (
        "sha256:"
        + __import__("hashlib")
        .sha256(
            json.dumps(
                [
                    target,
                    target_tree,
                    context.contract.hash,
                    context.plan.hash,
                    requirement.environment_hash,
                    list(command),
                    0,
                    normalized,
                ],
                separators=(",", ":"),
            ).encode()
        )
        .hexdigest()
    )
    attempt = ExecutionAttempt(
        requirement.attempt_id,
        requirement.execution_id,
        target,
        target_tree,
        context.contract.hash,
        context.plan.hash,
        requirement.environment_hash,
        command,
        b"",
        b"",
        0,
        junit,
        artifact,
        1,
        0,
        0,
        outcome,
    )
    attempt2 = replace(attempt, attempt_id="attempt-2", execution_id="exec-2")
    runner = RunnerResult(
        RunnerStatus.VERIFIED,
        (),
        pr.PythonOCIProfile().hash,
        (attempt.attempt_id, attempt2.attempt_id),
        (attempt.artifact_hash, attempt2.artifact_hash),
        (attempt, attempt2),
    )
    from product.evidence.ingestion import (
        TrustDecision,
        TrustReference,
        TrustRole,
        _hash,
        build_external_signature_payload,
        verify_external_ed25519_receipt,
    )

    subject = _hash((
        "nexus.trusted_prerequisite_subject.v1-experimental",
        context.hash,
        ingestion.bundle.hash,
    ))
    reference = TrustReference(
        TrustRole.AUTHORITY,
        "evidence-1",
        "issuer-1",
        subject,
        "merge",
        TrustDecision.ALLOW,
        "2026-08-29T11:59:00+00:00",
        "2026-08-29T13:00:00+00:00",
        None,
        external_hash,
        external_hash,
        "pytest",
        b"receipt",
        external_hash,
    )
    import json as _json

    acquisition_hash = (
        "sha256:"
        + __import__("hashlib")
        .sha256(_json.dumps(snapshot.to_dict(), sort_keys=True, separators=(",", ":")).encode())
        .hexdigest()
    )
    runner_hash = (
        "sha256:"
        + __import__("hashlib")
        .sha256(_json.dumps(runner.to_dict(), sort_keys=True, separators=(",", ":")).encode())
        .hexdigest()
    )
    payload = build_external_signature_payload(
        issuer_id="issuer-1",
        key_id="key-1",
        evidence_id="evidence-1",
        subject_hash=subject,
        action="merge",
        decision="ALLOW",
        external_receipt_hash=external_hash,
        acquisition_snapshot_hash=acquisition_hash,
        runner_result_hash=runner_hash,
    )
    reference = replace(
        reference, signed_payload_hash="sha256:" + __import__("hashlib").sha256(payload).hexdigest()
    )
    verification = verify_external_ed25519_receipt(
        _Verifier(),
        issuer_id="issuer-1",
        key_id="key-1",
        payload=payload,
        signature=b"s" * 64,
        external_receipt=b"receipt",
    )
    native_snapshot = GitHubAcquisitionReceipt.from_dict(snapshot.to_dict())
    runner_data = runner.to_dict()
    runner_data["profile"] = pr.PythonOCIProfile().to_dict()
    for item, source_attempt in zip(runner_data["attempts"], runner.attempts):
        item.update(
            junit_tests=source_attempt.junit_tests,
            junit_failures=source_attempt.junit_failures,
            junit_errors=source_attempt.junit_errors,
        )
    native_runner = PythonRunnerReceipt.from_dict(runner_data)
    acquisition_hash = (
        "sha256:"
        + __import__("hashlib")
        .sha256(
            json.dumps(native_snapshot.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        )
        .hexdigest()
    )
    runner_hash = (
        "sha256:"
        + __import__("hashlib")
        .sha256(json.dumps(native_runner.to_dict(), sort_keys=True, separators=(",", ":")).encode())
        .hexdigest()
    )
    payload = build_external_signature_payload(
        issuer_id="issuer-1",
        key_id="key-1",
        evidence_id="evidence-1",
        subject_hash=subject,
        action="merge",
        decision="ALLOW",
        external_receipt_hash=external_hash,
        acquisition_snapshot_hash=acquisition_hash,
        runner_result_hash=runner_hash,
    )
    reference = replace(
        reference, signed_payload_hash="sha256:" + __import__("hashlib").sha256(payload).hexdigest()
    )
    verification = verify_external_ed25519_receipt(
        _Verifier(),
        issuer_id="issuer-1",
        key_id="key-1",
        payload=payload,
        signature=b"s" * 64,
        external_receipt=b"receipt",
    )
    return (
        context,
        ingestion,
        native_snapshot,
        native_runner,
        verification,
        reference,
        payload,
        make_identity_envelope,
    )


@pytest.mark.parametrize("result", [True, False])
def test_external_ed25519_verifier_is_injected_and_public_metadata_only(result):
    from product.evidence.ingestion import verify_external_ed25519

    verifier = _Verifier(result)
    assert (
        verify_external_ed25519(
            verifier, issuer_id="issuer-1", key_id="key-1", payload=payload, signature=b"s" * 64
        )
        is result
    )
    assert verifier.calls == [
        {
            "issuer_id": "issuer-1",
            "key_id": "key-1",
            "algorithm": "Ed25519",
            "payload": b"payload",
            "signature": b"s" * 64,
        }
    ]


def test_external_verifier_rejects_malformed_and_wrong_bound_inputs():
    from product.evidence.ingestion import verify_external_ed25519

    verifier = _Verifier()
    assert (
        verify_external_ed25519(
            verifier, issuer_id="issuer-1", key_id="key-1", payload=b"", signature=b"sig"
        )
        is False
    )
    assert (
        verify_external_ed25519(
            verifier, issuer_id="issuer-1", key_id="key-1", payload=payload, signature=b""
        )
        is False
    )
    assert (
        verify_external_ed25519(
            verifier, issuer_id="issuer-1", key_id="key-1", payload=payload, signature="sig"
        )
        is False
    )
    assert (
        verify_external_ed25519(
            verifier, issuer_id="issuer-1", key_id="key-1", payload=payload, signature=b"s" * 64
        )
        is True
    )


def test_reference_signature_binds_issuer_payload_and_revocation():
    from product.evidence import _hash
    from product.evidence.ingestion import (
        TrustDecision,
        TrustReference,
        TrustRole,
        verify_trust_reference_signature,
    )

    payload = b"externally signed payload"
    digest = "sha256:" + __import__("hashlib").sha256(b"receipt").hexdigest()
    subject = _hash((
        "nexus.trusted_prerequisite_subject.v1-experimental",
        _hash("context"),
        _hash("bundle"),
    ))
    from product.evidence.ingestion import build_external_signature_payload

    payload = build_external_signature_payload(
        issuer_id="issuer-1",
        key_id="key-1",
        evidence_id="evidence-1",
        subject_hash=subject,
        action="merge",
        decision="ALLOW",
        external_receipt_hash=digest,
        acquisition_snapshot_hash="sha256:" + "0" * 64,
        runner_result_hash="sha256:" + "0" * 64,
    )
    reference = TrustReference(
        TrustRole.AUTHORITY,
        "evidence-1",
        "issuer-1",
        subject,
        "merge",
        TrustDecision.ALLOW,
        "2026-08-29T11:59:00+00:00",
        "2026-08-29T13:00:00+00:00",
        None,
        digest,
        "sha256:" + __import__("hashlib").sha256(payload).hexdigest(),
        "pytest",
        b"receipt",
        "sha256:" + __import__("hashlib").sha256(b"receipt").hexdigest(),
    )
    verifier = _Verifier()
    from product.evidence.ingestion import verify_external_ed25519_receipt

    receipt = verify_external_ed25519_receipt(
        verifier,
        issuer_id="issuer-1",
        key_id="key-1",
        payload=payload,
        signature=b"s" * 64,
        external_receipt=b"receipt",
    )
    assert verify_trust_reference_signature(
        reference,
        verifier,
        expected_issuer_id="issuer-1",
        key_id="key-1",
        payload=payload,
        signature=b"s" * 64,
        verification_receipt=receipt,
        observed_at="2026-08-29T12:00:00+00:00",
    )
    assert not verify_trust_reference_signature(
        reference,
        verifier,
        expected_issuer_id="issuer-2",
        key_id="key-1",
        payload=payload,
        signature=b"sig",
    )
    assert not verify_trust_reference_signature(
        reference,
        verifier,
        expected_issuer_id="issuer-1",
        key_id="key-1",
        payload=b"altered",
        signature=b"sig",
    )
    revoked = __import__("dataclasses").replace(reference, revoked_at="2026-08-29T12:01:00+00:00")
    assert not verify_trust_reference_signature(
        revoked,
        verifier,
        expected_issuer_id="issuer-1",
        key_id="key-1",
        payload=payload,
        signature=b"sig",
    )


@pytest.mark.parametrize(
    "field",
    (
        "repository_owner",
        "changed_paths",
        "base_sha",
        "head_sha",
        "base_tree_sha",
        "head_tree_sha",
        "diff_hash",
    ),
)
def test_tg1_subject_mutations_fail_closed(field):
    from dataclasses import replace

    context, ingestion, snapshot, runner, verification, reference, payload, make = (
        _accepted_tg1_tg2_fixture()
    )
    value = (
        "Other"
        if field == "repository_owner"
        else (
            "sha256:" + "0" * 64
            if field == "diff_hash"
            else ("e" * 40 if field.endswith("sha") else ("other.py",))
        )
    )
    with pytest.raises((ValueError, TypeError)):
        make(
            context,
            ingestion,
            acquisition_snapshot=replace(snapshot, **{field: value}),
            runner_result=runner,
            verification_receipt=verification,
            trust_reference=reference,
            verifier=_Verifier(),
            payload=payload,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(verification.external_receipt_hash,),
        )


@pytest.mark.parametrize(
    "variant", ("FAILED", "ZERO", "ONE", "SOURCE", "TREE", "ENV", "EXEC", "ATTEMPT")
)
def test_tg2_hostile_receipts_fail_closed(variant):
    from dataclasses import replace

    from product.execution.python_runner import RunnerStatus

    context, ingestion, snapshot, runner, verification, reference, payload, make = (
        _accepted_tg1_tg2_fixture()
    )
    if variant == "FAILED":
        hostile = _unsafe_replace(runner, status=RunnerStatus.FAILED_VERIFICATION)
    elif variant == "ZERO":
        hostile = replace(
            runner,
            status=RunnerStatus.UNVERIFIABLE,
            attempts=(),
            attempt_ids=(),
            artifact_hashes=(),
            reason_codes=("MISSING_BINDING",),
        )
    elif variant == "ONE":
        hostile = _unsafe_replace(
            runner,
            attempts=runner.attempts[:1],
            attempt_ids=runner.attempt_ids[:1],
            artifact_hashes=runner.artifact_hashes[:1],
        )
    else:
        attempt = runner.attempts[0]
        field, value = {
            "SOURCE": ("source_revision", "e" * 40),
            "TREE": ("source_tree", "e" * 40),
            "ENV": ("environment_hash", "sha256:" + "0" * 64),
            "EXEC": ("execution_id", "other"),
            "ATTEMPT": ("attempt_id", "other"),
        }[variant]
        hostile = _unsafe_replace(
            runner, attempts=(_unsafe_replace(attempt, **{field: value}), runner.attempts[1])
        )
    with pytest.raises((ValueError, TypeError)):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=hostile,
            verification_receipt=verification,
            trust_reference=reference,
            verifier=_Verifier(),
            payload=payload,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(verification.external_receipt_hash,),
        )


@pytest.mark.parametrize(
    "observed",
    [
        pytest.param("2026-08-29T11:00:00+00:00", id="expired"),
        pytest.param("2026-08-29T14:00:00+00:00", id="future"),
        pytest.param(None, id="missing"),
    ],
)
def test_reference_expired_future_or_missing_observed_at_fails(observed):
    from product.evidence.ingestion import (
        verify_trust_reference_signature,
    )

    context, ingestion, snapshot, runner, verification, reference, payload, make = (
        _accepted_tg1_tg2_fixture()
    )
    assert not verify_trust_reference_signature(
        reference,
        _Verifier(),
        expected_issuer_id="issuer-1",
        key_id="key-1",
        payload=payload,
        signature=b"s" * 64,
        verification_receipt=verification,
        observed_at=observed,
    )


@pytest.mark.parametrize(
    "field",
    (
        "key_id",
        "payload_hash",
        "signature_hash",
        "external_receipt_hash",
        "status",
        "revoked",
        "receipt_hash",
    ),
)
def test_verification_receipt_metadata_tamper_and_loader_fail_closed(field):
    from dataclasses import replace

    from product.evidence.ingestion import load_external_verification_receipt

    context, ingestion, snapshot, runner, verification, reference, payload, make = (
        _accepted_tg1_tg2_fixture()
    )
    value = (
        "wrong"
        if field in ("key_id", "status")
        else (not verification.revoked if field == "revoked" else "sha256:" + "0" * 64)
    )
    with pytest.raises((ValueError, TypeError)):
        hostile = replace(verification, **{field: value})
        load_external_verification_receipt(hostile.to_dict())


def test_external_hash_order_duplicate_and_typed_bypass_fail_closed():
    context, ingestion, snapshot, runner, verification, reference, payload, make = (
        _accepted_tg1_tg2_fixture()
    )
    args = dict(
        context=context,
        ingestion=ingestion,
        acquisition_snapshot=snapshot,
        runner_result=runner,
        verification_receipt=verification,
        trust_reference=reference,
        verifier=_Verifier(),
        payload=payload,
        signature=b"s" * 64,
        observed_at="2026-08-29T12:00:00+00:00",
    )
    with pytest.raises(ValueError, match="duplicates|sorted|CROSS_BOUND"):
        make(
            **args,
            external_receipt_hashes=(
                verification.external_receipt_hash,
                verification.external_receipt_hash,
            ),
        )
    with pytest.raises(ValueError, match="duplicates|sorted|CROSS_BOUND"):
        make(
            **args,
            external_receipt_hashes=("sha256:" + "f" * 64, verification.external_receipt_hash),
        )


def _resigned_reference(
    reference,
    *,
    issuer_id=None,
    key_id="key-1",
    subject_hash=None,
    action=None,
    decision=None,
    signature=b"s" * 64,
    external_receipt=b"receipt",
    acquisition_snapshot_hash="sha256:" + "0" * 64,
    runner_result_hash="sha256:" + "0" * 64,
):
    from product.evidence.ingestion import (
        build_external_signature_payload,
        verify_external_ed25519_receipt,
    )

    issuer_id = issuer_id or reference.issuer_id
    subject_hash = subject_hash or reference.subject_hash
    action = action or reference.action
    decision = decision or reference.decision.value
    receipt_hash = "sha256:" + __import__("hashlib").sha256(external_receipt).hexdigest()
    signed = build_external_signature_payload(
        issuer_id=issuer_id,
        key_id=key_id,
        evidence_id=reference.evidence_id,
        subject_hash=subject_hash,
        action=action,
        decision=decision,
        external_receipt_hash=receipt_hash,
        acquisition_snapshot_hash=acquisition_snapshot_hash,
        runner_result_hash=runner_result_hash,
    )
    verifier = _Verifier(key_id=key_id, signature=signature)
    receipt = verify_external_ed25519_receipt(
        verifier,
        issuer_id=issuer_id,
        key_id=key_id,
        payload=signed,
        signature=signature,
        external_receipt=external_receipt,
    )
    return (
        replace(
            reference,
            issuer_id=issuer_id,
            subject_hash=subject_hash,
            action=action,
            decision=type(reference.decision)(decision),
            signed_payload_hash="sha256:" + __import__("hashlib").sha256(signed).hexdigest(),
            external_verification_receipt=external_receipt,
            external_verification_receipt_hash=receipt_hash,
        ),
        signed,
        receipt,
        verifier,
        signature,
    )


@pytest.mark.parametrize(
    ("variant", "updates"),
    (
        ("issuer", {"issuer_id": "issuer-2"}),
        ("subject", {"subject_hash": "sha256:" + "9" * 64}),
        ("action", {"action": "release"}),
        ("decision", {"decision": "DENY"}),
    ),
)
def test_resigned_wrong_claims_reach_envelope_gate_and_fail_closed(variant, updates):
    context, ingestion, snapshot, runner, _, reference, _, make = _accepted_tg1_tg2_fixture()
    acq_hash = (
        "sha256:"
        + __import__("hashlib")
        .sha256(json.dumps(snapshot.to_dict(), sort_keys=True, separators=(",", ":")).encode())
        .hexdigest()
    )
    run_hash = (
        "sha256:"
        + __import__("hashlib")
        .sha256(json.dumps(runner.to_dict(), sort_keys=True, separators=(",", ":")).encode())
        .hexdigest()
    )
    hostile, signed, receipt, verifier, signature = _resigned_reference(
        reference, acquisition_snapshot_hash=acq_hash, runner_result_hash=run_hash, **updates
    )
    with pytest.raises(ValueError, match="CROSS_BOUND|UNTRUSTED"):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=runner,
            verification_receipt=receipt,
            trust_reference=hostile,
            verifier=verifier,
            payload=signed,
            signature=signature,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("role", "POLICY"),
        ("verification_method", "unapproved-method"),
    ),
)
def test_wrong_role_and_method_reach_envelope_gate_and_fail_closed(field, value):
    from product.evidence.ingestion import TrustRole

    context, ingestion, snapshot, runner, receipt, reference, signed, make = (
        _accepted_tg1_tg2_fixture()
    )
    hostile = replace(reference, **{field: TrustRole(value) if field == "role" else value})
    with pytest.raises(ValueError, match="CROSS_BOUND"):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=runner,
            verification_receipt=receipt,
            trust_reference=hostile,
            verifier=_Verifier(),
            payload=signed,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


@pytest.mark.parametrize("variant", ("wrong-key", "wrong-signature"))
def test_wrong_key_or_signature_produces_invalid_receipt_and_fails_envelope(variant):
    from product.evidence.ingestion import verify_external_ed25519_receipt

    context, ingestion, snapshot, runner, _, reference, signed, make = _accepted_tg1_tg2_fixture()
    key_id = "key-2" if variant == "wrong-key" else "key-1"
    signature = b"x" * 64 if variant == "wrong-signature" else b"s" * 64
    receipt = verify_external_ed25519_receipt(
        _Verifier(),
        issuer_id="issuer-1",
        key_id=key_id,
        payload=signed,
        signature=signature,
        external_receipt=b"receipt",
    )
    assert receipt.status == "INVALID"
    with pytest.raises(ValueError, match="UNTRUSTED_EXTERNAL_RECEIPT"):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=runner,
            verification_receipt=receipt,
            trust_reference=reference,
            verifier=_Verifier(),
            payload=signed,
            signature=signature,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


@pytest.mark.parametrize("variant", ("malformed", "noncanonical", "extra"))
def test_malformed_noncanonical_and_extra_signed_payloads_fail_actual_verification(variant):
    from product.evidence.ingestion import verify_external_ed25519_receipt

    context, ingestion, snapshot, runner, _, reference, signed, make = _accepted_tg1_tg2_fixture()
    if variant == "malformed":
        hostile = b"{"
    else:
        decoded = json.loads(signed)
        if variant == "extra":
            decoded["extra"] = "field"
        hostile = json.dumps(decoded, sort_keys=variant != "noncanonical").encode()
        if hostile == signed:
            hostile += b" "
    receipt = verify_external_ed25519_receipt(
        _Verifier(),
        issuer_id="issuer-1",
        key_id="key-1",
        payload=hostile,
        signature=b"s" * 64,
        external_receipt=b"receipt",
    )
    hostile_reference = replace(
        reference,
        signed_payload_hash="sha256:" + __import__("hashlib").sha256(hostile).hexdigest(),
    )
    with pytest.raises(ValueError, match="UNVERIFIED_EXTERNAL_RECEIPT"):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=runner,
            verification_receipt=receipt,
            trust_reference=hostile_reference,
            verifier=_Verifier(),
            payload=hostile,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


def test_signature_replay_against_separately_valid_context_subject_fails():
    original = _accepted_tg1_tg2_fixture()
    replay_target = _accepted_tg1_tg2_fixture(observed_at="2026-08-29T12:00:01+00:00")
    _, _, _, _, receipt, reference, signed, _ = original
    context, ingestion, snapshot, runner, _, _, _, make = replay_target
    with pytest.raises(ValueError, match="CROSS_BOUND:issuer_subject"):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=runner,
            verification_receipt=receipt,
            trust_reference=reference,
            verifier=_Verifier(),
            payload=signed,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


@pytest.mark.parametrize("component", ("snapshot", "runner"))
def test_internally_valid_alternate_tg1_tg2_receipt_is_cross_bound(component):
    context, ingestion, snapshot, runner, receipt, reference, signed, make = (
        _accepted_tg1_tg2_fixture()
    )
    _, _, alternate_snapshot, alternate_runner, _, _, _, _ = _accepted_tg1_tg2_fixture(seed=1)
    if component == "snapshot":
        snapshot = alternate_snapshot
    else:
        runner = alternate_runner
    with pytest.raises(ValueError, match="CROSS_BOUND:TG1_TG2"):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=runner,
            verification_receipt=receipt,
            trust_reference=reference,
            verifier=_Verifier(),
            payload=signed,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


def test_signature_cannot_be_replayed_after_acquisition_metadata_substitution():
    context, ingestion, snapshot, runner, receipt, reference, signed, make = (
        _accepted_tg1_tg2_fixture()
    )
    checks = (("ci", "sha256:" + "f" * 64),)
    substituted = _unsafe_replace(snapshot, checks=checks)
    with pytest.raises(ValueError, match="CROSS_BOUND:TG1_TG2"):
        make(
            context,
            ingestion,
            acquisition_snapshot=substituted,
            runner_result=runner,
            verification_receipt=receipt,
            trust_reference=reference,
            verifier=_Verifier(),
            payload=signed,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


def test_signature_cannot_be_replayed_after_runner_artifact_substitution():
    context, ingestion, snapshot, runner, receipt, reference, signed, make = (
        _accepted_tg1_tg2_fixture()
    )
    attempt = runner.attempts[0]
    substituted_attempt = _unsafe_replace(
        attempt,
        artifact_hash="sha256:" + "f" * 64,
    )
    substituted = _unsafe_replace(
        runner,
        attempts=(substituted_attempt, runner.attempts[1]),
        artifact_hashes=(substituted_attempt.artifact_hash, runner.attempts[1].artifact_hash),
    )
    with pytest.raises(ValueError, match="CROSS_BOUND:TG1_TG2"):
        make(
            context,
            ingestion,
            acquisition_snapshot=snapshot,
            runner_result=substituted,
            verification_receipt=receipt,
            trust_reference=reference,
            verifier=_Verifier(),
            payload=signed,
            signature=b"s" * 64,
            observed_at="2026-08-29T12:00:00+00:00",
            external_receipt_hashes=(receipt.external_receipt_hash,),
        )


@pytest.mark.parametrize("field", ("artifact_hash", "outcome_hash", "stdout", "junit", "exit_code"))
def test_native_runner_loader_recomputes_all_evidence_hashes(field):
    _, _, _, runner, _, _, _, _ = _accepted_tg1_tg2_fixture()
    data = runner.to_dict()
    attempt = data["attempts"][0]
    if field in {"artifact_hash", "outcome_hash"}:
        attempt[field] = "sha256:" + "f" * 64
    elif field == "stdout":
        attempt[field] = "ff"
    elif field == "junit":
        attempt[field] = "3c"
    else:
        attempt[field] = 1
    with pytest.raises(
        ValueError, match="(artifact_hash|outcome_hash|junit|inadequate|truth table)"
    ):
        type(runner).from_dict(data)


def test_native_runner_loader_rejects_forged_profile_limits():
    _, _, _, runner, _, _, _, _ = _accepted_tg1_tg2_fixture()
    data = runner.to_dict()
    data["profile"]["timeout_seconds"] = 301
    with pytest.raises(ValueError, match="profile_hash"):
        type(runner).from_dict(data)


@pytest.mark.parametrize("where", ("top", "profile", "attempt"))
def test_native_runner_loader_rejects_schema_key_substitution(where):
    _, _, _, runner, _, _, _, _ = _accepted_tg1_tg2_fixture()
    data = runner.to_dict()
    target = (
        data if where == "top" else data["profile"] if where == "profile" else data["attempts"][0]
    )
    target["unexpected"] = True
    with pytest.raises(ValueError, match="schema keys"):
        type(runner).from_dict(data, profile=data["profile"])


def test_native_runner_loader_rejects_oversized_streams():
    _, _, _, runner, _, _, _, _ = _accepted_tg1_tg2_fixture()
    data = runner.to_dict()
    data["attempts"][0]["stdout"] = (b"x" * (1_048_576 + 1)).hex()
    with pytest.raises(ValueError, match="stdout"):
        type(runner).from_dict(data)


@pytest.mark.parametrize(
    ("status", "reasons", "count"),
    (
        ("UNVERIFIABLE", ["invented"], 0),
        ("UNVERIFIABLE", ["MISSING_BINDING"], 1),
        ("FAILED_VERIFICATION", [], 2),
    ),
)
def test_native_runner_loader_rejects_arbitrary_status_shapes(status, reasons, count):
    _, _, _, runner, _, _, _, _ = _accepted_tg1_tg2_fixture()
    data = runner.to_dict()
    data["status"] = status
    data["reason_codes"] = reasons
    if count == 0:
        data["attempts"] = []
        data["attempt_ids"] = []
        data["artifact_hashes"] = []
    elif count == 1:
        data["attempts"] = data["attempts"][:1]
        data["attempt_ids"] = data["attempt_ids"][:1]
        data["artifact_hashes"] = data["artifact_hashes"][:1]
    with pytest.raises(ValueError, match="(truth table|reason|two attempts|zero or two)"):
        type(runner).from_dict(data)
