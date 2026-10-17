"""#296 G2: live-behavior witness consumer adapter (RED-first contract).

Control ids follow the G0 design report on nexus-core#296 (section 4):
P1-P2 positive, N1-N10 negative, C1-C3 compatibility. The Owner decision
(G1) is binding: Option A carrying-layer adapter, Sigstore trust root (fail
closed), predeclared execution_id replay binding, UNKNOWN_INFRA -> MISSING,
source mismatch -> STALE, binary/identity mismatch -> CROSS_BOUND, schema id
``nexus.live-behavior-witness.v1-experimental``.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from product.certification import CertificationDisposition, CertificationPolicy, certify_result
from product.clients.receipt_authentication import (
    AUTHENTICATED,
    NOT_AUTHENTICATED,
    UNAVAILABLE,
    ReceiptAuthentication,
    ReceiptSignerPolicy,
    SigstoreReceiptAuthenticator,
    signer_policy_for_identity,
)
from product.completion.sufficiency import (
    SUFFICIENCY_CLAIM_CEILING,
    EvidenceSufficiency,
    SufficiencyRequest,
    analyze_evidence_sufficiency,
)
from product.evidence import (
    AcceptanceContract,
    Applicability,
    ChangeSet,
    EvidenceBundle,
    ExpectedEvidenceSubject,
    IntegrityStatus,
    Observation,
    ObservationStatus,
    RequirementMode,
    VerificationPlan,
)
from product.kernel import CertificationInput, certify
from product.protocol.runtime_handoff import (
    HANDOFF_CLAIM_CEILING,
    HANDOFF_NON_CLAIMS,
    RUNTIME_HANDOFF_SCHEMA_ID,
)
from product.verification import CoverageCategory, VerificationStatus

MODULE = "product.adapters.live_behavior_witness"
SIGNER = (
    "https://github.com/James3014/Nexus-new/.github/workflows/live-witness.yml@refs/heads/main"
)
OTHER_SIGNER = (
    "https://github.com/James3014/Nexus-new/.github/workflows/other.yml@refs/heads/main"
)
NOW = "2026-10-17T10:00:30Z"
H = "sha256:" + "1" * 64


def _h(ch: str) -> str:
    return "sha256:" + ch * 64


@pytest.fixture
def lbw() -> ModuleType:
    return importlib.import_module(MODULE)


class FakeSigstore:
    """Deterministic stand-in for SigstoreReceiptAuthenticator.

    Authenticates only when the bundle's message digest equals the exact
    witness bytes and its (fake) certificate identity equals the policy.
    """

    def __init__(self, forced_status: str | None = None) -> None:
        self.forced_status = forced_status
        self.calls = 0

    def authenticate(
        self, *, receipt_bytes: bytes, bundle_json: bytes, policy: ReceiptSignerPolicy
    ) -> ReceiptAuthentication:
        self.calls += 1
        if self.forced_status is not None:
            return ReceiptAuthentication(self.forced_status, "forced")
        bundle = json.loads(bundle_json)
        digest = base64.b64decode(bundle["messageSignature"]["messageDigest"]["digest"])
        if digest != hashlib.sha256(receipt_bytes).digest():
            return ReceiptAuthentication(NOT_AUTHENTICATED, "signature mismatch")
        if bundle["fakeCertificateIdentity"] != policy.identity:
            return ReceiptAuthentication(NOT_AUTHENTICATED, "identity mismatch")
        return ReceiptAuthentication(AUTHENTICATED, policy.identity)


def _sign(witness_bytes: bytes, identity: str = SIGNER) -> bytes:
    return json.dumps(
        {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "fakeCertificateIdentity": identity,
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(hashlib.sha256(witness_bytes).digest()).decode(),
                },
                "signature": "ZmFrZQ==",
            },
        }
    ).encode()


def _promise(lbw: ModuleType, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "issue_ref": "James3014/Nexus-new#2453",
        "issue_contract_hash": _h("2"),
        "promise_id": "gateway-route-fix",
        "promise_generation": 3,
        "entry_id": "mcp.gateway",
        "action_id": "route.candidate",
        "input_digest": _h("3"),
        "probe_ids": ("route-entered",),
        "desired_source_revision": "a" * 40,
        "expected_runtime_identity": _h("4"),
        "execution_id": "exec-2026-10-17-001",
        "attempt_id": "attempt-1",
        "expected_side_effect_ids": ("receipt-written",),
        "max_age_seconds": 3600,
        "signer_identity": SIGNER,
    }
    values.update(overrides)
    return lbw.LiveBehaviorPromise(**values)


def _artifacts() -> list[dict[str, str]]:
    return [{"id": "receipt.json", "sha256": _h("5")}, {"id": "trace.json", "sha256": _h("6")}]


def _witness(lbw: ModuleType, promise: Any, **overrides: Any) -> dict[str, Any]:
    artifacts = _artifacts()
    value: dict[str, Any] = {
        "schema": lbw.LIVE_BEHAVIOR_WITNESS_SCHEMA,
        "issue_ref": promise.issue_ref,
        "issue_contract_hash": promise.issue_contract_hash,
        "promise_id": promise.promise_id,
        "promise_generation": promise.promise_generation,
        "entry_id": promise.entry_id,
        "action_id": promise.action_id,
        "input_digest": promise.input_digest,
        "execution_id": promise.execution_id,
        "attempt_id": promise.attempt_id,
        "loaded_source_revision": promise.desired_source_revision,
        "observed_runtime_identity": promise.expected_runtime_identity,
        "readiness_status": "READY",
        "producer_software_hash": _h("7"),
        "probes": [{"probe_id": p, "hit": True} for p in promise.probe_ids],
        "result_class": "PASS",
        "side_effects": list(promise.expected_side_effect_ids),
        "artifacts": artifacts,
        "artifacts_digest": lbw.live_witness_artifacts_digest(artifacts),
        "started_at": "2026-10-17T10:00:00Z",
        "finished_at": "2026-10-17T10:00:05Z",
        "observed_at": "2026-10-17T10:00:05Z",
        "expires_at": "2026-10-17T11:00:05Z",
    }
    value.update(overrides)
    return value


def _encode(witness: dict[str, Any]) -> bytes:
    return json.dumps(witness, sort_keys=True, separators=(",", ":")).encode()


def _contract(
    promise: Any, *, generation: int | None = None, extra_unit: bool = True
) -> AcceptanceContract:
    subjects = list(promise.expected_subjects)
    verifiers = list(promise.subject_ids)
    if extra_unit:
        subjects.append(
            ExpectedEvidenceSubject(
                "verifier/unit", "unit-tests", RequirementMode.REQUIRED, Applicability.APPLICABLE
            )
        )
        verifiers.append("unit")
    return AcceptanceContract(
        contract_id="issue-2453",
        requirements_hash=H,
        required_verifier_ids=tuple(verifiers),
        allowed_paths=("src/gateway.py",),
        deletion_policy="FORBID",
        expected_subjects=tuple(subjects),
        universe_generation=promise.promise_generation if generation is None else generation,
    )


def _binding(contract: AcceptanceContract) -> tuple[ChangeSet, VerificationPlan]:
    change_set = ChangeSet("cs-1", "b" * 40, "a" * 40, _h("8"), ("src/gateway.py",))
    plan = VerificationPlan("plan-1", contract.hash, change_set.hash, contract.required_verifier_ids)
    return change_set, plan


def _unit_observation() -> Observation:
    return Observation(
        "unit", "pytest-junit", _h("9"), ObservationStatus.PASS, "verifier/unit", "unit-tests"
    )


def _run(
    lbw: ModuleType,
    *,
    promise: Any = None,
    witness: dict[str, Any] | None = None,
    witness_bytes: bytes | None | str = "auto",
    bundle_json: bytes | None | str = "auto",
    authenticator: Any = "auto",
    signer_policy: Any = "auto",
    contract: AcceptanceContract | None = None,
    now: str = NOW,
    other: tuple[Observation, ...] | None = None,
) -> tuple[Any, AcceptanceContract, ChangeSet, VerificationPlan]:
    promise = promise if promise is not None else _promise(lbw)
    contract = contract if contract is not None else _contract(promise)
    change_set, plan = _binding(contract)
    if witness_bytes == "auto":
        witness_bytes = _encode(witness if witness is not None else _witness(lbw, promise))
    if bundle_json == "auto":
        bundle_json = _sign(witness_bytes) if isinstance(witness_bytes, bytes) else None
    outcome = lbw.verify_live_behavior_witness(
        promise=promise,
        contract=contract,
        change_set=change_set,
        plan=plan,
        witness_bytes=witness_bytes,
        bundle_json=bundle_json,
        authenticator=FakeSigstore() if authenticator == "auto" else authenticator,
        signer_policy=signer_policy_for_identity(SIGNER)
        if signer_policy == "auto"
        else signer_policy,
        now=now,
        other_observations=(_unit_observation(),) if other is None else other,
    )
    return outcome, contract, change_set, plan


def _disposition(outcome: Any) -> CertificationDisposition:
    return certify_result(outcome.result, CertificationPolicy())


# --------------------------------------------------------------------------- P


def test_p1_full_valid_witness_is_verified_covered_sufficient_but_not_certified(
    lbw: ModuleType,
) -> None:
    outcome, contract, change_set, plan = _run(lbw)
    result = outcome.result
    assert result.status is VerificationStatus.VERIFIED
    assert result.integrity is IntegrityStatus.VALID
    assert result.coverage is not None
    assert {e.category for e in result.coverage.entries} == {CoverageCategory.COVERED}
    assert outcome.evidence is not None
    analysis = analyze_evidence_sufficiency(
        SufficiencyRequest("req-1", "issue-2453"), contract, change_set, plan, outcome.evidence
    )
    assert analysis.sufficiency is EvidenceSufficiency.SUFFICIENT
    assert analysis.claim_ceiling == SUFFICIENCY_CLAIM_CEILING
    assert _disposition(outcome) is not CertificationDisposition.CERTIFIED
    assert _disposition(outcome) is CertificationDisposition.BLOCKED
    assert outcome.claim_ceiling == lbw.LIVE_WITNESS_CLAIM_CEILING
    live = [o for o in outcome.observations if o.logical_subject_id == "live/gateway-route-fix/route-entered"]
    assert len(live) == 1
    assert live[0].evidence_kind == lbw.LIVE_BEHAVIOR_EVIDENCE_KIND
    assert live[0].artifact_hash == outcome.witness_digest


def test_p2_authenticated_actual_failure_is_failed_verification_not_cross_bound(
    lbw: ModuleType,
) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, result_class="ACTUAL_FAILED"))
    result = outcome.result
    assert result.status is VerificationStatus.FAILED_VERIFICATION
    assert result.integrity is IntegrityStatus.VALID
    assert "EVIDENCE_CLAIM_FAILED" in result.reason_codes
    assert not any(code.startswith("CROSS_BOUND") for code in result.reason_codes)
    assert _disposition(outcome) is CertificationDisposition.REJECTED


def test_p2b_unexpected_side_effect_is_an_observed_failure(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    witness = _witness(lbw, promise, side_effects=["receipt-written", "db-dropped"])
    outcome, *_ = _run(lbw, witness=witness)
    assert outcome.result.status is VerificationStatus.FAILED_VERIFICATION
    assert "EVIDENCE_CLAIM_FAILED" in outcome.result.reason_codes


# --------------------------------------------------------------------------- N


def test_n1_handoff_ready_receipt_never_fills_the_live_subject(lbw: ModuleType) -> None:
    handoff_ready = {
        "schema": RUNTIME_HANDOFF_SCHEMA_ID,
        "verdict": "READY",
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
        "non_claims": list(HANDOFF_NON_CLAIMS),
        "receipt_hash": _h("a"),
    }
    outcome, *_ = _run(lbw, witness_bytes=_encode(handoff_ready))
    assert outcome.result.status is VerificationStatus.UNVERIFIABLE
    assert outcome.result.integrity is IntegrityStatus.MALFORMED
    assert outcome.evidence is None
    assert _disposition(outcome) is not CertificationDisposition.CERTIFIED


def test_n1_ready_daemon_but_probe_not_hit_is_not_covered_missing(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    witness = _witness(
        lbw,
        promise,
        probes=[{"probe_id": "route-entered", "hit": False}],
        result_class="NOT_EXERCISED",
    )
    outcome, *_ = _run(lbw, witness=witness)
    result = outcome.result
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.MISSING
    assert "live/gateway-route-fix/route-entered" in result.reason_codes
    assert result.coverage is not None
    live = [e for e in result.coverage.entries if e.logical_subject_id.startswith("live/")]
    assert [e.category for e in live] == [CoverageCategory.NOT_COVERED]
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n2_wrong_source_revision_is_stale(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, loaded_source_revision="c" * 40))
    assert outcome.result.integrity is IntegrityStatus.STALE
    assert "STALE:subject" in outcome.result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n2_wrong_binary_identity_is_cross_bound_rejected(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, observed_runtime_identity=_h("d")))
    assert outcome.result.integrity is IntegrityStatus.CROSS_BOUND
    assert "CROSS_BOUND:runtime" in outcome.result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.REJECTED


@pytest.mark.parametrize(
    "field,value", [("execution_id", "exec-2026-10-16-999"), ("attempt_id", "attempt-0")]
)
def test_n3_replayed_execution_is_cross_bound(lbw: ModuleType, field: str, value: str) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, **{field: value}))
    assert outcome.result.integrity is IntegrityStatus.CROSS_BOUND
    assert "CROSS_BOUND:execution" in outcome.result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.REJECTED


def test_n3_old_generation_witness_is_stale(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, promise_generation=2))
    assert outcome.result.integrity is IntegrityStatus.STALE
    assert "STALE:generation" in outcome.result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n3_contract_at_other_generation_is_stale_and_hash_differs(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    old_contract = _contract(promise, generation=2)
    assert old_contract.hash != _contract(promise).hash
    assert old_contract.universe_identity != _contract(promise).universe_identity
    outcome, *_ = _run(lbw, contract=old_contract)
    assert outcome.result.integrity is IntegrityStatus.STALE
    assert "STALE:generation" in outcome.result.reason_codes


def test_n3_contract_not_declaring_promise_subjects_is_cross_bound(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    other = _promise(lbw, promise_id="other-promise")
    outcome, *_ = _run(lbw, promise=promise, contract=_contract(other))
    assert outcome.result.integrity is IntegrityStatus.CROSS_BOUND
    assert "CROSS_BOUND:promise_contract" in outcome.result.reason_codes


@pytest.mark.parametrize(
    "field,value",
    [
        ("issue_ref", "James3014/Nexus-new#9999"),
        ("issue_contract_hash", _h("e")),
        ("promise_id", "other"),
        ("entry_id", "other.entry"),
        ("action_id", "other.action"),
        ("input_digest", _h("f")),
    ],
)
def test_n3_witness_for_other_promise_is_cross_bound(
    lbw: ModuleType, field: str, value: str
) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, **{field: value}))
    assert outcome.result.integrity is IntegrityStatus.CROSS_BOUND
    assert "CROSS_BOUND:promise" in outcome.result.reason_codes


def test_n4_untrusted_signer_is_cross_bound_rejected(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    data = _encode(_witness(lbw, promise))
    outcome, *_ = _run(lbw, witness_bytes=data, bundle_json=_sign(data, OTHER_SIGNER))
    assert outcome.result.integrity is IntegrityStatus.CROSS_BOUND
    assert "CROSS_BOUND:issuer" in outcome.result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.REJECTED


def test_n4_signer_policy_not_matching_promise_is_cross_bound(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, signer_policy=signer_policy_for_identity(OTHER_SIGNER))
    assert outcome.result.integrity is IntegrityStatus.CROSS_BOUND
    assert "CROSS_BOUND:signer_identity" in outcome.result.reason_codes


def test_n4_payload_bit_flip_after_signing_is_tampered(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    data = _encode(_witness(lbw, promise))
    bundle = _sign(data)
    tampered = data.replace(b'"PASS"', b'"PASs"')
    assert tampered != data
    outcome, *_ = _run(lbw, witness_bytes=tampered, bundle_json=bundle)
    assert outcome.result.integrity is IntegrityStatus.TAMPERED
    assert _disposition(outcome) is CertificationDisposition.REJECTED


def test_n4_artifacts_digest_mismatch_is_tampered(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, artifacts_digest=_h("0")))
    assert outcome.result.integrity is IntegrityStatus.TAMPERED
    assert "TAMPERED:artifacts_digest" in outcome.result.reason_codes


def test_n4_self_computed_hash_without_signature_is_not_authentication(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    data = _encode(_witness(lbw, promise))
    outcome, *_ = _run(lbw, witness_bytes=data, bundle_json=None)
    assert outcome.result.status is VerificationStatus.UNVERIFIABLE
    assert outcome.result.integrity is IntegrityStatus.MISSING
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n5_no_witness_is_missing(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, witness_bytes=None)
    result = outcome.result
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.MISSING
    assert "live/gateway-route-fix/route-entered" in result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n5_no_witness_and_no_other_observations_is_missing(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, witness_bytes=None, other=())
    assert outcome.result.integrity is IntegrityStatus.MISSING
    assert outcome.evidence is None
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n6_partial_probe_coverage_names_the_missing_subject(lbw: ModuleType) -> None:
    promise = _promise(lbw, probe_ids=("route-entered", "receipt-emitted"))
    witness = _witness(
        lbw,
        promise,
        probes=[
            {"probe_id": "route-entered", "hit": True},
            {"probe_id": "receipt-emitted", "hit": False},
        ],
        result_class="PARTIAL",
    )
    outcome, *_ = _run(lbw, promise=promise, witness=witness)
    result = outcome.result
    assert result.integrity is IntegrityStatus.MISSING
    assert "live/gateway-route-fix/receipt-emitted" in result.reason_codes
    assert "live/gateway-route-fix/route-entered" not in result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n6_pass_label_cannot_hide_unhit_probe(lbw: ModuleType) -> None:
    promise = _promise(lbw, probe_ids=("route-entered", "receipt-emitted"))
    witness = _witness(
        lbw,
        promise,
        probes=[
            {"probe_id": "route-entered", "hit": True},
            {"probe_id": "receipt-emitted", "hit": False},
        ],
        result_class="PASS",
    )
    outcome, *_ = _run(lbw, promise=promise, witness=witness)
    assert outcome.result.integrity is IntegrityStatus.MISSING
    assert "live/gateway-route-fix/receipt-emitted" in outcome.result.reason_codes


def test_n7_expired_witness_is_stale(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, now="2026-10-17T12:00:00Z")
    assert outcome.result.integrity is IntegrityStatus.STALE
    assert "STALE:observation" in outcome.result.reason_codes
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n7_witness_older_than_max_age_is_stale(lbw: ModuleType) -> None:
    promise = _promise(lbw, max_age_seconds=10)
    outcome, *_ = _run(lbw, promise=promise)
    assert outcome.result.integrity is IntegrityStatus.STALE
    assert "STALE:observation" in outcome.result.reason_codes


def test_n7_witness_from_the_future_is_stale(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, now="2026-10-17T09:00:00Z")
    assert outcome.result.integrity is IntegrityStatus.STALE


def test_n8_producer_reviewer_ids_change_nothing(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    plain, *_ = _run(lbw)
    reviewed, *_ = _run(
        lbw, witness=_witness(lbw, promise, reviewer_ids=["james3014", "owner-approval"])
    )
    assert reviewed.result.status is plain.result.status
    assert reviewed.result.integrity is plain.result.integrity
    assert reviewed.result.reason_codes == plain.result.reason_codes
    assert reviewed.result.coverage is not None and plain.result.coverage is not None
    assert [e.category for e in reviewed.result.coverage.entries] == [
        e.category for e in plain.result.coverage.entries
    ]
    assert _disposition(reviewed) is _disposition(plain) is CertificationDisposition.BLOCKED
    for name in ("authority_present", "approval_present", "signing_present", "accepted"):
        assert not hasattr(reviewed, name)


@pytest.mark.parametrize(
    "extra",
    [
        {"stdout": "hello"},
        {"stderr": "trace"},
        {"raw_output": "..."},
        {"env": {"HOME": "/x"}},
        {"api_key": "sk-123"},
        {"token": "ghs_x"},
        {"unexpected_field": 1},
    ],
)
def test_n9_raw_output_secret_or_unknown_fields_are_malformed(
    lbw: ModuleType, extra: dict[str, Any]
) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, **extra))
    assert outcome.result.integrity is IntegrityStatus.MALFORMED
    assert _disposition(outcome) is CertificationDisposition.REJECTED


def test_n9_nested_secret_in_artifact_entry_is_malformed(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    artifacts: list[dict[str, str]] = [{"id": "a", "sha256": _h("5"), "content": "secret"}]
    witness = _witness(
        lbw,
        promise,
        artifacts=artifacts,
        artifacts_digest=_h("0"),
    )
    outcome, *_ = _run(lbw, witness=witness)
    assert outcome.result.integrity is IntegrityStatus.MALFORMED


@pytest.mark.parametrize(
    "witness_bytes", [b"not json", b"[]", b'{"schema":"nexus.live-behavior-witness.v2"}']
)
def test_n9_unparseable_or_wrong_schema_is_malformed(lbw: ModuleType, witness_bytes: bytes) -> None:
    outcome, *_ = _run(lbw, witness_bytes=witness_bytes)
    assert outcome.result.integrity is IntegrityStatus.MALFORMED


def test_n10_authenticator_unavailable_fails_closed_as_missing(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, authenticator=FakeSigstore(UNAVAILABLE))
    assert outcome.result.status is VerificationStatus.UNVERIFIABLE
    assert outcome.result.integrity is IntegrityStatus.MISSING
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n10_no_authenticator_fails_closed(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, authenticator=None)
    assert outcome.result.integrity is IntegrityStatus.MISSING
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n10_unknown_infra_result_is_missing_blocked(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw, witness=_witness(lbw, promise, result_class="UNKNOWN_INFRA"))
    assert outcome.result.integrity is IntegrityStatus.MISSING
    assert _disposition(outcome) is CertificationDisposition.BLOCKED


def test_n10_real_sigstore_authenticator_never_verifies_a_fake_bundle(lbw: ModuleType) -> None:
    outcome, *_ = _run(lbw, authenticator=SigstoreReceiptAuthenticator(offline=True))
    assert outcome.result.status is VerificationStatus.UNVERIFIABLE
    assert _disposition(outcome) is not CertificationDisposition.CERTIFIED


# --------------------------------------------------------------------------- C

LEGACY_CONTRACT_HASH = "sha256:d289348c496e92236b87658b6159118f6034ea14445047727c8b139502e60519"
LEGACY_BUNDLE_HASH = "sha256:af45059b622bf9d9274934a2ad24f902fb2a3cb7a4b589482733e4116c466171"
LEGACY_RECEIPT_HASH = "sha256:cf4c091e66126148be42c2aa613cc696a8cb98e374cfe9da2564ccb64572e3e3"


def test_c1_legacy_contract_bundle_and_receipt_hashes_are_byte_identical(
    lbw: ModuleType,
) -> None:
    contract = AcceptanceContract("legacy-c1", H, ("unit",), ("src/a.py",), "FORBID")
    change_set = ChangeSet("cs-1", "base", "head", _h("b"), ("src/a.py",))
    plan = VerificationPlan("plan-1", contract.hash, change_set.hash, ("unit",))
    bundle = EvidenceBundle(
        "b-1",
        contract.hash,
        change_set.hash,
        plan.hash,
        (Observation("unit", "art-1", _h("c"), ObservationStatus.PASS),),
    )
    receipt = certify(
        CertificationInput(
            contract,
            change_set,
            plan,
            bundle,
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        )
    ).receipt
    assert contract.hash == LEGACY_CONTRACT_HASH
    assert bundle.hash == LEGACY_BUNDLE_HASH
    assert receipt.hash == LEGACY_RECEIPT_HASH


def test_c1_adapter_adds_no_core_protocol_fields(lbw: ModuleType) -> None:
    import dataclasses

    assert [f.name for f in dataclasses.fields(Observation)] == [
        "verifier_id",
        "artifact_id",
        "artifact_hash",
        "status",
        "logical_subject_id",
        "evidence_kind",
    ]
    assert {s.value for s in ObservationStatus} == {"PASS", "FAIL"}
    assert lbw.LIVE_BEHAVIOR_WITNESS_SCHEMA == "nexus.live-behavior-witness.v1-experimental"


async def test_c2_runtime_still_rejects_a_live_witness_universe_contract(
    lbw: ModuleType, tmp_path: Path
) -> None:
    from product.runtime.service import RuntimeCertificationService
    from tests.product.test_http_runtime import _valid_request_payload

    db = tmp_path / "nexus-core" / "ledger.sqlite3"
    db.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    svc = RuntimeCertificationService(db_path=db)
    promise = _promise(lbw)
    payload = _valid_request_payload()
    payload["acceptance_contract"]["expected_subjects"] = [
        {
            "logical_subject_id": s.logical_subject_id,
            "evidence_kind": s.evidence_kind,
            "requirement_mode": s.requirement_mode.value,
            "applicability": s.applicability.value,
        }
        for s in promise.expected_subjects
    ]
    payload["acceptance_contract"]["universe_generation"] = promise.promise_generation
    status, body = await svc.submit_certification(payload)
    assert status == 422
    assert body["code"] == "UNSUPPORTED_UNIVERSE_ON_RUNTIME_PATH"


def test_c3_witness_pass_cannot_raise_the_not_certified_ceiling(lbw: ModuleType) -> None:
    promise = _promise(lbw)
    outcome, *_ = _run(lbw)
    assert outcome.claim_ceiling == "LIVE_BEHAVIOR_OBSERVATION_ONLY_NOT_CERTIFIED"
    assert _disposition(outcome) is CertificationDisposition.BLOCKED
    claimed, *_ = _run(lbw, witness=_witness(lbw, promise, result_class="CERTIFIED"))
    assert claimed.result.integrity is IntegrityStatus.MALFORMED


def test_c3_adapter_source_never_mints_policy_facts(lbw: ModuleType) -> None:
    source = inspect.getsource(lbw)
    for forbidden in (
        "CertificationPolicy(",
        "CertificationInput(",
        "authority_present",
        "approval_present",
        "signing_present",
        "policy_accepted",
        "ingest_evidence",
        "make_identity_envelope",
        "product.clients",
    ):
        assert forbidden not in source, forbidden
