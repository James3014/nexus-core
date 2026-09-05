from dataclasses import replace

import pytest

from product.certification import CertificationDisposition, CertificationPolicy
from product.certification.receipt import Receipt
from product.evidence import EvidenceBundle, IntegrityStatus, _hash
from product.kernel import (
    CertificationInput,
    certify,
    validate_receipt,
    validate_serialized_receipt,
)
from product.protocol import CERTIFICATION_RECEIPT_SCHEMA, EVIDENCE_BUNDLE_SCHEMA
from product.verification import reduce_verification


def _replace_receipt(receipt, **changes):
    candidate = object.__new__(type(receipt))
    for field in receipt.__dataclass_fields__:
        object.__setattr__(candidate, field, changes.get(field, getattr(receipt, field)))
    return candidate


def _input(observations=None):
    contract = __import__("product.evidence", fromlist=["AcceptanceContract"]).AcceptanceContract(
        "ac", _hash("requirements"), ("unit",), ("src/a.py",), "FORBID"
    )
    change = __import__("product.evidence", fromlist=["ChangeSet"]).ChangeSet(
        "cs", "base", "head", _hash("diff"), ("src/a.py",)
    )
    plan = __import__("product.evidence", fromlist=["VerificationPlan"]).VerificationPlan(
        "plan", contract.hash, change.hash, ("unit",)
    )
    Observation = __import__("product.evidence", fromlist=["Observation"]).Observation
    ObservationStatus = __import__(
        "product.evidence", fromlist=["ObservationStatus"]
    ).ObservationStatus
    evidence = __import__("product.evidence", fromlist=["EvidenceBundle"]).EvidenceBundle(
        "bundle",
        contract.hash,
        change.hash,
        plan.hash,
        (Observation("unit", "artifact", _hash("artifact"), ObservationStatus.PASS),)
        if observations is None
        else observations,
    )
    return CertificationInput(contract, change, plan, evidence, True, True, True, True)


def test_canonical_json_is_stable_and_rejects_cycles():
    from product.evidence import canonical_json

    value = {"b": [2, 1], "a": True}
    assert canonical_json(value) == canonical_json({"a": True, "b": [2, 1]})
    value["cycle"] = value
    with pytest.raises(ValueError, match="cyclic"):
        canonical_json(value)


def test_evidence_semantic_and_envelope_hashes_are_distinct():
    evidence = _input().evidence
    assert evidence.hash != evidence.envelope_hash
    assert evidence.to_dict()["bundle_hash"] == evidence.envelope_hash


def test_evidence_expected_bundle_and_hash_round_trip():
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    data = _input()
    payload = data.evidence.to_dict()
    assert (
        validate_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
        )
        == ()
    )
    assert (
        validate_evidence_bundle_envelope(
            payload,
            data.contract,
            data.change_set,
            data.plan,
            expected_envelope_hash=data.evidence.envelope_hash,
        )
        == ()
    )
    assert (
        load_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
        )
        == data.evidence
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"expected_bundle": object()},
        {"expected_envelope_hash": _hash("x"), "expected_bundle": _input().evidence},
    ],
)
def test_evidence_requires_exactly_one_typed_trust_root(kwargs):
    from product.evidence import validate_evidence_bundle_envelope

    data = _input()
    if not kwargs:
        with pytest.raises(TypeError, match="exactly one"):
            validate_evidence_bundle_envelope(
                data.evidence.to_dict(), data.contract, data.change_set, data.plan
            )
    else:
        with pytest.raises(TypeError):
            validate_evidence_bundle_envelope(
                data.evidence.to_dict(), data.contract, data.change_set, data.plan, **kwargs
            )


@pytest.mark.parametrize(
    "field",
    [
        "bundle_id",
        "acceptance_contract_hash",
        "change_set_hash",
        "verification_plan_hash",
        "observations",
        "bundle_hash",
    ],
)
def test_evidence_missing_fields_fail_closed(field):
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    data = _input()
    payload = data.evidence.to_dict()
    payload.pop(field)
    errors = validate_evidence_bundle_envelope(
        payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
    )
    assert (
        errors
        and load_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
        )
        is None
    )


def test_evidence_rehashed_semantic_mutation_is_not_accepted():
    from product.evidence import validate_evidence_bundle_envelope

    data = _input()
    payload = data.evidence.to_dict()
    payload["bundle_id"] = "other"
    payload["bundle_hash"] = _hash({k: payload[k] for k in payload if k != "bundle_hash"})
    assert validate_evidence_bundle_envelope(
        payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
    ) == ("TAMPERED:fields",)


@pytest.mark.parametrize("bad", [b"bytes", {"set"}, float("nan"), float("inf"), {1: "nonstring"}])
def test_canonical_json_rejects_unsupported_values(bad):
    from product.evidence import canonical_json

    with pytest.raises((TypeError, ValueError)):
        canonical_json(bad)


def test_receipt_repeat_hash_and_serialized_validation():
    result = certify(_input())
    receipt = result.receipt
    assert receipt.hash == certify(_input()).receipt.hash
    assert receipt.to_dict()["receipt_hash"] == receipt.hash
    assert validate_serialized_receipt(receipt.to_dict(), _input()) == ()


def test_receipt_self_claim_is_checked_against_semantic_hash():
    result = certify(_input())
    receipt = _replace_receipt(result.receipt, claimed_receipt_hash=result.receipt.hash)
    assert receipt.validate()
    assert not _replace_receipt(receipt, claimed_receipt_hash=_hash("stale")).validate()


@pytest.mark.parametrize(
    "field",
    ["acceptance_contract_hash", "change_set_hash", "verification_plan_hash", "evidence_hash"],
)
def test_receipt_subject_mutations_are_rejected(field):
    data = _input()
    result = certify(data)
    kwargs = {field: _hash("other")}
    candidate = _replace_receipt(result.receipt, **kwargs)
    assert candidate.hash != result.receipt.hash
    from product.kernel import validate_receipt

    assert not validate_receipt(candidate, data)


@pytest.mark.parametrize(
    "field",
    ["receipt_schema", "protocol_version", "implementation_schema", "claim_ceiling", "unknown"],
)
def test_receipt_envelope_schema_mutations_fail(field):
    data = _input()
    payload = certify(data).receipt.to_dict()
    payload[field] = "bad" if field != "claim_ceiling" else ["bad"]
    errors = validate_serialized_receipt(payload, data)
    assert errors


def test_receipt_rejects_non_receipt_expected_root():
    from product.certification.receipt import _validate_receipt_envelope

    with pytest.raises(TypeError, match="expected_receipt"):
        _validate_receipt_envelope({}, object())


@pytest.mark.parametrize("bad", [b"bytes", {"set"}, float("nan"), float("inf"), {1: "bad"}])
def test_receipt_envelope_unsupported_values_fail_closed(bad):
    data = _input()
    payload = certify(data).receipt.to_dict()
    payload["bad"] = bad
    assert validate_serialized_receipt(payload, data)


def test_certification_result_cannot_forge_disposition():
    data = _input()
    result = certify(data)
    from product.certification.receipt import CertificationResult

    with pytest.raises(TypeError, match="internal"):
        CertificationResult(result.verification, CertificationDisposition.BLOCKED, result.receipt)


def test_public_receipt_constructor_cannot_create_certified_receipt():
    data = _input()
    result = certify(data)
    with pytest.raises(TypeError, match="internal"):
        Receipt(
            result.receipt.acceptance_contract_hash,
            result.receipt.change_set_hash,
            result.receipt.verification_plan_hash,
            result.receipt.evidence_hash,
            result.verification,
            CertificationDisposition.CERTIFIED,
            CertificationPolicy(True, True, True, True),
        )


def test_public_certification_result_constructor_cannot_create_result():
    data = _input()
    result = certify(data)
    from product.certification.receipt import CertificationResult

    with pytest.raises(TypeError, match="internal"):
        CertificationResult(result.verification, result.disposition, result.receipt)


def test_extra_physical_receipt_field_fails_closed_everywhere():
    data = _input()
    receipt = certify(data).receipt
    payload = receipt.to_dict()
    object.__setattr__(receipt, "unexpected", True)

    assert not receipt.validate()
    with pytest.raises(ValueError, match="fields"):
        receipt.to_dict()
    assert not validate_receipt(receipt, data)
    from product.certification.receipt import _validate_receipt_envelope

    assert _validate_receipt_envelope(payload, receipt)


def test_kernel_reexports_receipt_contract():
    import product.kernel as kernel

    assert kernel.Receipt is Receipt
    assert not hasattr(kernel, "validate_receipt_envelope")


def test_evidence_subject_roots_require_exact_types():
    from product.evidence import validate_evidence_bundle_envelope

    data = _input()
    for index, name in enumerate(("contract", "change_set", "plan")):
        args = [data.contract, data.change_set, data.plan]
        args[index] = object()
        with pytest.raises(TypeError, match=name):
            validate_evidence_bundle_envelope(
                data.evidence.to_dict(), *args, expected_bundle=data.evidence
            )


def test_claimed_hashes_cannot_be_serialized_or_used_as_trust_roots():
    data = _input()
    forged_evidence = replace(data.evidence, claimed_bundle_hash=_hash("forged"))
    with pytest.raises(ValueError, match="claimed_bundle_hash"):
        forged_evidence.to_dict()
    from product.evidence import validate_evidence_bundle_envelope

    with pytest.raises(ValueError, match="claimed hash"):
        validate_evidence_bundle_envelope(
            data.evidence.to_dict(),
            data.contract,
            data.change_set,
            data.plan,
            expected_bundle=forged_evidence,
        )
    receipt = certify(data).receipt
    forged_receipt = _replace_receipt(receipt, claimed_receipt_hash=_hash("forged"))
    with pytest.raises(ValueError, match="claimed_receipt_hash"):
        forged_receipt.to_dict()


def test_bundle_serializer_core_hash_is_sealed_against_alias_rebinding(monkeypatch):
    import product.evidence as evidence_module

    data = _input()
    forged = replace(data.evidence, claimed_bundle_hash=_hash("forged"))
    assert forged.claimed_bundle_hash != data.evidence.hash
    monkeypatch.setattr(
        evidence_module, "_SEALED_BUNDLE_CORE_HASH", lambda value: forged.claimed_bundle_hash
    )
    with pytest.raises(ValueError, match="claimed_bundle_hash"):
        forged.to_dict()


def test_hashes_are_sealed_against_module_rebinding(monkeypatch):
    import product.certification.receipt as receipt_module
    import product.evidence as evidence_module
    from product.evidence import validate_evidence_bundle_envelope

    data = _input()
    before = (data.contract.hash, data.change_set.hash, data.plan.hash, data.evidence.hash)
    receipt = certify(data).receipt
    receipt_before = receipt.hash
    evidence_payload = data.evidence.to_dict()
    receipt_payload = receipt.to_dict()

    class ZeroDigest:
        def hexdigest(self):
            return "0" * 64

    monkeypatch.setattr(evidence_module.hashlib, "sha256", lambda value: ZeroDigest())
    monkeypatch.setattr(evidence_module.json, "dumps", lambda *args, **kwargs: "forged")
    monkeypatch.setattr(evidence_module, "canonical_json", lambda value: "forged")
    monkeypatch.setattr(evidence_module, "_hash", lambda value: "sha256:" + "0" * 64)
    monkeypatch.setattr(receipt_module, "_hash", lambda value: "sha256:" + "0" * 64)
    for name in (
        "_AC_HASH",
        "_CS_HASH",
        "_VP_HASH",
        "_EB_HASH",
        "_EB_ENVELOPE_HASH",
        "_SEALED_EB_ENVELOPE_HASH",
        "_VALIDATOR_EB_ENVELOPE_HASH",
    ):
        monkeypatch.setattr(evidence_module, name, lambda value: "sha256:" + "0" * 64)
    for name in ("_require_hash", "_VALIDATOR_REQUIRE_HASH", "_SEALED_HASH_RE_FULLMATCH"):
        monkeypatch.setattr(evidence_module, name, lambda *args: None)
    for name in (
        "_RECEIPT_HASH",
        "_SEALED_RECEIPT_HASH",
        "_VALIDATOR_RECEIPT_HASH",
    ):
        monkeypatch.setattr(receipt_module, name, lambda value: "sha256:" + "0" * 64)
    for name in (
        "_REQUIRE_HASH",
        "_SEALED_RECEIPT_REQUIRE_HASH",
        "_VALIDATOR_RECEIPT_REQUIRE_HASH",
    ):
        monkeypatch.setattr(receipt_module, name, lambda *args: None)
    monkeypatch.setattr(receipt_module, "_strict_json", lambda *args: None)
    assert before == (data.contract.hash, data.change_set.hash, data.plan.hash, data.evidence.hash)
    assert receipt.hash == receipt_before
    assert certify(data).receipt.hash == receipt_before
    assert validate_serialized_receipt(receipt_payload, data) == ()
    assert (
        validate_evidence_bundle_envelope(
            evidence_payload,
            data.contract,
            data.change_set,
            data.plan,
            expected_bundle=data.evidence,
        )
        == ()
    )


def test_evidence_validation_ignores_mutable_bundle_methods(monkeypatch):
    import product.evidence as evidence_module

    data = _input()
    payload = data.evidence.to_dict()
    monkeypatch.setattr(evidence_module.EvidenceBundle, "to_dict", lambda self: {"forged": True})
    monkeypatch.setattr(
        evidence_module.EvidenceBundle, "canonical_value", property(lambda self: ("forged",))
    )
    monkeypatch.setattr(
        evidence_module.EvidenceBundle, "integrity", lambda *args: IntegrityStatus.TAMPERED
    )
    assert (
        evidence_module.validate_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
        )
        == ()
    )


def test_receipt_validation_ignores_mutable_receipt_methods(monkeypatch):
    import product.certification.receipt as receipt_module

    data = _input()
    receipt = certify(data).receipt
    payload = receipt.to_dict()
    monkeypatch.setattr(receipt_module.Receipt, "to_dict", lambda self: {"forged": True})
    monkeypatch.setattr(
        receipt_module.Receipt, "canonical_value", property(lambda self: {"forged": True})
    )
    monkeypatch.setattr(receipt_module.Receipt, "validate", lambda self: False)
    assert validate_serialized_receipt(payload, data) == ()


def test_kernel_factories_ignore_constructor_monkeypatches(monkeypatch):
    import product.certification as certification_module
    import product.certification.receipt as receipt_module

    data = _input()
    genuine = certify(data)
    genuine_hash = genuine.receipt.hash
    monkeypatch.setattr(certification_module.CertificationPolicy, "__init__", lambda *args: None)
    monkeypatch.setattr(
        certification_module.CertificationPolicy, "__post_init__", lambda self: None, raising=False
    )
    monkeypatch.setattr(receipt_module.Receipt, "__init__", lambda *args: None)
    monkeypatch.setattr(receipt_module.CertificationResult, "__init__", lambda *args: None)
    monkeypatch.setattr(
        receipt_module, "_SEALED_RECEIPT_CORE_HASH", lambda value: "sha256:" + "0" * 64
    )
    monkeypatch.setattr(receipt_module, "_SEALED_RECEIPT_INVARIANT", lambda value: None)
    monkeypatch.setattr(receipt_module, "Receipt", object)
    monkeypatch.setattr(receipt_module, "CertificationResult", object)
    monkeypatch.setattr(
        receipt_module,
        "_create_receipt",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()),
    )
    monkeypatch.setattr(
        receipt_module,
        "_create_certification_result",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()),
    )
    assert certify(data).disposition is CertificationDisposition.CERTIFIED
    assert certify(data).receipt.hash == genuine_hash
    assert validate_serialized_receipt(genuine.receipt.to_dict(), data) == ()
    rejected = _input()
    rejected = replace(rejected, policy_accepted=False)
    assert certify(rejected).disposition is CertificationDisposition.REJECTED


def test_evidence_subclass_trust_root_is_rejected():
    class ForgedEvidence(EvidenceBundle):
        def to_dict(self):
            payload = super().to_dict()
            payload["observations"][0]["status"] = "FAIL"
            return payload

    data = _input()
    forged = ForgedEvidence(
        data.evidence.bundle_id,
        data.evidence.acceptance_contract_hash,
        data.evidence.change_set_hash,
        data.evidence.verification_plan_hash,
        data.evidence.observations,
    )
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    for function in (validate_evidence_bundle_envelope, load_evidence_bundle_envelope):
        with pytest.raises(TypeError, match="expected_bundle"):
            function(
                data.evidence.to_dict(),
                data.contract,
                data.change_set,
                data.plan,
                expected_bundle=forged,
            )


def _serialized_mutation(data, mutate):
    payload = data.evidence.to_dict()
    mutate(payload)
    payload["bundle_hash"] = _hash(
        {key: value for key, value in payload.items() if key != "bundle_hash"}
    )
    return payload


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda p: p["observations"].__setitem__(0, {**p["observations"][0], "status": "FAIL"}),
            "TAMPERED:fields",
        ),
        (lambda p: p["observations"].append(dict(p["observations"][0])), "DUPLICATE:observations"),
        (
            lambda p: (
                p["observations"].append(
                    {**p["observations"][0], "verifier_id": "zzz", "artifact_id": "artifact-2"}
                ),
                p["observations"].reverse(),
            ),
            "MALFORMED:observation_order",
        ),
        (
            lambda p: p.__setitem__("acceptance_contract_hash", _hash("other")),
            "CROSS_BOUND:acceptance_contract_hash",
        ),
        (lambda p: p.__setitem__("change_set_hash", _hash("other")), "STALE:change_set_hash"),
        (lambda p: p.__setitem__("unknown", True), "MALFORMED:keys"),
    ],
)
def test_serialized_evidence_mutations_fail_and_loader_returns_none(mutate, expected):
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    data = _input()
    payload = _serialized_mutation(data, mutate)
    errors = validate_evidence_bundle_envelope(
        payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
    )
    assert expected in errors
    assert (
        load_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
        )
        is None
    )


def test_serialized_duplicate_verifier_and_artifact_are_distinct_errors():
    from product.evidence import validate_evidence_bundle_envelope

    data = _input()
    for field in ("verifier_id", "artifact_id"):
        payload = data.evidence.to_dict()
        row = dict(payload["observations"][0])
        row[field] = row[field] + "-other"
        payload["observations"].append(row)
        payload["bundle_hash"] = _hash(
            {key: value for key, value in payload.items() if key != "bundle_hash"}
        )
        errors = validate_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
        )
        assert "DUPLICATE:observations" in errors


def test_serialized_plan_binding_mismatch_is_rejected():
    from product.evidence import validate_evidence_bundle_envelope

    data = _input()
    payload = _serialized_mutation(
        data, lambda item: item.__setitem__("verification_plan_hash", _hash("other"))
    )
    errors = validate_evidence_bundle_envelope(
        payload, data.contract, data.change_set, data.plan, expected_bundle=data.evidence
    )
    assert "CROSS_BINDING_INVALID:verification_plan_hash" in errors


def test_evidence_schema_constants_and_envelope_hash_trust_root_fail_closed():
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    assert EVIDENCE_BUNDLE_SCHEMA == "nexus.evidence_bundle.v1-experimental"
    data = _input()
    payload = data.evidence.to_dict()
    assert validate_evidence_bundle_envelope(
        payload,
        data.contract,
        data.change_set,
        data.plan,
        expected_envelope_hash=_hash("wrong"),
    ) == ("TAMPERED:fields",)
    assert (
        load_evidence_bundle_envelope(
            payload,
            data.contract,
            data.change_set,
            data.plan,
            expected_envelope_hash=_hash("wrong"),
        )
        is None
    )


@pytest.mark.parametrize("field", ["status", "artifact_hash"])
def test_rehashed_evidence_mutations_fail_against_external_envelope_hash(field):
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    data = _input()
    payload = data.evidence.to_dict()
    payload["observations"][0][field] = "FAIL" if field == "status" else _hash("other-artifact")
    payload["bundle_hash"] = _hash(
        {key: value for key, value in payload.items() if key != "bundle_hash"}
    )
    errors = validate_evidence_bundle_envelope(
        payload,
        data.contract,
        data.change_set,
        data.plan,
        expected_envelope_hash=data.evidence.envelope_hash,
    )
    assert errors == ("TAMPERED:fields",)
    assert (
        load_evidence_bundle_envelope(
            payload,
            data.contract,
            data.change_set,
            data.plan,
            expected_envelope_hash=data.evidence.envelope_hash,
        )
        is None
    )


def test_rehashed_schema_mutation_is_stale_for_both_trust_roots():
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    data = _input()
    payload = data.evidence.to_dict()
    payload["evidence_bundle_schema"] = "nexus.evidence_bundle.v0"
    payload["bundle_hash"] = _hash(
        {key: value for key, value in payload.items() if key != "bundle_hash"}
    )
    for root in (
        {"expected_bundle": data.evidence},
        {"expected_envelope_hash": data.evidence.envelope_hash},
    ):
        errors = validate_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, **root
        )
        assert "STALE:evidence_bundle_schema" in errors
        assert (
            load_evidence_bundle_envelope(
                payload, data.contract, data.change_set, data.plan, **root
            )
            is None
        )


@pytest.mark.parametrize("field", ["verification", "condition", "disposition", "certification"])
def test_injected_authority_fields_are_rejected_for_both_trust_roots(field):
    from product.evidence import load_evidence_bundle_envelope, validate_evidence_bundle_envelope

    data = _input()
    genuine = data.evidence.to_dict()
    assert not set(genuine) & {"verification", "condition", "disposition", "certification"}
    payload = {**genuine, field: "forged"}
    payload["bundle_hash"] = _hash(
        {key: value for key, value in payload.items() if key != "bundle_hash"}
    )
    for root in (
        {"expected_bundle": data.evidence},
        {"expected_envelope_hash": data.evidence.envelope_hash},
    ):
        errors = validate_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, **root
        )
        assert "MALFORMED:keys" in errors
        assert (
            load_evidence_bundle_envelope(
                payload, data.contract, data.change_set, data.plan, **root
            )
            is None
        )


def test_receipt_schema_constant_is_exact():
    assert CERTIFICATION_RECEIPT_SCHEMA == "nexus.certification_receipt.v1-experimental"


def test_certification_revalidates_malformed_graph_after_trust_root_rebinding(monkeypatch):
    import product.evidence as evidence_module
    import product.verification as verification_module

    data = _input()
    for name in ("_require_hash", "_require_text", "_require_ids", "_require_paths"):
        monkeypatch.setattr(evidence_module, name, lambda *args: None)
    for cls in (
        evidence_module.AcceptanceContract,
        evidence_module.ChangeSet,
        evidence_module.VerificationPlan,
        evidence_module.Observation,
        evidence_module.EvidenceBundle,
    ):
        monkeypatch.setattr(cls, "__post_init__", lambda self: None)
        monkeypatch.setattr(cls, "hash", property(lambda self: _hash("forged")), raising=False)
    monkeypatch.setattr(
        evidence_module.EvidenceBundle, "integrity", lambda *args: IntegrityStatus.VALID
    )
    monkeypatch.setattr(
        evidence_module, "derive_evidence_integrity", lambda *args: IntegrityStatus.VALID
    )
    monkeypatch.setattr(evidence_module, "validate_evidence_subjects", lambda *args: ())
    monkeypatch.setattr(
        verification_module,
        "verify",
        lambda *args: verification_module.reduce_verification(IntegrityStatus.VALID),
    )

    def forged(cls, values):
        value = object.__new__(cls)
        for key, item in values.items():
            object.__setattr__(value, key, item)
        return value

    contract = forged(
        evidence_module.AcceptanceContract,
        {
            "contract_id": "ac",
            "requirements_hash": "bad",
            "required_verifier_ids": ("unit",),
            "allowed_paths": ("src/a.py",),
            "deletion_policy": "FORBID",
        },
    )
    change = forged(
        evidence_module.ChangeSet,
        {
            "change_set_id": "cs",
            "source_revision": "base",
            "target_revision": "head",
            "diff_hash": "bad",
            "paths": ("src/a.py",),
        },
    )
    plan = forged(
        evidence_module.VerificationPlan,
        {
            "plan_id": "plan",
            "acceptance_contract_hash": "bad",
            "change_set_hash": "bad",
            "required_verifier_ids": ("unit",),
        },
    )
    observation = forged(
        evidence_module.Observation,
        {
            "verifier_id": "unit",
            "artifact_id": "artifact",
            "artifact_hash": "bad",
            "status": evidence_module.ObservationStatus.PASS,
        },
    )
    bundle = forged(
        evidence_module.EvidenceBundle,
        {
            "bundle_id": "bundle",
            "acceptance_contract_hash": "bad",
            "change_set_hash": "bad",
            "verification_plan_hash": "bad",
            "observations": (observation,),
            "claimed_bundle_hash": None,
        },
    )
    forged_input = CertificationInput(contract, change, plan, bundle, True, True, True, True)
    with pytest.raises(ValueError, match="invalid_certification_input:MALFORMED"):
        certify(forged_input)
    assert validate_serialized_receipt({}, forged_input) == ("MALFORMED:input",)
    assert data.evidence is not bundle


@pytest.mark.parametrize(
    "field,value",
    [
        (field, value)
        for field in ("policy_accepted", "authority_present", "approval_present", "signing_present")
        for value in ("true", 1, [])
    ],
)
def test_certification_rejects_non_boolean_policy_fields(field, value):
    data = _input()
    malformed = replace(data, **{field: value})
    with pytest.raises(ValueError, match=f"invalid_certification_input:MALFORMED:{field}"):
        certify(malformed)
    assert validate_receipt(object(), malformed) is False
    assert validate_serialized_receipt({}, malformed) == ("MALFORMED:input",)


def test_receipt_rejects_contradictory_certified_missing_result():
    result = reduce_verification(IntegrityStatus.MISSING)
    with pytest.raises(TypeError, match="internal"):
        Receipt(
            _hash("contract"),
            _hash("change"),
            _hash("plan"),
            _hash("evidence"),
            result,
            CertificationDisposition.CERTIFIED,
            CertificationPolicy(True, True, True, True),
        )


def test_receipt_binds_protocol_and_claim_ceiling():
    result = reduce_verification(IntegrityStatus.MISSING)
    with pytest.raises(TypeError, match="internal"):
        Receipt(
            _hash("contract"),
            _hash("change"),
            _hash("plan"),
            _hash("evidence"),
            result,
            CertificationDisposition.BLOCKED,
            CertificationPolicy(),
            claim_ceiling=("OTHER",),
        )
    with pytest.raises(TypeError, match="internal"):
        Receipt(
            _hash("contract"),
            _hash("change"),
            _hash("plan"),
            _hash("evidence"),
            result,
            CertificationDisposition.BLOCKED,
            CertificationPolicy(),
            protocol_version="old",
        )
    with pytest.raises(TypeError, match="internal"):
        Receipt(
            _hash("contract"),
            _hash("change"),
            _hash("plan"),
            _hash("evidence"),
            result,
            CertificationDisposition.BLOCKED,
            CertificationPolicy(),
            implementation_schema="old",
        )
