import ast
import hashlib
from dataclasses import fields, replace
from pathlib import Path
from typing import Any

import pytest

from product.certification import CertificationDisposition, CertificationPolicy
from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    EvidenceBundle,
    IntegrityStatus,
    Observation,
    ObservationStatus,
    VerificationPlan,
    _hash,
)
from product.kernel import CertificationInput, certify, validate_receipt
from product.protocol import IMPLEMENTATION_SCHEMA, PUBLIC_PROTOCOL_VERSION
from product.verification import VerificationStatus, reduce_verification


def case(**kwargs):
    contract = AcceptanceContract("ac-1", _hash("req-1"), ("unit", "lint"), ("src/a.py",), "FORBID")
    change = ChangeSet("cs-1", "rev-a", "rev-b", _hash("diff-1"), ("src/a.py",))
    plan = VerificationPlan("vp-1", contract.hash, change.hash, ("unit", "lint"))
    observations = tuple(
        kwargs.pop(
            "observations",
            (
                Observation("unit", "art-u", _hash("hash-u"), ObservationStatus.PASS),
                Observation("lint", "art-l", _hash("hash-l"), ObservationStatus.PASS),
            ),
        )
    )
    evidence = EvidenceBundle("eb-1", contract.hash, change.hash, plan.hash, observations)
    kwargs.setdefault("policy_accepted", True)
    kwargs.setdefault("authority_present", True)
    kwargs.setdefault("approval_present", True)
    kwargs.setdefault("signing_present", True)
    return CertificationInput(contract, change, plan, evidence=evidence, **kwargs)


def _replace_receipt(receipt, **changes):
    candidate = object.__new__(type(receipt))
    for field in receipt.__dataclass_fields__:
        object.__setattr__(candidate, field, changes.get(field, getattr(receipt, field)))
    return candidate


def test_happy_path_is_stable_and_bound():
    result = certify(
        case(
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        )
    )
    assert result.verification.status is VerificationStatus.VERIFIED
    assert result.disposition is CertificationDisposition.CERTIFIED
    assert (
        result.receipt.hash
        == certify(
            case(
                policy_accepted=True,
                authority_present=True,
                approval_present=True,
                signing_present=True,
            )
        ).receipt.hash
    )


def test_fail_missing_and_scope_escape_are_fail_closed():
    failed = certify(
        case(
            observations=(
                Observation("unit", "u", _hash("hu"), ObservationStatus.FAIL),
                Observation("lint", "l", _hash("hl"), ObservationStatus.PASS),
            ),
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        )
    )
    assert failed.verification.status is VerificationStatus.FAILED_VERIFICATION
    assert failed.disposition is CertificationDisposition.REJECTED
    missing = certify(
        case(observations=(Observation("unit", "u", _hash("hu"), ObservationStatus.PASS),))
    )
    assert missing.verification.status is VerificationStatus.UNVERIFIABLE
    assert missing.disposition is CertificationDisposition.BLOCKED


def test_policy_and_prerequisites_are_certification_only():
    rejected = certify(case(policy_accepted=False))
    assert rejected.verification.status is VerificationStatus.VERIFIED
    assert rejected.disposition is CertificationDisposition.REJECTED
    assert certify(case(policy_accepted=None)).disposition is CertificationDisposition.BLOCKED
    assert certify(case(authority_present=False)).disposition is CertificationDisposition.BLOCKED


def test_protocol_versions_are_distinct():
    assert PUBLIC_PROTOCOL_VERSION == "0.1.0-experimental"
    assert IMPLEMENTATION_SCHEMA == "nexus.changeset_certification.v2"


_PRODUCT_PACKAGES = {
    "protocol",
    "evidence",
    "verification",
    "certification",
    "kernel",
    "execution",
    "adapters",
    "benchmark",
}
_BANNED_IMPORT_TOKENS = {
    "nexus",
    "github",
    "gh",
    "mcp",
    "agent",
    "model",
    "provider",
    "capabilityplanner",
    "planner",
    "workforce",
    "runtime",
    "cloud",
}
_ALLOWED_PRODUCT_IMPORTS = {
    "protocol": set(),
    "evidence": {"protocol"},
    "verification": {"protocol", "evidence"},
    "certification": {"protocol", "evidence", "verification"},
    "kernel": {"protocol", "evidence", "verification", "certification"},
    "execution": {"protocol", "evidence"},
    "adapters": {"protocol", "evidence", "verification", "certification", "kernel"},
    "benchmark": {"protocol", "evidence", "verification", "certification", "kernel", "adapters"},
}


def _assert_import_is_allowed(node: ast.AST, package: str) -> None:
    if isinstance(node, ast.Import):
        modules = [alias.name.lower() for alias in node.names]
        names = [part for module in modules for part in module.split(".")]
        names.extend(alias.asname.lower() for alias in node.names if alias.asname)
        product_imports = {
            module.split(".")[1] for module in modules if module.startswith("product.")
        }
    elif isinstance(node, ast.ImportFrom):
        assert node.level == 0
        module = (node.module or "").lower()
        names = module.split(".") + [alias.name.lower() for alias in node.names]
        product_imports = {module.split(".")[1]} if module.startswith("product.") else set()
    else:
        return
    assert not _BANNED_IMPORT_TOKENS.intersection(names)
    # A package submodule may import the types defined by its own package
    # initializer; this remains inward/self-contained and is not an outward
    # dependency.
    assert product_imports <= (_ALLOWED_PRODUCT_IMPORTS[package] | {package})
    assert not (package != "execution" and "execution" in product_imports)


def test_product_imports_obey_layer_dag_and_external_boundary():
    packages = _PRODUCT_PACKAGES
    discovered: set[str] = set()
    product_root = Path(__file__).parents[2] / "product"
    for path in product_root.rglob("*.py"):
        package = path.relative_to(product_root).parts[0]
        if package not in packages:
            continue
        discovered.add(package)
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            _assert_import_is_allowed(node, package)
    assert discovered == packages


def test_receipt_submodule_imports_only_allowed_inward_layers():
    tree = ast.parse((Path(__file__).parents[2] / "product/certification/receipt.py").read_text())
    for node in ast.walk(tree):
        _assert_import_is_allowed(node, "certification")


@pytest.mark.parametrize(
    "source",
    [
        "import github",
        "import mcp",
        "import agent",
        "from planner import X",
        "from workforce import Y",
    ],
)
def test_forbidden_import_tokens_are_rejected_by_gate(source):
    node = ast.parse(source).body[0]
    with pytest.raises(AssertionError):
        _assert_import_is_allowed(node, "kernel")


def test_certification_input_fields_are_factual_only():
    assert {field.name for field in fields(CertificationInput)} == {
        "contract",
        "change_set",
        "plan",
        "evidence",
        "policy_accepted",
        "authority_present",
        "approval_present",
        "signing_present",
    }
    assert {field.name for field in fields(CertificationInput)}.isdisjoint(
        {
            "factual_result",
            "verification",
            "verification_result",
            "status",
            "disposition",
            "claim_ceiling",
            "receipt",
            "receipt_hash",
        }
    )


def test_kernel_input_does_not_accept_claimed_results():
    with pytest.raises(TypeError):
        CertificationInput(**(case().__dict__ | {"disposition": "CERTIFIED"}))  # type: ignore[call-arg]


def test_scope_is_derived_and_evidence_is_exact():
    contract = AcceptanceContract("ac", _hash("req"), ("unit",), ("src/a.py",), "FORBID")
    change = ChangeSet("cs", "a", "b", _hash("d"), ("src/secret.py",))
    plan = VerificationPlan("vp", contract.hash, change.hash, ("unit",))
    evidence = EvidenceBundle(
        "eb",
        contract.hash,
        change.hash,
        plan.hash,
        (Observation("unit", "art", _hash("ah"), ObservationStatus.PASS),),
    )
    result = certify(CertificationInput(contract, change, plan, evidence, True, True, True, True))
    assert result.verification.status is VerificationStatus.FAILED_VERIFICATION
    assert result.disposition is CertificationDisposition.REJECTED


def test_observation_has_no_caller_scope_flag_and_duplicate_identity_blocks():
    with pytest.raises(TypeError):
        Observation("unit", "art", _hash("hash"), ObservationStatus.PASS, **{"scope_escaped": True})  # type: ignore[call-arg]
    contract = AcceptanceContract("ac", _hash("req"), ("unit", "lint"), ("src/a.py",), "FORBID")
    change = ChangeSet("cs", "a", "b", _hash("d"), ("src/a.py",))
    plan = VerificationPlan("vp", contract.hash, change.hash, ("unit", "lint"))
    evidence = EvidenceBundle(
        "eb",
        contract.hash,
        change.hash,
        plan.hash,
        (
            Observation("unit", "a", _hash("h"), ObservationStatus.PASS),
            Observation("unit", "a", _hash("h"), ObservationStatus.PASS),
        ),
    )
    result = certify(CertificationInput(contract, change, plan, evidence, True, True, True, True))
    assert result.verification.status is VerificationStatus.UNVERIFIABLE


def test_receipt_round_trip_and_tamper_validation():
    input_data = case()
    result = certify(input_data)
    receipt = result.receipt
    assert receipt.acceptance_contract_hash == input_data.contract.hash
    assert receipt.change_set_hash == input_data.change_set.hash
    assert receipt.verification_plan_hash == input_data.plan.hash
    assert receipt.evidence_hash == input_data.evidence.hash
    assert receipt.verification == reduce_verification(
        IntegrityStatus.VALID, (ObservationStatus.PASS, ObservationStatus.PASS)
    )
    assert receipt.policy == CertificationPolicy(True, True, True, True)
    assert receipt.disposition is CertificationDisposition.CERTIFIED
    assert receipt.claim_ceiling == (
        "NO_MERGE_AUTHORIZATION",
        "NO_DEPLOYMENT_TRUTH",
        "NO_OUTCOME_TRUTH",
        "NO_PRODUCTION_READINESS",
        "NO_PUBLIC_PROTOCOL_STABILITY",
    )
    assert receipt.protocol_version == PUBLIC_PROTOCOL_VERSION
    assert receipt.implementation_schema == IMPLEMENTATION_SCHEMA
    from product.evidence import canonical_json

    assert (
        receipt.hash
        == "sha256:" + hashlib.sha256(canonical_json(receipt.canonical_value).encode()).hexdigest()
    )
    assert validate_receipt(
        _replace_receipt(receipt, claimed_receipt_hash=receipt.hash), input_data
    )
    with pytest.raises(TypeError, match="internal"):
        replace(receipt, claimed_receipt_hash="sha256:bad")

    subject_tampered = (
        _replace_receipt(receipt, acceptance_contract_hash=_hash("bad")),
        _replace_receipt(receipt, change_set_hash=_hash("bad")),
        _replace_receipt(receipt, verification_plan_hash=_hash("bad")),
        _replace_receipt(receipt, evidence_hash=_hash("bad")),
    )
    assert all(not validate_receipt(candidate, input_data) for candidate in subject_tampered)
    for changes in (
        {"verification": reduce_verification(IntegrityStatus.MISSING)},
        {"disposition": CertificationDisposition.REJECTED},
        {"policy": CertificationPolicy(False, True, True, True)},
        {"claim_ceiling": ("TAMPERED",)},
        {"protocol_version": "0.0.0"},
        {"implementation_schema": "tampered"},
    ):
        with pytest.raises((TypeError, ValueError)):
            replace(receipt, **changes)


def test_stale_bindings_are_unverifiable_and_blocked():
    c = case().contract
    ch = case().change_set
    p = case().plan
    e = case().evidence
    stale = EvidenceBundle(
        e.bundle_id,
        e.acceptance_contract_hash,
        _hash("stale"),
        e.verification_plan_hash,
        e.observations,
    )
    result = certify(CertificationInput(c, ch, p, stale, True, True, True, True))
    assert result.verification.status is VerificationStatus.UNVERIFIABLE
    assert result.disposition is CertificationDisposition.BLOCKED


def test_claimed_evidence_hash_tamper_is_unverifiable_and_rejected():
    x = case()
    e = x.evidence
    bad = EvidenceBundle(
        e.bundle_id,
        e.acceptance_contract_hash,
        e.change_set_hash,
        e.verification_plan_hash,
        e.observations,
        _hash("not-the-bundle"),
    )
    r = certify(CertificationInput(x.contract, x.change_set, x.plan, bad, True, True, True, True))
    assert r.verification.status is VerificationStatus.UNVERIFIABLE
    assert r.disposition is CertificationDisposition.REJECTED


@pytest.mark.parametrize(
    "field", ["policy_accepted", "authority_present", "approval_present", "signing_present"]
)
def test_each_missing_prerequisite_blocks_after_verified(field):
    values: dict[str, Any] = {
        k: True
        for k in ("policy_accepted", "authority_present", "approval_present", "signing_present")
    }
    values[field] = None
    r = certify(case(**values))
    assert (
        r.verification.status is VerificationStatus.VERIFIED
        and r.disposition is CertificationDisposition.BLOCKED
    )


def test_claim_ceiling_and_schema_contract():
    r = certify(case()).receipt
    assert set(r.claim_ceiling) == {
        "NO_MERGE_AUTHORIZATION",
        "NO_DEPLOYMENT_TRUTH",
        "NO_OUTCOME_TRUTH",
        "NO_PRODUCTION_READINESS",
        "NO_PUBLIC_PROTOCOL_STABILITY",
    }
    assert not hasattr(r, "kernel_version")


def test_invalid_status_is_rejected_at_construction():
    with pytest.raises(TypeError):
        Observation("unit", "u", _hash("h"), "MAYBE")  # type: ignore[arg-type]


def test_canonical_json_rejects_unsupported_values_and_sorts_sets():
    from product.evidence import canonical_json

    with pytest.raises(TypeError):
        canonical_json({1: "x"})
    with pytest.raises(TypeError):
        canonical_json({"x": object()})
    assert canonical_json(("b", "a")) != canonical_json(tuple(sorted(("b", "a"))))
