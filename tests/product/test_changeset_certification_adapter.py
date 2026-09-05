import ast
from copy import deepcopy
from pathlib import Path

import pytest

import product.adapters.changeset_certification_v2 as adapter
import tests.product.changeset_certification_facade as facade
from product.certification import CertificationDisposition, CertificationPolicy, certify_result
from product.evidence import EvidenceCondition, validate_normalized_paths
from product.protocol import IMPLEMENTATION_SCHEMA, PUBLIC_PROTOCOL_VERSION
from product.verification import VerificationStatus, reduce_verification


def _envelope(verifier_status="PASS"):
    digest = "sha256:" + "a" * 64
    manifest = {
        "manifest_id": "manifest-1",
        "task_id": "task-1",
        "attempt_id": "attempt-1",
        "repository": "repo",
        "source": "source",
        "base_commit": "base",
        "base_tree": "tree-base",
        "candidate_commit": "candidate",
        "candidate_tree": "tree-candidate",
        "diff_hash": digest,
        "verifiers": [
            {
                "verifier_id": "unit",
                "artifact_id": "unit:attempt-1",
                "artifact_hash": "sha256:" + "b" * 64,
                "status": verifier_status,
            }
        ],
    }
    manifest["manifest_hash"] = adapter.canonical_hash(manifest)
    payload = {
        "schema": IMPLEMENTATION_SCHEMA,
        "version": 2,
        "task": {"task_id": "task-1", "attempt_id": "attempt-1"},
        "repository": {"repository": "repo", "source": "source"},
        "base": {"commit": "base", "tree": "tree-base"},
        "diff": {"hash": digest, "paths": ["src/a.py"]},
        "allowed_scope": {"paths": ["src/a.py"], "deletion_policy": "FORBID"},
        "candidate": {
            "commit": "candidate",
            "tree": "tree-candidate",
            "diff_hash": digest,
        },
        "verifier_manifest": manifest,
        "disposition": "CERTIFIED",
        "reasons": [],
        "claim_ceiling": adapter.CLAIM_CEILING,
        "approval": {"complete": True},
        "authority": {"complete": True},
        "signing": {"complete": True},
        "policy": {"allowed": True},
    }
    payload["canonical_payload_hash"] = adapter.canonical_hash(payload)
    return payload


def _rehash(payload):
    manifest = payload["verifier_manifest"]
    manifest.pop("manifest_hash", None)
    manifest["manifest_hash"] = adapter.canonical_hash(manifest)
    payload.pop("canonical_payload_hash", None)
    payload["canonical_payload_hash"] = adapter.canonical_hash(payload)
    return payload


def test_facade_is_a_semantic_free_projection():
    tree = ast.parse(Path(facade.__file__).read_text())
    for node in tree.body[1:]:
        assert isinstance(node, (ast.ImportFrom, ast.Assign))
        if isinstance(node, ast.Assign):
            assert all(
                isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
            )


def test_adapter_delegates_authoritative_reduction_to_product():
    tree = ast.parse(Path(adapter.__file__).read_text())
    forbidden_defs = {
        "VerificationStatus",
        "VerificationResult",
        "CertificationDisposition",
        "certify_result",
        "reduce_verification",
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            assert node.name not in forbidden_defs
            assert node.name not in {"_status_for", "_reject"}
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"CERTIFIED", "REJECTED", "BLOCKED"}
    expected = {
        "_result": {"certify_result"},
        "_blocked": {"certify_result"},
        "_minimal_invalid": {"certify_result", "reduce_verification"},
        "validate_changeset_certification": {"certify_result", "derive_verification_result"},
    }
    for function_name, calls in expected.items():
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        )
        actual = {
            node.func.id
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert calls <= actual


@pytest.mark.parametrize(
    ("name", "mutation", "status", "integrity", "disposition"),
    [
        (
            "happy",
            lambda p: None,
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.CERTIFIED,
        ),
        (
            "fail",
            lambda p: p["verifier_manifest"]["verifiers"][0].__setitem__("status", "FAIL"),
            VerificationStatus.FAILED_VERIFICATION,
            EvidenceCondition.VALID,
            CertificationDisposition.REJECTED,
        ),
        (
            "missing_manifest",
            lambda p: p.pop("verifier_manifest"),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.MISSING,
            CertificationDisposition.BLOCKED,
        ),
        (
            "missing_verifier",
            lambda p: p["verifier_manifest"].__setitem__("verifiers", []),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.MISSING,
            CertificationDisposition.BLOCKED,
        ),
        (
            "duplicate_verifier",
            lambda p: p["verifier_manifest"]["verifiers"].append(
                deepcopy(p["verifier_manifest"]["verifiers"][0])
            ),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.DUPLICATE,
            CertificationDisposition.REJECTED,
        ),
        (
            "duplicate_artifact",
            lambda p: p["verifier_manifest"]["verifiers"].append(
                {
                    "verifier_id": "other",
                    "artifact_id": "unit:attempt-1",
                    "artifact_hash": "sha256:" + "c" * 64,
                    "status": "PASS",
                }
            ),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.DUPLICATE,
            CertificationDisposition.REJECTED,
        ),
        (
            "stale",
            lambda p: p["candidate"].__setitem__("commit", "moved"),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.STALE,
            CertificationDisposition.BLOCKED,
        ),
        (
            "bad_payload_hash",
            lambda p: p.__setitem__("canonical_payload_hash", "sha256:" + "f" * 64),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.TAMPERED,
            CertificationDisposition.REJECTED,
        ),
        (
            "cross_binding",
            lambda p: p["verifier_manifest"].__setitem__("source", "other"),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.CROSS_BOUND,
            CertificationDisposition.REJECTED,
        ),
        (
            "bad_manifest_hash",
            lambda p: p["verifier_manifest"].__setitem__("manifest_hash", "sha256:" + "f" * 64),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.TAMPERED,
            CertificationDisposition.REJECTED,
        ),
        (
            "malformed_schema",
            lambda p: p.__setitem__("schema", "bad"),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.MALFORMED,
            CertificationDisposition.REJECTED,
        ),
        (
            "unknown_field",
            lambda p: p.__setitem__("unknown", True),
            VerificationStatus.UNVERIFIABLE,
            EvidenceCondition.MALFORMED,
            CertificationDisposition.REJECTED,
        ),
        (
            "policy_false",
            lambda p: (
                p.__setitem__("policy", {"allowed": False}),
                p.__setitem__("reasons", ["policy_disallowed"]),
                p.__setitem__("disposition", "REJECTED"),
            ),
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.REJECTED,
        ),
        (
            "policy_missing",
            lambda p: (
                p.pop("policy"),
                p.__setitem__("reasons", ["policy_missing"]),
                p.__setitem__("disposition", "BLOCKED"),
            ),
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.BLOCKED,
        ),
        (
            "approval_missing",
            lambda p: (
                p.pop("approval"),
                p.__setitem__("reasons", ["approval_missing"]),
                p.__setitem__("disposition", "BLOCKED"),
            ),
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.BLOCKED,
        ),
        (
            "authority_missing",
            lambda p: (
                p.pop("authority"),
                p.__setitem__("reasons", ["authority_missing"]),
                p.__setitem__("disposition", "BLOCKED"),
            ),
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.BLOCKED,
        ),
        (
            "signing_missing",
            lambda p: (
                p.pop("signing"),
                p.__setitem__("reasons", ["signing_missing"]),
                p.__setitem__("disposition", "BLOCKED"),
            ),
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.BLOCKED,
        ),
        (
            "claimed_result",
            lambda p: p.__setitem__(
                "verification_result", {"status": "VERIFIED", "reason_codes": []}
            ),
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.REJECTED,
        ),
        (
            "bad_waiver",
            lambda p: p.__setitem__("waiver", {"approved": "yes"}),
            VerificationStatus.VERIFIED,
            EvidenceCondition.VALID,
            CertificationDisposition.REJECTED,
        ),
    ],
)
def test_facade_and_direct_adapter_have_identical_v2_outputs(
    name, mutation, status, integrity, disposition
):
    left = _envelope("FAIL" if name == "fail" else "PASS")
    mutation(left)
    if name not in {"missing_manifest", "bad_payload_hash", "bad_manifest_hash"}:
        _rehash(left)
    direct = adapter.certify_changeset(deepcopy(left))
    projected = facade.certify_changeset(deepcopy(left))
    assert projected.to_dict() == direct.to_dict()
    assert projected.canonical_hash() == direct.canonical_hash()
    assert direct.verification_result.status is status
    assert direct.verification_result.integrity is integrity
    assert direct.status is disposition
    if name == "claimed_result":
        assert "unknown_field" in direct.reason_codes


def test_fail_result_ignores_caller_disposition_and_reasons():
    outputs = []
    for disposition, reasons in (("BLOCKED", []), ("REJECTED", ["status_substitution"])):
        payload = _envelope("FAIL")
        payload["disposition"] = disposition
        payload["reasons"] = reasons
        _rehash(payload)
        outputs.append(facade.certify_changeset(deepcopy(payload)).to_dict())
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("verifier_status", ["PASS", "FAIL"])
def test_v1_is_legacy_non_certifiable(verifier_status):
    result = adapter.certify_changeset(
        {"schema": "nexus.changeset_certification.v1", "version": 1, "status": verifier_status}
    )
    assert result.verification_result.status is VerificationStatus.UNVERIFIABLE
    assert result.verification_result.integrity is EvidenceCondition.LEGACY_NON_CERTIFIABLE
    assert result.status is CertificationDisposition.BLOCKED


def test_legacy_wire_shape_and_product_receipt_identity():
    payload = _envelope()
    wire = adapter.certify_changeset(payload).to_dict()
    assert set(wire["verification_result"]) == {"status", "reason_codes"}
    assert "condition" not in wire["verification_result"]
    assert "integrity" not in wire["verification_result"]
    assert "protocol_version" not in wire
    assert "kernel_version" not in wire
    assert wire["schema"] == IMPLEMENTATION_SCHEMA
    for key in ("condition", "integrity"):
        tampered = deepcopy(wire)
        tampered["verification_result"][key] = "VALID"
        _rehash(tampered)
        assert adapter.validate_changeset_certification(tampered) == ("evidence_malformed",)
    assert PUBLIC_PROTOCOL_VERSION == "0.1.0-experimental"


def test_builder_duplicate_verifier_is_product_derived_and_blocked():
    payload = adapter.build_changeset_certification(
        change_set={
            "change_set_id": "cs",
            "source_revision": "a",
            "target_revision": "b",
            "diff_hash": "sha256:" + "a" * 64,
        },
        evidence=[
            {
                "evidence_id": "e1",
                "kind": "unit",
                "content_hash": "sha256:" + "b" * 64,
                "source": "test",
            },
            {
                "evidence_id": "e2",
                "kind": "unit",
                "content_hash": "sha256:" + "c" * 64,
                "source": "test",
            },
        ],
    )
    assert payload["disposition"] == CertificationDisposition.BLOCKED.value
    assert payload["reasons"] == ["verifier_duplicate"]
    factual = reduce_verification(EvidenceCondition.MISSING, reasons=("verifier_duplicate",))
    assert factual.status is VerificationStatus.UNVERIFIABLE
    assert factual.integrity is EvidenceCondition.MISSING
    assert certify_result(factual, CertificationPolicy()) is CertificationDisposition.BLOCKED


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "src//a.py",
        "src/./a.py",
        "src/../a.py",
        "src\\a.py",
        "src/a.py/",
        " src/a.py",
        "src/a.py\x00",
    ],
)
def test_paths_reject_traversal_and_non_normalized_forms(path):
    with pytest.raises((TypeError, ValueError)):
        validate_normalized_paths((path,))
    payload = _envelope()
    payload["diff"]["paths"] = [path]
    payload["allowed_scope"]["paths"] = [path]
    _rehash(payload)
    assert adapter.certify_changeset(payload).status is not CertificationDisposition.CERTIFIED


@pytest.mark.parametrize("container", ["dict", "list"])
def test_recursive_cycles_fail_closed_at_json_boundary(container):
    payload = _envelope()
    cycle = {}
    if container == "dict":
        cycle["self"] = cycle
    else:
        cycle = []
        cycle.append(cycle)
    payload["cycle"] = cycle
    assert adapter.certify_changeset(payload).status is CertificationDisposition.BLOCKED
    assert adapter.validate_changeset_certification(payload) == ("identity_malformed",)


@pytest.mark.parametrize("policy", [False, "yes", 1, 0, {}, [], {"allowed": True, "extra": 1}])
def test_present_invalid_policy_is_rejected_and_roundtrips(policy):
    payload = _envelope()
    payload["policy"] = policy
    payload["reasons"] = ["policy_disallowed"]
    payload["disposition"] = "REJECTED"
    _rehash(payload)
    output = adapter.certify_changeset(payload).to_dict()
    assert output["disposition"] == "REJECTED"
    assert adapter.validate_changeset_certification(output) == ()


def test_explicit_none_policy_is_missing_and_roundtrips():
    payload = _envelope()
    payload["policy"] = None
    payload["reasons"] = ["policy_missing"]
    payload["disposition"] = "BLOCKED"
    _rehash(payload)
    output = adapter.certify_changeset(payload).to_dict()
    assert output["disposition"] == "BLOCKED"
    assert output["reasons"] == ["policy_missing"]
    assert adapter.validate_changeset_certification(output) == ()


def test_hash_mismatch_is_tampered_for_direct_and_certification_paths():
    payload = _envelope()
    payload["verifier_manifest"]["manifest_hash"] = "sha256:" + "f" * 64
    direct = adapter.derive_verification_result(payload)
    certified = adapter.certify_changeset(deepcopy(payload))
    assert direct.integrity is EvidenceCondition.TAMPERED
    assert certified.verification_result.integrity is EvidenceCondition.TAMPERED
    assert certified.status is CertificationDisposition.REJECTED


@pytest.mark.parametrize(
    "bad", [{1: "value"}, {"x": {1, 2}}, {"x": b"bytes"}, {"x": (float("nan"),)}]
)
def test_json_boundary_rejects_noncanonical_values_without_raising(bad):
    payload = _envelope()
    payload["bad"] = bad
    result = adapter.certify_changeset(payload)
    assert result.status is CertificationDisposition.BLOCKED
    assert adapter.validate_changeset_certification(payload) == ("identity_malformed",)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["verifier_manifest"]["verifiers"][0].__setitem__("status", "FAIL"),
        lambda p: p.__setitem__("policy", {"allowed": False}),
        lambda p: p.pop("policy"),
        lambda p: p.pop("approval"),
        lambda p: p.pop("authority"),
        lambda p: p.pop("signing"),
        lambda p: p.__setitem__("waiver", {"approved": "yes"}),
    ],
)
def test_semantic_outputs_roundtrip_through_validator(mutation):
    payload = _envelope()
    mutation(payload)
    _rehash(payload)
    output = adapter.certify_changeset(payload).to_dict()
    assert adapter.validate_changeset_certification(output) == ()


@pytest.mark.parametrize("bad", [" leading", "trailing ", "embedded\x00nul"])
def test_identity_text_fields_reject_whitespace_and_nul(bad):
    fields = (
        ("task", "task_id"),
        ("task", "attempt_id"),
        ("repository", "repository"),
        ("repository", "source"),
        ("base", "commit"),
        ("base", "tree"),
        ("candidate", "commit"),
        ("candidate", "tree"),
        ("verifier_manifest", "manifest_id"),
        ("verifier_manifest", "task_id"),
        ("verifier_manifest", "attempt_id"),
        ("verifier_manifest", "repository"),
        ("verifier_manifest", "source"),
        ("verifier_manifest", "base_commit"),
        ("verifier_manifest", "base_tree"),
        ("verifier_manifest", "candidate_commit"),
        ("verifier_manifest", "candidate_tree"),
    )
    for container, key in fields:
        payload = _envelope()
        payload[container][key] = bad
        _rehash(payload)
        result = adapter.certify_changeset(payload)
        assert result.status is not CertificationDisposition.CERTIFIED
        assert adapter.validate_changeset_certification(result) != ()


@pytest.mark.parametrize(
    "path",
    [
        ("diff", "hash"),
        ("candidate", "diff_hash"),
        ("verifier_manifest", "diff_hash"),
        ("verifier_manifest.verifiers.0", "artifact_hash"),
    ],
)
def test_sha256_fields_require_exact_lowercase_digest(path):
    payload = _envelope()
    target = payload
    for part in path[0].split("."):
        target = target[int(part)] if part.isdigit() else target[part]
    target[path[1]] = "sha256:" + "A" * 64
    _rehash(payload)
    result = adapter.certify_changeset(payload)
    assert result.status is not CertificationDisposition.CERTIFIED
    assert adapter.validate_changeset_certification(result) != ()


@pytest.mark.parametrize(
    "path",
    [
        ("verifier_manifest", "manifest_hash"),
        (None, "canonical_payload_hash"),
    ],
)
def test_dependent_sha256_fields_reject_uppercase_without_empty_validation(path):
    payload = _envelope()
    _rehash(payload)
    target = payload if path[0] is None else payload[path[0]]
    target[path[1]] = "sha256:" + "A" * 64

    result = adapter.certify_changeset(payload)

    assert result.status is not CertificationDisposition.CERTIFIED
    assert adapter.validate_changeset_certification(payload) != ()


def test_public_certification_constructor_rejects_reducer_owned_fields():
    identity = adapter.ChangeSetIdentity("cs", "base", "target", "sha256:" + "a" * 64)
    factual = reduce_verification(EvidenceCondition.MISSING)
    assert not hasattr(adapter.ChangeSetCertification, "_from_reducer")
    with pytest.raises(TypeError):
        adapter.ChangeSetCertification(
            identity,
            status=CertificationDisposition.CERTIFIED,
            reason_codes=(),
            verification_result=factual,
        )


def test_public_constructor_cannot_serialize_caller_selected_envelope_truth():
    identity = adapter.ChangeSetIdentity("cs", "base", "target", "sha256:" + "a" * 64)
    with pytest.raises(TypeError):
        adapter.ChangeSetCertification(
            identity,
            envelope={
                "schema": adapter.CHANGESET_CERTIFICATION_SCHEMA,
                "version": adapter.CHANGESET_CERTIFICATION_VERSION,
                "disposition": "CERTIFIED",
                "reasons": [],
                "claim_ceiling": "caller-selected",
            },
        )
