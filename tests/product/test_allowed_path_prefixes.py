"""Issue #268: optional segment-aware ``allowed_path_prefixes`` on the acceptance contract."""

from __future__ import annotations

import copy

import pytest

from product.adapters.generic_verification import verify_generic_changeset
from product.evidence import (
    AcceptanceContract,
    Applicability,
    ExpectedEvidenceSubject,
    IntegrityStatus,
    RequirementMode,
    derive_evidence_integrity,
    validate_evidence_subjects,
)
from product.protocol.generic_verification import (
    GENERIC_PROTOCOL_CONFORMANCE_VECTORS,
    acceptance_contract_hash,
    is_allowed_path_prefix,
)
from tests.product.test_generic_verification_protocol import _entry, _payload, _rehash

# Frozen pre-#268 hashes. They must stay byte-identical for contracts that do not
# declare prefixes (legacy wire requests and domain objects alike).
_LEGACY_HASHES = {
    "acceptance_contract": "sha256:5a97aa6989c3ddf00e08c57327436f626bb0be918844eef0225e276121e21eff",
    "acceptance_contract_unicode": "sha256:21face1a76514a320f54660053e4c1e9e51f54ab31f346a599db88a2107174d4",
    "acceptance_contract_universe": "sha256:6bf2f53e4147ea5d1f9e02089c7237ab6b1cfbb94204d16a6f351e4c0f4f061b",
}


def _domain(value: dict) -> AcceptanceContract:
    subjects = tuple(
        ExpectedEvidenceSubject(
            s["logical_subject_id"],
            s["evidence_kind"],
            RequirementMode(s["requirement_mode"]),
            Applicability(s["applicability"]),
        )
        for s in value.get("expected_subjects", ())
    )
    return AcceptanceContract(
        value["contract_id"],
        value["requirements_hash"],
        tuple(value["required_verifier_ids"]),
        tuple(value["allowed_paths"]),
        value["deletion_policy"],
        subjects,
        value.get("universe_generation", 0),
        tuple(value.get("allowed_path_prefixes", ())),
    )


def _scoped(paths, *, allowed_paths, prefixes, deletion_policy="FORBID", deleted=()):
    entries = [
        _entry(
            path,
            kind="DELETE",
            before="f" * 40,
            after=None,
            before_mode="100644",
            after_mode=None,
        )
        if path in deleted
        else _entry(path)
        for path in paths
    ]
    payload = _payload(entries=entries, deletion_policy=deletion_policy)
    payload["acceptance_contract"]["allowed_paths"] = list(allowed_paths)
    if prefixes is not None:
        payload["acceptance_contract"]["allowed_path_prefixes"] = list(prefixes)
    return _rehash(payload)


def _verify(payload):
    status, body = verify_generic_changeset(payload)
    assert status == 200, body
    return body["verification"]


# --- hash stability -------------------------------------------------------


@pytest.mark.parametrize("name", sorted(_LEGACY_HASHES))
def test_legacy_contract_hashes_are_byte_identical(name):
    value = GENERIC_PROTOCOL_CONFORMANCE_VECTORS[name]["value"]
    assert "allowed_path_prefixes" not in value
    assert GENERIC_PROTOCOL_CONFORMANCE_VECTORS[name]["expected_hash"] == _LEGACY_HASHES[name]
    assert acceptance_contract_hash(value) == _LEGACY_HASHES[name]
    assert _domain(value).hash == _LEGACY_HASHES[name]


def test_prefix_vector_hash_binds_prefixes_and_matches_domain():
    vector = GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract_path_prefixes"]
    value = vector["value"]
    assert acceptance_contract_hash(value) == vector["expected_hash"]
    assert _domain(value).hash == vector["expected_hash"]
    # Order-independent, content-sensitive.
    reordered = dict(value, allowed_path_prefixes=list(reversed(value["allowed_path_prefixes"])))
    assert acceptance_contract_hash(reordered) == vector["expected_hash"]
    changed = dict(value, allowed_path_prefixes=["src/pkg/"])
    assert acceptance_contract_hash(changed) != vector["expected_hash"]
    without = {k: v for k, v in value.items() if k != "allowed_path_prefixes"}
    assert acceptance_contract_hash(without) != vector["expected_hash"]


def test_prefixes_with_universe_hash_matches_domain():
    value = copy.deepcopy(GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract_universe"]["value"])
    value["allowed_path_prefixes"] = ["src/"]
    assert acceptance_contract_hash(value) == _domain(value).hash
    assert acceptance_contract_hash(value) != _LEGACY_HASHES["acceptance_contract_universe"]


def test_legacy_request_without_field_keeps_wire_hash():
    payload = _payload()
    assert "allowed_path_prefixes" not in payload["acceptance_contract"]
    status, body = verify_generic_changeset(payload)
    assert status == 200
    assert body["hashes"]["acceptance_contract_hash"] == acceptance_contract_hash(
        payload["acceptance_contract"]
    )
    assert body["verification"]["status"] == "VERIFIED"


def test_integrity_deriver_hash_binds_prefixes():
    value = GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract_path_prefixes"]["value"]
    payload = _scoped(["src/pkg/a.py"], allowed_paths=["README.md"], prefixes=value["allowed_path_prefixes"])
    status, body = verify_generic_changeset(payload)
    assert status == 200
    assert body["hashes"]["acceptance_contract_hash"] == acceptance_contract_hash(
        payload["acceptance_contract"]
    )


# --- segment boundary -----------------------------------------------------


def test_file_under_prefix_is_verified():
    verification = _verify(_scoped(["src/pkg/a.py", "src/pkg/deep/b.py"], allowed_paths=["README.md"], prefixes=["src/pkg/"]))
    assert verification["status"] == "VERIFIED"


@pytest.mark.parametrize(
    "path",
    ["src/pkgx/a.py", "src/pkg", "src/pk/a.py", "src/a.py", "other/src/pkg/a.py"],
)
def test_lookalike_or_outside_path_is_scope_escape(path):
    verification = _verify(_scoped([path], allowed_paths=["README.md"], prefixes=["src/pkg/"]))
    assert verification["status"] == "FAILED_VERIFICATION"
    assert verification["reason_codes"] == ["SCOPE_ESCAPE"]


def test_mix_of_prefixes_and_exact_files():
    ok = _scoped(
        ["README.md", "src/pkg/a.py", "tests/test_a.py"],
        allowed_paths=["README.md"],
        prefixes=["src/pkg/", "tests/"],
    )
    assert _verify(ok)["status"] == "VERIFIED"
    escape = _scoped(
        ["README.md", "src/pkg/a.py", "setup.py"],
        allowed_paths=["README.md"],
        prefixes=["src/pkg/", "tests/"],
    )
    assert _verify(escape)["reason_codes"] == ["SCOPE_ESCAPE"]


def test_exact_allowed_paths_still_work_without_prefixes():
    assert _verify(_scoped(["src/a.py"], allowed_paths=["src/a.py"], prefixes=None))["status"] == "VERIFIED"
    escaped = _verify(_scoped(["src/b.py"], allowed_paths=["src/a.py"], prefixes=None))
    assert escaped["reason_codes"] == ["SCOPE_ESCAPE"]


def test_deletion_policy_applies_unchanged_under_prefix():
    forbid = _scoped(
        ["src/pkg/old.py", "src/pkg/new.py"],
        allowed_paths=["README.md"],
        prefixes=["src/pkg/"],
        deleted={"src/pkg/old.py"},
    )
    result = _verify(forbid)
    assert result["status"] == "FAILED_VERIFICATION"
    assert result["reason_codes"] == ["DELETION_FORBIDDEN"]
    allow = _scoped(
        ["src/pkg/old.py", "src/pkg/new.py"],
        allowed_paths=["README.md"],
        prefixes=["src/pkg/"],
        deleted={"src/pkg/old.py"},
        deletion_policy="ALLOW",
    )
    assert _verify(allow)["status"] == "VERIFIED"


# --- rejection of malformed prefixes --------------------------------------

_BAD_PREFIXES = [
    "",
    "/",
    "/src/",
    "src/pkg",
    "./",
    "src/./",
    "../",
    "src/../",
    "src/../../etc/",
    "src//",
    "src\\pkg/",
    "src/*/",
    "src/?/",
    "src/[a]/",
    " src/",
    "src/\x00/",
    "a" * 600 + "/",
]


@pytest.mark.parametrize("prefix", _BAD_PREFIXES)
def test_bad_prefix_is_rejected_on_the_wire(prefix):
    payload = _scoped(["src/pkg/a.py"], allowed_paths=["README.md"], prefixes=[prefix])
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"] == {
        "code": "MALFORMED_REQUEST",
        "field": "acceptance_contract.allowed_path_prefixes",
    }
    assert is_allowed_path_prefix(prefix) is False


# The 512-byte cap is a wire constraint (as for exact allowed_paths); the domain
# object enforces shape only.
@pytest.mark.parametrize("prefix", [p for p in _BAD_PREFIXES if len(p) <= 512])
def test_bad_prefix_is_rejected_by_domain(prefix):
    with pytest.raises((TypeError, ValueError)):
        AcceptanceContract(
            "ac", "sha256:" + "1" * 64, ("unit",), ("README.md",), "FORBID",
            allowed_path_prefixes=(prefix,),
        )


@pytest.mark.parametrize(
    "value",
    [[], ["src/", "src/"], "src/", [1], None],
)
def test_empty_duplicate_or_mistyped_prefix_list_is_rejected(value):
    payload = _scoped(["src/a.py"], allowed_paths=["src/a.py"], prefixes=None)
    payload["acceptance_contract"]["allowed_path_prefixes"] = value
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"]["field"] == "acceptance_contract.allowed_path_prefixes"


def test_domain_rejects_list_and_duplicates():
    for value in (["src/"], ("src/", "src/")):
        with pytest.raises((TypeError, ValueError)):
            AcceptanceContract(
                "ac", "sha256:" + "1" * 64, ("unit",), ("README.md",), "FORBID",
                allowed_path_prefixes=value,  # type: ignore[arg-type]
            )


@pytest.mark.parametrize("prefix", ["src/", "src/pkg/", "a/.b/", "..a/", "雪/"])
def test_good_prefix_is_accepted(prefix):
    assert is_allowed_path_prefix(prefix) is True
    AcceptanceContract(
        "ac", "sha256:" + "1" * 64, ("unit",), ("README.md",), "FORBID",
        allowed_path_prefixes=(prefix,),
    )


def test_tampered_domain_prefix_fails_closed_in_validator():
    contract = AcceptanceContract(
        "ac", "sha256:" + "1" * 64, ("unit",), ("README.md",), "FORBID",
        allowed_path_prefixes=("src/",),
    )
    object.__setattr__(contract, "allowed_path_prefixes", ("",))
    from product.adapters.generic_verification import _domain_objects
    from tests.product.test_generic_verification_protocol import _payload as _p

    _, change_set, plan, evidence = _domain_objects(_p())
    errors = validate_evidence_subjects(contract, change_set, plan, evidence)
    assert "MALFORMED:contract.allowed_path_prefixes" in errors
    assert derive_evidence_integrity(contract, change_set, plan, evidence) is IntegrityStatus.MALFORMED


def test_descriptor_negative_vectors_cover_prefix_cases():
    from product.protocol.generic_verification import protocol_descriptor

    names = set(protocol_descriptor()["negative_conformance_vectors"])
    assert {
        "invalid_path_prefix_traversal",
        "invalid_path_prefix_missing_trailing_slash",
        "invalid_path_prefix_glob",
        "invalid_path_prefix_root",
    } <= names


# --- runtime receipt recomputation binds prefixes (Codex review finding) ---


def _runtime_case(prefixes):
    from product.evidence import (
        ChangeSet,
        EvidenceBundle,
        Observation,
        ObservationStatus,
        VerificationPlan,
        _hash,
    )
    from product.kernel import CertificationInput

    contract = AcceptanceContract(
        "ac", _hash("requirements"), ("unit",), ("README.md",), "FORBID",
        allowed_path_prefixes=prefixes,
    )
    change = ChangeSet("cs", "base", "head", _hash("diff"), ("src/pkg/a.py",))
    plan = VerificationPlan("plan", contract.hash, change.hash, ("unit",))
    evidence = EvidenceBundle(
        "bundle", contract.hash, change.hash, plan.hash,
        (Observation("unit", "artifact", _hash("artifact"), ObservationStatus.PASS),),
    )
    return CertificationInput(contract, change, plan, evidence, True, True, True, True)


def _original_inputs(cert_in, prefixes):
    contract = {
        "contract_id": cert_in.contract.contract_id,
        "requirements_hash": cert_in.contract.requirements_hash,
        "required_verifier_ids": list(cert_in.contract.required_verifier_ids),
        "allowed_paths": list(cert_in.contract.allowed_paths),
        "deletion_policy": cert_in.contract.deletion_policy,
    }
    if prefixes is not None:
        contract["allowed_path_prefixes"] = list(prefixes)
    return {
        "acceptance_contract": contract,
        "change_set": {
            "change_set_id": cert_in.change_set.change_set_id,
            "source_revision": cert_in.change_set.source_revision,
            "target_revision": cert_in.change_set.target_revision,
            "diff_hash": cert_in.change_set.diff_hash,
            "paths": list(cert_in.change_set.paths),
        },
        "verification_plan": {
            "plan_id": cert_in.plan.plan_id,
            "required_verifier_ids": list(cert_in.plan.required_verifier_ids),
        },
        "evidence": {
            "bundle_id": cert_in.evidence.bundle_id,
            "observations": [
                {
                    "verifier_id": o.verifier_id,
                    "artifact_id": o.artifact_id,
                    "artifact_hash": o.artifact_hash,
                    "status": o.status.value,
                }
                for o in cert_in.evidence.observations
            ],
        },
    }


@pytest.mark.asyncio
async def test_full_receipt_recomputation_binds_prefixes(tmp_path):
    from product.kernel import certify
    from product.runtime.service import RuntimeCertificationService

    cert_in = _runtime_case(("src/pkg/",))
    result = certify(cert_in)
    assert result.disposition.value == "CERTIFIED"
    receipt = result.receipt.to_dict()
    service = RuntimeCertificationService(db_path=str(tmp_path / "ledger.db"))

    async def full(prefixes):
        code, body = await service.verify_receipt(
            {
                "receipt": receipt,
                "requested_scope": "FULL",
                "original_inputs": _original_inputs(cert_in, prefixes),
            }
        )
        assert code == 200, body
        return body["status"]

    assert await full(["src/pkg/"]) == "VALID"
    assert await full(None) == "INVALID"
    assert await full(["src/"]) == "INVALID"
