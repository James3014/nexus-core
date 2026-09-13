import copy

import pytest

from product.adapters.generic_verification import verify_generic_changeset
from product.evidence import AcceptanceContract, ChangeSet, _hash
from product.protocol import PUBLIC_PROTOCOL_VERSION
from product.protocol.generic_verification import (
    GENERIC_PROTOCOL_CONFORMANCE_VECTORS,
    GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
    acceptance_contract_hash,
    change_manifest_hash,
    change_set_hash,
    evidence_bundle_hash,
    protocol_descriptor,
    verification_plan_hash,
)
from product.verification import VerificationStatus


def _entry(
    path: str = "src/a.py",
    *,
    kind: str = "MODIFY",
    before: str | None = "1" * 40,
    after: str | None = "2" * 40,
    before_mode: str | None = "100644",
    after_mode: str | None = "100644",
):
    return {
        "path": path,
        "change_type": kind,
        "before_oid": before,
        "after_oid": after,
        "before_mode": before_mode,
        "after_mode": after_mode,
    }


def _payload(
    *,
    deletion_policy: str = "FORBID",
    entries=None,
    policy=None,
    observation_status: str = "PASS",
):
    entries = entries or [_entry()]
    manifest = {
        "source_tree": "git-tree:" + "a" * 40,
        "target_tree": "git-tree:" + "b" * 40,
        "entries": entries,
    }
    paths = sorted(row["path"] for row in entries)
    deleted = sorted(row["path"] for row in entries if row["change_type"] == "DELETE")
    contract = {
        "contract_id": "ac-1",
        "requirements_hash": "sha256:" + "c" * 64,
        "required_verifier_ids": ["unit"],
        "allowed_paths": paths,
        "deletion_policy": deletion_policy,
    }
    change_set = {
        "change_set_id": "cs-1",
        "source_revision": "git-commit:" + "d" * 40,
        "target_revision": manifest["target_tree"],
        "diff_hash": change_manifest_hash(manifest),
        "paths": paths,
        "deleted_paths": deleted,
    }
    plan = {
        "plan_id": "vp-1",
        "acceptance_contract_hash": acceptance_contract_hash(contract),
        "change_set_hash": change_set_hash(change_set),
        "required_verifier_ids": ["unit"],
    }
    evidence = {
        "bundle_id": "eb-1",
        "acceptance_contract_hash": plan["acceptance_contract_hash"],
        "change_set_hash": plan["change_set_hash"],
        "verification_plan_hash": verification_plan_hash(plan),
        "observations": [
            {
                "verifier_id": "unit",
                "artifact_id": "artifact-1",
                "artifact_hash": "sha256:" + "e" * 64,
                "status": observation_status,
            }
        ],
        "claimed_bundle_hash": None,
    }
    return {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
        "acceptance_contract": contract,
        "change_set": change_set,
        "change_manifest": manifest,
        "verification_plan": plan,
        "evidence_bundle": evidence,
        "certification_policy": policy,
    }


def _rehash(payload):
    payload["change_set"]["diff_hash"] = change_manifest_hash(payload["change_manifest"])
    payload["verification_plan"]["acceptance_contract_hash"] = acceptance_contract_hash(
        payload["acceptance_contract"]
    )
    payload["verification_plan"]["change_set_hash"] = change_set_hash(payload["change_set"])
    payload["evidence_bundle"]["acceptance_contract_hash"] = payload["verification_plan"][
        "acceptance_contract_hash"
    ]
    payload["evidence_bundle"]["change_set_hash"] = payload["verification_plan"][
        "change_set_hash"
    ]
    payload["evidence_bundle"]["verification_plan_hash"] = verification_plan_hash(
        payload["verification_plan"]
    )
    payload["evidence_bundle"]["claimed_bundle_hash"] = None
    return payload


def test_generic_verify_supports_uncommitted_git_tree_without_certification():
    status, body = verify_generic_changeset(_payload())
    assert status == 200
    assert body["verification"] == {
        "status": "VERIFIED",
        "reason_codes": [],
        "integrity": "VALID",
    }
    assert body["certification"] is None
    assert body["hashes"]["change_set_hash"] == change_set_hash(_payload()["change_set"])


def test_certification_is_optional_and_missing_policy_facts_do_not_get_synthesized():
    policy = {
        "accepted": True,
        "authority_present": True,
        "approval_present": None,
        "signing_present": None,
    }
    status, body = verify_generic_changeset(_payload(policy=policy))
    assert status == 200
    assert body["verification"]["status"] == "VERIFIED"
    assert body["certification"]["disposition"] == "BLOCKED"
    assert body["certification"]["receipt"]["certification"]["policy"]["approval_present"] is None
    assert body["certification"]["receipt"]["certification"]["policy"]["signing_present"] is None


def test_certification_can_be_certified_only_when_all_facts_are_true():
    policy = {
        "accepted": True,
        "authority_present": True,
        "approval_present": True,
        "signing_present": True,
    }
    status, body = verify_generic_changeset(_payload(policy=policy))
    assert status == 200
    assert body["verification"]["status"] == "VERIFIED"
    assert body["certification"]["disposition"] == "CERTIFIED"


def test_forbidden_deletion_is_failed_verification_but_allow_can_verify():
    deletion = _entry(
        "src/old.py",
        kind="DELETE",
        before="f" * 40,
        after=None,
        before_mode="100644",
        after_mode=None,
    )
    forbidden = _payload(entries=[deletion], deletion_policy="FORBID")
    status, body = verify_generic_changeset(forbidden)
    assert status == 200
    assert body["verification"]["status"] == "FAILED_VERIFICATION"
    assert body["verification"]["reason_codes"] == ["DELETION_FORBIDDEN"]

    allowed = _payload(entries=[deletion], deletion_policy="ALLOW")
    status, body = verify_generic_changeset(allowed)
    assert status == 200
    assert body["verification"]["status"] == "VERIFIED"


def test_failed_verifier_remains_failed_verification():
    status, body = verify_generic_changeset(_payload(observation_status="FAIL"))
    assert status == 200
    assert body["verification"]["status"] == "FAILED_VERIFICATION"
    assert body["verification"]["reason_codes"] == ["VERIFIER_FAILED", "unit"]


def test_scope_escape_is_derived_by_core_not_caller_prose():
    payload = _payload()
    payload["acceptance_contract"]["allowed_paths"] = ["src/other.py"]
    _rehash(payload)
    status, body = verify_generic_changeset(payload)
    assert status == 200
    assert body["verification"]["status"] == "FAILED_VERIFICATION"
    assert body["verification"]["reason_codes"] == ["SCOPE_ESCAPE"]


def test_manifest_and_changeset_cross_binding_is_fail_closed():
    payload = _payload()
    payload["change_set"]["diff_hash"] = "sha256:" + "0" * 64
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"] == {"code": "CROSS_BINDING_INVALID", "field": "change_set.diff_hash"}

    payload = _payload()
    payload["change_set"]["deleted_paths"] = ["src/a.py"]
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"]["field"] == "change_set.deleted_paths"


def test_revision_reference_is_typed_and_tree_target_is_bound_to_manifest():
    payload = _payload()
    payload["change_set"]["target_revision"] = "b" * 40
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"]["field"] == "change_set.target_revision"

    payload = _payload()
    payload["change_set"]["target_revision"] = "git-tree:" + "9" * 40
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"]["field"] == "change_manifest.target_tree"


def test_manifest_hash_is_order_independent_but_content_sensitive():
    first = _entry("src/a.py")
    second = _entry(
        "src/b.py",
        kind="ADD",
        before=None,
        after="7" * 40,
        before_mode=None,
        after_mode="100644",
    )
    a = {
        "source_tree": "git-tree:" + "1" * 40,
        "target_tree": "git-tree:" + "2" * 40,
        "entries": [first, second],
    }
    b = copy.deepcopy(a)
    b["entries"].reverse()
    assert change_manifest_hash(a) == change_manifest_hash(b)
    b["entries"][0]["after_oid"] = "8" * 40
    assert change_manifest_hash(a) != change_manifest_hash(b)


def test_no_deletion_changeset_preserves_existing_kernel_hash_identity():
    value = _payload()["change_set"]
    existing = ChangeSet(
        value["change_set_id"],
        value["source_revision"],
        value["target_revision"],
        value["diff_hash"],
        tuple(value["paths"]),
    )
    assert existing.deleted_paths == ()
    assert existing.hash == change_set_hash(value)


def test_changeset_rejects_non_tuple_or_out_of_scope_deleted_paths():
    value = _payload()["change_set"]
    with pytest.raises(TypeError):
        ChangeSet(
            value["change_set_id"],
            value["source_revision"],
            value["target_revision"],
            value["diff_hash"],
            tuple(value["paths"]),
            [],  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        ChangeSet(
            value["change_set_id"],
            value["source_revision"],
            value["target_revision"],
            value["diff_hash"],
            tuple(value["paths"]),
            ("src/not-in-paths.py",),
        )


def test_deletion_changeset_hash_binds_deleted_paths():
    value = _payload(
        entries=[
            _entry(
                "src/old.py",
                kind="DELETE",
                before="9" * 40,
                after=None,
                before_mode="100644",
                after_mode=None,
            )
        ],
        deletion_policy="ALLOW",
    )["change_set"]
    existing = ChangeSet(
        value["change_set_id"],
        value["source_revision"],
        value["target_revision"],
        value["diff_hash"],
        tuple(value["paths"]),
        tuple(value["deleted_paths"]),
    )
    without_deletion_fact = ChangeSet(
        value["change_set_id"],
        value["source_revision"],
        value["target_revision"],
        value["diff_hash"],
        tuple(value["paths"]),
    )
    assert existing.hash == change_set_hash(value)
    assert existing.hash != without_deletion_fact.hash


def test_public_hash_functions_match_existing_core_domain_including_unicode():
    vector = GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract_unicode"]
    value = vector["value"]
    domain = AcceptanceContract(
        value["contract_id"],
        value["requirements_hash"],
        tuple(value["required_verifier_ids"]),
        tuple(value["allowed_paths"]),
        value["deletion_policy"],
    )
    assert acceptance_contract_hash(value) == vector["expected_hash"]
    assert acceptance_contract_hash(value) == domain.hash


def test_protocol_descriptor_vectors_are_literal_and_self_consistent():
    descriptor = protocol_descriptor()
    assert descriptor["protocol_version"] == PUBLIC_PROTOCOL_VERSION
    assert descriptor["canonicalization"]["ensure_ascii"] is True
    vectors = descriptor["conformance_vectors"]
    assert acceptance_contract_hash(vectors["acceptance_contract"]["value"]) == vectors[
        "acceptance_contract"
    ]["expected_hash"]
    assert acceptance_contract_hash(vectors["acceptance_contract_unicode"]["value"]) == vectors[
        "acceptance_contract_unicode"
    ]["expected_hash"]
    assert change_set_hash(vectors["change_set_no_deletion"]["value"]) == vectors[
        "change_set_no_deletion"
    ]["expected_hash"]
    assert change_set_hash(vectors["change_set_with_deletion"]["value"]) == vectors[
        "change_set_with_deletion"
    ]["expected_hash"]
    assert verification_plan_hash(vectors["verification_plan"]["value"]) == vectors[
        "verification_plan"
    ]["expected_hash"]
    assert evidence_bundle_hash(vectors["evidence_bundle"]["value"]) == vectors[
        "evidence_bundle"
    ]["expected_hash"]
    assert change_manifest_hash(vectors["change_manifest"]["value"]) == vectors[
        "change_manifest"
    ]["expected_hash"]


def test_claimed_evidence_hash_tampering_is_rejected_before_core_projection():
    payload = _payload()
    payload["evidence_bundle"]["claimed_bundle_hash"] = "sha256:" + "0" * 64
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"]["code"] == "TAMPERED"


def test_domain_verification_status_enum_remains_the_existing_core_enum():
    status, body = verify_generic_changeset(_payload())
    assert status == 200
    assert body["verification"]["status"] == VerificationStatus.VERIFIED.value


def test_evidence_bundle_public_hash_matches_domain_hash():
    payload = _payload()
    status, body = verify_generic_changeset(payload)
    assert status == 200
    assert body["hashes"]["evidence_bundle_hash"] == evidence_bundle_hash(
        payload["evidence_bundle"]
    )


def test_unknown_top_level_field_is_rejected_not_ignored():
    payload = _payload()
    payload["caller_claim"] = "VERIFIED"
    status, body = verify_generic_changeset(payload)
    assert status == 422
    assert body["error"] == {"code": "MALFORMED_REQUEST", "field": "request"}


def test_legacy_hash_helper_still_remains_available_for_existing_tests():
    assert _hash("stable") == _hash("stable")
