from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


protocol_path = Path("product/protocol/generic_verification.py")
protocol = protocol_path.read_text()

protocol = replace_once(
    protocol,
    '_PATH_SCHEMA: dict[str, Any] = {"type": "string", "minLength": 1, "pattern": _PATH_PATTERN}\n',
    '''_NORMALIZED_TEXT_SCHEMA: dict[str, Any] = {\n    "type": "string",\n    "minLength": 1,\n    "x-nexus-normalized-text": True,\n    "x-nexus-max-utf8-bytes": 512,\n}\n_PATH_SCHEMA: dict[str, Any] = {\n    **_NORMALIZED_TEXT_SCHEMA,\n    "pattern": _PATH_PATTERN,\n    "x-nexus-repository-relative-path": True,\n}\n''',
    "normalized text schema",
)

for old, new, label in (
    ('"contract_id": {"type": "string", "minLength": 1},', '"contract_id": _NORMALIZED_TEXT_SCHEMA,', "contract id schema"),
    ('"items": {"type": "string", "minLength": 1},\n        },\n        "allowed_paths"', '"items": _NORMALIZED_TEXT_SCHEMA,\n        },\n        "allowed_paths"', "contract verifier schema"),
    ('"change_set_id": {"type": "string", "minLength": 1},', '"change_set_id": _NORMALIZED_TEXT_SCHEMA,', "change set id schema"),
    ('"plan_id": {"type": "string", "minLength": 1},', '"plan_id": _NORMALIZED_TEXT_SCHEMA,', "plan id schema"),
    ('"required_verifier_ids": {\n            "type": "array",\n            "minItems": 1,\n            "uniqueItems": True,\n            "items": {"type": "string", "minLength": 1},\n        },\n    },\n    "additionalProperties": False,\n}\n\nOBSERVATION_SCHEMA', '"required_verifier_ids": {\n            "type": "array",\n            "minItems": 1,\n            "uniqueItems": True,\n            "items": _NORMALIZED_TEXT_SCHEMA,\n        },\n    },\n    "additionalProperties": False,\n}\n\nOBSERVATION_SCHEMA', "plan verifier schema"),
    ('"verifier_id": {"type": "string", "minLength": 1},\n        "artifact_id": {"type": "string", "minLength": 1},', '"verifier_id": _NORMALIZED_TEXT_SCHEMA,\n        "artifact_id": _NORMALIZED_TEXT_SCHEMA,', "observation id schemas"),
    ('"bundle_id": {"type": "string", "minLength": 1},', '"bundle_id": _NORMALIZED_TEXT_SCHEMA,', "bundle id schema"),
):
    protocol = replace_once(protocol, old, new, label)

insert_marker = "\n\n\ndef protocol_descriptor() -> dict[str, Any]:\n"
insert = r'''


def _request_conformance_vector() -> dict[str, Any]:
    manifest = {
        "source_tree": "git-tree:" + "a" * 40,
        "target_tree": "git-tree:" + "b" * 40,
        "entries": [
            {
                "path": "src/a.py",
                "change_type": "MODIFY",
                "before_oid": "1" * 40,
                "after_oid": "2" * 40,
                "before_mode": "100644",
                "after_mode": "100644",
            }
        ],
    }
    contract = {
        "contract_id": "ac-request-vector-1",
        "requirements_hash": "sha256:" + "c" * 64,
        "required_verifier_ids": ["unit"],
        "allowed_paths": ["src/a.py"],
        "deletion_policy": "FORBID",
    }
    change_set = {
        "change_set_id": "cs-request-vector-1",
        "source_revision": "git-commit:" + "d" * 40,
        "target_revision": manifest["target_tree"],
        "diff_hash": change_manifest_hash(manifest),
        "paths": ["src/a.py"],
        "deleted_paths": [],
    }
    plan = {
        "plan_id": "vp-request-vector-1",
        "acceptance_contract_hash": acceptance_contract_hash(contract),
        "change_set_hash": change_set_hash(change_set),
        "required_verifier_ids": ["unit"],
    }
    evidence = {
        "bundle_id": "eb-request-vector-1",
        "acceptance_contract_hash": plan["acceptance_contract_hash"],
        "change_set_hash": plan["change_set_hash"],
        "verification_plan_hash": verification_plan_hash(plan),
        "observations": [
            {
                "verifier_id": "unit",
                "artifact_id": "artifact-request-vector-1",
                "artifact_hash": "sha256:" + "e" * 64,
                "status": "PASS",
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
        "certification_policy": None,
    }


GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR = _request_conformance_vector()

GENERIC_PROTOCOL_ORDERING_CONFORMANCE_VECTORS: dict[str, Any] = {
    "json_object_field_order": {
        "left": {"b": 2, "a": 1},
        "right": {"a": 1, "b": 2},
        "expected_canonical_json": '{"a":1,"b":2}',
        "expected_hash": "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
    },
    "acceptance_path_and_verifier_order": {
        "left": {
            "contract_id": "ac-order-vector-1",
            "requirements_hash": "sha256:" + "f" * 64,
            "required_verifier_ids": ["lint", "unit"],
            "allowed_paths": ["src/a.py", "tests/test_a.py"],
            "deletion_policy": "FORBID",
        },
        "right": {
            "deletion_policy": "FORBID",
            "allowed_paths": ["tests/test_a.py", "src/a.py"],
            "required_verifier_ids": ["unit", "lint"],
            "requirements_hash": "sha256:" + "f" * 64,
            "contract_id": "ac-order-vector-1",
        },
    },
    "evidence_observation_order": {
        "left": {
            "bundle_id": "eb-order-vector-1",
            "acceptance_contract_hash": "sha256:" + "1" * 64,
            "change_set_hash": "sha256:" + "2" * 64,
            "verification_plan_hash": "sha256:" + "3" * 64,
            "observations": [
                {
                    "verifier_id": "unit",
                    "artifact_id": "artifact-unit",
                    "artifact_hash": "sha256:" + "4" * 64,
                    "status": "PASS",
                },
                {
                    "verifier_id": "lint",
                    "artifact_id": "artifact-lint",
                    "artifact_hash": "sha256:" + "5" * 64,
                    "status": "PASS",
                },
            ],
            "claimed_bundle_hash": None,
        },
        "right": {
            "claimed_bundle_hash": None,
            "observations": [
                {
                    "status": "PASS",
                    "artifact_hash": "sha256:" + "5" * 64,
                    "artifact_id": "artifact-lint",
                    "verifier_id": "lint",
                },
                {
                    "status": "PASS",
                    "artifact_hash": "sha256:" + "4" * 64,
                    "artifact_id": "artifact-unit",
                    "verifier_id": "unit",
                },
            ],
            "verification_plan_hash": "sha256:" + "3" * 64,
            "change_set_hash": "sha256:" + "2" * 64,
            "acceptance_contract_hash": "sha256:" + "1" * 64,
            "bundle_id": "eb-order-vector-1",
        },
    },
}

GENERIC_PROTOCOL_NEGATIVE_CONFORMANCE_VECTORS: dict[str, Any] = {
    "invalid_path": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/allowed_paths",
        "value": ["../escape.py"],
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.allowed_paths"},
    },
    "invalid_deletion_policy": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/deletion_policy",
        "value": "MAYBE",
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.deletion_policy"},
    },
    "malformed_hash": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/requirements_hash",
        "value": "sha256:not-a-hash",
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.requirements_hash"},
    },
    "duplicate_verifier_ids": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/required_verifier_ids",
        "value": ["unit", "unit"],
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.required_verifier_ids"},
    },
    "padded_identifier": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/contract_id",
        "value": " ac-request-vector-1 ",
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.contract_id"},
    },
    "overlong_utf8_identifier": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/contract_id",
        "value": "雪" * 171,
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.contract_id"},
    },
}

GENERIC_PROTOCOL_VALIDATION_CONSTRAINTS: dict[str, Any] = {
    "normalized_text": {
        "nonblank": True,
        "leading_or_trailing_strip_characters_forbidden": True,
        "nul_forbidden": True,
        "max_utf8_bytes": 512,
        "normative_rule": "type(value) is str and bool(value) and value == value.strip() and NUL not in value and len(value.encode('utf-8')) <= 512",
    },
    "repository_relative_path": {
        "inherits": "normalized_text",
        "absolute_forbidden": True,
        "backslash_forbidden": True,
        "empty_segment_forbidden": True,
        "dot_segment_forbidden": True,
        "dotdot_segment_forbidden": True,
    },
}
'''
protocol = replace_once(protocol, insert_marker, insert + insert_marker, "descriptor metadata insert")

protocol = replace_once(
    protocol,
    '        "conformance_vectors": GENERIC_PROTOCOL_CONFORMANCE_VECTORS,\n',
    '        "conformance_vectors": GENERIC_PROTOCOL_CONFORMANCE_VECTORS,\n        "request_conformance_vector": GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR,\n        "ordering_conformance_vectors": GENERIC_PROTOCOL_ORDERING_CONFORMANCE_VECTORS,\n        "negative_conformance_vectors": GENERIC_PROTOCOL_NEGATIVE_CONFORMANCE_VECTORS,\n        "validation_constraints": GENERIC_PROTOCOL_VALIDATION_CONSTRAINTS,\n',
    "descriptor fields",
)

protocol = replace_once(
    protocol,
    '    "GENERIC_PROTOCOL_CONFORMANCE_VECTORS",\n',
    '    "GENERIC_PROTOCOL_CONFORMANCE_VECTORS",\n    "GENERIC_PROTOCOL_NEGATIVE_CONFORMANCE_VECTORS",\n    "GENERIC_PROTOCOL_ORDERING_CONFORMANCE_VECTORS",\n    "GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR",\n    "GENERIC_PROTOCOL_VALIDATION_CONSTRAINTS",\n',
    "public exports",
)

protocol_path.write_text(protocol)


test_path = Path("tests/product/test_generic_verification_protocol.py")
tests = test_path.read_text()
tests = replace_once(
    tests,
    "import pytest\n\n",
    "import pytest\n\nimport product.protocol.generic_verification as generic_protocol\n\n",
    "test module alias",
)

tests += r'''


def _replace_pointer(value, pointer, replacement):
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]
    target = value
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = replacement


def test_public_ordering_conformance_vectors_cover_object_path_verifier_and_observation_order():
    vectors = generic_protocol.GENERIC_PROTOCOL_ORDERING_CONFORMANCE_VECTORS
    object_order = vectors["json_object_field_order"]
    assert generic_protocol.canonical_json(object_order["left"]) == object_order["expected_canonical_json"]
    assert generic_protocol.canonical_json(object_order["right"]) == object_order["expected_canonical_json"]
    assert generic_protocol.canonical_hash(object_order["left"]) == object_order["expected_hash"]
    assert generic_protocol.canonical_hash(object_order["right"]) == object_order["expected_hash"]

    acceptance = vectors["acceptance_path_and_verifier_order"]
    assert acceptance_contract_hash(acceptance["left"]) == acceptance_contract_hash(acceptance["right"])

    evidence = vectors["evidence_observation_order"]
    assert evidence_bundle_hash(evidence["left"]) == evidence_bundle_hash(evidence["right"])


def test_public_negative_conformance_vectors_are_executable_fail_closed_cases():
    descriptor = protocol_descriptor()
    assert descriptor["request_conformance_vector"] == generic_protocol.GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR
    for name, vector in descriptor["negative_conformance_vectors"].items():
        payload = copy.deepcopy(descriptor["request_conformance_vector"])
        _replace_pointer(payload, vector["replace_pointer"], vector["value"])
        status, body = verify_generic_changeset(payload)
        assert status == vector["expected_http_status"], name
        assert body["error"] == vector["expected_error"], name


def test_public_descriptor_exposes_parser_normalization_and_utf8_byte_limit():
    constraints = protocol_descriptor()["validation_constraints"]
    assert constraints["normalized_text"]["max_utf8_bytes"] == 512
    assert constraints["normalized_text"]["nul_forbidden"] is True
    assert constraints["normalized_text"]["leading_or_trailing_strip_characters_forbidden"] is True
    assert constraints["repository_relative_path"]["dotdot_segment_forbidden"] is True
    assert generic_protocol.ACCEPTANCE_CONTRACT_SCHEMA["properties"]["contract_id"]["x-nexus-max-utf8-bytes"] == 512
    assert generic_protocol.ACCEPTANCE_CONTRACT_SCHEMA["properties"]["allowed_paths"]["items"]["x-nexus-repository-relative-path"] is True
'''

test_path.write_text(tests)

print("patched Core #29 public conformance metadata and focused tests")
