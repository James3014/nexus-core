"""#266 public universe identity and #267 git-free Core build identity."""

from __future__ import annotations

import copy
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from product.adapters.generic_verification import verify_generic_changeset
from product.clients.local_golden_path import (
    _core_responses_equivalent,  # pyright: ignore[reportPrivateUsage]
)
from product.evidence import (
    AcceptanceContract,
    Applicability,
    ExpectedEvidenceSubject,
    RequirementMode,
)
from product.protocol import core_identity
from product.protocol.build_identity import (
    BUILD_IDENTITY_FILENAME,
    CORE_IDENTITY_SCHEMA,
    SOURCE_DIGEST_CONFORMANCE_VECTOR,
    make_build_identity,
    select_shipped_paths,
    shipped_source_paths,
    source_digest,
    source_digest_of_files,
)
from product.protocol.generic_verification import (
    GENERIC_PROTOCOL_CONFORMANCE_VECTORS,
    GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR,
    GENERIC_PROTOCOL_SCHEMA_BUNDLE_HASH,
    acceptance_contract_hash,
    change_set_hash,
    evidence_bundle_hash,
    expected_universe_identity,
    protocol_descriptor,
    verification_plan_hash,
)

REPO_ROOT = Path(__file__).parents[2].resolve()
PRODUCT_DIR = REPO_ROOT / "product"

# Literal copies of the pre-#266/#267 expected hashes. They are deliberately not
# read from GENERIC_PROTOCOL_CONFORMANCE_VECTORS so an edit there cannot hide a
# change to an existing hash.
LEGACY_EXPECTED_HASHES = {
    "acceptance_contract": "sha256:5a97aa6989c3ddf00e08c57327436f626bb0be918844eef0225e276121e21eff",
    "acceptance_contract_unicode": "sha256:21face1a76514a320f54660053e4c1e9e51f54ab31f346a599db88a2107174d4",
    "change_set_no_deletion": "sha256:6a5d849712b409d4a30a30b50138ddd840847ae4aaf4c1916108e6711fae594c",
    "change_set_with_deletion": "sha256:ffa70fd13cb1651d951437c0fc8006e5e3888f81115d2c40d96a56b0d4cde39f",
    "verification_plan": "sha256:3e1e5d25ac55d605cf52620f658cb8bd399f501e85caac9cc2e6a7814c4a73c9",
    "evidence_bundle": "sha256:f245f85800e26e13af723108c56c1eeb0d4b6e801e1cef5b1c35d694a1e93113",
    "acceptance_contract_universe": "sha256:6bf2f53e4147ea5d1f9e02089c7237ab6b1cfbb94204d16a6f351e4c0f4f061b",
    "evidence_bundle_universe": "sha256:acea73418cb51bc8993a2754d62dd07a62e3344267ed262e2efd16092f483698",
}
UNIVERSE_VECTOR_IDENTITY = "sha256:86a8e20e6a99a9c49cffe0110999d51affb3a9082f65f89c067b152f5462ae29"
# Recorded schema bundle change: main (after #269) -> this value; see PR #270 body.
SCHEMA_BUNDLE_HASH = "sha256:7f57b29707ce9cb59a87f422fb746110c1ad63a520bfb464d3143a152e9da769"

_HASH_FNS = {
    "acceptance_contract": acceptance_contract_hash,
    "acceptance_contract_unicode": acceptance_contract_hash,
    "acceptance_contract_universe": acceptance_contract_hash,
    "change_set_no_deletion": change_set_hash,
    "change_set_with_deletion": change_set_hash,
    "verification_plan": verification_plan_hash,
    "evidence_bundle": evidence_bundle_hash,
    "evidence_bundle_universe": evidence_bundle_hash,
}


def _domain_contract(value) -> AcceptanceContract:
    return AcceptanceContract(
        value["contract_id"],
        value["requirements_hash"],
        tuple(value["required_verifier_ids"]),
        tuple(value["allowed_paths"]),
        value["deletion_policy"],
        tuple(
            ExpectedEvidenceSubject(
                row["logical_subject_id"],
                row["evidence_kind"],
                RequirementMode(row["requirement_mode"]),
                Applicability(row["applicability"]),
            )
            for row in value.get("expected_subjects") or ()
        ),
        value.get("universe_generation", 0),
    )


# --------------------------------------------------------------------------- #266


@pytest.mark.parametrize("name", sorted(LEGACY_EXPECTED_HASHES))
def test_existing_conformance_hashes_are_unchanged(name):
    vector = GENERIC_PROTOCOL_CONFORMANCE_VECTORS[name]
    assert vector["expected_hash"] == LEGACY_EXPECTED_HASHES[name]
    assert _HASH_FNS[name](vector["value"]) == LEGACY_EXPECTED_HASHES[name]


def test_universe_conformance_vector_carries_expected_identity():
    vector = GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract_universe"]
    assert vector["expected_universe_identity"] == UNIVERSE_VECTOR_IDENTITY
    assert expected_universe_identity(vector["value"]) == UNIVERSE_VECTOR_IDENTITY
    assert _domain_contract(vector["value"]).universe_identity == UNIVERSE_VECTOR_IDENTITY
    descriptor = protocol_descriptor()
    assert (
        descriptor["conformance_vectors"]["acceptance_contract_universe"]["expected_universe_identity"]
        == UNIVERSE_VECTOR_IDENTITY
    )
    assert "universe_identity" in descriptor["canonicalization"]


def test_legacy_contract_has_no_universe_identity():
    for name in ("acceptance_contract", "acceptance_contract_unicode"):
        value = GENERIC_PROTOCOL_CONFORMANCE_VECTORS[name]["value"]
        assert expected_universe_identity(value) is None
        assert _domain_contract(value).universe_identity is None
    empty = dict(GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract"]["value"])
    empty["expected_subjects"] = []
    assert expected_universe_identity(empty) is None


def test_universe_identity_is_stable_across_subject_and_key_order():
    value = copy.deepcopy(GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract_universe"]["value"])
    reordered = copy.deepcopy(value)
    reordered["expected_subjects"] = [
        dict(reversed(list(row.items()))) for row in reversed(reordered["expected_subjects"])
    ]
    reordered = dict(reversed(list(reordered.items())))
    assert expected_universe_identity(reordered) == UNIVERSE_VECTOR_IDENTITY
    assert acceptance_contract_hash(reordered) == LEGACY_EXPECTED_HASHES["acceptance_contract_universe"]


def test_universe_identity_binds_generation_and_subject_fields():
    base = GENERIC_PROTOCOL_CONFORMANCE_VECTORS["acceptance_contract_universe"]["value"]
    seen = {expected_universe_identity(base)}
    bumped = copy.deepcopy(base)
    bumped["universe_generation"] = 2
    seen.add(expected_universe_identity(bumped))
    for field, new in (
        ("logical_subject_id", "subject-9"),
        ("evidence_kind", "kind-z"),
        ("applicability", "NOT_APPLICABLE"),
    ):
        changed = copy.deepcopy(base)
        changed["expected_subjects"][1][field] = new
        seen.add(expected_universe_identity(changed))
    assert len(seen) == 5
    # Contract fields outside the universe do not move the universe identity.
    other = copy.deepcopy(base)
    other["contract_id"] = "ac-other"
    other["allowed_paths"] = ["src/b.py"]
    assert expected_universe_identity(other) == expected_universe_identity(base)


def test_wire_identity_matches_domain_property_on_random_contracts():
    rng = random.Random(266)
    modes = [
        ("REQUIRED", "APPLICABLE"),
        ("CONDITIONALLY_REQUIRED", "APPLICABLE"),
        ("CONDITIONALLY_REQUIRED", "NOT_APPLICABLE"),
        ("CONDITIONALLY_REQUIRED", "UNRESOLVED"),
        ("NOT_APPLICABLE", "NOT_APPLICABLE"),
    ]
    alphabet = ["a", "Z", "雪", "-", "0", "é", "_"]
    for _ in range(300):
        count = rng.randint(1, 6)
        ids = set()
        while len(ids) < count:
            ids.add("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 6))))
        subjects = []
        for subject_id in ids:
            mode, applicability = rng.choice(modes)
            subjects.append(
                {
                    "logical_subject_id": subject_id,
                    "evidence_kind": rng.choice(["test-result", "static-analysis", "k雪"]),
                    "requirement_mode": mode,
                    "applicability": applicability,
                }
            )
        value = {
            "contract_id": "ac-prop",
            "requirements_hash": "sha256:" + "f" * 64,
            "required_verifier_ids": ["unit"],
            "allowed_paths": ["src/a.py"],
            "deletion_policy": "FORBID",
            "expected_subjects": subjects,
        }
        if rng.random() < 0.8:
            value["universe_generation"] = rng.randint(0, 5)
        domain = _domain_contract(value)
        assert expected_universe_identity(value) == domain.universe_identity
        assert acceptance_contract_hash(value) == domain.hash
        rng.shuffle(subjects)
        assert expected_universe_identity(value) == domain.universe_identity


def _universe_request():
    request = copy.deepcopy(GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR)
    contract = request["acceptance_contract"]
    contract["universe_generation"] = 1
    contract["expected_subjects"] = [
        {
            "logical_subject_id": "subject-1",
            "evidence_kind": "test-result",
            "requirement_mode": "REQUIRED",
            "applicability": "APPLICABLE",
        }
    ]
    plan = request["verification_plan"]
    plan["acceptance_contract_hash"] = acceptance_contract_hash(contract)
    evidence = request["evidence_bundle"]
    evidence["acceptance_contract_hash"] = plan["acceptance_contract_hash"]
    evidence["verification_plan_hash"] = verification_plan_hash(plan)
    evidence["observations"][0]["logical_subject_id"] = "subject-1"
    evidence["observations"][0]["evidence_kind"] = "test-result"
    return request


def test_response_carries_universe_identity_only_when_declared():
    status, legacy = verify_generic_changeset(copy.deepcopy(GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR))
    assert status == 200
    assert sorted(legacy["hashes"]) == [
        "acceptance_contract_hash",
        "change_manifest_hash",
        "change_set_hash",
        "evidence_bundle_hash",
        "verification_plan_hash",
    ]
    assert "coverage" not in legacy["verification"]

    request = _universe_request()
    status, body = verify_generic_changeset(request)
    assert status == 200, body
    identity = expected_universe_identity(request["acceptance_contract"])
    assert identity is not None
    assert body["hashes"]["universe_identity"] == identity
    assert body["verification"]["coverage"]["universe_identity"] == identity


def test_legacy_response_fields_are_unchanged_and_core_identity_is_additive():
    status, body = verify_generic_changeset(copy.deepcopy(GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR))
    assert status == 200
    assert set(body) == {"protocol_version", "schema", "verification", "hashes", "certification", "core_identity"}
    request = GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR
    assert body["hashes"] == {
        "acceptance_contract_hash": request["verification_plan"]["acceptance_contract_hash"],
        "change_set_hash": request["verification_plan"]["change_set_hash"],
        "verification_plan_hash": request["evidence_bundle"]["verification_plan_hash"],
        "evidence_bundle_hash": evidence_bundle_hash(request["evidence_bundle"]),
        "change_manifest_hash": request["change_set"]["diff_hash"],
    }
    assert body["core_identity"] == core_identity()


def test_schema_bundle_hash_change_is_recorded():
    assert GENERIC_PROTOCOL_SCHEMA_BUNDLE_HASH == SCHEMA_BUNDLE_HASH
    response = protocol_descriptor()["schemas"]["response"]
    assert "universe_identity" in response["properties"]["hashes"]["properties"]
    assert "universe_identity" not in response["properties"]["hashes"]["required"]
    assert "core_identity" in response["properties"]
    assert "core_identity" not in response["required"]


def test_receipt_comparison_tolerates_only_the_additive_fields():
    status, recomputed = verify_generic_changeset(_universe_request())
    assert status == 200
    assert _core_responses_equivalent(recomputed, copy.deepcopy(recomputed))

    legacy = copy.deepcopy(recomputed)
    del legacy["core_identity"]
    del legacy["hashes"]["universe_identity"]
    assert _core_responses_equivalent(recomputed, legacy)

    other_build = copy.deepcopy(recomputed)
    other_build["core_identity"]["source_digest"] = "sha256:" + "0" * 64
    assert _core_responses_equivalent(recomputed, other_build)

    wrong_universe = copy.deepcopy(recomputed)
    wrong_universe["hashes"]["universe_identity"] = "sha256:" + "0" * 64
    assert not _core_responses_equivalent(recomputed, wrong_universe)

    wrong_hash = copy.deepcopy(legacy)
    wrong_hash["hashes"]["acceptance_contract_hash"] = "sha256:" + "0" * 64
    assert not _core_responses_equivalent(recomputed, wrong_hash)

    wrong_verdict = copy.deepcopy(legacy)
    wrong_verdict["verification"]["status"] = "FAILED_VERIFICATION"
    assert not _core_responses_equivalent(recomputed, wrong_verdict)
    assert not _core_responses_equivalent(recomputed, None)


# --------------------------------------------------------------------------- #267


def _copy_product(tmp_path: Path) -> Path:
    target = tmp_path / "site" / "product"
    shutil.copytree(
        PRODUCT_DIR,
        target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", BUILD_IDENTITY_FILENAME),
    )
    return target


def test_source_digest_conformance_vector():
    files = {
        row["path"]: row["content_utf8"].encode("utf-8")
        for row in SOURCE_DIGEST_CONFORMANCE_VECTOR["files"]
    }
    assert source_digest_of_files(files) == SOURCE_DIGEST_CONFORMANCE_VECTOR["expected_digest"]
    assert source_digest_of_files(list(reversed(list(files.items())))) == (
        SOURCE_DIGEST_CONFORMANCE_VECTOR["expected_digest"]
    )
    descriptor = protocol_descriptor()
    assert descriptor["source_digest_conformance_vector"] == SOURCE_DIGEST_CONFORMANCE_VECTOR
    assert "core_source_digest" in descriptor["canonicalization"]


def test_source_digest_ignores_pycache_and_bytecode(tmp_path):
    root = _copy_product(tmp_path)
    before = source_digest(root)
    subprocess.run(
        [sys.executable, "-m", "compileall", "-q", str(root)], check=True, capture_output=True
    )
    (root / "protocol" / "stray.pyc").write_bytes(b"\x00junk")
    (root / "__pycache__" / "extra.cpython-311.pyc").write_bytes(b"\x00junk")
    assert any(root.rglob("__pycache__"))
    assert source_digest(root) == before


def test_source_digest_unchanged_by_importing_core(tmp_path):
    root = _copy_product(tmp_path)
    before = core_identity(root)["source_digest"]
    env = {key: value for key, value in os.environ.items() if key != "PYTHONDONTWRITEBYTECODE"}
    env["PYTHONPATH"] = str(root.parent)
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import product, product.protocol, product.adapters.generic_verification; "
            f"assert product.__file__.startswith({str(root)!r}), product.__file__",
        ],
        check=True,
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
    )
    assert any(root.rglob("__pycache__"))
    assert core_identity(root)["source_digest"] == before


def test_source_digest_changes_with_any_shipped_byte(tmp_path):
    root = _copy_product(tmp_path)
    before = source_digest(root)
    target = root / "protocol" / "generic_verification.py"
    original = target.read_bytes()
    target.write_bytes(original + b" ")
    assert source_digest(root) != before
    target.write_bytes(original)
    assert source_digest(root) == before
    profile = next((root / "execution" / "profiles").glob("*.lock"))
    profile.write_bytes(profile.read_bytes() + b"\n")
    assert source_digest(root) != before


def test_source_digest_ignores_unshipped_files(tmp_path):
    root = _copy_product(tmp_path)
    before = source_digest(root)
    (root / "benchmark").mkdir(exist_ok=True)
    (root / "benchmark" / "extra.py").write_text("x = 1\n")
    (root / ".DS_Store").write_bytes(b"\x00")
    (root / "notes.txt").write_text("not shipped\n")
    (root / BUILD_IDENTITY_FILENAME).write_text("{}")
    assert source_digest(root) == before
    (root / "new_module.py").write_text("x = 1\n")
    assert source_digest(root) != before


def test_shipped_paths_cover_python_and_package_data_only():
    paths = shipped_source_paths(PRODUCT_DIR)
    assert "product/__init__.py" in paths
    assert "product/protocol/build_identity.py" in paths
    assert "product/execution/profiles/python-oci-pytest-v1.json" in paths
    assert "product/execution/profiles/python-oci-pytest-v1.lock" in paths
    assert not [p for p in paths if p.startswith("product/benchmark/")]
    assert not [p for p in paths if "__pycache__" in p or p.endswith(".pyc")]


def test_core_identity_needs_no_git(tmp_path):
    root = _copy_product(tmp_path)
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["PATH"] = str(tmp_path / "empty-bin")
    env["PYTHONPATH"] = str(root.parent)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, shutil, sys, product.protocol as p; "
            "assert shutil.which('git') is None; "
            f"assert p.__file__.startswith({str(root)!r}), p.__file__; "
            "print(json.dumps(p.core_identity()))",
        ],
        check=True,
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
    )
    identity = json.loads(result.stdout)
    assert identity["build_identity"] == "UNSTAMPED"
    assert identity["git_commit"] is None and identity["git_tree"] is None
    assert identity["source_digest"] == source_digest(PRODUCT_DIR)


def _assert_matches_schema(identity):
    schema = CORE_IDENTITY_SCHEMA
    assert set(identity) == set(schema["required"])
    assert identity["schema"] == schema["properties"]["schema"]["const"]


def test_unstamped_checkout_reports_null_git_fields():
    identity = core_identity()
    _assert_matches_schema(identity)
    assert identity["build_identity"] == "UNSTAMPED"
    for key in ("version", "git_commit", "git_tree", "git_dirty", "build_source_digest", "source_matches_build"):
        assert identity[key] is None
    assert identity["source_digest"] == source_digest(PRODUCT_DIR)


def test_embedded_stamp_is_reported_and_checked_against_source(tmp_path):
    root = _copy_product(tmp_path)
    stamp = make_build_identity(
        version="0.3.0",
        git_commit="a" * 40,
        git_tree="b" * 40,
        git_dirty=False,
        source_digest_value=source_digest(root),
    )
    (root / BUILD_IDENTITY_FILENAME).write_text(json.dumps(stamp))
    identity = core_identity(root)
    _assert_matches_schema(identity)
    assert identity["build_identity"] == "EMBEDDED"
    assert (identity["git_commit"], identity["git_tree"], identity["git_dirty"]) == ("a" * 40, "b" * 40, False)
    assert identity["version"] == "0.3.0"
    assert identity["source_matches_build"] is True

    (root / "__init__.py").write_bytes((root / "__init__.py").read_bytes() + b"\n")
    tampered = core_identity(root)
    assert tampered["git_commit"] == "a" * 40
    assert tampered["source_matches_build"] is False


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b"\xff\xfe",
        json.dumps({"schema": "x"}).encode(),
        json.dumps(
            {
                "schema": "nexus.core.build-identity.v1-experimental",
                "distribution": "nexus-certify",
                "version": "0.3.0",
                "git_commit": "A" * 40,
                "git_tree": "b" * 40,
                "git_dirty": False,
                "source_digest": "sha256:" + "0" * 64,
            }
        ).encode(),
        json.dumps(
            {
                "schema": "nexus.core.build-identity.v1-experimental",
                "distribution": "nexus-certify",
                "version": "0.3.0",
                "git_commit": None,
                "git_tree": "b" * 40,
                "git_dirty": None,
                "source_digest": "sha256:" + "0" * 64,
            }
        ).encode(),
    ],
)
def test_malformed_stamp_is_invalid_and_exposes_no_git_fields(tmp_path, content):
    root = _copy_product(tmp_path)
    (root / BUILD_IDENTITY_FILENAME).write_bytes(content)
    identity = core_identity(root)
    _assert_matches_schema(identity)
    assert identity["build_identity"] == "INVALID_STAMP"
    assert identity["git_commit"] is None and identity["version"] is None
    assert identity["source_digest"] == source_digest(root)


def test_make_build_identity_rejects_bad_values():
    with pytest.raises(ValueError):
        make_build_identity(
            version="0.3.0", git_commit="x", git_tree="b" * 40, git_dirty=False,
            source_digest_value="sha256:" + "0" * 64,
        )
    with pytest.raises(ValueError):
        make_build_identity(
            version="0.3.0", git_commit=None, git_tree=None, git_dirty=None,
            source_digest_value="sha1:abc",
        )


def test_sha256_object_format_git_ids_are_accepted(tmp_path):
    root = _copy_product(tmp_path)
    stamp = make_build_identity(
        version="0.3.0",
        git_commit="c" * 64,
        git_tree="d" * 64,
        git_dirty=True,
        source_digest_value=source_digest(root),
    )
    (root / BUILD_IDENTITY_FILENAME).write_text(json.dumps(stamp))
    identity = core_identity(root)
    assert identity["build_identity"] == "EMBEDDED"
    assert identity["git_commit"] == "c" * 64
    with pytest.raises(ValueError):
        make_build_identity(
            version="0.3.0", git_commit="c" * 50, git_tree="d" * 64, git_dirty=False,
            source_digest_value=source_digest(root),
        )


def test_symlinked_package_directory_fails_closed(tmp_path):
    root = _copy_product(tmp_path)
    outside = tmp_path / "outside_pkg"
    outside.mkdir()
    (outside / "__init__.py").write_text("x = 1\n")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked directory"):
        source_digest(root)
    with pytest.raises(ValueError, match="symlinked directory"):
        core_identity(root)


def test_digest_mirrors_packages_find(tmp_path):
    root = _copy_product(tmp_path)
    before = source_digest(root)
    # Not a regular package (no __init__.py): setuptools packages.find skips it.
    (root / "loose").mkdir()
    (root / "loose" / "mod.py").write_text("x = 1\n")
    # Excluded by "product.benchmark*".
    (root / "benchmark_extra").mkdir()
    (root / "benchmark_extra" / "__init__.py").write_text("")
    assert source_digest(root) == before
    (root / "loose" / "__init__.py").write_text("")
    assert source_digest(root) != before


def test_select_shipped_paths_matches_the_walk():
    every = [
        "product/" + str(path.relative_to(PRODUCT_DIR)).replace(os.sep, "/")
        for path in PRODUCT_DIR.rglob("*")
        if path.is_file()
    ]
    every += ["product/loose/mod.py", "product/benchmark/x.py", "README.md"]
    assert select_shipped_paths(every) == shipped_source_paths(PRODUCT_DIR)
