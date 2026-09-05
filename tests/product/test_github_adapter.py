import ast
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

import product.adapters.github as github
from product.adapters.github import (
    GitHubPullRequestSnapshot,
    certify_pull_request,
    load_github_pull_request_snapshot,
    serialize_github_pull_request_snapshot,
    snapshot_to_dict,
    to_changeset,
)
from product.certification import CertificationDisposition
from product.evidence import (
    AcceptanceContract,
    EvidenceBundle,
    IntegrityStatus,
    Observation,
    ObservationStatus,
    VerificationPlan,
    _hash,
)
from product.kernel import CertificationInput, certify
from product.verification import VerificationStatus


def snapshot():
    return GitHubPullRequestSnapshot(
        "octo", "repo", 7, "a" * 40, "b" * 40, "sha256:" + "c" * 64, ("src/a.py",)
    )


def certification_case():
    change = to_changeset(snapshot())
    contract = AcceptanceContract("ac", _hash("requirements"), ("unit",), ("src/a.py",), "FORBID")
    plan = VerificationPlan("plan", contract.hash, change.hash, ("unit",))
    evidence = EvidenceBundle(
        "bundle",
        contract.hash,
        change.hash,
        plan.hash,
        (Observation("unit", "artifact", _hash("artifact"), ObservationStatus.PASS),),
    )
    return contract, plan, evidence


def test_snapshot_mapping_and_serialized_replay_are_deterministic():
    value = snapshot()
    assert to_changeset(value) == to_changeset(
        load_github_pull_request_snapshot(serialize_github_pull_request_snapshot(value))
    )
    assert to_changeset(value).change_set_id == "github:octo/repo#pr-7@" + "b" * 40
    reversed_value = GitHubPullRequestSnapshot(
        "octo", "repo", 7, "a" * 40, "b" * 40, "sha256:" + "c" * 64, ("z", "a")
    )
    assert to_changeset(reversed_value).paths == ("a", "z")
    assert serialize_github_pull_request_snapshot(reversed_value)["changed_paths"] == ["a", "z"]
    assert reversed_value.to_dict() == serialize_github_pull_request_snapshot(reversed_value)


def test_certification_delegates_with_explicit_policy_and_bound_evidence():
    contract, plan, evidence = certification_case()
    result = certify_pull_request(
        snapshot(),
        contract,
        plan,
        evidence,
        policy_accepted=True,
        authority_present=True,
        approval_present=True,
        signing_present=True,
    )
    assert result.verification.status is VerificationStatus.VERIFIED


def test_certification_matches_direct_kernel_and_omitted_policy_does_not_infer_authority():
    contract, plan, evidence = certification_case()
    direct = certify(
        CertificationInput(
            contract, to_changeset(snapshot()), plan, evidence, True, True, True, True
        )
    )
    explicit = github.certify_pull_request(
        snapshot(),
        contract,
        plan,
        evidence,
        policy_accepted=True,
        authority_present=True,
        approval_present=True,
        signing_present=True,
    )
    omitted = github.certify_pull_request(snapshot(), contract, plan, evidence)
    assert direct.receipt.hash == explicit.receipt.hash
    assert direct.verification == explicit.verification
    assert direct.receipt.hash != omitted.receipt.hash
    assert omitted.verification.status is VerificationStatus.VERIFIED
    assert omitted.disposition.value == "BLOCKED"


def test_github_name_grammar_prevents_change_set_id_collisions():
    left = GitHubPullRequestSnapshot(
        "a", "b.c", 1, "a" * 40, "b" * 40, "sha256:" + "c" * 64, ("x",)
    )
    right = GitHubPullRequestSnapshot(
        "a-b", "c", 1, "a" * 40, "b" * 40, "sha256:" + "c" * 64, ("x",)
    )
    assert to_changeset(left).change_set_id != to_changeset(right).change_set_id
    with pytest.raises(ValueError):
        GitHubPullRequestSnapshot(
            "a/b", "repo", 1, "a" * 40, "b" * 40, "sha256:" + "c" * 64, ("x",)
        )


def test_public_adapter_revalidates_forged_snapshot_after_module_rebinding(monkeypatch):
    values = vars(snapshot()).copy()
    values["diff_hash"] = "bad"
    forged = object.__new__(GitHubPullRequestSnapshot)
    for key, value in values.items():
        object.__setattr__(forged, key, value)
    monkeypatch.setattr(
        github, "certify", lambda *args, **kwargs: pytest.fail("rebound certify used")
    )
    monkeypatch.setattr(github, "ChangeSet", lambda *args: pytest.fail("rebound ChangeSet used"))
    with pytest.raises(ValueError):
        github.to_changeset(forged)


def test_valid_adapter_path_survives_module_and_class_rebinding(monkeypatch):
    value = snapshot()
    contract, plan, evidence = certification_case()
    expected = github.certify_pull_request(
        value,
        contract,
        plan,
        evidence,
        policy_accepted=True,
        authority_present=True,
        approval_present=True,
        signing_present=True,
    )
    monkeypatch.setattr(github, "GitHubPullRequestSnapshot", lambda *args: None)
    monkeypatch.setattr(github, "ChangeSet", lambda *args: None)
    monkeypatch.setattr(github, "CertificationInput", lambda *args: None)
    monkeypatch.setattr(github, "certify", lambda *args: pytest.fail("rebound certify used"))
    monkeypatch.setattr(type(value), "to_dict", lambda self: {"forged": True})
    actual = github.certify_pull_request(
        value,
        contract,
        plan,
        evidence,
        policy_accepted=True,
        authority_present=True,
        approval_present=True,
        signing_present=True,
    )
    assert actual.receipt.hash == expected.receipt.hash
    assert github.to_changeset(value) == to_changeset(value)
    assert github.serialize_github_pull_request_snapshot(value) == snapshot_to_dict(value)


@pytest.mark.parametrize(
    "field,expected_status,expected_disposition",
    [
        ("change_set_hash", VerificationStatus.UNVERIFIABLE, CertificationDisposition.BLOCKED),
        (
            "acceptance_contract_hash",
            VerificationStatus.UNVERIFIABLE,
            CertificationDisposition.REJECTED,
        ),
        (
            "verification_plan_hash",
            VerificationStatus.UNVERIFIABLE,
            CertificationDisposition.REJECTED,
        ),
    ],
)
def test_cross_bound_snapshot_evidence_is_factual_and_never_certified(
    field, expected_status, expected_disposition
):
    contract, plan, evidence = certification_case()
    altered = replace(evidence, **{field: _hash("other")})
    result = certify_pull_request(
        snapshot(),
        contract,
        plan,
        altered,
        policy_accepted=True,
        authority_present=True,
        approval_present=True,
        signing_present=True,
    )
    assert result.verification.status is expected_status
    assert result.disposition is expected_disposition
    assert result.disposition is not CertificationDisposition.CERTIFIED
    assert result.verification.integrity in {
        IntegrityStatus.STALE,
        IntegrityStatus.CROSS_BOUND,
        IntegrityStatus.CROSS_BINDING_INVALID,
    }


def test_loader_revalidates_after_post_init_rebinding(monkeypatch):
    values = serialize_github_pull_request_snapshot(snapshot())
    values["diff_hash"] = "bad"
    monkeypatch.setattr(GitHubPullRequestSnapshot, "__post_init__", lambda self: None)
    with pytest.raises(ValueError):
        load_github_pull_request_snapshot(values)


def test_loader_rejects_valid_constructor_substitution(monkeypatch):
    original_init = GitHubPullRequestSnapshot.__init__
    payload = serialize_github_pull_request_snapshot(snapshot())

    def substitute(self, *args, **kwargs):
        original_init(
            self, "other", "repository", 99, "c" * 40, "d" * 40, "sha256:" + "e" * 64, ("other.py",)
        )

    monkeypatch.setattr(GitHubPullRequestSnapshot, "__init__", substitute)
    with pytest.raises(ValueError, match="loaded snapshot differs"):
        load_github_pull_request_snapshot(payload)


def test_valid_snapshot_diff_change_is_stale_and_blocked():
    contract, plan, evidence = certification_case()
    altered = replace(snapshot(), diff_hash="sha256:" + "d" * 64)
    result = certify_pull_request(
        altered,
        contract,
        plan,
        evidence,
        policy_accepted=True,
        authority_present=True,
        approval_present=True,
        signing_present=True,
    )
    assert result.verification.status is VerificationStatus.UNVERIFIABLE
    assert result.verification.integrity is IntegrityStatus.STALE
    assert result.disposition is CertificationDisposition.BLOCKED
    assert result.disposition is not CertificationDisposition.CERTIFIED


def test_mapping_rejects_rebound_changeset_constructor(monkeypatch):
    monkeypatch.setattr(github.ChangeSet, "__init__", lambda self, *args, **kwargs: None)
    monkeypatch.setattr(github.ChangeSet, "__post_init__", lambda self: None)
    with pytest.raises(ValueError, match="malformed mapped ChangeSet"):
        github.to_changeset(snapshot())


@pytest.mark.parametrize(
    "paths",
    [
        (),
        ("src/a.py", "src/a.py"),
        ("/tmp/a",),
        ("src\\a.py",),
        (".",),
        ("..",),
        ("src//a",),
        (" src/a",),
        (1,),
    ],
)
def test_snapshot_rejects_path_matrix(paths):
    values = serialize_github_pull_request_snapshot(snapshot())
    values["changed_paths"] = list(paths)
    with pytest.raises((TypeError, ValueError)):
        load_github_pull_request_snapshot(values)


def test_adapter_has_no_network_sdk_or_mutation_surface():
    tree = ast.parse(Path(github.__file__).read_text())
    forbidden = {
        "requests",
        "http",
        "urllib",
        "socket",
        "gh",
        "github",
        "boto3",
        "merge",
        "comment",
        "check",
        "network",
        "planner",
        "workforce",
        "provider",
        "model",
    }
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    imports += [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert set(imports) <= {"re", "dataclasses", "product.evidence", "product.kernel"}
    assert all(not any(token in item.lower() for token in forbidden) for item in imports)
    calls = [
        node.func.attr.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert not any(
        token in call for call in calls for token in {"request", "merge", "comment", "check"}
    )


@pytest.mark.parametrize(
    "field,value", [("pr_number", True), ("base_sha", "A" * 40), ("changed_paths", ("../unsafe",))]
)
def test_snapshot_rejects_malformed_values(field, value):
    values = serialize_github_pull_request_snapshot(snapshot())
    values[field] = value
    with pytest.raises((TypeError, ValueError)):
        load_github_pull_request_snapshot(values)


def test_snapshot_loader_rejects_unknown_or_claimed_hash_fields():
    values = serialize_github_pull_request_snapshot(snapshot())
    values["unknown"] = True
    with pytest.raises(ValueError):
        load_github_pull_request_snapshot(values)
    values = serialize_github_pull_request_snapshot(snapshot())
    values["snapshot_hash"] = hashlib.sha256(b"forged").hexdigest()
    with pytest.raises(ValueError):
        load_github_pull_request_snapshot(values)
