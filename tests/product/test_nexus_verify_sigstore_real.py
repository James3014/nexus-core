"""Real Sigstore signatures for Nexus Verify receipt authentication (#231).

The fixtures are the unmodified receipt and Sigstore bundle uploaded by the
``nexus-core-issue-completion.yml`` run 38239679410 (PR #241, head
4fd00829996214d648f85bd2c63a7afee7945f02), downloaded read-only with
``gh run download``. They hold public CI output only (no tokens or secrets).

The tests need the optional ``sigstore`` package and skip cleanly without it,
e.g. run them with ``uv run --with sigstore==4.5.0 pytest tests/product/test_nexus_verify_sigstore_real.py``.
They verify offline against the trust root embedded in sigstore, because the
bundle carries its Rekor inclusion proof; if that trust root cannot be loaded
the tests skip rather than pass.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from product.clients.nexus_verify import (
    RECEIPT_NOT_AUTHENTICATED,
    evaluate_code_change_evidence_subject,
)
from product.clients.receipt_authentication import (
    AUTHENTICATED,
    NOT_AUTHENTICATED,
    UNAVAILABLE,
    SigstoreReceiptAuthenticator,
    github_workflow_signer_policy,
)

pytest.importorskip("sigstore", reason="optional sigstore package not installed")

FIXTURES = Path(__file__).parent / "fixtures" / "nexus_verify_sigstore"
RECEIPT_PATH = FIXTURES / "ci_receipt_pr241_run38239679410.json"
BUNDLE_PATH = FIXTURES / "ci_receipt_pr241_run38239679410.json.sigstore.json"
IDENTITY = (
    "https://github.com/James3014/nexus-core/.github/workflows/"
    "nexus-core-issue-completion.yml@refs/heads/main"
)
HEAD_SHA = "4fd00829996214d648f85bd2c63a7afee7945f02"


@pytest.fixture(scope="module")
def authenticator() -> SigstoreReceiptAuthenticator:
    instance = SigstoreReceiptAuthenticator(offline=True)
    probe = instance.authenticate(
        receipt_bytes=RECEIPT_PATH.read_bytes(),
        bundle_json=BUNDLE_PATH.read_bytes(),
        policy=github_workflow_signer_policy("James3014", "nexus-core"),
    )
    if probe.status == UNAVAILABLE:
        pytest.skip(f"Sigstore trust root unavailable: {probe.detail}")
    return instance


def _receipt_bytes() -> bytes:
    return RECEIPT_PATH.read_bytes()


def _bundle() -> dict[str, Any]:
    return json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))


def _subject(receipt: dict[str, Any], *, repository: str = "nexus-core") -> dict[str, Any]:
    change_set = receipt["inputs"]["request"]["change_set"]
    return {
        "repository_owner": "James3014",
        "repository_name": repository,
        "pr_number": 241,
        "current_base_sha": receipt["source_revision"].removeprefix("git-commit:"),
        "current_head_sha": HEAD_SHA,
        "current_base_tree": receipt["source_tree"].removeprefix("git-tree:"),
        "current_head_tree": receipt["target_tree"].removeprefix("git-tree:"),
        "changed_paths": list(change_set["paths"]),
        "deleted_paths": list(change_set["deleted_paths"]),
    }


def _signature(receipt_bytes: bytes) -> dict[str, Any]:
    return {
        "receipt_base64": base64.b64encode(receipt_bytes).decode("ascii"),
        "sigstore_bundle": _bundle(),
    }


def test_fixture_is_the_genuine_ci_receipt():
    receipt = json.loads(_receipt_bytes())
    assert receipt["subject_head"] == f"git-commit:{HEAD_SHA}"
    assert receipt["config_source"]["kind"] == "base-ref"
    assert receipt["outcome"]["status"] == "VERIFIED"
    assert _bundle()["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json"
    assert github_workflow_signer_policy("James3014", "nexus-core").identity == IDENTITY


def test_genuine_ci_receipt_with_valid_bundle_is_verified(authenticator):
    """#231 acceptance (2)."""
    receipt = json.loads(_receipt_bytes())

    result = evaluate_code_change_evidence_subject(
        _subject(receipt),
        receipt,
        receipt_signature=_signature(_receipt_bytes()),
        authenticator=authenticator,
    )

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "APPLIES"
    assert result["core_verification"] == "VERIFIED"
    assert result["reason_codes"] == []


def test_genuine_receipt_without_bundle_is_not_authenticated(authenticator):
    receipt = json.loads(_receipt_bytes())

    result = evaluate_code_change_evidence_subject(
        _subject(receipt), receipt, authenticator=authenticator
    )

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["core_verification"] == "NOT_AVAILABLE"
    assert result["reason_codes"] == [RECEIPT_NOT_AUTHENTICATED]


def test_rehashed_forgery_of_genuine_receipt_fails_real_signature(authenticator):
    from product.clients.local_golden_path import _receipt_hash

    forged = json.loads(_receipt_bytes())
    forged["outcome"]["reason_codes"] = ["FORGED"]
    forged["core_response"]["verification"]["reason_codes"] = ["FORGED"]
    forged["receipt_hash"] = _receipt_hash(forged)
    forged_bytes = (json.dumps(forged, indent=2, sort_keys=True) + "\n").encode("utf-8")

    outcome = authenticator.authenticate(
        receipt_bytes=forged_bytes,
        bundle_json=BUNDLE_PATH.read_bytes(),
        policy=github_workflow_signer_policy("James3014", "nexus-core"),
    )
    assert outcome.status == NOT_AUTHENTICATED

    result = evaluate_code_change_evidence_subject(
        _subject(forged),
        forged,
        receipt_signature=_signature(forged_bytes),
        authenticator=authenticator,
    )
    assert result["core_verification"] != "VERIFIED"
    assert result["evidence_applicability"] != "APPLIES"


def test_same_json_value_with_different_bytes_fails_real_signature(authenticator):
    receipt = json.loads(_receipt_bytes())
    reformatted = _receipt_bytes() + b" "

    result = evaluate_code_change_evidence_subject(
        _subject(receipt),
        receipt,
        receipt_signature=_signature(reformatted),
        authenticator=authenticator,
    )

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["reason_codes"] == [RECEIPT_NOT_AUTHENTICATED]


def test_wrong_workflow_identity_fails_real_signature(authenticator):
    outcome = authenticator.authenticate(
        receipt_bytes=_receipt_bytes(),
        bundle_json=BUNDLE_PATH.read_bytes(),
        policy=github_workflow_signer_policy("James3014", "nexus-core", workflow_file="ci.yml"),
    )
    assert outcome.status == NOT_AUTHENTICATED

    outcome = authenticator.authenticate(
        receipt_bytes=_receipt_bytes(),
        bundle_json=BUNDLE_PATH.read_bytes(),
        policy=github_workflow_signer_policy("James3014", "nexus-core", ref="refs/heads/dev"),
    )
    assert outcome.status == NOT_AUTHENTICATED


def test_genuine_receipt_presented_for_another_repository_is_not_authenticated(authenticator):
    receipt = json.loads(_receipt_bytes())

    result = evaluate_code_change_evidence_subject(
        _subject(receipt, repository="other-repo"),
        receipt,
        receipt_signature=_signature(_receipt_bytes()),
        authenticator=authenticator,
    )

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["reason_codes"] == [RECEIPT_NOT_AUTHENTICATED]


def test_malformed_bundle_fails_real_verifier(authenticator):
    outcome = authenticator.authenticate(
        receipt_bytes=_receipt_bytes(),
        bundle_json=b'{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}',
        policy=github_workflow_signer_policy("James3014", "nexus-core"),
    )
    assert outcome.status == NOT_AUTHENTICATED


def test_direct_authentication_reports_identity(authenticator):
    outcome = authenticator.authenticate(
        receipt_bytes=_receipt_bytes(),
        bundle_json=BUNDLE_PATH.read_bytes(),
        policy=github_workflow_signer_policy("James3014", "nexus-core"),
    )
    assert outcome.status == AUTHENTICATED
    assert outcome.detail == IDENTITY
