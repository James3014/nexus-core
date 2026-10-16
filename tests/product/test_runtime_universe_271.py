"""#271: Evidence Coverage universe through runtime FULL recomputation and certification."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from product.adapters.generic_verification import (
    _domain_objects,  # pyright: ignore[reportPrivateUsage]
)
from product.evidence import EvidenceBundle, VerificationPlan
from product.kernel import CertificationInput, certify
from product.runtime.service import RuntimeCertificationService
from tests.product.test_generic_verification_protocol import _payload as _generic_payload
from tests.product.test_http_runtime import _valid_request_payload
from tests.product.test_runtime_ledger_read_fail_closed import _CountingGitHubPort

SUBJECTS = [
    {
        "logical_subject_id": "S1",
        "evidence_kind": "unit-kind",
        "requirement_mode": "REQUIRED",
        "applicability": "APPLICABLE",
    }
]


def _scenario(with_universe: bool) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Return (receipt dict, original_inputs, adapter-path receipt hash)."""
    payload = _generic_payload()
    if with_universe:
        payload["acceptance_contract"]["expected_subjects"] = SUBJECTS
        payload["acceptance_contract"]["universe_generation"] = 3
        obs = payload["evidence_bundle"]["observations"][0]
        obs["logical_subject_id"] = "S1"
        obs["evidence_kind"] = "unit-kind"
    contract, change_set, plan, evidence = _domain_objects(payload)
    # Re-bind hashes to the (possibly universe-bearing) contract, as FULL recompute does.
    plan = VerificationPlan(
        plan.plan_id, contract.hash, change_set.hash, plan.required_verifier_ids
    )
    evidence = EvidenceBundle(
        evidence.bundle_id, contract.hash, change_set.hash, plan.hash, evidence.observations
    )
    receipt = certify(
        CertificationInput(
            contract,
            change_set,
            plan,
            evidence,
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        )
    ).receipt
    c = dict(payload["acceptance_contract"])
    original_inputs = {
        "acceptance_contract": c,
        "change_set": payload["change_set"],
        "verification_plan": {
            "plan_id": plan.plan_id,
            "required_verifier_ids": list(plan.required_verifier_ids),
        },
        "evidence": {
            "bundle_id": evidence.bundle_id,
            "observations": payload["evidence_bundle"]["observations"],
        },
    }
    return receipt.to_dict(), original_inputs, receipt.hash


def _service(tmp_path: Path, **kw: Any) -> RuntimeCertificationService:
    db = tmp_path / "nexus-core" / "ledger.sqlite3"
    db.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    return RuntimeCertificationService(db_path=db, **kw)


async def _verify(svc: RuntimeCertificationService, receipt: dict[str, Any], inputs: Any):
    return await svc.verify_receipt(
        {"receipt": receipt, "requested_scope": "FULL", "original_inputs": inputs}
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("with_universe", [True, False])
async def test_full_recompute_matches_adapter_hash(tmp_path: Path, with_universe: bool) -> None:
    receipt, inputs, adapter_hash = _scenario(with_universe)
    status, body = await _verify(_service(tmp_path), receipt, inputs)
    assert status == 200
    assert body["status"] == "VALID"
    assert body["recomputed_hash"] == adapter_hash == receipt["receipt_hash"]


@pytest.mark.asyncio
async def test_full_recompute_without_universe_hash_differs_from_universe_hash(
    tmp_path: Path,
) -> None:
    receipt, inputs, adapter_hash = _scenario(True)
    stripped = {k: dict(v) if isinstance(v, dict) else v for k, v in inputs.items()}
    c = stripped["acceptance_contract"]
    c.pop("expected_subjects")
    c.pop("universe_generation")
    stripped["evidence"] = {
        **inputs["evidence"],
        "observations": [
            {k: v for k, v in o.items() if k not in ("logical_subject_id", "evidence_kind")}
            for o in inputs["evidence"]["observations"]
        ],
    }
    status, body = await _verify(_service(tmp_path), receipt, stripped)
    assert status == 200
    assert body["status"] != "VALID"
    assert body["recomputed_hash"] != adapter_hash


async def _drain(svc: RuntimeCertificationService) -> None:
    tasks = [j.task for j in svc._in_flight.values() if j.task is not None]
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_runtime_certification_rejects_declared_universe(tmp_path: Path) -> None:
    github_port = _CountingGitHubPort()
    runner_calls: list[int] = []

    def runner_executor(*args: Any, **kwargs: Any) -> dict[str, Any]:
        runner_calls.append(1)
        raise AssertionError("runner must not run")

    svc = _service(tmp_path, github_port=github_port, runner_executor=runner_executor)
    payload = _valid_request_payload()
    payload["acceptance_contract"]["expected_subjects"] = SUBJECTS
    payload["acceptance_contract"]["universe_generation"] = 1
    status, body = await svc.submit_certification(payload)
    assert status == 422
    assert body["code"] == "UNSUPPORTED_UNIVERSE_ON_RUNTIME_PATH"
    assert svc._in_flight == {}
    assert github_port.calls == 0 and runner_calls == []


@pytest.mark.asyncio
async def test_pipeline_guard_defence_in_depth(tmp_path: Path) -> None:
    from product.runtime.service import InFlightJob

    github_port = _CountingGitHubPort()
    svc = _service(tmp_path, github_port=github_port, runner_executor=lambda *a, **k: {})
    payload = _valid_request_payload()
    payload["acceptance_contract"]["expected_subjects"] = SUBJECTS
    job = InFlightJob(
        request_id="req_x",
        idempotency_key="k",
        request_hash="h",
        state="PENDING",
        generation=0,
        payload=payload,
    )
    await svc._execute_pipeline(job)
    assert job.state == "UNVERIFIABLE"
    assert job.error_code == "UNSUPPORTED_UNIVERSE_ON_RUNTIME_PATH"
    assert github_port.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        {"expected_subjects": [], "universe_generation": 1},
        {"expected_subjects": "S1"},
        {"expected_subjects": {"a": 1}},
        {"expected_subjects": None},
        {"universe_generation": True},
        {"universe_generation": "0"},
        {"universe_generation": 0.0},
        {"universe_generation": 2},
    ],
)
async def test_falsey_or_malformed_universe_is_rejected(tmp_path: Path, fields: dict) -> None:
    svc = _service(tmp_path, github_port=_CountingGitHubPort(), runner_executor=lambda *a, **k: {})
    payload = _valid_request_payload()
    payload["acceptance_contract"].update(fields)
    status, body = await svc.submit_certification(payload)
    assert status == 422
    assert body["code"] == "UNSUPPORTED_UNIVERSE_ON_RUNTIME_PATH"


@pytest.mark.asyncio
async def test_empty_universe_with_generation_zero_is_accepted(tmp_path: Path) -> None:
    svc = _service(tmp_path, github_port=_CountingGitHubPort(), runner_executor=lambda *a, **k: {})
    payload = _valid_request_payload()
    payload["acceptance_contract"].update({"expected_subjects": [], "universe_generation": 0})
    status, _ = await svc.submit_certification(payload)
    assert status == 202
    await _drain(svc)


@pytest.mark.asyncio
async def test_replay_cannot_return_certified_for_universe_request(tmp_path: Path) -> None:
    """A ledger entry for the (universe-dropping) request must not be replayed as certified."""
    svc = _service(tmp_path, github_port=_CountingGitHubPort(), runner_executor=lambda *a, **k: {})
    payload = _valid_request_payload()
    payload["acceptance_contract"]["expected_subjects"] = SUBJECTS

    lookups: list[str] = []

    def spy(ikey: str) -> Any:
        lookups.append(ikey)
        raise AssertionError("ledger must not be consulted before the universe guard")

    svc._get_ledger_entry_by_idempotency = spy  # type: ignore[method-assign]
    status, body = await svc.submit_certification(payload)
    assert status == 422
    assert body["code"] == "UNSUPPORTED_UNIVERSE_ON_RUNTIME_PATH"
    assert "receipt" not in body
    assert lookups == []


@pytest.mark.asyncio
async def test_runtime_certification_without_universe_still_proceeds(tmp_path: Path) -> None:
    github_port = _CountingGitHubPort()
    svc = _service(tmp_path, github_port=github_port, runner_executor=lambda *a, **k: {})
    status, _ = await svc.submit_certification(_valid_request_payload())
    assert status == 202
    await _drain(svc)
    (job,) = svc._in_flight.values()
    # Reached acquisition (the counting port raises), i.e. not rejected for a universe.
    assert github_port.calls == 1
    assert job.error_code != "UNSUPPORTED_UNIVERSE_ON_RUNTIME_PATH"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        {"expected_subjects": {}},
        {"expected_subjects": ""},
        {"expected_subjects": 0},
        {"expected_subjects": "x"},
        {"universe_generation": True},
        {"universe_generation": "0"},
        {"universe_generation": 0.0},
        {"universe_generation": -1},
    ],
)
async def test_full_recompute_rejects_malformed_universe_fields(
    tmp_path: Path, fields: dict[str, Any]
) -> None:
    """Codex r2 (#271): a malformed universe field must not recompute a different contract."""
    receipt, inputs, _ = _scenario(False)
    inputs = {**inputs, "acceptance_contract": {**inputs["acceptance_contract"], **fields}}
    status, body = await _verify(_service(tmp_path), receipt, inputs)
    assert status == 422
    assert body["code"] == "RECEIPT_INVALID"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [{}, {"expected_subjects": None}, {"expected_subjects": []}, {"universe_generation": 0}],
)
async def test_full_recompute_absent_or_empty_universe_still_valid(
    tmp_path: Path, fields: dict[str, Any]
) -> None:
    receipt, inputs, adapter_hash = _scenario(False)
    inputs = {**inputs, "acceptance_contract": {**inputs["acceptance_contract"], **fields}}
    status, body = await _verify(_service(tmp_path), receipt, inputs)
    assert status == 200
    assert body["status"] == "VALID"
    assert body["recomputed_hash"] == adapter_hash
