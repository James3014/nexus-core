"""Regression coverage for fail-closed runtime admission on ledger read errors."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from product.evidence import _hash
from product.protocol import IMPLEMENTATION_SCHEMA, PUBLIC_PROTOCOL_VERSION
from product.runtime.service import RuntimeCertificationService


class _CountingGitHubPort:
    def __init__(self) -> None:
        self.calls = 0

    def read_pull_request(self, locator: Any) -> dict[str, Any]:
        self.calls += 1
        raise AssertionError("GitHub acquisition must not run when durable ledger reads fail")


def _request_payload() -> dict[str, Any]:
    return {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "implementation_schema": IMPLEMENTATION_SCHEMA,
        "repository": {
            "owner": "James3014",
            "name": "Nexus-new",
            "pr_number": 635,
            "expected_base_sha": "a" * 40,
            "expected_head_sha": "b" * 40,
        },
        "acceptance_contract": {
            "contract_id": "ac-ledger-read-failure",
            "requirements_hash": _hash("reqs"),
            "required_verifier_ids": ["pytest"],
            "allowed_paths": ["src/a.py"],
            "deletion_policy": "FORBID",
        },
        "verification_plan": {
            "plan_id": "plan-ledger-read-failure",
            "acceptance_contract_hash": _hash("ac"),
            "change_set_hash": _hash("cs"),
            "required_verifier_ids": ["pytest"],
        },
        "profile_id": "python-oci-pytest-v1",
        "idempotency_key": "ledger-read-failure",
        "expected_generation": 0,
    }


def _malformed_ledger(tmp_path: Path) -> Path:
    db_path = tmp_path / "nexus-core" / "ledger.sqlite3"
    db_path.parent.mkdir(parents=True, mode=0o700)
    db_path.write_bytes(b"not-a-sqlite-database")
    return db_path


async def _cancel_background_jobs(service: RuntimeCertificationService) -> None:
    tasks = [job.task for job in service._in_flight.values() if job.task is not None]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_submit_fails_closed_when_idempotency_ledger_read_fails(tmp_path: Path) -> None:
    github_port = _CountingGitHubPort()
    runner_calls: list[int] = []

    def runner_executor(*args: Any, **kwargs: Any) -> dict[str, Any]:
        runner_calls.append(1)
        raise AssertionError("runner must not execute when durable ledger reads fail")

    service = RuntimeCertificationService(
        db_path=_malformed_ledger(tmp_path),
        github_port=github_port,
        runner_executor=runner_executor,
    )
    try:
        status, body = await service.submit_certification(_request_payload())
        assert status == 503
        assert body["code"] == "SERVICE_UNAVAILABLE"
        await asyncio.sleep(0)
        assert github_port.calls == 0
        assert runner_calls == []
        assert service._in_flight == {}
        assert service._by_idempotency == {}
    finally:
        await _cancel_background_jobs(service)


@pytest.mark.asyncio
async def test_submit_fails_closed_when_generation_ledger_read_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github_port = _CountingGitHubPort()
    runner_calls: list[int] = []

    def runner_executor(*args: Any, **kwargs: Any) -> dict[str, Any]:
        runner_calls.append(1)
        raise AssertionError("runner must not execute when durable ledger reads fail")

    service = RuntimeCertificationService(
        db_path=_malformed_ledger(tmp_path),
        github_port=github_port,
        runner_executor=runner_executor,
    )
    monkeypatch.setattr(service, "_get_ledger_entry_by_idempotency", lambda _key: None)
    try:
        status, body = await service.submit_certification(_request_payload())
        assert status == 503
        assert body["code"] == "SERVICE_UNAVAILABLE"
        await asyncio.sleep(0)
        assert github_port.calls == 0
        assert runner_calls == []
        assert service._in_flight == {}
        assert service._by_idempotency == {}
    finally:
        await _cancel_background_jobs(service)
