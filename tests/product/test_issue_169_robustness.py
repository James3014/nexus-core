from __future__ import annotations

import tomllib
from datetime import datetime, timedelta, timezone

import pytest

from product.clients import local_golden_path, runtime_handoff
from product.clients.cli import main
from product.completion import analyze_completion_evidence
from product.evidence import ObservationStatus, code_integrity, ingestion

_JUNIT = (
    "<testsuite tests='1' failures='0' errors='0'><testcase classname='a' name='b'/></testsuite>"
)


@pytest.mark.parametrize("module", [local_golden_path, runtime_handoff])
def test_toml_string_round_trips_non_bmp_and_control_chars(module) -> None:
    value = 'smile \U0001f600 tab\t del\x7f quote" back\\ é'
    parsed = tomllib.loads(f"k = {module._toml_string(value)}\n")
    assert parsed["k"] == value
    assert tomllib.loads(f"k = {module._toml_array([value])}\n")["k"] == [value]


def test_handoff_init_rejects_out_of_range_port_cleanly(tmp_path, capsys) -> None:
    code = main(
        [
            "handoff-init",
            "--repo",
            str(tmp_path),
            "--handoff-id",
            "x",
            "--service",
            "s=http://h:99999",
            "--verifier",
            "true",
        ]
    )
    assert code == 2
    assert "INVALID_HANDOFF_CONFIG" in capsys.readouterr().err


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
@pytest.mark.parametrize("payload", ["<!DOCTYPE x><r/>", "<!ENTITY a 'b'><r/>"])
def test_utf16_xml_with_doctype_or_entity_is_rejected(encoding: str, payload: str) -> None:
    data = payload.encode(encoding)
    with pytest.raises(ValueError):
        ingestion._native_junit_counts(data, 0)
    with pytest.raises(ValueError):
        code_integrity._junit_cases(data)


def test_plain_utf8_junit_still_accepted() -> None:
    assert code_integrity._junit_cases(_JUNIT.encode())


def test_swapped_verifier_artifact_bindings_do_not_verify() -> None:
    from product.completion import CompletionClaim
    from product.evidence import (
        AcceptanceContract,
        ChangeSet,
        EvidenceBundle,
        Observation,
        VerificationPlan,
        _hash,
    )

    contract = AcceptanceContract("ac-1", _hash("r"), ("lint", "unit"), ("src/a.py",), "FORBID")
    change_set = ChangeSet(
        "cs-1", "git-commit:" + "a" * 40, "git-commit:" + "b" * 40, _hash("d"), ("src/a.py",)
    )
    plan = VerificationPlan("vp-1", contract.hash, change_set.hash, ("lint", "unit"))
    h = _hash("final")
    evidence = EvidenceBundle(
        "eb-1",
        contract.hash,
        change_set.hash,
        plan.hash,
        (
            Observation("lint", "art-lint", h, ObservationStatus.PASS),
            Observation("unit", "art-unit", h, ObservationStatus.PASS),
        ),
    )

    def claim(bindings):
        return CompletionClaim(
            claim_id="cl-1",
            target_revision=change_set.target_revision,
            content_hashes=(("src/a.py", h),),
            verified_artifacts=tuple(sorted(bindings)),
            asserted_by="model:t",
            claimed_complete=True,
        )

    good = claim([("lint", "art-lint", "src/a.py"), ("unit", "art-unit", "src/a.py")])
    assert analyze_completion_evidence(good, contract, change_set, plan, evidence).claims_verified
    swapped = claim([("lint", "art-unit", "src/a.py"), ("unit", "art-lint", "src/a.py")])
    analysis = analyze_completion_evidence(swapped, contract, change_set, plan, evidence)
    assert analysis.claims_verified is False


def test_runtime_freshness_expiry_equality_is_stale() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)

    def runtime(expires: datetime):
        return ingestion.RuntimeSourceObservation(
            generation=ingestion.EvidenceGeneration.RUNTIME,
            desired_source_revision="target-r2",
            loaded_source_revision="target-r2",
            desired_generation=7,
            observed_generation=7,
            observed_at=(now - timedelta(seconds=10)).isoformat(),
            expires_at=expires.isoformat(),
            expected_runtime_identity="runtime-1",
            observed_runtime_identity="runtime-1",
            readiness_status="READY",
        )

    assert (
        ingestion.derive_runtime_freshness(runtime(now), now.isoformat()).name
        == "STALE_OBSERVATION"
    )
    assert (
        ingestion.derive_runtime_freshness(
            runtime(now + timedelta(seconds=1)), now.isoformat()
        ).name
        == "READY_IDENTITY_BOUND"
    )
