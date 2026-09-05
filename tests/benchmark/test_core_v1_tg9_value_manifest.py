"""TG9 paired usability/value evidence manifest tests."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from product.benchmark import tg9_value as gate


def _fixture():
    return copy.deepcopy(gate._synthetic_fixture())


def _rehash(value: dict, key: str) -> dict:
    body = {name: item for name, item in value.items() if name != key}
    value[key] = gate._digest(body)
    return value


def _nonsynthetic():
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    manifest["synthetic"] = False
    _rehash(manifest, "manifest_hash")
    return manifest, eligibility, consent, observations, trust, signal


def _rehash_observation(row: dict) -> None:
    _rehash(row, "observation_hash")


def _refresh_trust(trust: dict, observations: list[dict]) -> None:
    assigned = [row for row in observations if not row["excluded"]]
    trust["all_assigned_pairs"] = len(assigned)
    trust["baseline_counts"] = gate._counts(assigned, "baseline_outcome")
    trust["assisted_counts"] = gate._counts(assigned, "assisted_outcome")
    trust["partner_high_risk_errors"] = sorted({
        row["partner_id"] for row in assigned if row["high_risk_error"]
    })
    _rehash(trust, "trust_hash")


def _write_json(path: Path, value: dict) -> None:
    path.write_text(gate._canonical(value) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(gate._canonical(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def test_synthetic_self_test_is_claim_bounded() -> None:
    result = gate.synthetic_self_test()
    assert result["state"] == gate.SYNTHETIC_STATE
    assert result["synthetic"] is True
    assert result["negative_checks_passed"] is True
    assert result["negative_state"] != gate.VALUE_READY_STATE


def test_positive_synthetic_fixture_never_becomes_value_ready() -> None:
    report = gate.adjudicate(*_fixture())
    assert report["state"] == gate.SYNTHETIC_STATE
    assert report["synthetic"] is True
    assert report["cohort_median_improvement"] >= gate.MIN_IMPROVEMENT
    assert report["positive_pair_fraction"] >= gate.MIN_POSITIVE_FRACTION


def test_complete_nonsynthetic_fixture_exercises_value_ready_path() -> None:
    report = gate.adjudicate(*_nonsynthetic())
    assert report["state"] == gate.VALUE_READY_STATE
    assert report["reasons"] == []
    assert report["trust"]["assisted_counts"]["FALSE_ACCEPT"] == 0


def test_report_hash_is_canonical() -> None:
    report = gate.adjudicate(*_fixture())
    body = {key: value for key, value in report.items() if key != "report_hash"}
    assert report["report_hash"] == gate._digest(body)


def test_assignment_is_deterministic() -> None:
    value = gate.assignment_for("s", "p_0000000000000001", "pair-01")
    assert value in {"AB", "BA"}
    assert value == gate.assignment_for("s", "p_0000000000000001", "pair-01")


def test_assignment_mismatch_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[0]["assignment"] = "BA" if observations[0]["assignment"] == "AB" else "AB"
    _rehash_observation(observations[0])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("ASSIGNMENT_MISMATCH" in reason for reason in report["reasons"])


def test_missing_nexus_followup_overhead_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[0].pop("nexus_read_followup_ms")
    _rehash_observation(observations[0])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("MISSING_KEYS" in reason for reason in report["reasons"])


def test_negative_nexus_followup_overhead_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[0]["nexus_read_followup_ms"] = -1
    _rehash_observation(observations[0])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("INVALID_TIMING:nexus_read_followup_ms" in reason for reason in report["reasons"])


def test_same_task_in_both_arms_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[0]["assisted_task_id"] = observations[0]["baseline_task_id"]
    _rehash_observation(observations[0])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("TASKS_NOT_DISTINCT" in reason for reason in report["reasons"])


def test_short_washout_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[0]["washout_ms"] = gate.MIN_WASHOUT_MS - 1
    _rehash_observation(observations[0])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("WASHOUT_TOO_SHORT" in reason for reason in report["reasons"])


def test_duplicate_pair_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations.append(copy.deepcopy(observations[0]))
    _refresh_trust(trust, observations)
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("DUPLICATE_PAIR" in reason for reason in report["reasons"])


def test_duplicate_attempt_identity_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[1]["attempt_ids"][0] = observations[0]["attempt_ids"][0]
    _rehash_observation(observations[1])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("DUPLICATE_ATTEMPT" in reason for reason in report["reasons"])


def test_open_ended_exclusion_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[0]["excluded"] = True
    observations[0]["exclusion_reason"] = "OUTLIER"
    _rehash_observation(observations[0])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("OPEN_ENDED_EXCLUSION" in reason for reason in report["reasons"])


def test_missing_consent_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    consent["receipts"].pop()
    _rehash(consent, "consent_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert "MISSING_CONSENT" in report["reasons"]


def test_withdrawn_consent_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    receipt = consent["receipts"][0]
    receipt["status"] = "WITHDRAWN"
    _rehash(receipt, "receipt_hash")
    _rehash(consent, "consent_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert "WITHDRAWN_PARTNER" in report["reasons"]


def test_source_revision_drift_fails_closed() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    observations[0]["source_commit"] = "c" * 40
    _rehash_observation(observations[0])
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any("REVISION_DRIFT:source_commit" in reason for reason in report["reasons"])


def test_short_study_duration_cannot_be_value_ready() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    manifest["study_end_at"] = "2026-01-22T00:00:00+00:00"
    manifest["analysis_at"] = "2026-01-22T12:00:00+00:00"
    _rehash(manifest, "manifest_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "MISSING_EVIDENCE"
    assert "DURATION_BELOW_MINIMUM" in report["reasons"]


def test_negative_partner_median_blocks_value_ready() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    partner_id = observations[0]["partner_id"]
    for row in observations:
        if row["partner_id"] == partner_id:
            row["nexus_human_ms"] = 110_000
            row["nexus_read_followup_ms"] = 10_000
            _rehash_observation(row)
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "MISSING_EVIDENCE"
    assert "NEGATIVE_PARTNER_MEDIAN" in report["reasons"]


def test_positive_pair_fraction_threshold_is_enforced() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    for row in observations[:8]:
        row["nexus_human_ms"] = 95_000
        row["nexus_read_followup_ms"] = 10_000
        _rehash_observation(row)
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "MISSING_EVIDENCE"
    assert "POSITIVE_PAIR_FRACTION_BELOW_THRESHOLD" in report["reasons"]


def test_assisted_false_accept_blocks_value_ready() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    observations[0]["assisted_outcome"] = "FALSE_ACCEPT"
    _rehash_observation(observations[0])
    _refresh_trust(trust, observations)
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "MISSING_EVIDENCE"
    assert "ASSISTED_FALSE_ACCEPT" in report["reasons"]


def test_high_risk_partner_error_blocks_value_ready() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    observations[0]["high_risk_error"] = True
    _rehash_observation(observations[0])
    _refresh_trust(trust, observations)
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "MISSING_EVIDENCE"
    assert "HIGH_RISK_PARTNER_ERROR" in report["reasons"]


def test_trust_summary_is_recomputed_not_trusted() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    trust["assisted_counts"]["FALSE_ACCEPT"] = 1
    trust["assisted_counts"]["CORRECT"] -= 1
    _rehash(trust, "trust_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert "ASSISTED_TRUST_COUNTS_MISMATCH" in report["reasons"]


def test_unverified_signal_cannot_be_value_ready() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    signal["verified"] = False
    _rehash(signal, "signal_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "MISSING_EVIDENCE"
    assert "SIGNAL_NOT_EXTERNALLY_VERIFIED" in report["reasons"]


def test_revoked_signal_cannot_be_value_ready() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    signal["revoked"] = True
    _rehash(signal, "signal_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "MISSING_EVIDENCE"
    assert "SIGNAL_REVOKED" in report["reasons"]


def test_verbal_signal_is_rejected() -> None:
    manifest, eligibility, consent, observations, trust, signal = _nonsynthetic()
    signal["type"] = "VERBAL_PROMISE"
    _rehash(signal, "signal_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert "INVALID_SIGNAL_TYPE" in report["reasons"]


def test_privacy_findings_detect_forbidden_keys_and_values() -> None:
    findings = gate.privacy_findings([
        {
            "email": "synthetic@example.invalid",
            "private_url": "https://example.invalid/private",
            "ip_address": "10.0.0.1",
        }
    ])
    assert any(item.startswith("FORBIDDEN_KEY:") for item in findings)
    assert any(item.startswith("EMAIL_VALUE:") for item in findings)
    assert any(item.startswith("URL_VALUE:") for item in findings)
    assert any(item.startswith("IP_VALUE:") for item in findings)


def test_privacy_in_evidence_blocks_adjudication() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    eligibility["partners"][0]["role_class"] = "person@example.invalid"
    _rehash(eligibility, "eligibility_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any(reason.startswith("PRIVACY:EMAIL_VALUE") for reason in report["reasons"])


def test_privacy_scan_accepts_secure_synthetic_root(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    _write_json(tmp_path / "study-manifest.json", {"schema": "synthetic", "value": "SAFE_CODE"})
    scan = gate.scan_privacy_root(tmp_path)
    assert scan["status"] == "PASS"
    assert scan["finding_count"] == 0
    body = {key: value for key, value in scan.items() if key != "scan_hash"}
    assert scan["scan_hash"] == gate._digest(body)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_privacy_scan_rejects_broad_permissions(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o755)
    path = tmp_path / "study-manifest.json"
    path.write_text('{"schema":"synthetic"}\n', encoding="utf-8")
    os.chmod(path, 0o644)
    scan = gate.scan_privacy_root(tmp_path)
    assert scan["status"] == "FAIL"
    assert "ROOT_PERMISSIONS_TOO_BROAD" in scan["findings"]
    assert any(item.startswith("FILE_PERMISSIONS_TOO_BROAD") for item in scan["findings"])


def test_manifest_threshold_drift_is_invalid() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    manifest["min_improvement"] = 0.10
    _rehash(manifest, "manifest_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert "THRESHOLD_DRIFT:min_improvement" in report["reasons"]


def test_unknown_manifest_key_is_invalid() -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    manifest["market_fit"] = True
    _rehash(manifest, "manifest_hash")
    report = gate.adjudicate(manifest, eligibility, consent, observations, trust, signal)
    assert report["state"] == "INVALID_EVIDENCE"
    assert any(reason.startswith("UNKNOWN_KEYS:") for reason in report["reasons"])


def test_bootstrap_interval_is_deterministic() -> None:
    values = [0.31, 0.42, 0.37]
    assert gate.bootstrap_interval(values) == gate.bootstrap_interval(values)


def test_cli_synthetic_self_test_emits_only_synthetic(capsys: pytest.CaptureFixture[str]) -> None:
    assert gate.main(["--synthetic-self-test"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == gate.SYNTHETIC_STATE
    assert payload["synthetic"] is True
    assert "value_ready" not in json.dumps(payload).lower()


def test_cli_full_synthetic_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest, eligibility, consent, observations, trust, signal = _fixture()
    manifest_path = tmp_path / "manifest.json"
    eligibility_path = tmp_path / "eligibility.json"
    consent_path = tmp_path / "consent.json"
    observations_path = tmp_path / "observations.jsonl"
    trust_path = tmp_path / "trust.json"
    signal_path = tmp_path / "signal.json"
    report_path = tmp_path / "report.json"
    for path, value in (
        (manifest_path, manifest),
        (eligibility_path, eligibility),
        (consent_path, consent),
        (trust_path, trust),
        (signal_path, signal),
    ):
        _write_json(path, value)
    _write_jsonl(observations_path, observations)
    rc = gate.main([
        "--manifest",
        str(manifest_path),
        "--eligibility",
        str(eligibility_path),
        "--consent",
        str(consent_path),
        "--observations",
        str(observations_path),
        "--trust",
        str(trust_path),
        "--signal",
        str(signal_path),
        "--report",
        str(report_path),
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == gate.SYNTHETIC_STATE
    assert json.loads(report_path.read_text()) == payload


def test_cli_privacy_scan_requires_report(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="requires --report"):
        gate.main(["--privacy-scan", str(tmp_path)])


def test_cli_synthetic_mode_rejects_evidence_paths(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="cannot be combined"):
        gate.main(["--synthetic-self-test", "--report", str(tmp_path / "report.json")])
