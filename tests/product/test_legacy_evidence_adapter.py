import ast
import importlib
import inspect
import sys
from dataclasses import fields

import pytest


def _api():
    from product.adapters import legacy

    return legacy


def _fixture():
    from tests.product.test_trusted_evidence_ingestion import _fixture as make_fixture

    return make_fixture()


def test_legacy_adapter_reuses_task3_submission_and_ingestion_symbols():
    api = _api()
    from product.evidence import ingestion

    assert api.EvidenceSubmission is ingestion.EvidenceSubmission
    assert api.IngestionResult is ingestion.IngestionResult
    assert api.IntegrityStatus is ingestion.IntegrityStatus
    assert api.ingest_evidence is ingestion.ingest_evidence


def test_legacy_result_exact_frozen_shape():
    api = _api()
    assert api.LegacyAdapterResult.__dataclass_params__.frozen is True
    assert tuple(field.name for field in fields(api.LegacyAdapterResult)) == (
        "ingestion",
        "fallback_integrity",
        "reasons",
    )


def test_legacy_adapter_signature_is_exact_and_task3_parser_is_reused():
    api = _api()
    from product.evidence import ingestion

    assert tuple(inspect.signature(api.adapt_legacy_evidence).parameters) == (
        "context",
        "value",
    )
    assert api._parse_time is ingestion._parse_time
    assert api.classify_ingestion_result is ingestion.classify_ingestion_result
    assert api.is_trusted_ingestion_result is ingestion.is_trusted_ingestion_result


def test_exact_submission_delegates_once_to_task3_and_preserves_exact_result(monkeypatch):
    _, context, submission, _ = _fixture()
    from product.evidence import ingestion

    calls = []
    returned = []
    original = ingestion.ingest_evidence

    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        result = original(*args, **kwargs)
        returned.append(result)
        return result

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(ingestion, "ingest_evidence", counted)
            sys.modules.pop("product.adapters.legacy", None)
            api = importlib.import_module("product.adapters.legacy")
            signature = inspect.signature(api.adapt_legacy_evidence)
            parameters = tuple(signature.parameters.values())
            assert tuple(parameter.name for parameter in parameters) == ("context", "value")
            assert all(
                parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
                for parameter in parameters
            )
            assert signature.return_annotation in (api.LegacyAdapterResult, "LegacyAdapterResult")
            outcome = api.adapt_legacy_evidence(context, submission)
            assert calls == [((context, (submission,)), {})]
            assert outcome.ingestion is returned[0]
    finally:
        restored = importlib.reload(importlib.import_module("product.adapters.legacy"))
        assert restored.ingest_evidence is ingestion.ingest_evidence


def test_legacy_accepts_only_exact_evidence_submission_type():
    api = _api()
    _, context, submission, _ = _fixture()
    submission_type = type(submission)
    child_type = type("EvidenceSubmissionChild", (submission_type,), {})
    child = child_type(submission.content, submission.status, submission.provenance)
    outcome = api.adapt_legacy_evidence(context, child)
    assert outcome.ingestion is None
    assert outcome.fallback_integrity is api.IntegrityStatus.MALFORMED
    assert outcome.reasons == ("LEGACY_STRUCTURED_MALFORMED",)


def test_legacy_field_identical_wires_and_foreign_lookalikes_never_reconstruct():
    api = _api()
    _, context, submission, _ = _fixture()
    values = {field.name: getattr(submission, field.name) for field in fields(submission)}
    foreign = type("ForeignSubmission", (), values)()
    for value in (values, foreign):
        outcome = api.adapt_legacy_evidence(context, value)
        assert outcome.ingestion is None
        assert outcome.fallback_integrity is api.IntegrityStatus.MALFORMED
        assert outcome.reasons == ("LEGACY_STRUCTURED_MALFORMED",)


def test_legacy_invalid_context_is_a_raw_boundary_error():
    api = _api()
    _, _, submission, _ = _fixture()
    with pytest.raises((TypeError, ValueError)):
        api.adapt_legacy_evidence(None, submission)


def test_exact_submission_routes_through_ingestion_and_preserves_result_type():
    api = _api()
    _, context, submission, _ = _fixture()
    outcome = api.adapt_legacy_evidence(context, submission)
    assert type(outcome.ingestion) is api.IngestionResult
    assert outcome.fallback_integrity is None
    assert outcome.reasons == ()


@pytest.mark.parametrize("value", ({"content": b"x"}, {"status": "PASS"}, object()))
def test_dict_wire_and_lookalike_values_are_malformed_without_reconstruction(value):
    api = _api()
    _, context, _, _ = _fixture()
    outcome = api.adapt_legacy_evidence(context, value)
    assert outcome.ingestion is None
    assert outcome.fallback_integrity is api.IntegrityStatus.MALFORMED
    assert outcome.reasons == ("LEGACY_STRUCTURED_MALFORMED",)


def test_task6_h10_unparseable_structured_provenance_cannot_downgrade_to_legacy():
    """H10: malformed structured input is not reclassified as narrative evidence."""
    _, context, _, _ = _fixture()
    api = _api()
    malformed = {"status": "PASS", "provenance": {"generated_at": "not-a-time"}}
    outcome = api.adapt_legacy_evidence(context, malformed)
    assert outcome.ingestion is None
    assert outcome.fallback_integrity is api.IntegrityStatus.MALFORMED
    assert outcome.reasons == ("LEGACY_STRUCTURED_MALFORMED",)


@pytest.mark.parametrize("value", ("PASS", "FAIL", "legacy narrative", "caller:reason"))
def test_legacy_narratives_are_non_certifiable_without_product_evidence(value):
    api = _api()
    _, context, _, _ = _fixture()
    outcome = api.adapt_legacy_evidence(context, value)
    assert outcome.ingestion is None
    assert outcome.fallback_integrity is api.IntegrityStatus.LEGACY_NON_CERTIFIABLE
    assert outcome.reasons == ("LEGACY_NARRATIVE_NON_CERTIFIABLE",)


def test_legacy_does_not_define_parallel_observation_bundle_or_certification_types():
    api = _api()
    for name in (
        "Observation",
        "EvidenceBundle",
        "TrustedCertificationResult",
        "LegacySchema",
        "LegacyRecord",
        "load_legacy_evidence",
    ):
        assert not hasattr(api, name)


def test_legacy_source_has_no_direct_product_mint_or_forbidden_import_cycle():
    api = _api()
    tree = ast.parse(inspect.getsource(api))
    forbidden_imports = {"product.kernel", "product.verification", "product.certification"}
    forbidden_calls = {
        "Observation",
        "EvidenceBundle",
        "TrustedCertificationResult",
        "_bootstrap_external_receipt_expectation",
        "validate_prerequisites",
        "certify_ingested",
        "certify",
    }

    def qualified_name(node):
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            return qualified_name(node.value) + (node.attr,)
        return ()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                not any(
                    alias.name == path or alias.name.startswith(path + ".")
                    for path in forbidden_imports
                )
                for alias in node.names
            )
        if isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden_imports
            if node.module == "product":
                assert all(f"product.{alias.name}" not in forbidden_imports for alias in node.names)
        if isinstance(node, ast.Call):
            qualified = qualified_name(node.func)
            assert not any(part in forbidden_calls for part in qualified)


def test_legacy_status_authority_remains_v2_expected_status():
    api = _api()
    _, context, submission, _ = _fixture()
    from product.evidence import ObservationStatus

    assert context.requirements[0].expected_status.value == "PASS"
    failed = submission.__class__(submission.content, ObservationStatus.FAIL, submission.provenance)
    outcome = api.adapt_legacy_evidence(context, failed)
    assert outcome.ingestion is not None
    assert outcome.ingestion.bundle is None
    assert outcome.ingestion.reason_codes == ("CROSS_BOUND:observation_status",)
