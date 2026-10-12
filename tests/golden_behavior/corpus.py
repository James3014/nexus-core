"""Curated, authority-bound Nexus Core Golden Behavior Corpus.

This module is data, not a second behavior authority.  Each case points back to
the repository contract documents, product source, or a GitHub Issue that owns
the behavior, and to the existing pytest node ids that witness it.  A node id
without a ``[param]`` suffix stands for every parametrization of that test.

Findings (``status="finding"``) record known gaps without changing product
behavior; they carry no witness node ids.

The corpus is deliberately a pure literal (every ``_c(...)`` argument is a
string/tuple literal) so tools can parse it with ``ast`` without importing it.
Run it with ``scripts/golden_behavior_eval.py``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GoldenCase:
    case_id: str
    title: str
    classification: str
    scenario: str
    expected_behavior: str
    authority_sources: tuple[str, ...]
    automated_tests: tuple[str, ...] = ()
    status: str = "covered"
    finding_id: str | None = None


def _c(
    case_id: str,
    title: str,
    classification: str,
    scenario: str,
    expected_behavior: str,
    authority_sources: tuple[str, ...],
    automated_tests: tuple[str, ...] = (),
    *,
    status: str = "covered",
    finding_id: str | None = None,
) -> GoldenCase:
    return GoldenCase(
        case_id,
        title,
        classification,
        scenario,
        expected_behavior,
        authority_sources,
        automated_tests,
        status,
        finding_id,
    )


CASES: tuple[GoldenCase, ...] = (
    _c(
        "NCG-001",
        "Committed external repository check is VERIFIED and replayable",
        "invariant",
        "normal",
        "A committed change in an external repository with a passing base-ref verifier yields VERIFIED (not CERTIFIED) and a self-hashed receipt that revalidates.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Exact first-use journey",
            "docs/LOCAL_GOLDEN_PATH.md#Durable receipt contract",
            "product/clients/local_golden_path.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_committed_external_repo_check_is_verified_and_replayable",
        ),
    ),
    _c(
        "NCG-002",
        "Acquisition leaves the caller repository untouched",
        "invariant",
        "normal",
        "Local acquisition uses a temporary index and never changes HEAD, the normal Git index, or working-tree files of the caller repository.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Exact first-use journey",
            "SECURITY.md#Threat Model & Trust Boundaries",
        ),
        (
            "tests/product/test_local_golden_path.py::test_dirty_check_preserves_head_index_and_worktree",
        ),
    ),
    _c(
        "NCG-003",
        "doctor is read-only",
        "invariant",
        "normal",
        "doctor reports success and failure without writing to the repository.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Exact first-use journey",
            "product/clients/local_golden_path.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_doctor_is_read_only_and_reports_success_and_failure",
        ),
    ),
    _c(
        "NCG-004",
        "init creates minimal config and refuses overwrite",
        "invariant",
        "idempotency",
        "init writes the minimal deterministic config once; a second init refuses to overwrite an existing config.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Minimal deterministic config",
            "product/clients/local_golden_path.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_init_creates_minimal_config_and_refuses_overwrite",
        ),
    ),
    _c(
        "NCG-005",
        "Issue binding enters the requirements",
        "invariant",
        "normal",
        "issue-init binds the exact Issue contract and issue-check carries that binding into the verified requirements.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Issue-bound quick binding",
            "AGENTS.md#Nexus Core issue-bound completion evidence",
            "product/clients/issue_golden_path.py",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_issue_init_and_check_bind_requirements_to_issue",
        ),
    ),
    _c(
        "NCG-006",
        "Bound Issue receipt passes every gate expectation",
        "invariant",
        "normal",
        "A real VERIFIED Issue-bound receipt satisfies every receipt-check expectation flag used by the CI gate.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Receipt subject binding and `receipt-check` expectations",
            "docs/GITHUB_REPOSITORY_CHECK.md#Verify a receipt yourself",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_bound_issue_receipt_verified_passes_all_expectations",
            "tests/product/test_local_golden_path.py::test_receipt_check_cli_expectations_pass_on_real_receipt",
        ),
    ),
    _c(
        "NCG-007",
        "No changes fails closed",
        "invariant",
        "boundary",
        "A candidate identical to the base ref fails closed with NO_CHANGES for both check and issue-check.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Fail-closed negative controls",
            "product/clients/local_golden_path.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_check_fails_closed_when_there_are_no_changes",
            "tests/product/test_issue_golden_path.py::test_issue_check_no_changes_preserves_existing_fail_closed_behavior",
        ),
    ),
    _c(
        "NCG-008",
        "Scope and deletion policy fail closed with typed reasons",
        "invariant",
        "failure",
        "Paths outside allowed_patterns fail with FORBIDDEN_PATH and forbidden deletions (including the tracked config) fail with FORBIDDEN_DELETION.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Fail-closed negative controls",
            "docs/LOCAL_GOLDEN_PATH.md#Minimal deterministic config",
        ),
        (
            "tests/product/test_local_golden_path.py::test_policy_projection_fails_closed_with_typed_reason",
            "tests/product/test_local_golden_path.py::test_tracked_config_legitimate_deletion_fails_closed_with_forbidden_deletion",
        ),
    ),
    _c(
        "NCG-009",
        "Non-zero verifier exit is FAILED_VERIFICATION",
        "invariant",
        "failure",
        "A verifier that runs and exits non-zero yields FAILED_VERIFICATION, not a transport or availability error.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Fail-closed negative controls",
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
        ),
        (
            "tests/product/test_local_golden_path.py::test_verifier_fail_is_failed_verification_not_transport_error",
        ),
    ),
    _c(
        "NCG-010",
        "Verifier unavailable or timed out fails closed and kills the process group",
        "invariant",
        "failure",
        "An unavailable verifier or a timeout fails closed with a typed reason, and the whole verifier process group, including backgrounded grandchildren, is killed.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Fail-closed negative controls",
            "SECURITY.md#Threat Model & Trust Boundaries",
        ),
        (
            "tests/product/test_local_golden_path.py::test_verifier_unavailable_fails_closed_with_typed_reason",
            "tests/product/test_local_golden_path.py::test_verifier_timeout_fails_closed_with_typed_reason",
            "tests/product/test_local_golden_path.py::test_verifier_timeout_kills_backgrounded_grandchildren",
        ),
    ),
    _c(
        "NCG-011",
        "Container isolation unavailable fails closed",
        "security",
        "failure",
        "Container mode without docker fails with ISOLATION_UNAVAILABLE, an image pull failure with ISOLATION_IMAGE_UNAVAILABLE, and a wrong mount nonce with ISOLATION_MOUNT_UNAVAILABLE, each with a receipt.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Isolation modes",
            "SECURITY.md#Threat Model & Trust Boundaries",
        ),
        (
            "tests/product/test_local_golden_path.py::test_container_mode_without_docker_fails_closed",
            "tests/product/test_local_golden_path.py::test_container_image_pull_failure_fails_closed_with_receipt",
            "tests/product/test_local_golden_path.py::test_mount_probe_wrong_nonce_fails_closed_with_receipt",
        ),
    ),
    _c(
        "NCG-012",
        "Verifier mutating the subject is detected",
        "security",
        "partial_state",
        "Any change to the original target tree during the verifier run fails closed even if the verifier itself passed.",
        (
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
            "docs/LOCAL_GOLDEN_PATH.md#Ignored residue policy",
        ),
        ("tests/product/test_local_golden_path.py::test_check_detects_target_changed_by_verifier",),
    ),
    _c(
        "NCG-013",
        "Sandbox cleanup failure fails closed",
        "invariant",
        "partial_state",
        "A failure to clean up the verifier sandbox fails the check closed instead of reporting VERIFIED.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Isolation modes",
            "product/clients/local_golden_path.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_check_fails_closed_on_verifier_sandbox_cleanup_failure",
        ),
    ),
    _c(
        "NCG-014",
        "Verifier sandbox cannot reach the original repository",
        "security",
        "authority_conflict",
        "The detached clone has no origin remote, so a verifier cannot reach back into the original repository through Git (2026-10-08 regression).",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "docs/LOCAL_GOLDEN_PATH.md#Isolation modes",
        ),
        (
            "tests/product/test_local_golden_path.py::test_sandbox_has_no_origin_and_cannot_reach_original_repository",
        ),
    ),
    _c(
        "NCG-015",
        "Verifier environment is an allowlist",
        "security",
        "authority_conflict",
        "Secrets such as GITHUB_TOKEN are not inherited; only allowlisted variables and a sandbox-private HOME are passed, and env_passthrough names are explicit and recorded.",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "docs/LOCAL_GOLDEN_PATH.md#Isolation modes",
        ),
        (
            "tests/product/test_local_golden_path.py::test_verifier_secret_env_is_not_inherited_but_passthrough_is_explicit",
            "tests/product/test_local_golden_path.py::test_verifier_environment_is_allowlist_with_sandbox_home",
        ),
    ),
    _c(
        "NCG-016",
        "Ignored residue is sandbox-only",
        "regression",
        "boundary",
        "Ignored files such as .venv and __pycache__ do not block check, and doctor reports them as informational only.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Ignored residue policy",
            "SECURITY.md#Threat Model & Trust Boundaries",
        ),
        (
            "tests/product/test_local_golden_path.py::test_check_verifies_checkout_with_venv_and_pycache",
            "tests/product/test_local_golden_path.py::test_doctor_reports_ignored_residue_informationally",
        ),
    ),
    _c(
        "NCG-017",
        "Widened worktree config has no effect",
        "security",
        "authority_conflict",
        "A widened allowed_patterns in the worktree config, committed or not, cannot override the base-ref config.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Trusted config source",
            "SECURITY.md#Threat Model & Trust Boundaries",
        ),
        (
            "tests/product/test_local_golden_path.py::test_widened_worktree_config_cannot_override_base_ref_config",
        ),
    ),
    _c(
        "NCG-018",
        "Untracked config is untrusted",
        "security",
        "authority_conflict",
        "A config absent from the base ref is reported as config: untrusted, and --require-trusted-config or NEXUS_CERTIFY_REQUIRE_TRUSTED_CONFIG=1 fails closed with CONFIG_UNTRUSTED.",
        ("docs/LOCAL_GOLDEN_PATH.md#Trusted config source",),
        (
            "tests/product/test_local_golden_path.py::test_untracked_config_is_worktree_source_and_can_be_rejected",
            "tests/product/test_local_golden_path.py::test_cli_check_prints_config_trust_and_honors_env",
        ),
    ),
    _c(
        "NCG-019",
        "Differing base_ref is CONFIG_BASE_REF_MISMATCH",
        "security",
        "authority_conflict",
        "When the base-ref config names a different base_ref than the worktree config, the run fails with CONFIG_BASE_REF_MISMATCH.",
        ("docs/LOCAL_GOLDEN_PATH.md#Trusted config source",),
        (
            "tests/product/test_local_golden_path.py::test_base_ref_config_with_different_base_ref_is_rejected",
        ),
    ),
    _c(
        "NCG-020",
        "Revision-expression base_ref is never trusted",
        "security",
        "authority_conflict",
        "A base_ref revision expression such as HEAD~1 is candidate-chosen and never yields base-ref trust; --require-trusted-config fails closed with CONFIG_UNTRUSTED.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Trusted config source",
            "SECURITY.md#Threat Model & Trust Boundaries",
        ),
        (
            "tests/product/test_local_golden_path.py::test_require_trusted_config_rejects_candidate_chosen_base_ref_expression",
        ),
    ),
    _c(
        "NCG-021",
        "Base ref outside HEAD ancestry is rejected",
        "invariant",
        "stale_state",
        "doctor, check, and candidate acquisition reject a base ref (or source) that is not an ancestor of the candidate head.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Fail-closed negative controls",
            "product/runtime/candidate_acquisition.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_doctor_and_check_reject_base_ref_outside_head_ancestry",
            "tests/product/test_cli_candidate_acquisition.py::test_source_not_ancestor_fails_closed",
        ),
    ),
    _c(
        "NCG-022",
        "Tampered receipt is rejected",
        "security",
        "malformed_input",
        "receipt-check fails closed on a receipt whose manifest or result was edited without re-hashing.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Durable receipt contract",
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
        ),
        (
            "tests/product/test_local_golden_path.py::test_receipt_check_cli_fails_closed_on_tampered_receipt",
            "tests/product/test_local_golden_path.py::test_receipt_rejects_tampered_manifest_and_result",
        ),
    ),
    _c(
        "NCG-023",
        "Re-hashed semantic tamper is rejected",
        "security",
        "malformed_input",
        "Editing the outcome, verifier status, or requirements config and re-hashing the receipt still fails recomputation and cross-binding checks.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Durable receipt contract",
            "product/certification/receipt.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_receipt_rejects_rehashed_outcome_tamper",
            "tests/product/test_local_golden_path.py::test_receipt_rejects_rehashed_verifier_status_tamper",
            "tests/product/test_local_golden_path.py::test_receipt_rejects_rehashed_requirements_config_tamper",
        ),
    ),
    _c(
        "NCG-024",
        "Malformed receipt values are rejected, not raised",
        "security",
        "malformed_input",
        "Malformed, deeply nested, or option-shaped untrusted values are rejected with a typed result, never an uncaught exception or a Git side effect; malformed JSON input to acquisition yields machine-readable errors.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Durable receipt contract",
            "product/runtime/candidate_acquisition.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_receipt_malformed_untrusted_values_are_rejected_not_raised",
            "tests/product/test_local_golden_path.py::test_receipt_deeply_nested_value_is_rejected_not_raised",
            "tests/product/test_local_golden_path.py::test_receipt_option_shaped_tree_id_is_rejected_without_git_side_effects",
            "tests/product/test_cli_candidate_acquisition.py::test_malformed_json_input_is_machine_readable",
        ),
    ),
    _c(
        "NCG-025",
        "Expectation mismatch exits 2 with a typed reason",
        "invariant",
        "failure",
        "Each receipt-check expectation mismatch yields its typed reason and exit code 2; malformed hex arguments are rejected.",
        ("docs/LOCAL_GOLDEN_PATH.md#Receipt subject binding and `receipt-check` expectations",),
        (
            "tests/product/test_local_golden_path.py::test_evaluate_receipt_expectations_negative",
            "tests/product/test_local_golden_path.py::test_receipt_check_cli_expectation_mismatch_exits_2",
            "tests/product/test_local_golden_path.py::test_receipt_check_cli_rejects_malformed_hex_argument",
        ),
    ),
    _c(
        "NCG-026",
        "Tamper beats passing expectations",
        "security",
        "malformed_input",
        "A tampered receipt fails receipt-check even when every supplied expectation would otherwise match.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Receipt subject binding and `receipt-check` expectations",
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
        ),
        (
            "tests/product/test_local_golden_path.py::test_receipt_check_cli_tampered_receipt_with_passing_expectations_still_fails",
        ),
    ),
    _c(
        "NCG-027",
        "Receipts without subject fields still validate",
        "compatibility",
        "normal",
        "Older receipts that predate the subject binding fields still validate structurally.",
        ("docs/LOCAL_GOLDEN_PATH.md#Receipt subject binding and `receipt-check` expectations",),
        (
            "tests/product/test_local_golden_path.py::test_receipt_without_subject_fields_still_validates",
        ),
    ),
    _c(
        "NCG-028",
        "Dirty subject is recorded and can be refused",
        "invariant",
        "partial_state",
        "A success receipt over an uncommitted change records the subject as not clean, and --require-clean-subject fails for a dirty worktree.",
        ("docs/LOCAL_GOLDEN_PATH.md#Receipt subject binding and `receipt-check` expectations",),
        (
            "tests/product/test_local_golden_path.py::test_success_receipt_subject_not_clean_with_uncommitted_change",
            "tests/product/test_local_golden_path.py::test_receipt_check_cli_require_clean_subject_fails_for_dirty_worktree",
        ),
    ),
    _c(
        "NCG-029",
        "Repository VERIFIED is not Issue VERIFIED",
        "regression",
        "authority_conflict",
        "An unbound or false-green Issue receipt carries a non-VERIFIED issue_verification and fails --expect-issue / --expect-status VERIFIED even when outcome.status is VERIFIED (#134).",
        (
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
            "https://github.com/James3014/nexus-core/issues/134",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_unbound_issue_receipt_carries_unverifiable_verdict_and_fails_gate",
            "tests/product/test_issue_golden_path.py::test_nexus_runtime_false_green_receipt_fails_issue_expectations",
            "tests/product/test_local_golden_path.py::test_expect_issue_requires_verified_issue_verification",
        ),
    ),
    _c(
        "NCG-030",
        "Stale evidence universe fails the gate",
        "invariant",
        "stale_state",
        "An Issue receipt whose evidence-universe binding no longer matches the current verification contract carries a STALE verdict and fails the gate.",
        (
            "docs/GITHUB_REPOSITORY_CHECK.md#Two jobs: run and verify",
            "product/clients/issue_golden_path.py",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_stale_issue_receipt_carries_stale_verdict_and_fails_gate",
            "tests/product/test_issue_golden_path.py::test_issue_evidence_universe_binding_goes_stale_when_verification_contract_changes",
        ),
    ),
    _c(
        "NCG-031",
        "Issue contract drift and closed Issues are rejected",
        "invariant",
        "stale_state",
        "issue-check requires a rebind after the Issue contract drifts and rejects a closed Issue.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Issue-bound quick binding",
            "product/clients/issue_golden_path.py",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_issue_check_requires_rebind_after_contract_drift",
            "tests/product/test_issue_golden_path.py::test_issue_check_rejects_closed_issue",
        ),
    ),
    _c(
        "NCG-032",
        "Issue binding tamper fails closed",
        "security",
        "malformed_input",
        "A tampered Issue binding, or a re-hashed substituted evidence binding, fails closed.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Issue-bound quick binding",
            "product/clients/issue_golden_path.py",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_issue_binding_tamper_fails_closed",
            "tests/product/test_issue_golden_path.py::test_rehashed_substituted_issue_evidence_binding_fails_closed",
        ),
    ),
    _c(
        "NCG-033",
        "Evidence-universe marker parsing is strict",
        "invariant",
        "malformed_input",
        "Two exact markers or a marker with a bad value is malformed; prose mentions of the marker are ignored.",
        (
            "docs/GITHUB_REPOSITORY_CHECK.md#Two jobs: run and verify",
            "product/clients/issue_golden_path.py",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_evidence_universe_marker_two_exact_markers_malformed",
            "tests/product/test_issue_golden_path.py::test_evidence_universe_marker_comment_with_bad_value_malformed",
            "tests/product/test_issue_golden_path.py::test_evidence_universe_marker_ignores_prose_mentions",
        ),
    ),
    _c(
        "NCG-034",
        "Repository identity conflict is rejected",
        "security",
        "authority_conflict",
        "issue-init rejects a repository mismatch and issue-check rejects a binding whose repository differs from origin.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Issue-bound quick binding",
            "product/clients/issue_golden_path.py",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_issue_init_rejects_repository_mismatch",
            "tests/product/test_issue_golden_path.py::test_issue_check_rejects_binding_repository_that_differs_from_origin",
        ),
    ),
    _c(
        "NCG-035",
        "Material transitions need Issue authority",
        "security",
        "authority_conflict",
        "Only a privileged Issue marker with the exact current from-identity authorizes a material pin bump; unprivileged, stale, or malformed markers and identity mismatches fail closed with a receipt.",
        (
            "docs/MULTI_EVIDENCE_GOLDEN_PATH.md#Issue-authorized material transitions",
            "docs/MULTI_EVIDENCE_GOLDEN_PATH.md#Exact external material identity",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_issue_marker_authorizes_pin_bump_end_to_end",
            "tests/product/test_issue_golden_path.py::test_transition_marker_from_unprivileged_author_fails_closed_with_receipt",
            "tests/product/test_issue_golden_path.py::test_issue_marker_with_stale_from_fails_closed_with_receipt",
            "tests/product/test_issue_golden_path.py::test_material_transition_marker_malformed_fails_closed",
            "tests/product/test_local_golden_path.py::test_v2_required_material_identity_mismatch_blocks_linked_verifier",
        ),
    ),
    _c(
        "NCG-036",
        "Legacy receipt without material_transitions stays valid",
        "compatibility",
        "normal",
        "A receipt that predates the material_transitions key still validates.",
        (
            "docs/MULTI_EVIDENCE_GOLDEN_PATH.md#Compatibility",
            "product/certification/receipt.py",
        ),
        (
            "tests/product/test_issue_golden_path.py::test_legacy_receipt_without_material_transitions_key_stays_valid",
        ),
    ),
    _c(
        "NCG-037",
        "markers hash is stable",
        "invariant",
        "idempotency",
        "The markers hash is stable across committing the config, and markers text without an Issue warns that it is untrusted.",
        (
            "docs/MULTI_EVIDENCE_GOLDEN_PATH.md#Issue-authorized material transitions",
            "product/clients/cli.py",
        ),
        (
            "tests/product/test_cli_markers.py::test_markers_hash_is_stable_across_committing_config",
            "tests/product/test_cli_markers.py::test_markers_text_without_issue_untrusted_warns",
        ),
    ),
    _c(
        "NCG-038",
        "Rerun artifact lineage binds the producing attempt",
        "regression",
        "recovery",
        "Each attempt's receipt artifact has a distinct identity, a verifier-only rerun reads the producer attempt, and the workflow passes the producer artifact identity to the verifier (#142).",
        (
            "docs/GITHUB_REPOSITORY_CHECK.md#Two jobs: run and verify",
            "https://github.com/James3014/nexus-core/issues/142",
            ".github/actions/issue-gate/action.yml",
        ),
        (
            "tests/architecture/test_receipt_artifact_lineage.py::test_rerun_attempts_produce_distinct_artifact_identities",
            "tests/architecture/test_receipt_artifact_lineage.py::test_verifier_only_rerun_reads_the_producer_attempt",
            "tests/architecture/test_receipt_artifact_lineage.py::test_download_model_reproduces_the_issue_142_incident",
            "tests/architecture/test_receipt_artifact_lineage.py::test_core_workflow_passes_producer_artifact_identity_to_verifier",
        ),
    ),
    _c(
        "NCG-039",
        "Same-name artifact substitution is never downloaded",
        "security",
        "authority_conflict",
        "A same-name artifact appearing after resolution is never downloaded; ambiguous identities and artifact ids from another attempt fail closed.",
        (
            "docs/GITHUB_REPOSITORY_CHECK.md#Two jobs: run and verify",
            ".github/actions/receipt-verify/action.yml",
        ),
        (
            "tests/architecture/test_receipt_artifact_lineage.py::test_same_name_artifact_appearing_after_resolution_is_never_downloaded",
            "tests/architecture/test_receipt_artifact_lineage.py::test_ambiguous_artifact_identity_fails_closed",
            "tests/architecture/test_receipt_artifact_lineage.py::test_artifact_id_from_another_attempt_fails_closed",
        ),
    ),
    _c(
        "NCG-040",
        "Missing or expired producer artifact fails closed",
        "invariant",
        "partial_state",
        "If the producer attempt's artifact is missing or expired the verify job fails closed.",
        (
            "docs/GITHUB_REPOSITORY_CHECK.md#Two jobs: run and verify",
            ".github/actions/receipt-verify/action.yml",
        ),
        (
            "tests/architecture/test_receipt_artifact_lineage.py::test_missing_producer_artifact_fails_closed",
            "tests/architecture/test_receipt_artifact_lineage.py::test_expired_producer_artifact_fails_closed",
        ),
    ),
    _c(
        "NCG-041",
        "Exact replay is idempotent",
        "invariant",
        "idempotency",
        "An exact replay returns replayed=true without rerunning the verifier, a different request under the same key conflicts, and repeated receipt hashing is stable.",
        (
            "docs/architecture/LEDGER_TRUST_MODEL.md#Ledger signatures are unauthenticated metadata",
            "product/ledger.py",
        ),
        (
            "tests/product/test_cli_candidate_acquisition.py::test_exact_replay_returns_replayed_true_verifier_not_rerun",
            "tests/product/test_ledger.py::test_idempotent_replay_success",
            "tests/product/test_ledger.py::test_idempotency_conflict_different_request",
            "tests/product/test_evidence_receipt_hardening.py::test_receipt_repeat_hash_and_serialized_validation",
        ),
    ),
    _c(
        "NCG-042",
        "Runtime receipt verification reports provenance",
        "security",
        "authority_conflict",
        "verify_receipt reports an offline-minted receipt as NOT_RECORDED and fails closed with LEDGER_UNAVAILABLE when the ledger cannot be read (#233).",
        (
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
            "docs/architecture/LEDGER_TRUST_MODEL.md#Runtime receipt verification is not provenance",
        ),
        (
            "tests/product/test_http_runtime.py::test_runtime_verify_receipt_reports_offline_receipt_as_not_recorded",
            "tests/product/test_http_runtime.py::test_runtime_verify_receipt_fails_closed_when_ledger_unavailable",
        ),
    ),
    _c(
        "NCG-043",
        "Runtime ledger and replay failures fail closed",
        "invariant",
        "recovery",
        "A failed idempotency-ledger read or a corrupt carried replay payload fails closed, and ledger failpoints reconcile.",
        (
            "docs/architecture/LEDGER_TRUST_MODEL.md#Ledger signatures are unauthenticated metadata",
            "product/ledger.py",
            "product/runtime/service.py",
        ),
        (
            "tests/product/test_runtime_ledger_read_fail_closed.py::test_submit_fails_closed_when_idempotency_ledger_read_fails",
            "tests/product/test_runtime_corrupt_replay_fail_closed.py::test_submit_replay_fails_closed_when_carried_payload_is_corrupt",
            "tests/product/test_ledger.py::test_failpoints_and_reconciliation",
        ),
    ),
    _c(
        "NCG-044",
        "Handoff readiness requires fresh, untampered prerequisites",
        "invariant",
        "stale_state",
        "Repository VERIFIED alone does not imply HANDOFF_READY; HEAD drift invalidates a handoff receipt and a tampered prerequisite receipt blocks handoff.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Three-Level Governance Hierarchy (Issue #83)",
            "docs/RUNTIME_HANDOFF.md#The Three Governance Levels",
        ),
        (
            "tests/product/test_runtime_handoff.py::test_nc01_repo_verified_alone_does_not_imply_handoff_ready",
            "tests/product/test_runtime_handoff.py::test_nc02_head_drift_invalidates_handoff_receipt",
            "tests/product/test_runtime_handoff.py::test_prerequisite_tampered_repository_receipt_blocks_handoff",
        ),
    ),
    _c(
        "NCG-045",
        "Handoff state cannot survive a later failure or interruption",
        "invariant",
        "recovery",
        "An earlier pass cannot survive a later failure, and an interrupted attempt cannot leave an old READY receipt current.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Three-Level Governance Hierarchy (Issue #83)",
            "docs/RUNTIME_HANDOFF.md#The Three Governance Levels",
        ),
        (
            "tests/product/test_runtime_handoff.py::test_nc07_earlier_pass_cannot_survive_later_failure",
            "tests/product/test_runtime_handoff.py::test_interrupted_attempt_cannot_leave_old_ready_current",
        ),
    ),
    _c(
        "NCG-046",
        "Claim ceiling excludes acceptance, merge, release and deploy",
        "invariant",
        "normal",
        "Receipts and handoff evidence never claim acceptance, merge, release or deployment authority, and public constructors cannot forge a certified disposition.",
        (
            "AGENTS.md#Nexus Core issue-bound completion evidence",
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
        ),
        (
            "tests/product/test_cli_candidate_acquisition.py::test_claim_ceiling_excludes_acceptance_merge_release_deploy",
            "tests/product/test_runtime_handoff.py::test_nc08_claim_ceiling_enforces_no_merge_no_deploy",
            "tests/product/test_evidence_receipt_hardening.py::test_public_receipt_constructor_cannot_create_certified_receipt",
            "tests/product/test_evidence_receipt_hardening.py::test_certification_result_cannot_forge_disposition",
        ),
    ),
    _c(
        "NCG-047",
        "v2 multi-evidence cannot false-green",
        "invariant",
        "partial_state",
        "A failed required verifier cannot produce VERIFIED, and an unresolved conditional subject is UNVERIFIABLE.",
        (
            "docs/MULTI_EVIDENCE_GOLDEN_PATH.md#Named required evidence",
            "docs/MULTI_EVIDENCE_GOLDEN_PATH.md#Applicability",
        ),
        (
            "tests/product/test_local_golden_path.py::test_v2_failed_required_verifier_cannot_false_green",
            "tests/product/test_local_golden_path.py::test_v2_unresolved_conditional_subject_is_unverifiable",
        ),
    ),
    _c(
        "NCG-048",
        "Nexus Verify reports staleness explicitly",
        "invariant",
        "stale_state",
        "Target-tree and source staleness are explicit, a missing receipt never upgrades GitHub state to VERIFIED, and worktree-config or forged base-ref config receipts are UNVERIFIABLE.",
        (
            "product/runtime/nexus_verify.py",
            "docs/nexus_verify/PUBLIC_REVIEW_READINESS.md#Tool contract",
        ),
        (
            "tests/product/test_nexus_verify_plugin.py::test_receipt_target_tree_staleness_is_explicit",
            "tests/product/test_nexus_verify_plugin.py::test_receipt_source_staleness_is_explicit",
            "tests/product/test_nexus_verify_plugin.py::test_missing_receipt_never_upgrades_github_state_to_verified",
            "tests/product/test_nexus_verify_plugin.py::test_untrusted_worktree_config_receipt_is_unverifiable",
            "tests/product/test_nexus_verify_plugin.py::test_forged_base_ref_config_source_with_wrong_commit_is_unverifiable",
        ),
    ),
    _c(
        "NCG-049",
        "CI actions are pinned to immutable SHAs",
        "security",
        "normal",
        "Production workflows and composite actions reference actions only by immutable commit SHA; movable tags are rejected.",
        ("docs/architecture/WORKFLOW_DEPENDENCIES.md#Enforcement & Anti-Regression Guard",),
        (
            "tests/architecture/test_workflow_dependency_pinning.py::test_production_github_workflows_are_pinned_to_immutable_shas",
            "tests/architecture/test_workflow_dependency_pinning.py::test_production_composite_actions_are_pinned_to_immutable_shas",
            "tests/architecture/test_workflow_dependency_pinning.py::test_negative_control_movable_tag_rejected",
        ),
    ),
    _c(
        "NCG-050",
        "Required-check documentation agrees with workflows",
        "compatibility",
        "normal",
        "Documented required status checks agree with each other and correspond to real workflow jobs.",
        ("docs/governance/CANONICAL_REPOSITORY_PROTECTION.md#Repository Required Checks",),
        (
            "tests/architecture/test_required_status_check_documentation.py::test_required_status_check_documentation_agrees",
            "tests/architecture/test_required_status_check_documentation.py::test_documented_contexts_have_corresponding_workflow_jobs",
        ),
    ),
    _c(
        "NCG-051",
        "Fork PR rejected before the verifier (legacy action)",
        "security",
        "authority_conflict",
        "The legacy repository-check action rejects a fork pull request before any verifier runs.",
        (
            "docs/GITHUB_REPOSITORY_CHECK.md#Why fork pull requests are excluded",
            "product/clients/github_action.py",
        ),
        (
            "tests/product/test_github_action_repository.py::test_repository_check_rejects_fork_pr_before_verifier",
        ),
    ),
    _c(
        "NCG-052",
        "Nexus Verify authenticates receipts",
        "security",
        "malformed_input",
        "SECURITY.md: 'Nexus Verify Does Not Authenticate Receipts ... A caller who edits and re-hashes a receipt can still obtain VERIFIED'; a re-hashed relabelled receipt currently gets APPLIES+VERIFIED (pinned as current unsafe behavior by tests/product/test_nexus_verify_plugin.py::test_rehashed_receipt_claiming_current_base_is_not_authenticated). Required: only a Sigstore-verified CI receipt may yield APPLIES/VERIFIED (Issue #231, OPEN).",
        (
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
            "https://github.com/James3014/nexus-core/issues/231",
            "product/runtime/nexus_verify.py",
        ),
        status="finding",
        finding_id="NCGF-001",
    ),
    _c(
        "NCG-053",
        "Candidate-created branch base_ref is not trusted",
        "security",
        "authority_conflict",
        "LOCAL_GOLDEN_PATH 'Trusted config source': 'a revision expression such as HEAD~1 or a commit SHA is chosen by the candidate and is treated as untrusted'. A local branch the candidate creates is equally candidate-chosen, yet base_ref=\"weak\" on a candidate-created branch earns 'config: trusted (weak@<sha>)' and VERIFIED under --require-trusted-config even though main's verifier fails. CI is not affected (plain-Git fetch has no such branch and receipt-verify pins --expect-config-commit BASE_SHA); local/advisory gap.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Trusted config source",
            "SECURITY.md#Threat Model & Trust Boundaries",
            "product/clients/local_golden_path.py",
        ),
        status="finding",
        finding_id="NCGF-002",
    ),
    _c(
        "NCG-054",
        "Sandbox clone has no hardlinks and no alternates",
        "security",
        "boundary",
        "SECURITY.md 'Verifier sandbox': 'The sandbox is cloned with --no-hardlinks, the origin remote is removed and objects/info/alternates must be absent'. product/clients/local_golden_path.py implements both, but no test witnesses --no-hardlinks or the alternates rejection (only the origin removal is tested by NCG-014).",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "product/clients/local_golden_path.py",
        ),
        status="finding",
        finding_id="NCGF-003",
    ),
    _c(
        "NCG-055",
        "PR gate workflow structure is enforced",
        "security",
        "authority_conflict",
        "SECURITY.md 'PR gate': 'Same-repository branches only (fork guard)'; the verify job runs receipt-check with all eight expectation flags including --require-trusted-config. No test asserts the fork guard on both jobs, issue-check --require-trusted-config, or that receipt-verify passes all eight flags (GITHUB_REPOSITORY_CHECK 'Why fork pull requests are excluded').",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "docs/GITHUB_REPOSITORY_CHECK.md#Why fork pull requests are excluded",
            ".github/workflows/nexus-core-issue-completion.yml",
            ".github/actions/issue-gate/action.yml",
            ".github/actions/receipt-verify/action.yml",
        ),
        status="finding",
        finding_id="NCGF-004",
    ),
    _c(
        "NCG-056",
        "PR gate token exposure matches SECURITY.md",
        "compatibility",
        "normal",
        "SECURITY.md 'PR gate': 'GITHUB_TOKEN is set only on the issue-init/issue-check steps', but .github/actions/issue-gate/action.yml also passes github.token as FETCH_TOKEN to the plain-Git acquisition step (documented in GITHUB_REPOSITORY_CHECK 'Candidate acquisition'). Wording mismatch, not a vulnerability.",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "docs/GITHUB_REPOSITORY_CHECK.md#Candidate acquisition",
            ".github/actions/issue-gate/action.yml",
        ),
        status="finding",
        finding_id="NCGF-005",
    ),
)


FINDINGS = {
    "NCGF-001": "Nexus Verify does not authenticate receipts: a re-hashed relabelled receipt gets APPLIES+VERIFIED; tracked in #231 (OPEN).",
    "NCGF-002": "A candidate-created local branch used as base_ref earns `config: trusted` and VERIFIED under --require-trusted-config; local/advisory only.",
    "NCGF-003": "Sandbox --no-hardlinks clone and objects/info/alternates rejection are implemented but have no witness test.",
    "NCGF-004": "No test asserts the PR gate workflow structure (fork guard on both jobs, --require-trusted-config, all eight receipt-check expectations).",
    "NCGF-005": "SECURITY.md says GITHUB_TOKEN is only on issue-init/issue-check, but issue-gate also passes it as FETCH_TOKEN to acquisition.",
}
