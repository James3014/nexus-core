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
        "Only a receipt whose exact bytes carry a Sigstore bundle that verifies against the subject repository's gate workflow identity (issuer GitHub Actions, nexus-core-issue-completion.yml@refs/heads/main, same workflow repository) may yield APPLIES/VERIFIED. The Issue #231 forgery (relabel config_source as base-ref at the current base commit and re-hash) stays receipt_integrity VALID but is UNVERIFIABLE / NOT_AVAILABLE with RECEIPT_NOT_AUTHENTICATED, with no bundle, with another receipt's genuine bundle, or with a bundle for other bytes, another workflow or another repository; malformed or DSSE bundles are RECEIPT_NOT_AUTHENTICATED and a missing sigstore package or trust root is RECEIPT_AUTHENTICATION_UNAVAILABLE, never VERIFIED. A genuine CI receipt with its bundle is VALID/APPLIES/VERIFIED (real signature: tests/product/test_nexus_verify_sigstore_real.py, needs the optional sigstore package).",
        (
            "SECURITY.md#Security Claim Boundaries: What `VERIFIED` Means",
            "docs/nexus_verify/PUBLIC_REVIEW_READINESS.md#Receipt authentication",
            "https://github.com/James3014/nexus-core/issues/231",
            "product/clients/nexus_verify.py",
            "product/clients/receipt_authentication.py",
        ),
        (
            "tests/product/test_nexus_verify_plugin.py::test_rehashed_receipt_claiming_current_base_is_not_authenticated",
            "tests/product/test_nexus_verify_plugin.py::test_fresh_valid_receipt_applies_to_current_pr",
            "tests/product/test_nexus_verify_plugin.py::test_missing_bundle_is_not_authenticated",
            "tests/product/test_nexus_verify_plugin.py::test_bundle_for_different_bytes_is_not_authenticated",
            "tests/product/test_nexus_verify_plugin.py::test_signed_bytes_must_encode_the_exact_receipt_value",
            "tests/product/test_nexus_verify_plugin.py::test_wrong_signer_identity_is_not_authenticated",
            "tests/product/test_nexus_verify_plugin.py::test_authenticator_unavailable_or_unknown_is_never_verified",
            "tests/product/test_nexus_verify_plugin.py::test_default_authenticator_without_sigstore_is_unavailable",
            "tests/product/test_nexus_verify_plugin.py::test_malformed_signature_material_is_not_authenticated",
            "tests/product/test_nexus_verify_plugin.py::test_acquisition_failure_never_reports_verified_for_unsigned_receipt",
            "tests/benchmark/test_nexus_verify_g2.py::test_unauthenticated_receipt_is_never_accepted",
        ),
    ),
    _c(
        "NCG-053",
        "Candidate-created branch base_ref is advisory; only a pin enforces",
        "security",
        "authority_conflict",
        "A named base_ref is only advisory locally because any process with repository write access can create a ref: base_ref=\"weak\" on a candidate-created branch is reported as 'config: base-ref, unpinned (weak@<sha>)', never 'config: trusted', and --require-trusted-config keeps accepting it for CI compatibility. With --expect-config-commit <sha> (or NEXUS_CERTIFY_EXPECT_CONFIG_COMMIT; malformed value fails closed) obtained outside the candidate's control, any config source other than base-ref at that commit fails closed with CONFIG_SOURCE_MISMATCH before the verifier runs and still writes a receipt; a matching pin prints 'config: trusted (<ref>@<sha>, pinned)'.",
        (
            "docs/LOCAL_GOLDEN_PATH.md#Trusted config source",
            "SECURITY.md#Threat Model & Trust Boundaries",
            "product/clients/local_golden_path.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_candidate_created_branch_is_reported_unpinned_not_trusted",
            "tests/product/test_local_golden_path.py::test_pinned_config_commit_rejects_candidate_created_branch_before_verifier",
            "tests/product/test_local_golden_path.py::test_pinned_config_commit_also_rejects_worktree_source",
            "tests/product/test_local_golden_path.py::test_pinned_legit_base_commit_is_verified_and_labelled_pinned",
            "tests/product/test_local_golden_path.py::test_expect_config_commit_env_pins_and_flag_wins",
            "tests/product/test_local_golden_path.py::test_malformed_expect_config_commit_env_fails_closed",
        ),
    ),
    _c(
        "NCG-054",
        "Sandbox clone has no hardlinks and no alternates",
        "security",
        "boundary",
        "SECURITY.md 'Verifier sandbox': the sandbox is cloned with --no-hardlinks and objects/info/alternates must be absent. After a real check the sandbox object files share no inode with the source repository and each has st_nlink == 1, and no alternates file exists (a negative control that drops --no-hardlinks makes the same inspection see shared inodes). If alternates are present after the clone, the run fails closed with VERIFIER_SANDBOX_PREPARE_FAILED and a FAILED_CLOSED receipt, the verifier never runs, and the sandbox is still removed.",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "product/clients/local_golden_path.py",
        ),
        (
            "tests/product/test_local_golden_path.py::test_sandbox_clone_shares_no_hardlinked_objects_and_has_no_alternates",
            "tests/product/test_local_golden_path.py::test_sandbox_hardlink_detector_negative_control",
            "tests/product/test_local_golden_path.py::test_sandbox_with_object_alternates_fails_closed_before_verifier",
        ),
    ),
    _c(
        "NCG-055",
        "PR gate workflow structure is enforced",
        "security",
        "authority_conflict",
        "SECURITY.md 'PR gate': the workflow triggers only on pull_request_target; both the run and verify jobs carry the same-repository guard head.repo.full_name == github.repository (never head.repo.fork == false); issue-check runs with --require-trusted-config; receipt-verify's and receipt-reuse's receipt-check pass all eight expectation flags; and the Sigstore identity is pinned to this workflow on refs/heads/main. The reuse-enabled consumer example (#255) triggers only on pull_request_target and repository_dispatch (types [nexus-core-precheck]); its reuse, run and verify jobs carry exact conditions whose pull-request arm includes the same-repository guard and whose dispatch arm requires the default-branch ref, and receipt-verify is skipped only when the reuse job succeeded with reused == 'true'. Negative controls feed mutated workflow/action text to the same checkers and expect failure.",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "docs/GITHUB_REPOSITORY_CHECK.md#Why fork pull requests are excluded",
            ".github/workflows/nexus-core-issue-completion.yml",
            ".github/actions/issue-gate/action.yml",
            ".github/actions/receipt-verify/action.yml",
            ".github/actions/receipt-reuse/action.yml",
            "docs/examples/nexus-core-issue-completion.consumer.yml",
        ),
        (
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_pr_gate_workflow_trigger_fork_guard_and_identity",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_consumer_example_trigger_fork_guard_conditions_and_identity",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_issue_gate_runs_issue_check_with_trusted_config",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_receipt_verify_passes_all_eight_expectations",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_negative_control_removed_fork_guard_is_detected",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_negative_control_trigger_and_identity_mutations_are_detected",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_negative_control_missing_expectations_are_detected",
        ),
    ),
    _c(
        "NCG-056",
        "PR gate token exposure matches SECURITY.md",
        "compatibility",
        "normal",
        "SECURITY.md 'PR gate' names every composite step that sees the GitHub token: in issue-gate the plain-Git candidate fetch (FETCH_TOKEN via an env-scoped http.extraheader, never written to .git/config) and issue-init/issue-check (GITHUB_TOKEN); in receipt-verify the artifact resolution and head-tree fetch; in receipt-reuse the prior-run lookup, the bare-repository lineage fetch, the Issue-state read and the artifact download. The set of token-referencing steps in each action equals that documented set, so drift fails.",
        (
            "SECURITY.md#Threat Model & Trust Boundaries",
            "docs/GITHUB_REPOSITORY_CHECK.md#Candidate acquisition",
            ".github/actions/issue-gate/action.yml",
        ),
        (
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_token_exposure_matches_security_documentation",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_candidate_fetch_token_is_env_scoped_and_never_persisted",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_security_md_pr_gate_row_documents_token_steps",
            "tests/architecture/test_pr_gate_workflow_invariants.py::test_negative_control_token_drift_is_detected",
        ),
    ),
)


# NCGF-001 (Nexus Verify did not authenticate receipts) was resolved by #231 and
# NCG-052 is now covered.
FINDINGS = {}
