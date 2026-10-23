# pyright: strict
"""Copy-paste remediation lines for Core gate failures (diagnostics only, #243/#244).

Every function here is pure text rendering plus an optional job-summary append.
Nothing in this module decides a verdict: the remediation codes are labels for
"what to fix", emitted next to the unchanged fail-closed reason codes.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any, TextIO

EVIDENCE_MARKER_PREFIX = "<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: "
EVIDENCE_MARKER_SUFFIX = " -->"

ISSUE_MISSING_EVIDENCE_UNIVERSE = "ISSUE_MISSING_EVIDENCE_UNIVERSE"
ISSUE_EVIDENCE_UNIVERSE_STALE = "ISSUE_EVIDENCE_UNIVERSE_STALE"
ISSUE_EVIDENCE_UNIVERSE_MALFORMED = "ISSUE_EVIDENCE_UNIVERSE_BINDING_MALFORMED"
BASE_REF_NOT_ANCESTOR = "BASE_REF_NOT_ANCESTOR"

PR_MISSING_CORE_ISSUE_BINDING = "PR_MISSING_CORE_ISSUE_BINDING"
RECEIPT_ISSUE_BINDING_MISMATCH = "RECEIPT_ISSUE_BINDING_MISMATCH"
REPOSITORY_VERIFICATION_NOT_VERIFIED = "REPOSITORY_VERIFICATION_NOT_VERIFIED"
RECEIPT_STATUS = "RECEIPT_STATUS"

SUMMARY_HEADING = "### Nexus Core gate: how to fix"


# Diagnostic only (#272). Keep in sync with the inline copy in
# .github/actions/issue-gate/action.yml (a test asserts they agree).
_CORE_ISSUE_KEYWORD_REF_RE = (
    r"(?<![\w/])(?:refs?|closes?|closed|fix(?:es|ed)?|resolves?|resolved)"
    r"[ \t]*(?::[ \t]*)?#([1-9][0-9]{0,9})(?!\w)"
)
# Text GitHub does not render as a reference: fenced code blocks (line scanner below)
# and HTML comments (an unterminated comment or fence runs to the end of the body).
# Inline code spans are deliberately not stripped: a hint from one is acceptable.
_HIDDEN_TEXT_RES = (r"<!--[\s\S]*?(?:-->|\Z)",)
_SUGGEST_MAX_BODY_CHARS = 65536


def _strip_fenced_code(text: str) -> str:
    """Drop fenced code blocks with a linear line scan (no backtracking regex)."""

    out: list[str] = []
    fence: tuple[str, int] | None = None
    for line in text.split("\n"):
        stripped = line.lstrip(" \t")
        char = stripped[:1]
        if char in ("\x60", "~"):
            run = len(stripped) - len(stripped.lstrip(char))
            if fence is None:
                if run >= 3:
                    fence = (char, run)
                    continue
            elif char == fence[0] and run >= fence[1] and not stripped[run:].strip(" \t"):
                fence = None
                continue
        if fence is None:
            out.append(line)
    return "\n".join(out)


def suggest_core_issue_marker(body: str) -> int | None:
    """Return N when the body names exactly one same-repo Issue by keyword.

    Diagnostic only: the caller may print the marker with N filled in, but the
    binding itself is never inferred. Only digits are ever returned.
    """

    text = _strip_fenced_code(body[:_SUGGEST_MAX_BODY_CHARS])
    for pattern in _HIDDEN_TEXT_RES:
        text = re.sub(pattern, "", text, flags=re.MULTILINE)
    found = {int(n) for n in re.findall(_CORE_ISSUE_KEYWORD_REF_RE, text, flags=re.IGNORECASE)}
    return next(iter(found)) if len(found) == 1 else None


def evidence_marker_line(config_hash: str) -> str:
    """The exact Issue-body line binding the current verification contract."""

    return f"{EVIDENCE_MARKER_PREFIX}{config_hash}{EVIDENCE_MARKER_SUFFIX}"


def missing_evidence_universe(issue_number: int, config_hash: str) -> str:
    return (
        f"{ISSUE_MISSING_EVIDENCE_UNIVERSE}: add this line to the body of Issue "
        f"#{issue_number}, then re-run the gate: {evidence_marker_line(config_hash)}"
    )


def stale_evidence_universe(issue_number: int | None, config_hash: str) -> str:
    target = f"Issue #{issue_number}" if issue_number is not None else "the Issue"
    return (
        f"{ISSUE_EVIDENCE_UNIVERSE_STALE}: replace the NEXUS_CORE_EVIDENCE_UNIVERSE line "
        f"in the body of {target} with this line, then re-run the gate: "
        f"{evidence_marker_line(config_hash)}"
    )


def stale_trusted_config_universe(issue_number: int | None) -> str:
    target = f"Issue #{issue_number}" if issue_number is not None else "the Issue"
    return (
        f"{ISSUE_EVIDENCE_UNIVERSE_STALE}: the verification contract changed since {target} was "
        "bound in trusted-config mode (no Issue marker is used); re-run "
        "'nexus-certify issue-init --force --evidence-universe trusted-config', "
        "then re-run the gate"
    )


def malformed_evidence_universe(issue_number: int, config_hash: str) -> str:
    return (
        f"{ISSUE_EVIDENCE_UNIVERSE_MALFORMED}: keep exactly one NEXUS_CORE_EVIDENCE_UNIVERSE "
        f"line in the body of Issue #{issue_number}, exactly: {evidence_marker_line(config_hash)}"
    )


def _rebase_command(base_ref: str) -> str:
    for prefix in ("refs/remotes/origin/", "origin/"):
        if base_ref.startswith(prefix):
            return f"git fetch origin && git rebase origin/{base_ref[len(prefix) :]}"
    return f"git rebase {base_ref}"


def base_ref_not_ancestor(base_ref: str, base_sha: str) -> str:
    return (
        f"{BASE_REF_NOT_ANCESTOR}: HEAD does not descend from {base_ref} at {base_sha}; "
        f"rebase onto {base_sha} ({_rebase_command(base_ref)}) and push again"
    )


def material_transition_remediations(receipt: Mapping[str, Any]) -> list[str]:
    """Suggest Issue markers only for explicit material git-commit mismatches."""

    lines: list[str] = []
    for value in _as_sequence(receipt.get("evidence_artifacts")):
        artifact = _as_mapping(value)
        if artifact.get("producer_kind") != "material":
            continue
        material_id = artifact.get("producer_id")
        # the marker's <from> must be the committed (trusted) pin, not an effective expectation that an
        # existing transition already moved (MATERIAL_TRANSITION_STALE otherwise)
        expected = artifact.get("trusted_expected_identity") or artifact.get("expected_identity")
        observed = artifact.get("observed_identity")
        # an already-applied transition makes the effective expectation equal the observed pin: no
        # mismatch, so nothing to suggest (the marker is already in the Issue)
        effective = artifact.get("expected_identity")
        if (
            not isinstance(material_id, str)
            or re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", material_id) is None
            or not isinstance(expected, str)
            or not isinstance(observed, str)
            or expected == observed
            or observed == effective
            or any(
                re.fullmatch(r"git-commit:[0-9a-fA-F]{1,64}", v) is None
                for v in (expected, observed)
            )
        ):
            continue
        line = (
            f"Material {material_id} expected {expected}, observed {observed}; "
            "if this pin change is intended, add (or replace the material's existing) line in the tracking Issue body, "
            "then re-run the gate: "
            f"<!-- NEXUS_CORE_MATERIAL_TRANSITION: {material_id} {expected} -> {observed} -->"
        )
        if line not in lines:
            lines.append(line)
    return lines


def receipt_remediations(payload: Any, *, expect_issue: int | None) -> list[str]:
    """Remediation lines for a receipt that failed issue/status expectations (pure)."""

    if not isinstance(payload, Mapping):
        return []
    receipt = _as_mapping(payload)
    lines: list[str] = []
    verdict = _as_mapping(receipt.get("issue_verification"))
    inputs = _as_mapping(receipt.get("inputs"))
    context = _as_mapping(inputs.get("requirements_context"))
    bound_number = context.get("issue_number")
    if expect_issue is not None and not isinstance(bound_number, int):
        lines.append(
            f"{PR_MISSING_CORE_ISSUE_BINDING}: the receipt is not bound to any Issue; add "
            f"<!-- NEXUS_CORE_ISSUE: {expect_issue} --> to the PR body, then re-run the gate"
        )
    elif expect_issue is not None and bound_number != expect_issue:
        lines.append(
            f"{RECEIPT_ISSUE_BINDING_MISMATCH}: the receipt is bound to Issue #{bound_number}, "
            f"not #{expect_issue}; make the PR body name one Issue, then re-run the gate"
        )
    number = bound_number if isinstance(bound_number, int) else expect_issue
    target = f"Issue #{number}" if number is not None else "the Issue"
    universe = verdict.get("evidence_universe")
    if universe == "UNBOUND":
        lines.append(
            f"{ISSUE_MISSING_EVIDENCE_UNIVERSE}: {target} has no NEXUS_CORE_EVIDENCE_UNIVERSE "
            "line; copy the line printed in the issue-gate job summary (or by "
            f"'nexus-certify markers --issue {number if number is not None else 'N'} --check') "
            "into the Issue body, then re-run the gate"
        )
    elif universe == "STALE":
        lines.append(
            f"{ISSUE_EVIDENCE_UNIVERSE_STALE}: the NEXUS_CORE_EVIDENCE_UNIVERSE line in {target} "
            "does not match the current config; replace it with the line printed in the "
            "issue-gate job summary, then re-run the gate"
        )
    outcome = _as_mapping(receipt.get("outcome"))
    status = outcome.get("status")
    if status is not None and status != "VERIFIED":
        reasons = outcome.get("reason_codes")
        reason_text = ", ".join(str(item) for item in _as_sequence(reasons)) if reasons else "none"
        lines.append(
            f"{REPOSITORY_VERIFICATION_NOT_VERIFIED}: repository verification is {status} "
            f"(reasons: {reason_text}); fix the cause shown in the issue-gate "
            "'Diagnose Core verifier failure' step, then re-run the gate"
        )
    lines.extend(material_transition_remediations(receipt))
    return lines


def receipt_status_line(receipt: Any) -> str | None:
    """One line naming the receipt's own outcome, printed before any expectation mismatch.

    Returns None for a VERIFIED receipt (passing output stays unchanged) and when the
    receipt carries no readable outcome status.
    """

    outcome = _as_mapping(_as_mapping(receipt).get("outcome"))
    status = outcome.get("status")
    if not isinstance(status, str) or not status or status == "VERIFIED":
        return None
    reasons = outcome.get("reason_codes")
    reason_text = ", ".join(str(item) for item in _as_sequence(reasons)) if reasons else "none"
    return (
        f"{RECEIPT_STATUS}: {status} (reasons: {reason_text}); this is the gate's own "
        "verdict, fix its reasons first; the mismatch lines that follow are consequences of it"
    )


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}  # pyright: ignore[reportUnknownVariableType]


def _as_sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, (list, tuple)):
        return value  # pyright: ignore[reportUnknownVariableType]
    return [value]


def emit(lines: Sequence[str], *, stream: TextIO | None = None, summary: bool = True) -> None:
    """Print each line, and append them to $GITHUB_STEP_SUMMARY when it is set.

    The summary renders each line inside a fenced block so the HTML-comment
    markers stay visible and copy-pasteable instead of being hidden by Markdown.
    """

    if not lines:
        return
    out = stream if stream is not None else sys.stdout
    for line in lines:
        print(line, file=out)
    target = os.environ.get("GITHUB_STEP_SUMMARY") if summary else None
    if not target:
        return
    blocks = "".join(f"```text\n{line}\n```\n" for line in lines)
    try:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(f"{SUMMARY_HEADING}\n\n{blocks}\n")
    except OSError:
        print("warning: could not write GITHUB_STEP_SUMMARY", file=sys.stderr)
