# pyright: strict
"""Display-only one-screen summary of a Core receipt (#273).

Pure rendering. Nothing here decides or changes a verdict: the receipt has
already been produced (and, in receipt-verify, checked) by other code. Every
accessor tolerates missing or odd fields and renders an em dash instead.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

DASH = "—"
MAX_VALUE = 200
MAX_PATHS = 20
FOOTER = "*Display only — Core is an evidence notary; this summary does not change enforcement.*"
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")


def _get(obj: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(obj, Mapping):
            return None
        obj = obj.get(key)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return obj  # pyright: ignore[reportUnknownVariableType]


def _clean(value: Any, limit: int = MAX_VALUE) -> str:
    if value is None or value == "":
        return DASH
    text = _CONTROL.sub(" ", str(value)).strip()
    if not text:
        return DASH
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


_MD_SPECIAL = "\\`*_{}[]()#+!|<>~&"


def _md(value: Any, limit: int = MAX_VALUE) -> str:
    text = _clean(value, limit)
    text = "".join("\\" + ch if ch in _MD_SPECIAL and ch != "&" else ch for ch in text)
    # Entities are inserted last so they are never re-escaped.
    text = text.replace("&", "&#38;")
    # Neutralise autolinks (URLs, www., email) without changing visible text.
    return text.replace(":", "&#58;").replace("@", "@<!-- -->").replace("www.", "www&#46;")


def _short(value: Any, n: int = 12) -> str:
    if not isinstance(value, str) or not value:
        return DASH
    text = value.split(":", 1)[1] if value.startswith(("sha256:", "git-commit:")) else value
    return _md(text[:n])


def _seq(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(value)  # pyright: ignore[reportUnknownArgumentType]
    return []


def _entries(receipt: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        e
        for e in _seq(_get(receipt, "core_response", "verification", "coverage", "entries"))
        if isinstance(e, Mapping)
    ]  # pyright: ignore[reportUnknownVariableType]


def _is_covered(entry: Mapping[str, Any]) -> bool:
    category = entry.get("category")
    if isinstance(category, str):
        return category == "COVERED"
    return entry.get("observed_status") == "PASS"


def _status(receipt: Mapping[str, Any]) -> str:
    return (
        _get(receipt, "outcome", "status") or _get(receipt, "issue_verification", "status") or DASH
    )


def _generation(receipt: Mapping[str, Any]) -> Any:
    for path in (
        ("core_response", "verification", "coverage", "universe_generation"),
        ("evidence_universe", "universe_generation"),
    ):
        value = _get(receipt, *path)
        if value is not None:
            return value
    return None


def _joined(value: Any) -> str:
    items = [_clean(v, 80) for v in _seq(value)]
    return ", ".join(items)


GATE_VERDICTS = ("verified", "rejected", "unverified")


def _verdict_label(verdict: str) -> str:
    if verdict == "verified":
        return "GATE VERIFIED"
    if verdict == "rejected":
        return "GATE REJECTED"
    return "UNVERIFIED (producer side; receipt-verify decides)"


def render_markdown(
    receipt: Mapping[str, Any],
    receipt_sha256: str | None = None,
    gate_verdict: str = "unverified",
) -> str:
    gen = _generation(receipt)
    repo = _get(receipt, "issue_verification", "github_repository")
    number = _get(receipt, "issue_verification", "issue_number")
    issue = f"{_md(repo)}#{_md(number)}" if repo and number is not None else DASH
    reasons = _joined(_get(receipt, "outcome", "reason_codes"))
    universe = " ".join(
        [
            _md(_get(receipt, "issue_verification", "evidence_universe_source")),
            f"g{_md(gen)}" if gen is not None else DASH,
            _short(_get(receipt, "core_response", "verification", "coverage", "universe_identity")),
        ]
    )
    rows: list[tuple[str, str]] = [
        ("gate verdict", _verdict_label(gate_verdict)),
        ("receipt claims", _md(_status(receipt))),
        ("reason codes", _md(reasons) if reasons else "none"),
        ("claim ceiling", _md(_get(receipt, "issue_verification", "claim_ceiling"))),
        ("issue", issue),
        ("evidence universe (source, generation, identity)", universe),
        ("subject head", _short(_get(receipt, "subject_head"))),
        ("config commit", _short(_get(receipt, "config_source", "commit"), 12)),
        ("core commit", _short(_get(receipt, "core_response", "core_identity", "git_commit"))),
        ("receipt hash", _short(_get(receipt, "receipt_hash"))),
    ]
    if receipt_sha256:
        rows.append(("receipt file sha256", _short(receipt_sha256)))
    out = [
        f"### Nexus Core receipt: {_verdict_label(gate_verdict)} (receipt claims {_md(_status(receipt))})",
        "",
        "| field | value |",
        "| --- | --- |",
    ]
    out += [f"| {k} | {v} |" for k, v in rows]
    out += [
        "",
        "| subject | kind | observed | requirement | applicability |",
        "| --- | --- | --- | --- | --- |",
    ]
    entries = _entries(receipt)
    if not entries:
        out.append(f"| {DASH} | {DASH} | {DASH} | {DASH} | {DASH} |")
    for e in entries:
        out.append(
            "| {} | {} | {} | {} | {} |".format(
                _md(e.get("logical_subject_id")),
                _md(e.get("evidence_kind")),
                _md(e.get("observed_status")),
                _md(e.get("requirement_mode")),
                _md(e.get("applicability")),
            )
        )
    unexpected = _joined(
        _get(receipt, "core_response", "verification", "coverage", "unexpected_subjects")
    )
    out += ["", f"Unexpected subjects: {_md(unexpected) if unexpected else 'none'}"]
    paths = [p for p in _seq(_get(receipt, "inputs", "request", "change_set", "paths"))]
    deleted = _seq(_get(receipt, "inputs", "request", "change_set", "deleted_paths"))
    protected = {
        str(p)
        for p in _seq(_get(receipt, "inputs", "config", "deletion_exception", "protected_paths"))
    }
    touched = [p for p in paths if str(p) in protected]
    listed = ", ".join(_md(p, 120) for p in paths[:MAX_PATHS])
    more = f" (+{len(paths) - MAX_PATHS} more)" if len(paths) > MAX_PATHS else ""
    out.append(f"Changed paths: {len(paths)}" + (f": {listed}{more}" if paths else ""))
    out.append(
        f"Deleted paths: {len(deleted)}"
        + (": " + ", ".join(_md(p, 120) for p in deleted[:MAX_PATHS]) if deleted else "")
    )
    out.append(
        "Protected paths touched: "
        + (", ".join(_md(p, 120) for p in touched[:MAX_PATHS]) if touched else "none")
    )
    adv = _get(receipt, "owner_signature_advisory")
    if isinstance(adv, Mapping):
        out.append(f"Owner signature advisory: {_md(_get(adv, 'reason_code'))}")
    out += ["", FOOTER, ""]
    return "\n".join(out)


def render_notice(receipt: Mapping[str, Any], gate_verdict: str = "unverified") -> str:
    entries = _entries(receipt)
    if entries:
        covered = sum(1 for e in entries if _is_covered(e))
        cover = f"{covered}/{len(entries)} subjects covered"
    else:
        cover = "no declared universe"
    gen = _generation(receipt)
    universe = " ".join(
        [
            _clean(_get(receipt, "issue_verification", "evidence_universe_source")),
            f"g{_clean(gen)}" if gen is not None else DASH,
        ]
    )
    parts = [
        _verdict_label(gate_verdict),
        f"receipt claims {_clean(_status(receipt))}",
        cover,
        f"universe {universe}",
        _clean(_get(receipt, "issue_verification", "claim_ceiling")),
    ]
    return " · ".join(parts)


def escape_workflow_message(message: str) -> str:
    """Escape a workflow-command message so it cannot start another command."""
    message = message.replace("::", " ")
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_notice_command(receipt: Mapping[str, Any], gate_verdict: str = "unverified") -> str:
    level = "warning" if gate_verdict == "rejected" else "notice"
    message = escape_workflow_message(render_notice(receipt, gate_verdict))
    return f"::{level} title=Nexus Core receipt::{message}"
