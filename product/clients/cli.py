# pyright: strict, reportUnnecessaryIsInstance=false, reportUnnecessaryComparison=false
"""Nexus Core V1 nexus-certify thin CLI.

Canonical CLI transport for Core V1 certification runtime (TG-6).
Does not construct trust decisions, dispositions, or receipts locally.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

from product.clients import gate_diagnostics, issue_golden_path
from product.clients.issue_golden_path import (
    ISSUE_EVIDENCE_MARKER_PREFIX,
    ISSUE_EVIDENCE_MARKER_SUFFIX,
    check_issue,
    init_issue_binding,
)
from product.clients.local_golden_path import (
    LocalCheckError,
    _load_effective_config,  # pyright: ignore[reportPrivateUsage]
    _normalize_material_transitions,  # pyright: ignore[reportPrivateUsage]
    check_repository,
    doctor_repository,
    evaluate_receipt_expectations,
    init_repository,
    validate_verification_receipt,
)
from product.protocol.generic_verification import canonical_hash

DEFAULT_URL = "http://127.0.0.1:8767"
HEADER_READ_TIMEOUT_SECONDS = 10.0
CERTIFICATION_WAIT_TIMEOUT_SECONDS = 330.0
POLL_INTERVAL_SECONDS = 0.5


class CertifyCLIError(Exception):
    def __init__(self, message: str, exit_code: int):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


class CertifyArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        sys.stderr.write(f"usage error: {message}\n")
        sys.exit(2)


_RUNTIME_HINT = "this command requires: pip install 'nexus-certify[runtime]'"


def _require_runtime() -> None:
    """Fail with exit 2 and an install hint when the optional runtime extra is absent."""
    try:
        import aiohttp  # noqa: F401  # pyright: ignore[reportUnusedImport]
    except ModuleNotFoundError as exc:
        if exc.name is not None and exc.name.split(".")[0] != "aiohttp":
            raise
        raise CertifyCLIError(_RUNTIME_HINT, exit_code=2) from exc


def _make_http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    timeout: float = HEADER_READ_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any]]:
    """Perform HTTP request returning (status_code, response_dict)."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.getcode()
            data = resp.read().decode("utf-8")
            parsed: dict[str, Any]
            try:
                parsed = json.loads(data) if data else {}
            except json.JSONDecodeError:
                parsed = {"raw": data}
            return status_code, parsed
    except urllib.error.HTTPError as e:
        status_code = e.code
        err_body = e.read().decode("utf-8", errors="ignore")
        parsed_err: dict[str, Any]
        try:
            parsed_err = json.loads(err_body) if err_body else {}
        except json.JSONDecodeError:
            parsed_err = {"error": err_body}
        return status_code, parsed_err
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CertifyCLIError(f"transport error: {e}", exit_code=7) from e


def _map_http_status_to_exit_code(status_code: int, payload: dict[str, Any]) -> int:
    if status_code in (401, 403):
        return 3
    if status_code == 404:
        return 4
    if status_code == 409:
        return 5
    if status_code in (400, 413, 415):
        return 2
    if status_code >= 500:
        return 7
    if 200 <= status_code < 300:
        return 0
    return 1


def _exit_code_for_terminal_state(state: Any) -> int:
    """FAILED -> 1 and UNVERIFIABLE -> 6, matching github_action.exit_code_for_state."""
    if state == "FAILED":
        return 1
    if state == "UNVERIFIABLE":
        return 6
    return 0


def _get_token(token_file: str | None) -> str:
    from product.runtime.auth import AuthSecurityError, read_bearer_token

    try:
        return read_bearer_token(token_file)
    except (AuthSecurityError, ValueError, OSError) as exc:
        raise CertifyCLIError(f"authentication error: {exc}", exit_code=3) from exc


def cmd_submit(args: argparse.Namespace) -> int:
    _require_runtime()
    from product.runtime.schemas import validate_certification_request

    req_path = Path(args.request)
    if not req_path.is_file():
        raise CertifyCLIError(f"request file not found: {args.request}", exit_code=2)
    try:
        with open(req_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise CertifyCLIError(f"malformed request file: {e}", exit_code=2) from e

    errs = validate_certification_request(payload)
    if errs:
        raise CertifyCLIError(f"invalid certification request: {'; '.join(errs)}", exit_code=2)

    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body_bytes = json.dumps(payload).encode("utf-8")

    status_code, resp = _make_http_request(
        method="POST",
        url=f"{service_url}/v1/certifications",
        headers=headers,
        body=body_bytes,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )

    if status_code not in (200, 202):
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(f"submit failed with HTTP {status_code}: {resp.get('message', resp)}\n")
        return err_code

    req_id = resp.get("request_id")
    state = resp.get("state")

    # If already terminal (e.g. 200 replayed or terminal)
    if status_code == 200 or state in ("COMPLETED", "FAILED", "UNVERIFIABLE"):
        print(json.dumps(resp, indent=2))
        return _exit_code_for_terminal_state(state)

    if not req_id:
        raise CertifyCLIError("missing request_id in submit response", exit_code=7)

    deadline = time.time() + CERTIFICATION_WAIT_TIMEOUT_SECONDS
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
        st_code, st_resp = _make_http_request(
            method="GET",
            url=f"{service_url}/v1/certifications/{req_id}",
            headers=headers,
            timeout=HEADER_READ_TIMEOUT_SECONDS,
        )
        if st_code != 200:
            err_code = _map_http_status_to_exit_code(st_code, st_resp)
            sys.stderr.write(
                f"polling status failed with HTTP {st_code}: {st_resp.get('message', st_resp)}\n"
            )
            return err_code

        cur_state = st_resp.get("state")
        if cur_state in ("COMPLETED", "FAILED", "UNVERIFIABLE"):
            print(json.dumps(st_resp, indent=2))
            return _exit_code_for_terminal_state(cur_state)

    sys.stderr.write(f"certification timed out after {CERTIFICATION_WAIT_TIMEOUT_SECONDS}s\n")
    return 7


def cmd_status(args: argparse.Namespace) -> int:
    _require_runtime()
    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
    }
    status_code, resp = _make_http_request(
        method="GET",
        url=f"{service_url}/v1/certifications/{args.request_id}",
        headers=headers,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )
    if status_code != 200:
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(
            f"status query failed with HTTP {status_code}: {resp.get('message', resp)}\n"
        )
        return err_code

    print(json.dumps(resp, indent=2))
    return _exit_code_for_terminal_state(resp.get("state"))


def cmd_receipt(args: argparse.Namespace) -> int:
    _require_runtime()
    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
    }
    status_code, resp = _make_http_request(
        method="GET",
        url=f"{service_url}/v1/certifications/{args.request_id}/receipt",
        headers=headers,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )
    if status_code != 200:
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(
            f"receipt query failed with HTTP {status_code}: {resp.get('message', resp)}\n"
        )
        return err_code

    print(json.dumps(resp, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    _require_runtime()
    from product.runtime.schemas import validate_receipt_verify_request

    receipt_path = Path(args.receipt)
    if not receipt_path.is_file():
        raise CertifyCLIError(f"receipt file not found: {args.receipt}", exit_code=2)
    try:
        with open(receipt_path, "r", encoding="utf-8") as f:
            receipt_payload = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise CertifyCLIError(f"malformed receipt file: {e}", exit_code=2) from e

    verify_payload = {
        "receipt": receipt_payload,
        "requested_scope": getattr(args, "scope", "AUTO") or "AUTO",
        "original_inputs": None,
    }
    errs = validate_receipt_verify_request(verify_payload)
    if errs:
        raise CertifyCLIError(f"invalid verify request: {'; '.join(errs)}", exit_code=2)

    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body_bytes = json.dumps(verify_payload).encode("utf-8")

    status_code, resp = _make_http_request(
        method="POST",
        url=f"{service_url}/v1/receipts/verify",
        headers=headers,
        body=body_bytes,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )

    if status_code != 200:
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(
            f"receipt verify failed with HTTP {status_code}: {resp.get('message', resp)}\n"
        )
        return err_code

    print(json.dumps(resp, indent=2))
    if resp.get("status") == "UNVERIFIABLE":
        return 6
    return 0


def cmd_acquire(args: argparse.Namespace) -> int:
    """Machine-readable candidate acquisition command.

    Reads exactly one JSON request document from a file path or stdin,
    delegates to the runtime facade, emits exactly one JSON result on stdout,
    and returns a non-zero exit code on any error.
    """
    _require_runtime()
    from product.runtime.candidate_acquisition import (
        make_candidate_acquisition_input_error,
        run_candidate_acquisition,
    )


    def emit_input_error(reason_code: str, detail: str) -> int:
        result = make_candidate_acquisition_input_error(reason_code, detail)
        print(json.dumps(result, indent=2, sort_keys=True))
        sys.stderr.write(f"acquire: {reason_code}: {detail}\n")
        return 2

    request_source = getattr(args, "request", None)
    try:
        if request_source is None or request_source == "-":
            raw = sys.stdin.read()
        else:
            req_path = Path(request_source)
            if not req_path.is_file():
                return emit_input_error(
                    "REQUEST_FILE_NOT_FOUND",
                    f"request file not found: {request_source}",
                )
            raw = req_path.read_text(encoding="utf-8")
    except OSError as exc:
        return emit_input_error("REQUEST_READ_ERROR", f"cannot read request: {exc}")

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return emit_input_error(
            "JSON_PARSE_ERROR",
            f"malformed JSON request at line {exc.lineno} column {exc.colno}",
        )

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=True)
    print(json.dumps(result, indent=2, sort_keys=True))
    return exit_code


def cmd_init(args: argparse.Namespace) -> int:
    path = init_repository(
        args.repo,
        base_ref=args.base_ref,
        allowed_patterns=tuple(args.allow or ["**"]),
        deletion_policy="ALLOW" if args.allow_deletions else "FORBID",
        verifier_command=tuple(args.verifier),
        timeout_seconds=args.timeout,
        force=args.force,
    )
    print(f"initialized: {path}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    result = doctor_repository(args.repo)
    verdict = "OK" if result["healthy"] else "FAILED"
    print(f"doctor: {verdict}")
    for name, status in result["checks"].items():
        print(f"  {name}: {status}")
    if result["reason_codes"]:
        print("  reasons: " + ", ".join(result["reason_codes"]))
    return 0 if result["healthy"] else 2


def _require_trusted_config(args: argparse.Namespace) -> bool:
    return bool(
        getattr(args, "require_trusted_config", False)
        or os.environ.get("NEXUS_CERTIFY_REQUIRE_TRUSTED_CONFIG") == "1"
    )


def _expect_config_commit(args: argparse.Namespace) -> str | None:
    """Pinned trusted-config commit: the flag wins; a malformed env value fails closed."""

    flag = getattr(args, "expect_config_commit", None)
    if flag is not None:
        return flag
    env = os.environ.get("NEXUS_CERTIFY_EXPECT_CONFIG_COMMIT")
    if env is None:
        return None
    if re.fullmatch(r"[0-9a-f]{40}", env) is None:
        raise CertifyCLIError(
            "usage error: NEXUS_CERTIFY_EXPECT_CONFIG_COMMIT: expected 40 lowercase hex characters",
            exit_code=2,
        )
    return env


def _print_config_source(result: dict[str, Any], pin: str | None = None) -> None:
    source: dict[str, Any] = result.get("config_source") or {}
    if source.get("kind") == "base-ref":
        label = f"{source['ref']}@{source['commit'][:12]}"
        if pin is not None and source.get("commit") == pin:
            print(f"config: trusted ({label}, pinned)")
        else:
            print(f"config: base-ref, unpinned ({label})")
    else:
        print(f"config: untrusted (not committed on {result.get('base_ref', 'base ref')})")


def cmd_check(args: argparse.Namespace) -> int:
    pin = _expect_config_commit(args)
    result = check_repository(
        args.repo,
        require_trusted_config=_require_trusted_config(args),
        expect_config_commit=pin,
    )
    print(f"verification: {result['status']} (not CERTIFIED)")
    _print_config_source(result, pin)
    if result["reason_codes"]:
        print("reasons: " + ", ".join(result["reason_codes"]))
    print(f"receipt: {result['receipt_path']}")
    return 0 if result["status"] == "VERIFIED" else 1


def _hex40(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise argparse.ArgumentTypeError("expected 40 lowercase hex characters")
    return value


def cmd_receipt_check(args: argparse.Namespace) -> int:
    """Project canonical local receipt validation as machine-readable JSON."""
    result = validate_verification_receipt(args.receipt, repo=args.repo)
    wanted = {
        "expect_status": args.expect_status,
        "expect_subject_head": args.expect_subject_head,
        "expect_target_tree": args.expect_target_tree,
        "expect_config_commit": args.expect_config_commit,
        "expect_issue": args.expect_issue,
        "expect_github_repository": args.expect_github_repository,
        "require_clean_subject": args.require_clean_subject,
        "require_trusted_config": args.require_trusted_config,
    }
    expectations_failed = False
    if any(value not in (None, False) for value in wanted.values()):
        payload: Any
        try:
            payload = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        # The receipt's own verdict comes first: every mismatch line below is a
        # consequence of it when the gate itself did not reach VERIFIED.
        status_line = gate_diagnostics.receipt_status_line(payload)
        if status_line:
            print(status_line, file=sys.stderr)
        evaluation = evaluate_receipt_expectations(payload, **wanted)
        result["expectations"] = evaluation["expectations"]
        result["reason_codes"] = sorted(
            {*result.get("reason_codes", []), *evaluation["reason_codes"]}
        )
        if not evaluation["passed"]:
            result["valid"] = False
            expectations_failed = True
        if result["reason_codes"]:
            print("reasons: " + ", ".join(result["reason_codes"]), file=sys.stderr)
        if expectations_failed:
            # stdout stays one JSON document; remediation goes to stderr and the job summary.
            gate_diagnostics.emit(
                gate_diagnostics.receipt_remediations(payload, expect_issue=args.expect_issue),
                stream=sys.stderr,
            )
    print(json.dumps(result, sort_keys=True))
    if result.get("valid") is True:
        return 0
    return 2 if expectations_failed else 1


def cmd_evidence_check(args: argparse.Namespace) -> int:
    """Evaluate one supplied exact PR subject through the canonical Core reducer."""
    _require_runtime()
    import base64

    from product.clients.nexus_verify import evaluate_code_change_evidence_subject
    from product.clients.receipt_authentication import (
        SigstoreReceiptAuthenticator,
        signer_policy_for_identity,
    )

    try:
        receipt_bytes = Path(args.receipt).read_bytes()
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertifyCLIError(f"malformed receipt file: {exc}", exit_code=2) from exc
    # The bundle CI uploads next to the receipt; without it the result is
    # UNVERIFIABLE / RECEIPT_NOT_AUTHENTICATED (#231).
    bundle_path = args.sigstore_bundle
    if bundle_path is None:
        default_bundle = Path(f"{args.receipt}.sigstore.json")
        bundle_path = str(default_bundle) if default_bundle.is_file() else None
    receipt_signature: dict[str, Any] | None = None
    if bundle_path is not None:
        try:
            bundle: Any = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CertifyCLIError(f"malformed Sigstore bundle file: {exc}", exit_code=2) from exc
        if not isinstance(bundle, dict):
            raise CertifyCLIError("malformed Sigstore bundle file: not an object", exit_code=2)
        receipt_signature = {
            "receipt_base64": base64.b64encode(receipt_bytes).decode("ascii"),
            "sigstore_bundle": bundle,
        }
    try:
        signer_policy = (
            signer_policy_for_identity(args.signer_identity) if args.signer_identity else None
        )
    except ValueError as exc:
        raise CertifyCLIError(str(exc), exit_code=2) from exc
    subject = {
        "repository_owner": args.repository_owner,
        "repository_name": args.repository_name,
        "pr_number": args.pr_number,
        "current_base_sha": args.base_sha,
        "current_head_sha": args.head_sha,
        "current_base_tree": args.base_tree,
        "current_head_tree": args.head_tree,
        "changed_paths": args.changed_path,
        "deleted_paths": args.deleted_path,
    }
    try:
        result = evaluate_code_change_evidence_subject(
            subject,
            receipt,
            receipt_signature=receipt_signature,
            authenticator=SigstoreReceiptAuthenticator(offline=args.sigstore_offline),
            signer_policy=signer_policy,
        )
    except ValueError as exc:
        raise CertifyCLIError(str(exc), exit_code=2) from exc
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_issue_init(args: argparse.Namespace) -> int:
    path = init_issue_binding(
        args.repo,
        issue_number=args.issue,
        github_repo=args.github_repo,
        force=args.force,
        evidence_universe=args.evidence_universe,
    )
    print(f"issue binding initialized: {path}")
    binding: Any
    try:
        binding = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        binding = {}
    if binding.get("evidence_sufficiency") is None:
        print(
            "hint: the Issue has no NEXUS_CORE_EVIDENCE_UNIVERSE marker; run "
            "'nexus-certify markers' and paste the line into the Issue body, "
            "then re-run issue-init --force"
        )
        print(gate_diagnostics.missing_evidence_universe(args.issue, _expected_config_hash(args.repo)))
    return 0


def _material_transition_markers(config: dict[str, Any], specs: list[str]) -> list[str]:
    """Render one transition marker per ``<material_id>=<to_identity>`` flag (pure)."""

    trusted = {
        item["id"]: item["expected_identity"] for item in config.get("materials", [])
    }
    markers: list[str] = []
    transitions: list[dict[str, str]] = []
    for spec in specs:
        material_id, separator, to_identity = spec.partition("=")
        if material_id not in trusted and separator:
            raise LocalCheckError("MATERIAL_TRANSITION_UNKNOWN_MATERIAL", material_id)
        transitions.append(
            {
                "material_id": material_id,
                "from_identity": trusted.get(material_id, ""),
                "to_identity": to_identity if separator else "",
                "source": "issue-contract-marker",
            }
        )
    # Reuse the receipt-side shape validation (normalized text, unique ids, no no-ops).
    try:
        normalized = _normalize_material_transitions(transitions)
    except LocalCheckError as exc:
        raise LocalCheckError(
            exc.reason_code,
            f"{exc.detail}; expected --material-transition <material_id>=<to_identity>",
        ) from exc
    for item in normalized:
        markers.append(
            f"<!-- NEXUS_CORE_MATERIAL_TRANSITION: {item['material_id']} "
            f"{item['from_identity']} -> {item['to_identity']} -->"
        )
    return markers


def cmd_markers(args: argparse.Namespace) -> int:
    """Print the exact Issue-body and PR-body markers the gate expects."""
    config, source, _worktree = _load_effective_config(Path(args.repo))
    config_hash = canonical_hash(config)
    issue_marker = f"{ISSUE_EVIDENCE_MARKER_PREFIX}{config_hash}{ISSUE_EVIDENCE_MARKER_SUFFIX}"
    pr_marker = f"<!-- NEXUS_CORE_ISSUE: {args.issue} -->" if args.issue is not None else None
    transition_markers = _material_transition_markers(config, args.material_transition or [])
    if args.check and args.issue is None:
        raise CertifyCLIError("usage error: markers --check requires --issue N", exit_code=2)
    check = _check_issue_marker(args, config_hash) if args.check else None
    if source.get("kind") != "base-ref":
        print(
            f"warning: config is not committed on {config['base_ref']}; "
            "the hash will change once it is",
            file=sys.stderr,
        )
    if args.json:
        print(
            json.dumps(
                {
                    "config_hash": config_hash,
                    "config_source": source,
                    "issue_marker": issue_marker,
                    "pr_marker": pr_marker,
                    "material_transition_markers": transition_markers,
                    **({"issue_check": check} if check is not None else {}),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if check is None or check["status"] == "MATCH" else 1
    print(f"Issue body: {issue_marker}")
    for marker in transition_markers:
        print(f"Issue body: {marker}")
    if pr_marker is not None:
        print(f"PR body:    {pr_marker}")
    if check is None:
        return 0
    if check["status"] == "MATCH":
        print(f"check: Issue #{args.issue} evidence-universe marker matches ({config_hash})")
        return 0
    print(check["remediation"])
    return 1


def _check_issue_marker(args: argparse.Namespace, config_hash: str) -> dict[str, Any]:
    """Read-only: compare the live Issue body's marker with the expected one."""

    repo = issue_golden_path._repo_root(args.repo)  # pyright: ignore[reportPrivateUsage]
    github_repo = issue_golden_path._resolve_github_repo(  # pyright: ignore[reportPrivateUsage]
        repo, args.github_repo
    )
    raw = issue_golden_path._default_issue_reader(  # pyright: ignore[reportPrivateUsage]
        github_repo, args.issue
    )
    contract = issue_golden_path._issue_contract(  # pyright: ignore[reportPrivateUsage]
        github_repo, args.issue, raw
    )
    try:
        declared = issue_golden_path._issue_evidence_universe_marker(  # pyright: ignore[reportPrivateUsage]
            contract
        )
    except LocalCheckError:
        return {
            "status": "MALFORMED",
            "declared": None,
            "remediation": gate_diagnostics.malformed_evidence_universe(args.issue, config_hash),
        }
    if declared is None:
        return {
            "status": "MISSING",
            "declared": None,
            "remediation": gate_diagnostics.missing_evidence_universe(args.issue, config_hash),
        }
    if declared != config_hash:
        return {
            "status": "STALE",
            "declared": declared,
            "remediation": gate_diagnostics.stale_evidence_universe(args.issue, config_hash),
        }
    return {"status": "MATCH", "declared": declared, "remediation": None}


def cmd_issue_check(args: argparse.Namespace) -> int:
    pin = _expect_config_commit(args)
    result = check_issue(
        args.repo,
        issue_number=args.issue,
        require_trusted_config=_require_trusted_config(args),
        expect_config_commit=pin,
        evidence_universe=args.evidence_universe,
    )
    print(f"issue verification: {result['status']} (not RELEASED)")
    _print_config_source(result, pin)
    print(f"claim ceiling: {result['claim_ceiling']}")
    if result["reason_codes"]:
        print("reasons: " + ", ".join(result["reason_codes"]))
    print(f"receipt: {result['receipt_path']}")
    if result["status"] != "VERIFIED":
        gate_diagnostics.emit(_issue_check_remediations(args, result))
    return 0 if result["status"] == "VERIFIED" else 1


def cmd_pr_state(args: argparse.Namespace) -> int:
    from product.clients import pr_state

    action = pr_state.gate_preflight if args.mode == "gate" else pr_state.verify_skip
    record = action(args.github_repo, args.pr, args.expect_head)
    print(json.dumps(record, sort_keys=True))
    return 0


def _expected_config_hash(repo: str) -> str:
    config, _source, _worktree = _load_effective_config(Path(repo))
    return canonical_hash(config)


def _issue_check_remediations(args: argparse.Namespace, result: dict[str, Any]) -> list[str]:
    reasons: list[str] = list(result.get("reason_codes") or [])
    if result.get("issue_evidence_sufficiency_status") == "UNBOUND" and (
        result.get("repository_evidence_status") == "VERIFIED"
    ):
        return [
            gate_diagnostics.missing_evidence_universe(
                args.issue, _expected_config_hash(args.repo)
            )
        ]
    return [
        f"{gate_diagnostics.REPOSITORY_VERIFICATION_NOT_VERIFIED}: repository verification is "
        f"{result.get('repository_evidence_status')} (reasons: {', '.join(reasons) or 'none'}); "
        f"fix the cause recorded in receipt {result.get('receipt_path')}, then re-run the gate"
    ]


def cmd_handoff_init(args: argparse.Namespace) -> int:
    from product.clients.runtime_handoff import init_handoff

    services: list[dict[str, Any]] = []
    service_args: list[str] = args.service or []
    for service in service_args:
        if "=" in service:
            service_id, endpoint = service.split("=", 1)
            parsed = urllib.parse.urlparse(endpoint)
            try:
                port = parsed.port
            except ValueError as exc:
                raise LocalCheckError(
                    "INVALID_HANDOFF_CONFIG", f"invalid service endpoint port: {exc}"
                ) from exc
            services.append(
                {
                    "service_id": service_id.strip(),
                    "endpoint": endpoint.strip(),
                    "port": port,
                }
            )
        else:
            services.append({"service_id": service.strip(), "endpoint": service.strip()})
    path = init_handoff(
        args.repo,
        handoff_id=args.handoff_id,
        services=services,
        verifier_command=tuple(args.verifier),
        timeout_seconds=args.timeout,
        force=args.force,
    )
    print(f"handoff initialized: {path}")
    return 0


def cmd_handoff_check(args: argparse.Namespace) -> int:
    from product.clients.runtime_handoff import check_handoff

    result = check_handoff(args.repo)
    print(f"handoff verification: {result['status']} (not RELEASED)")
    print(f"claim ceiling: {result['claim_ceiling']}")
    if result["reason_codes"]:
        print("reasons: " + ", ".join(result["reason_codes"]))
    if result.get("receipt_path") is not None:
        print(f"receipt: {result['receipt_path']}")
    return 0 if result["status"] == "HANDOFF_READY" else 1


def cmd_handoff_status(args: argparse.Namespace) -> int:
    from product.clients.runtime_handoff import handoff_status

    result = handoff_status(args.repo)
    print(
        f"handoff status: {result['status']} "
        f"({'fresh' if result['fresh'] else 'not fresh'})"
    )
    print(f"claim ceiling: {result['claim_ceiling']}")
    if result["reason_codes"]:
        print("reasons: " + ", ".join(result["reason_codes"]))
    if result["receipt_path"] is not None:
        print(f"receipt: {result['receipt_path']}")
    return 0 if result["fresh"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = CertifyArgumentParser(
        prog="nexus-certify",
        description="Nexus Core V1 canonical certification CLI (transport-only)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # submit
    p_submit = subparsers.add_parser("submit", help="Submit certification request")
    p_submit.add_argument("--request", required=True, help="Path to request JSON file")
    p_submit.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_submit.add_argument("--token-file", default=None, help="Path to protected token file")

    # status
    p_status = subparsers.add_parser("status", help="Get certification status")
    p_status.add_argument("request_id", help="Request ID")
    p_status.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_status.add_argument("--token-file", default=None, help="Path to protected token file")

    # receipt
    p_receipt = subparsers.add_parser("receipt", help="Get certification receipt")
    p_receipt.add_argument("request_id", help="Request ID")
    p_receipt.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_receipt.add_argument("--token-file", default=None, help="Path to protected token file")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify receipt")
    p_verify.add_argument("--receipt", required=True, help="Path to receipt JSON file")
    p_verify.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_verify.add_argument("--token-file", default=None, help="Path to protected token file")
    p_verify.add_argument(
        "--scope",
        choices=["AUTO", "ENVELOPE_ONLY", "FULL"],
        default="AUTO",
        help="Requested verification scope (default: AUTO)",
    )

    # Local Golden Path. These commands acquire inputs and execute a verifier,
    # but the canonical generic adapter remains the sole factual verifier.
    p_init = subparsers.add_parser("init", help="Create local Golden Path config")
    p_init.add_argument("--repo", default=".", help="Git repository (default: current)")
    p_init.add_argument("--base-ref", default="main", help="Base Git ref (default: main)")
    p_init.add_argument(
        "--allow",
        action="append",
        default=None,
        metavar="GLOB",
        help="Allowed repository-relative path glob (repeatable; default: **)",
    )
    p_init.add_argument(
        "--allow-deletions", action="store_true", help="Permit deletions in the bounded change"
    )
    p_init.add_argument(
        "--verifier",
        nargs=argparse.REMAINDER,
        default=[sys.executable, "-m", "pytest", "-q"],
        metavar="ARG",
        help="Verifier argv without a shell; must be the final init option",
    )
    p_init.add_argument("--timeout", type=int, default=300, help="Verifier timeout seconds")
    p_init.add_argument("--force", action="store_true", help="Replace an existing config")

    p_doctor = subparsers.add_parser("doctor", help="Diagnose local Golden Path readiness")
    p_doctor.add_argument("--repo", default=".", help="Git repository (default: current)")

    p_check = subparsers.add_parser("check", help="Run local deterministic verification")
    p_check.add_argument("--repo", default=".", help="Git repository (default: current)")
    p_check.add_argument(
        "--require-trusted-config",
        action="store_true",
        help="Fail closed unless the config is committed on the base ref",
    )
    p_check.add_argument(
        "--expect-config-commit",
        default=None,
        type=_hex40,
        help="Fail closed unless the effective config is committed on this base commit "
        "(obtain it outside the candidate's control; env NEXUS_CERTIFY_EXPECT_CONFIG_COMMIT)",
    )

    p_receipt_check = subparsers.add_parser(
        "receipt-check", help="Validate a local verification receipt without rerunning its verifier"
    )
    p_receipt_check.add_argument("--receipt", required=True, help="Path to local receipt JSON")
    p_receipt_check.add_argument(
        "--repo", default=None, help="Optional Git repository for physical manifest readback"
    )
    p_receipt_check.add_argument("--expect-status", default=None)
    p_receipt_check.add_argument("--expect-subject-head", default=None, type=_hex40)
    p_receipt_check.add_argument("--expect-target-tree", default=None, type=_hex40)
    p_receipt_check.add_argument("--expect-config-commit", default=None, type=_hex40)
    p_receipt_check.add_argument("--expect-issue", default=None, type=int)
    p_receipt_check.add_argument("--expect-github-repository", default=None)
    p_receipt_check.add_argument("--require-clean-subject", action="store_true")
    p_receipt_check.add_argument("--require-trusted-config", action="store_true")

    p_evidence_check = subparsers.add_parser(
        "evidence-check", help="Apply canonical Core evidence applicability to a supplied PR subject"
    )
    p_evidence_check.add_argument("--receipt", required=True, help="Path to local receipt JSON")
    p_evidence_check.add_argument("--repository-owner", required=True)
    p_evidence_check.add_argument("--repository-name", required=True)
    p_evidence_check.add_argument("--pr-number", required=True, type=int)
    p_evidence_check.add_argument("--base-sha", required=True)
    p_evidence_check.add_argument("--head-sha", required=True)
    p_evidence_check.add_argument("--base-tree", required=True)
    p_evidence_check.add_argument("--head-tree", required=True)
    p_evidence_check.add_argument("--changed-path", action="append", default=[])
    p_evidence_check.add_argument("--deleted-path", action="append", default=[])
    p_evidence_check.add_argument(
        "--sigstore-bundle",
        help="Sigstore bundle for the receipt (default: <receipt>.sigstore.json when present)",
    )
    p_evidence_check.add_argument(
        "--signer-identity",
        help=(
            "Expected signing workflow identity, e.g. https://github.com/OWNER/REPO/"
            ".github/workflows/<file>.yml@refs/heads/main (default: the subject "
            "repository's nexus-core-issue-completion.yml on refs/heads/main)"
        ),
    )
    p_evidence_check.add_argument(
        "--sigstore-offline",
        action="store_true",
        help="Use the cached/embedded Sigstore trust root instead of refreshing it",
    )

    p_issue_init = subparsers.add_parser(
        "issue-init", help="Bind one GitHub Issue to the repository verification contract"
    )
    p_issue_init.add_argument("--repo", default=".", help="Git repository (default: current)")
    p_issue_init.add_argument("--issue", required=True, type=int, help="GitHub Issue number")
    p_issue_init.add_argument(
        "--github-repo",
        default=None,
        help="GitHub repository owner/name (default: derive from origin)",
    )
    p_issue_init.add_argument("--force", action="store_true", help="Replace existing binding")
    p_issue_init.add_argument(
        "--evidence-universe",
        choices=issue_golden_path.EVIDENCE_UNIVERSE_MODES,
        default="issue-marker",
        help="issue-marker (default, fail closed): the Issue body must carry the "
        "NEXUS_CORE_EVIDENCE_UNIVERSE marker; trusted-config: derive the universe from the "
        "trusted base config (no Issue marker; gives up the agent re-acknowledgement step)",
    )

    p_issue_check = subparsers.add_parser(
        "issue-check", help="Verify the current repository change against a bound GitHub Issue"
    )
    p_issue_check.add_argument("--repo", default=".", help="Git repository (default: current)")
    p_issue_check.add_argument(
        "--require-trusted-config",
        action="store_true",
        help="Fail closed unless the config is committed on the base ref",
    )
    p_issue_check.add_argument(
        "--expect-config-commit",
        default=None,
        type=_hex40,
        help="Fail closed unless the effective config is committed on this base commit "
        "(obtain it outside the candidate's control; env NEXUS_CERTIFY_EXPECT_CONFIG_COMMIT)",
    )
    p_issue_check.add_argument("--issue", required=True, type=int, help="GitHub Issue number")
    p_issue_check.add_argument(
        "--evidence-universe",
        choices=issue_golden_path.EVIDENCE_UNIVERSE_MODES,
        default="issue-marker",
        help="must match the mode used by issue-init (default: issue-marker)",
    )

    p_pr_state = subparsers.add_parser(
        "pr-state",
        help="Read the live PR state: 'gate' says PROCEED or PR_ALREADY_CLOSED_SKIPPED; "
        "'verify-skip' accepts a skip only for a PR merged at --expect-head (read-only)",
    )
    p_pr_state.add_argument("--mode", required=True, choices=("gate", "verify-skip"))
    p_pr_state.add_argument("--github-repo", required=True, help="GitHub repository owner/name")
    p_pr_state.add_argument("--pr", required=True, type=int, help="Pull request number")
    p_pr_state.add_argument(
        "--expect-head", required=True, type=_hex40, help="40-hex head commit of this run"
    )

    p_markers = subparsers.add_parser(
        "markers", help="Print the Issue-body and PR-body markers the gate expects (read-only)"
    )
    p_markers.add_argument("--repo", default=".", help="Git repository (default: current)")
    p_markers.add_argument(
        "--issue", type=int, default=None, help="Also print the PR-body marker for this Issue"
    )
    p_markers.add_argument(
        "--material-transition",
        action="append",
        metavar="MATERIAL_ID=TO_IDENTITY",
        help="Also print a NEXUS_CORE_MATERIAL_TRANSITION marker moving this material's "
        "pinned identity from the trusted config value to TO_IDENTITY (repeatable)",
    )
    p_markers.add_argument(
        "--check",
        action="store_true",
        help="Read the live Issue (--issue N) and exit 1 unless its "
        "NEXUS_CORE_EVIDENCE_UNIVERSE marker matches; prints the expected line (read-only)",
    )
    p_markers.add_argument(
        "--github-repo",
        default=None,
        help="GitHub repository owner/name for --check (default: derive from origin)",
    )
    p_markers.add_argument("--json", action="store_true", help="Emit JSON")

    # Machine-readable candidate acquisition (issue-1312).
    p_acquire = subparsers.add_parser(
        "acquire",
        help="Machine-readable candidate acquisition (reads a JSON request, emits a JSON result)",
    )
    p_acquire.add_argument(
        "--request",
        default=None,
        metavar="FILE",
        help="Path to acquisition request JSON file, or '-' to read from stdin (default: stdin)",
    )


    # runtime/manual handoff readiness
    p_handoff_init = subparsers.add_parser(
        "handoff-init", help="Initialize handoff readiness configuration"
    )
    p_handoff_init.add_argument("--repo", default=".", help="Git repository (default: current)")
    p_handoff_init.add_argument(
        "--handoff-id", required=True, help="Stable handoff target identifier"
    )
    p_handoff_init.add_argument(
        "--service",
        action="append",
        required=True,
        help="Service spec (service_id=endpoint)",
    )
    p_handoff_init.add_argument(
        "--timeout", type=int, default=300, help="Verifier timeout seconds"
    )
    p_handoff_init.add_argument(
        "--force", action="store_true", help="Replace existing handoff configuration"
    )
    p_handoff_init.add_argument(
        "--verifier",
        nargs=argparse.REMAINDER,
        required=True,
        metavar="ARG",
        help="Handoff verifier argv without a shell; must be the final option",
    )

    p_handoff_check = subparsers.add_parser(
        "handoff-check", help="Verify runtime and manual handoff readiness"
    )
    p_handoff_check.add_argument(
        "--repo", default=".", help="Git repository (default: current)"
    )

    p_handoff_status = subparsers.add_parser(
        "handoff-status", help="Read-only freshness check of handoff receipt"
    )
    p_handoff_status.add_argument(
        "--repo", default=".", help="Git repository (default: current)"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "submit":
            return cmd_submit(args)
        elif args.command == "status":
            return cmd_status(args)
        elif args.command == "receipt":
            return cmd_receipt(args)
        elif args.command == "verify":
            return cmd_verify(args)
        elif args.command == "init":
            return cmd_init(args)
        elif args.command == "doctor":
            return cmd_doctor(args)
        elif args.command == "check":
            return cmd_check(args)
        elif args.command == "receipt-check":
            return cmd_receipt_check(args)
        elif args.command == "evidence-check":
            return cmd_evidence_check(args)
        elif args.command == "issue-init":
            return cmd_issue_init(args)
        elif args.command == "issue-check":
            return cmd_issue_check(args)
        elif args.command == "pr-state":
            return cmd_pr_state(args)
        elif args.command == "markers":
            return cmd_markers(args)
        elif args.command == "acquire":
            return cmd_acquire(args)
        elif args.command == "handoff-init":
            return cmd_handoff_init(args)
        elif args.command == "handoff-check":
            return cmd_handoff_check(args)
        elif args.command == "handoff-status":
            return cmd_handoff_status(args)
        else:
            sys.stderr.write(f"unknown command: {args.command}\n")
            return 2
    except CertifyCLIError as exc:
        sys.stderr.write(f"{exc.message}\n")
        return exc.exit_code
    except LocalCheckError as exc:
        sys.stderr.write(f"{exc.reason_code}: {exc.detail}\n")
        if exc.receipt_path is not None:
            sys.stderr.write(f"receipt: {exc.receipt_path}\n")
        if exc.remediation is not None:
            gate_diagnostics.emit([exc.remediation])
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return 7


if __name__ == "__main__":
    sys.exit(main())
