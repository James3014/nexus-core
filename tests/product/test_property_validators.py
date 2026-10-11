"""Issue #174: property-style totality tests for public validators and HTTP routes.

Stdlib only: inputs come from ``random.Random(seed)`` over a fixed seed range, so
runs are deterministic. A failure reports the seed and the (truncated) offending
input, which replaces shrinking: re-run ``gen(random.Random(seed))`` to reproduce.
"""

from __future__ import annotations

import asyncio
import copy
import json
import random
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

import product.adapters.changeset_certification_v2 as adapter
from product.certification import CertificationDisposition
from product.clients.local_golden_path import (
    _receipt_hash,
    validate_verification_receipt_payload,
)
from product.evidence import validate_evidence_bundle_envelope
from product.evidence.handoff import (
    HandoffIdentity,
    HandoffVerification,
    verify_handoff_evidence,
)
from product.evidence.runtime_handoff import validate_handoff_evidence_envelope
from product.kernel import certify, validate_receipt, validate_serialized_receipt
from product.protocol.runtime_handoff import (
    HANDOFF_CLAIM_CEILING,
    HANDOFF_NON_CLAIMS,
    RUNTIME_HANDOFF_RECEIPT_KIND,
    RUNTIME_HANDOFF_SCHEMA_ID,
    is_git_commit_ref,
    is_git_tree_ref,
    is_sha256_hash,
    runtime_handoff_receipt_hash,
)
from product.runtime.auth import generate_bearer_token, write_secure_token
from product.runtime.http import start_runtime
from tests.product.test_changeset_certification_adapter import _envelope as _changeset_payload
from tests.product.test_evidence_receipt_hardening import _input
from tests.product.test_workflow_handoff_evidence import _envelope

N = 150  # examples per property (seeds 0..N-1)
N_HTTP = 40

# ------------------------------------------------------------- generators

_STRINGS = ["", "a", "sha256:", "git-commit:", "\n", "\x00", "é", "日本語", "😀", "x" * 70, " "]


def gen_scalar(rng: random.Random, floats: bool = True) -> Any:
    kind = rng.randrange(6 if floats else 5)
    if kind == 0:
        return None
    if kind == 1:
        return rng.random() < 0.5
    if kind == 2:
        return rng.choice([0, 1, -1, 2**63, -(2**70), rng.randrange(-1000, 1000)])
    if kind == 3:
        return rng.choice(_STRINGS)
    if kind == 4:
        return "".join(
            chr(rng.choice([rng.randrange(32, 127), rng.randrange(0xA0, 0x3000)]))
            for _ in range(rng.randrange(0, 12))
        )
    return rng.choice([0.0, -0.0, 1.5, float("nan"), float("inf"), -float("inf"), 1e308])


def gen_json(rng: random.Random, depth: int = 3, floats: bool = True) -> Any:
    if depth <= 0 or rng.random() < 0.45:
        return gen_scalar(rng, floats)
    if rng.random() < 0.5:
        return [gen_json(rng, depth - 1, floats) for _ in range(rng.randrange(0, 4))]
    return {
        str(gen_scalar(rng, False)): gen_json(rng, depth - 1, floats)
        for _ in range(rng.randrange(0, 4))
    }


def _paths(value: Any, prefix: tuple = ()) -> list[tuple]:
    out: list[tuple] = []
    if isinstance(value, dict):
        for key, child in value.items():
            out.append(prefix + (key,))
            out.extend(_paths(child, prefix + (key,)))
    return out


def mutate(rng: random.Random, base: Any, scalar_only: bool = False, floats: bool = True) -> Any:
    """Copy of a valid fixture with one field, at any depth, replaced."""
    payload = copy.deepcopy(base)
    path = rng.choice(_paths(payload))
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = gen_scalar(rng, floats) if scalar_only else gen_json(rng, floats=floats)
    return payload


def make_input(rng: random.Random, base: Any, scalar_only: bool = False, floats: bool = True):
    if not scalar_only and rng.random() < 0.3:
        return gen_json(rng)
    return mutate(rng, base, scalar_only, floats)


def check_all(
    gen: Callable[[random.Random], Any], check: Callable[[Any], None], n: int = N
) -> None:
    for seed in range(n):
        value = gen(random.Random(seed))
        try:
            check(value)
        except Exception as exc:
            raise AssertionError(
                f"property failed for seed={seed}: {type(exc).__name__}: {exc}\n"
                f"input={value!r:.600}"
            ) from exc


# --------------------------------------------------------------- fixtures

_DIGEST = "sha256:" + "1" * 64


def _handoff_receipt() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": RUNTIME_HANDOFF_SCHEMA_ID,
        "receipt_kind": RUNTIME_HANDOFF_RECEIPT_KIND,
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
        "non_claims": list(HANDOFF_NON_CLAIMS),
        "handoff_id": "h",
        "handoff_config_hash": _DIGEST,
        "handoff_verifier": {
            "command": ["t"],
            "exit_code": 0,
            "stdout_sha256": _DIGEST,
            "stderr_sha256": _DIGEST,
            "duration_ms": 3,
        },
        "verdict": "HANDOFF_READY",
    }
    payload["receipt_hash"] = runtime_handoff_receipt_hash(payload)
    return payload


def _verification_receipt() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "product": "nexus-core",
        "inputs": {"config_hash": _DIGEST, "paths": ["a.py"]},
        "status": "VERIFIED",
        "config_source": {"kind": "base-ref", "config_drift": False},
    }
    payload["receipt_hash"] = _receipt_hash(payload)
    return payload


_HANDOFF_IDENTITY = HandoffIdentity(
    repository="James3014/nexus-runtime",
    source_revision="git-commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    runtime_identity="runtime-sha:0000000000000000",
)

_NEW_ISSUE_DISPOSITION = (
    "#176: certify_changeset raises TypeError 'unhashable type: list' when `disposition` "
    "(or a verifier `status`) is a list (`x not in <set>` on unhashable JSON values)"
)
_NEW_ISSUE_FLOAT = (
    "#177: validate_verification_receipt_payload raises TypeError on a float field "
    "(product=0.0: 'unsupported canonical value: float') or a list config_source.kind "
    "('unhashable type: list') instead of returning valid=False"
)

_NEW_ISSUE_HANDOFF = (
    "<new issue needed>: verify_handoff_evidence raises TypeError 'unhashable type' when "
    "envelope `schema` is a list or dict (membership check at product/evidence/handoff.py:283)"
)

# ---------------------------------------------------- a. validator totality


def _check_verify_handoff(payload):
    result = verify_handoff_evidence(payload, current_identity=_HANDOFF_IDENTITY)
    assert isinstance(result, HandoffVerification)


def test_verify_handoff_evidence_is_total_excluding_known_gap():
    base = _envelope()
    check_all(lambda r: make_input(r, base, scalar_only=True), _check_verify_handoff)


@pytest.mark.xfail(strict=True, raises=TypeError, reason=_NEW_ISSUE_HANDOFF)
def test_verify_handoff_evidence_list_schema_known_gap():
    _check_verify_handoff({**_envelope(), "schema": []})


def test_validate_handoff_evidence_envelope_is_total():
    base = _handoff_receipt()

    def check(payload):
        result = validate_handoff_evidence_envelope(payload)
        assert isinstance(result, dict) and isinstance(result["valid"], bool)
        if not result["valid"]:
            assert result["reason_codes"]

    check_all(lambda r: make_input(r, base), check)


@pytest.mark.parametrize("by_hash", [False, True])
def test_validate_evidence_bundle_envelope_is_total(by_hash):
    data = _input()
    base = data.evidence.to_dict()
    kwargs: dict[str, Any] = (
        {"expected_envelope_hash": data.evidence.envelope_hash}
        if by_hash
        else {"expected_bundle": data.evidence}
    )

    def check(payload):
        errors = validate_evidence_bundle_envelope(
            payload, data.contract, data.change_set, data.plan, **kwargs
        )
        assert isinstance(errors, tuple)

    check_all(lambda r: make_input(r, base), check)


def test_validate_serialized_receipt_is_total():
    base = certify(_input()).receipt.to_dict()
    check_all(
        lambda r: make_input(r, base),
        lambda p: (
            isinstance(validate_serialized_receipt(p, _input()), tuple) or pytest.fail("type")
        ),
    )


def test_validate_receipt_is_total():
    check_all(
        lambda r: gen_json(r),
        lambda c: validate_receipt(c, _input()) is False or pytest.fail("accepted"),
    )
    receipt = certify(_input()).receipt
    check_all(
        lambda r: gen_json(r),
        lambda v: validate_receipt(receipt, v) is False or pytest.fail("accepted"),
    )


def _check_changeset_total(payload):
    result = adapter.certify_changeset(payload)
    assert isinstance(result, adapter.ChangeSetCertification)
    errors = adapter.validate_changeset_certification(result)
    assert isinstance(errors, tuple)
    # b. round trip: a CERTIFIED disposition must validate cleanly
    if result.status is CertificationDisposition.CERTIFIED:
        assert errors == ()
        assert adapter.validate_changeset_certification(result.to_dict()) == ()


def test_certify_changeset_is_total_excluding_known_gap():
    base = _changeset_payload()
    check_all(lambda r: make_input(r, base, scalar_only=True), _check_changeset_total)


def test_certified_changeset_results_round_trip():
    base = _changeset_payload()
    certified = 0

    def check(payload):
        nonlocal certified
        result = adapter.certify_changeset(payload)
        if result.status is CertificationDisposition.CERTIFIED:
            certified += 1
            assert adapter.validate_changeset_certification(result) == ()
            assert adapter.validate_changeset_certification(result.to_dict()) == ()

    check_all(lambda r: mutate(r, base, scalar_only=True), check)
    # control: the unmutated fixture certifies and round-trips
    check(base)
    assert certified >= 1


@pytest.mark.xfail(strict=True, raises=TypeError, reason=_NEW_ISSUE_DISPOSITION)
def test_certify_changeset_list_disposition_known_gap():
    _check_changeset_total({**_changeset_payload(), "disposition": []})


def test_validate_changeset_certification_is_total():
    base = _changeset_payload()

    def check(payload):
        assert isinstance(adapter.validate_changeset_certification(payload), tuple)

    check_all(lambda r: make_input(r, base), check)

    def rejects(value):
        assert adapter.validate_changeset_certification(value)

    check_all(lambda r: gen_json(r), rejects)


def _check_verification_receipt_total(payload):
    result = validate_verification_receipt_payload(payload)
    assert isinstance(result, dict) and isinstance(result["valid"], bool)


def test_validate_verification_receipt_payload_is_total_excluding_known_gap():
    base = _verification_receipt()
    check_all(
        lambda r: make_input(r, base, scalar_only=True, floats=False),
        _check_verification_receipt_total,
    )


def _receipt_with(**fields: Any) -> dict[str, Any]:
    payload = _verification_receipt()
    for key, value in fields.items():
        if key == "kind":
            payload["config_source"]["kind"] = value
        else:
            payload[key] = value
    return payload


@pytest.mark.xfail(strict=True, raises=TypeError, reason=_NEW_ISSUE_FLOAT)
def test_verification_receipt_list_kind_known_gap():
    _check_verification_receipt_total(_receipt_with(kind=[]))


@pytest.mark.xfail(strict=True, raises=TypeError, reason=_NEW_ISSUE_FLOAT)
def test_verification_receipt_float_field_known_gap():
    _check_verification_receipt_total(_receipt_with(product=0.0))


# ------------------------------------------------ c. canonical identifiers

_HEX = "0123456789abcdef"


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_HEX) for _ in range(n))


def test_identifiers_accept_canonical_and_reject_other_suffixes():
    def check(rng_value):
        rng = random.Random(rng_value)
        for fn, prefix, n in (
            (is_sha256_hash, "sha256:", 64),
            (is_git_commit_ref, "git-commit:", 40),
            (is_git_tree_ref, "git-tree:", 40),
        ):
            canon = prefix + _hex(rng, n)
            assert fn(canon)
            for suffix in (" ", "\r\n", "\x00", "\t", "0", "é"):
                assert not fn(canon + suffix), (prefix, suffix)
            assert not fn(canon.upper().replace(prefix.upper(), prefix))
            assert not fn(canon[:-1])

    check_all(lambda r: r.randrange(10**9), check, 60)


def test_accepted_identifiers_equal_canonical_form_except_newline():
    def check(value):
        for fn, prefix, n in (
            (is_sha256_hash, "sha256:", 64),
            (is_git_commit_ref, "git-commit:", 40),
            (is_git_tree_ref, "git-tree:", 40),
        ):
            assert isinstance(fn(value), bool)
            if fn(value):
                body = value[len(prefix) :]
                body = body[:-1] if body.endswith("\n") else body  # known #160
                assert value.startswith(prefix) and len(body) == n
                assert all(c in _HEX for c in body)

    def gen(rng):
        if rng.random() < 0.5:
            return gen_scalar(rng, False) if rng.random() < 0.3 else str(gen_json(rng, 1, False))
        prefix = rng.choice(["sha256:", "git-commit:", "git-tree:", "x:"])
        return (
            prefix + _hex(rng, rng.choice([39, 40, 41, 63, 64, 65])) + rng.choice(["", "\n", " "])
        )

    check_all(gen, check, 300)


@pytest.mark.xfail(
    strict=True,
    reason="#160: re.match + '$' accepts a trailing newline "
    "(https://github.com/James3014/nexus-core/issues/160)",
)
def test_identifiers_reject_trailing_newline():
    def check(seed):
        rng = random.Random(seed)
        assert not is_sha256_hash("sha256:" + _hex(rng, 64) + "\n")
        assert not is_git_commit_ref("git-commit:" + _hex(rng, 40) + "\n")
        assert not is_git_tree_ref("git-tree:" + _hex(rng, 40) + "\n")

    check_all(lambda r: r.randrange(10**9), check, 20)


# ----------------------------------------------------------------- d. HTTP


class _Server:
    def __init__(self, tmp: Path) -> None:
        token_dir = tmp / ".config" / "nexus-core"
        token_dir.mkdir(parents=True, mode=0o700)
        token_path = token_dir / "token"
        write_secure_token(generate_bearer_token(), token_path)
        state = tmp / ".local" / "state" / "nexus-core"
        state.mkdir(parents=True, mode=0o700)
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run() -> None:
            asyncio.set_event_loop(self.loop)
            self.handle = self.loop.run_until_complete(
                start_runtime(
                    host="127.0.0.1",
                    port=0,
                    token_path=token_path,
                    db_path=state / "ledger.sqlite3",
                )
            )
            ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        assert ready.wait(30)

    def stop(self) -> None:
        asyncio.run_coroutine_threadsafe(self.handle.stop(), self.loop).result(30)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)


@pytest.fixture(scope="module")
def http_server(tmp_path_factory):
    server = _Server(tmp_path_factory.mktemp("property-http"))
    yield server
    server.stop()


_POST_ROUTES = ["/v1/certifications", "/v1/receipts/verify", "/v1/changesets/verify"]
_CONTENT_TYPES = ["application/json", "text/plain", "application/octet-stream"]


def _gen_body(rng: random.Random) -> tuple[bytes, str]:
    if rng.random() < 0.5:
        body = rng.randbytes(rng.randrange(0, 2048))
    else:
        body = json.dumps(gen_json(rng), allow_nan=True).encode()
    return body, rng.choice(_CONTENT_TYPES)


@pytest.mark.parametrize("route", _POST_ROUTES)
def test_post_routes_never_5xx_on_arbitrary_bodies(http_server, route):
    url = f"http://127.0.0.1:{http_server.handle.port}{route}"

    def check(case):
        body, content_type = case
        headers = {
            "Authorization": f"Bearer {http_server.handle.token}",
            "Content-Type": content_type,
        }
        resp = httpx.post(url, headers=headers, content=body, timeout=30)
        assert 400 <= resp.status_code < 500, (resp.status_code, resp.text[:200], content_type)

    check_all(_gen_body, check, N_HTTP)
