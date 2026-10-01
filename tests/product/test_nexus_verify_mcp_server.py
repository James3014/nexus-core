from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from product.clients.nexus_verify import verify_code_change_evidence

SCRIPT = Path("scripts/nexus_verify_mcp_server.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("nexus_verify_mcp_server", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeRequester:
    def __init__(
        self,
        *,
        token_expected: str | None = None,
        private_repo: bool = False,
    ) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.token_expected = token_expected
        self.private_repo = private_repo
        self.base_sha = "a" * 40
        self.head_sha = "b" * 40
        self.base_tree = "c" * 40
        self.head_tree = "d" * 40
        self.diff = b"diff --git a/app.py b/app.py\n+VALUE = 2\n"

    def __call__(self, url: str, headers: Any):
        normalized_headers = dict(headers)
        self.calls.append((url, normalized_headers))
        assert normalized_headers["X-GitHub-Api-Version"] == "2022-11-28"
        assert normalized_headers["User-Agent"] == "nexus-verify-g1-developer-mode"
        if self.token_expected is not None:
            assert normalized_headers["Authorization"] == f"Bearer {self.token_expected}"

        parsed = urlparse(url)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/repos/example/demo":
            return 200, {}, json.dumps({"private": self.private_repo}).encode()

        if path == "/repos/example/demo/pulls/7":
            if normalized_headers["Accept"] == "application/vnd.github.v3.diff":
                return 200, {}, self.diff
            return (
                200,
                {},
                json.dumps(
                    {
                        "base": {"sha": self.base_sha},
                        "head": {"sha": self.head_sha},
                        "updated_at": "2026-10-01T00:00:00Z",
                    }
                ).encode(),
            )

        if path == f"/repos/example/demo/git/commits/{self.base_sha}":
            return 200, {}, json.dumps({"tree": {"sha": self.base_tree}}).encode()

        if path == f"/repos/example/demo/git/commits/{self.head_sha}":
            return 200, {}, json.dumps({"tree": {"sha": self.head_tree}}).encode()

        if path == "/repos/example/demo/pulls/7/files":
            assert query == {"per_page": ["100"], "page": ["1"]}
            return (
                200,
                {},
                json.dumps([{"filename": "app.py", "status": "modified"}]).encode(),
            )

        if path == f"/repos/example/demo/commits/{self.head_sha}/check-runs":
            assert query == {"per_page": ["100"], "page": ["1"]}
            return (
                200,
                {},
                json.dumps(
                    {
                        "total_count": 1,
                        "check_runs": [
                            {
                                "id": 11,
                                "name": "test",
                                "status": "completed",
                                "conclusion": "success",
                                "head_sha": self.head_sha,
                                "details_url": "https://example.test/check/11",
                                "app": {"slug": "github-actions"},
                            }
                        ],
                    }
                ).encode(),
            )

        raise AssertionError(f"unexpected request: {url}")


def test_server_module_imports_without_installing_mcp_dependency():
    module = _load_module()
    assert module.DEFAULT_HOST == "127.0.0.1"
    assert module.DEFAULT_PORT == 8768


def test_public_github_port_supports_canonical_double_read():
    module = _load_module()
    requester = FakeRequester()
    port = module.PublicGitHubReadPort(requester=requester)

    result = verify_code_change_evidence(
        {
            "repository_owner": "example",
            "repository_name": "demo",
            "pr_number": 7,
            "receipt": None,
        },
        github_port=port,
    )

    assert result["evidence_applicability"] == "EVIDENCE_NOT_SUPPLIED"
    assert result["receipt_integrity"] == "ABSENT"
    assert result["core_verification"] == "NOT_AVAILABLE"
    assert result["subject"] == {
        "repository_owner": "example",
        "repository_name": "demo",
        "pr_number": 7,
        "current_base_sha": "a" * 40,
        "current_head_sha": "b" * 40,
        "current_base_tree": "c" * 40,
        "current_head_tree": "d" * 40,
        "freshness_cas": result["subject"]["freshness_cas"],
    }
    # One canonical acquisition performs two full independent six-request reads.
    assert len(requester.calls) == 12
    assert all(headers["Accept"].startswith("application/vnd.github") for _, headers in requester.calls)


def test_public_review_profile_rechecks_public_visibility_on_double_read():
    module = _load_module()
    requester = FakeRequester()
    port = module.PublicGitHubReadPort(requester=requester, public_only=True)

    result = verify_code_change_evidence(
        {
            "repository_owner": "example",
            "repository_name": "demo",
            "pr_number": 7,
            "receipt": None,
        },
        github_port=port,
    )

    assert result["evidence_applicability"] == "EVIDENCE_NOT_SUPPLIED"
    visibility_calls = [
        url for url, _headers in requester.calls if urlparse(url).path == "/repos/example/demo"
    ]
    assert len(visibility_calls) == 2


def test_public_review_profile_fails_closed_for_private_repository():
    module = _load_module()
    requester = FakeRequester(private_repo=True)
    port = module.PublicGitHubReadPort(requester=requester, public_only=True)

    result = verify_code_change_evidence(
        {
            "repository_owner": "example",
            "repository_name": "demo",
            "pr_number": 7,
            "receipt": None,
        },
        github_port=port,
    )

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["reason_codes"] == ["GITHUB_READ_PERMISSION_DENIED"]
    assert len(requester.calls) == 1


def test_public_review_environment_uses_only_dedicated_service_token(monkeypatch):
    module = _load_module()
    monkeypatch.setenv("NEXUS_VERIFY_GITHUB_TOKEN", "developer-token")
    monkeypatch.setenv("GITHUB_TOKEN", "generic-token")
    monkeypatch.delenv(module.PUBLIC_REVIEW_GITHUB_TOKEN_ENV, raising=False)

    port = module.PublicGitHubReadPort.from_public_review_environment()

    assert port._token is None
    assert port._public_only is True

    monkeypatch.setenv(module.PUBLIC_REVIEW_GITHUB_TOKEN_ENV, "public-service-token")
    port = module.PublicGitHubReadPort.from_public_review_environment()
    assert port._token == "public-service-token"
    assert port._public_only is True


def test_public_review_tool_metadata_declares_noauth_and_bounded_status_text():
    module = _load_module()

    assert module.PUBLIC_TOOL_META == {
        "securitySchemes": [{"type": "noauth"}],
        "openai/toolInvocation/invoking": "Checking verification evidence...",
        "openai/toolInvocation/invoked": "Verification evidence checked",
    }


def test_public_tool_argument_validation_matches_advertised_schema():
    module = _load_module()
    valid = {
        "repository_owner": "example",
        "repository_name": "demo",
        "pr_number": 7,
        "receipt": None,
    }
    module._validate_public_tool_arguments(valid, public_review=True)

    with pytest.raises(ValueError, match="unexpected tool arguments"):
        module._validate_public_tool_arguments(
            {**valid, "extra": True},
            public_review=True,
        )

    with pytest.raises(ValueError, match="receipt must be an object or null"):
        module._validate_public_tool_arguments(
            {**valid, "receipt": []},
            public_review=True,
        )

    with pytest.raises(ValueError, match="receipt exceeds public-review size limit"):
        module._validate_public_tool_arguments(
            {**valid, "receipt": {"blob": "x" * (513 * 1024)}},
            public_review=True,
        )


def test_public_review_server_binds_scanned_schemas_to_frozen_contract():
    source = SCRIPT.read_text(encoding="utf-8")

    assert "class ContractBoundMCPServer(MCPServer)" in source
    assert '"input_schema": dict(INPUT_SCHEMA)' in source
    assert '"output_schema": dict(OUTPUT_SCHEMA)' in source
    assert "_validate_public_tool_arguments(" in source


def test_github_token_is_host_owned_and_read_only():
    module = _load_module()
    requester = FakeRequester(token_expected="secret-token")
    port = module.PublicGitHubReadPort(token="secret-token", requester=requester)

    result = verify_code_change_evidence(
        {
            "repository_owner": "example",
            "repository_name": "demo",
            "pr_number": 7,
        },
        github_port=port,
    )

    assert result["evidence_applicability"] == "EVIDENCE_NOT_SUPPLIED"
    assert requester.calls
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'method="GET"' in source
    assert 'method="POST"' not in source
    assert 'method="PUT"' not in source
    assert 'method="PATCH"' not in source
    assert 'method="DELETE"' not in source


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "example.com"])
def test_g1_server_rejects_non_loopback_bind(host):
    module = _load_module()
    with pytest.raises(ValueError, match="loopback"):
        module._require_loopback(host)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_g1_server_accepts_loopback_bind(host):
    module = _load_module()
    assert module._require_loopback(host) == host


def test_public_review_profile_does_not_expand_network_binding():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "create_public_review_mcp_server" in source
    assert "_require_loopback(host)" in source
    assert '"public-review"' in source
    assert "transport_security=_transport_security_settings(" in source


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("verify.snowskill.app", "verify.snowskill.app"),
        ("VERIFY.SNOWSKILL.APP", "verify.snowskill.app"),
    ],
)
def test_public_host_normalization_accepts_exact_dns_hostname(raw, expected):
    module = _load_module()
    assert module._normalize_public_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " verify.snowskill.app",
        "verify.snowskill.app ",
        "https://verify.snowskill.app",
        "verify.snowskill.app/mcp",
        "verify.snowskill.app:443",
        "*.snowskill.app",
        "user@verify.snowskill.app",
    ],
)
def test_public_host_normalization_rejects_ambiguous_or_broad_values(raw):
    module = _load_module()
    with pytest.raises(ValueError, match="public host"):
        module._normalize_public_host(raw)


def test_pep723_dependency_is_isolated_from_project_runtime():
    source = SCRIPT.read_text(encoding="utf-8")
    assert (
        '# dependencies = ["mcp==2.2.0", "aiohttp==3.14.3", "PyGithub==2.10.0"]'
        in source
    )
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    project_dependencies = pyproject.split("[project.urls]", 1)[0]
    assert '"mcp' not in project_dependencies.lower()


def test_mcp_host_declares_one_read_only_tool_only():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "@server.tool(" in source
    assert source.count("@server.tool(") == 1
    assert "read_only_hint=True" in source
    assert "open_world_hint=True" in source
    for forbidden in (
        "merge_pull_request",
        "create_comment",
        "workflow_dispatch",
        "subprocess.run",
        "os.system",
    ):
        assert forbidden not in source.lower()
