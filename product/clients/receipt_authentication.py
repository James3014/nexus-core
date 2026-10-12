"""Receipt authentication seam for Nexus Verify (Issue #231).

A Nexus receipt's ``receipt_hash`` is an unkeyed SHA-256, so it proves
self-consistency only. Authenticity comes from the Sigstore bundle that the
``issue-gate`` action produces when it signs the CI receipt
(``<receipt>.json.sigstore.json``). This module checks such a bundle against an
expected GitHub Actions workflow identity, the same check the ``receipt-verify``
action performs with ``sigstore verify github``.

The core package stays zero-dependency: Sigstore verification sits behind the
injectable :class:`ReceiptAuthenticator` protocol. The default
:class:`SigstoreReceiptAuthenticator` imports the ``sigstore`` package lazily.
It is deliberately not a declared dependency or extra (an extra would change
``uv.lock``, which the sealed ``python-oci-pytest-v1`` profile pins); install it
alongside with ``pip install 'sigstore>=4.5,<5'``. When it is missing, or the
trust root cannot be loaded, the result is ``UNAVAILABLE`` and never
``AUTHENTICATED``.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from typing import Any, Protocol

AUTHENTICATED = "AUTHENTICATED"
NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
UNAVAILABLE = "UNAVAILABLE"

GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
DEFAULT_SIGNER_WORKFLOW = "nexus-core-issue-completion.yml"
DEFAULT_SIGNER_REF = "refs/heads/main"

_REPO_PART = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_WORKFLOW_FILE = re.compile(r"[A-Za-z0-9_.-]{1,200}\.ya?ml\Z")
_GIT_REF = re.compile(r"refs/(heads|tags)/[A-Za-z0-9_./-]{1,200}\Z")
_IDENTITY = re.compile(
    r"https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    r"/\.github/workflows/(?P<workflow>[A-Za-z0-9_.-]+\.ya?ml)@(?P<ref>refs/[A-Za-z0-9_./-]+)\Z"
)


@dataclass(frozen=True)
class ReceiptSignerPolicy:
    """The exact signer a receipt bundle must name.

    ``identity`` is the Fulcio certificate SAN of the signing workflow,
    ``issuer`` the OIDC issuer, and ``repository`` the ``owner/name`` recorded in
    the certificate's GitHub workflow-repository extension.
    """

    identity: str
    issuer: str
    repository: str

    def __post_init__(self) -> None:
        match = _IDENTITY.fullmatch(self.identity) if isinstance(self.identity, str) else None
        if match is None:
            raise ValueError(
                "signer identity must be https://github.com/<owner>/<repo>/.github/workflows/<file>.yml@refs/..."
            )
        if self.repository != f"{match['owner']}/{match['repo']}":
            raise ValueError("signer identity must belong to the signer repository")
        if self.issuer != GITHUB_ACTIONS_OIDC_ISSUER:
            raise ValueError("signer issuer must be the GitHub Actions OIDC issuer")


def github_workflow_signer_policy(
    repository_owner: str,
    repository_name: str,
    *,
    workflow_file: str = DEFAULT_SIGNER_WORKFLOW,
    ref: str = DEFAULT_SIGNER_REF,
) -> ReceiptSignerPolicy:
    """Signer policy for ``<owner>/<repo>``'s gate workflow on ``ref``."""

    for value in (repository_owner, repository_name):
        if not isinstance(value, str) or _REPO_PART.fullmatch(value) is None:
            raise ValueError("invalid repository owner or name for signer policy")
    if not isinstance(workflow_file, str) or _WORKFLOW_FILE.fullmatch(workflow_file) is None:
        raise ValueError("signer workflow must be a workflow file name such as gate.yml")
    if not isinstance(ref, str) or _GIT_REF.fullmatch(ref) is None:
        raise ValueError("signer ref must be refs/heads/<name> or refs/tags/<name>")
    repository = f"{repository_owner}/{repository_name}"
    return ReceiptSignerPolicy(
        identity=f"https://github.com/{repository}/.github/workflows/{workflow_file}@{ref}",
        issuer=GITHUB_ACTIONS_OIDC_ISSUER,
        repository=repository,
    )


def signer_policy_for_identity(identity: str) -> ReceiptSignerPolicy:
    """Build a policy from a full workflow identity URL (``receipt-verify`` style)."""

    match = _IDENTITY.fullmatch(identity) if isinstance(identity, str) else None
    if match is None:
        raise ValueError("invalid signer workflow identity")
    return ReceiptSignerPolicy(
        identity=identity,
        issuer=GITHUB_ACTIONS_OIDC_ISSUER,
        repository=f"{match['owner']}/{match['repo']}",
    )


@dataclass(frozen=True)
class ReceiptAuthentication:
    """Outcome of one authentication attempt; only ``AUTHENTICATED`` is positive."""

    status: str
    detail: str = ""

    @property
    def authenticated(self) -> bool:
        return self.status == AUTHENTICATED


class ReceiptAuthenticator(Protocol):
    """Checks that ``bundle_json`` signs exactly ``receipt_bytes`` as ``policy``."""

    def authenticate(
        self,
        *,
        receipt_bytes: bytes,
        bundle_json: bytes,
        policy: ReceiptSignerPolicy,
    ) -> ReceiptAuthentication: ...


class SigstoreReceiptAuthenticator:
    """Default authenticator backed by the optional ``sigstore`` package.

    Mirrors ``sigstore verify github --cert-identity <identity> --repository
    <owner/repo>``: the issuer must be GitHub Actions, the certificate identity
    must equal the expected workflow identity, the workflow-repository extension
    must equal the expected repository, and the bundle signature, certificate
    chain and transparency-log entry must verify for the exact receipt bytes.

    ``offline=False`` (the default) refreshes the Sigstore trust root over the
    network; ``offline=True`` uses the cached or embedded trust root.
    """

    def __init__(self, *, offline: bool = False) -> None:
        self._offline = offline
        self._verifier: Any = None

    def _load(self) -> tuple[Any, Any, Any, Any] | ReceiptAuthentication:
        try:
            errors = importlib.import_module("sigstore.errors")
            models = importlib.import_module("sigstore.models")
            verify = importlib.import_module("sigstore.verify")
            policy = importlib.import_module("sigstore.verify.policy")
        except ImportError:
            return ReceiptAuthentication(
                UNAVAILABLE, "sigstore is not installed (pip install 'sigstore>=4.5,<5')"
            )
        if self._verifier is None:
            try:
                self._verifier = verify.Verifier.production(offline=self._offline)
            except Exception as exc:  # noqa: BLE001 - any trust-root failure is UNAVAILABLE
                return ReceiptAuthentication(
                    UNAVAILABLE, f"sigstore trust root unavailable: {type(exc).__name__}"
                )
        return errors, models, policy, self._verifier

    def authenticate(
        self,
        *,
        receipt_bytes: bytes,
        bundle_json: bytes,
        policy: ReceiptSignerPolicy,
    ) -> ReceiptAuthentication:
        loaded = self._load()
        if isinstance(loaded, ReceiptAuthentication):
            return loaded
        errors, models, policy_module, verifier = loaded
        try:
            bundle = models.Bundle.from_json(bundle_json)
        except Exception as exc:  # noqa: BLE001 - malformed bundles never authenticate
            return ReceiptAuthentication(NOT_AUTHENTICATED, f"malformed bundle: {type(exc).__name__}")
        verification_policy = policy_module.AllOf(
            [
                policy_module.OIDCIssuer(policy.issuer),
                policy_module.Identity(identity=policy.identity, issuer=None),
                policy_module.GitHubWorkflowRepository(policy.repository),
            ]
        )
        try:
            verifier.verify_artifact(
                input_=bytes(receipt_bytes), bundle=bundle, policy=verification_policy
            )
        except (errors.NetworkError, errors.TUFError, errors.RootError, errors.MetadataError) as exc:
            return ReceiptAuthentication(UNAVAILABLE, f"sigstore unavailable: {type(exc).__name__}")
        except Exception as exc:  # noqa: BLE001 - any other failure is not authenticated
            return ReceiptAuthentication(NOT_AUTHENTICATED, f"{type(exc).__name__}: {exc}")
        return ReceiptAuthentication(AUTHENTICATED, policy.identity)


__all__ = [
    "AUTHENTICATED",
    "DEFAULT_SIGNER_REF",
    "DEFAULT_SIGNER_WORKFLOW",
    "GITHUB_ACTIONS_OIDC_ISSUER",
    "NOT_AUTHENTICATED",
    "UNAVAILABLE",
    "ReceiptAuthentication",
    "ReceiptAuthenticator",
    "ReceiptSignerPolicy",
    "SigstoreReceiptAuthenticator",
    "github_workflow_signer_policy",
    "signer_policy_for_identity",
]
