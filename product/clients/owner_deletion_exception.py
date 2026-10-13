"""Owner-signed governed deletion exception for ``deletion_policy = "FORBID"``.

A repository whose trusted (base-ref) config carries a ``[deletion_exception]``
table keeps ``deletion_policy = "FORBID"`` for every ordinary change. A change
may physically delete files only when all of the following hold:

(a) every deleted path is preserved: it exists in ``archive.commit`` and that
    commit is an ancestor of the exact base commit (so it lives in the
    protected, non-rewritable default-branch history; ``archive.ref`` names the
    human-facing archive branch);
(b) an owner-signed deletion manifest lists it: the change adds exactly one
    ``<manifest_dir>/<id>.json`` plus its OpenSSH ``SSHSIG`` signature
    ``<id>.json.sig`` made with a key listed in the trusted config's
    ``allowed_signers`` under ``signature_namespace``;
(c) the change is dedicated: every entry of the exact Git manifest is either a
    listed deletion (exact path, blob/gitlink oid and mode), the manifest or
    its signature, or a listed companion change (exact path, change type and
    resulting oid, e.g. ``.gitmodules`` or the ARCHIVED ledger).

The same signed manifest is the only way to change a path listed in
``protected_paths`` (``.nexus-core/config.toml`` is always protected), so the
signer list and this policy cannot be relaxed by an unsigned change. The one
exception is a config change exactly covered by Issue-authorized material
transitions, which the caller has already validated.

Nothing here trusts the candidate: the policy, signer list and namespace come
from the base-ref config, and the manifest bytes are read from the exact
target tree.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

SECTION = "deletion_exception"
MODE = "OWNER_SIGNED_ARCHIVE"
MANIFEST_SCHEMA = "nexus.core.deletion-manifest.v1"
RECORD_SCHEMA = "nexus.core.owner-deletion-exception.v1"
CONFIG_PATH = ".nexus-core/config.toml"
_SECTION_KEYS = {
    "mode",
    "manifest_dir",
    "signature_namespace",
    "allowed_signers",
    "protected_paths",
}
_MANIFEST_KEYS = {
    "schema",
    "id",
    "reason",
    "archive",
    "deletions",
    "companion_changes",
}
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.@_-]{0,127}$")
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.@_-]{0,127}$")
_SIGNER_RE = re.compile(
    r"^(?P<principal>[A-Za-z0-9][A-Za-z0-9.@_-]{0,127}) "
    r"(?P<key>(?:ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|"
    r"sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+)(?: [^\n]*)?$"
)
_MODES = {"100644", "100755", "120000", "160000"}


class DeletionExceptionError(Exception):
    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(f"{reason_code}: {detail}")
        self.reason_code = reason_code
        self.detail = detail


def _fail(code: str, detail: str) -> DeletionExceptionError:
    return DeletionExceptionError(code, detail)


def _relative_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise _fail("INVALID_CONFIG", f"{label} must be a normalized relative path")
    return value


def validate_section(value: Any) -> dict[str, Any]:
    """Validate the optional ``[deletion_exception]`` config table."""

    if not isinstance(value, dict) or set(value) != _SECTION_KEYS:
        raise _fail("INVALID_CONFIG", f"{SECTION} must have exactly {sorted(_SECTION_KEYS)}")
    if value["mode"] != MODE:
        raise _fail("INVALID_CONFIG", f"{SECTION}.mode must be {MODE}")
    manifest_dir = _relative_path(value["manifest_dir"], f"{SECTION}.manifest_dir")
    namespace = value["signature_namespace"]
    if not isinstance(namespace, str) or not _NAMESPACE_RE.fullmatch(namespace):
        raise _fail("INVALID_CONFIG", f"{SECTION}.signature_namespace is malformed")
    signers = value["allowed_signers"]
    if (
        not isinstance(signers, list)
        or not signers
        or any(not isinstance(item, str) or not _SIGNER_RE.fullmatch(item) for item in signers)
    ):
        raise _fail(
            "INVALID_CONFIG",
            f"{SECTION}.allowed_signers must be '<principal> <ssh key type> <base64>' lines",
        )
    protected = value["protected_paths"]
    if not isinstance(protected, list) or any(not isinstance(item, str) for item in protected):
        raise _fail("INVALID_CONFIG", f"{SECTION}.protected_paths must be a list of paths")
    for item in protected:
        _relative_path(item, f"{SECTION}.protected_paths")
    return {
        "mode": MODE,
        "manifest_dir": manifest_dir,
        "signature_namespace": namespace,
        "allowed_signers": list(signers),
        "protected_paths": sorted({CONFIG_PATH, *protected}),
    }


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _fail("DELETION_MANIFEST_MALFORMED", f"not UTF-8 JSON: {exc}") from exc
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
        raise _fail("DELETION_MANIFEST_MALFORMED", f"keys must be {sorted(_MANIFEST_KEYS)}")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise _fail("DELETION_MANIFEST_MALFORMED", f"schema must be {MANIFEST_SCHEMA}")
    if not isinstance(manifest["id"], str) or not _ID_RE.fullmatch(manifest["id"]):
        raise _fail("DELETION_MANIFEST_MALFORMED", "id is malformed")
    if not isinstance(manifest["reason"], str) or not manifest["reason"].strip():
        raise _fail("DELETION_MANIFEST_MALFORMED", "reason is required")
    archive = manifest["archive"]
    if (
        not isinstance(archive, dict)
        or set(archive) != {"ref", "commit"}
        or not isinstance(archive["ref"], str)
        or not archive["ref"].startswith("refs/heads/archive/")
        or not isinstance(archive["commit"], str)
        or not _HEX40.fullmatch(archive["commit"])
    ):
        raise _fail(
            "DELETION_MANIFEST_MALFORMED",
            "archive must be {ref: refs/heads/archive/..., commit: <40-hex>}",
        )
    deletions = manifest["deletions"]
    if not isinstance(deletions, list):
        raise _fail("DELETION_MANIFEST_MALFORMED", "deletions must be a list")
    seen: set[str] = set()
    for item in deletions:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "before_oid", "before_mode"}
            or not isinstance(item["before_oid"], str)
            or not _HEX40.fullmatch(item["before_oid"])
            or item["before_mode"] not in _MODES
        ):
            raise _fail("DELETION_MANIFEST_MALFORMED", "deletion entry is malformed")
        path = _relative_path(item["path"], "deletion path")
        if path in seen:
            raise _fail("DELETION_MANIFEST_MALFORMED", f"duplicate path {path}")
        seen.add(path)
    companions = manifest["companion_changes"]
    if not isinstance(companions, list):
        raise _fail("DELETION_MANIFEST_MALFORMED", "companion_changes must be a list")
    for item in companions:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "change_type", "after_oid"}
            or item["change_type"] not in {"ADD", "MODIFY"}
            or not isinstance(item["after_oid"], str)
            or not _HEX40.fullmatch(item["after_oid"])
        ):
            raise _fail("DELETION_MANIFEST_MALFORMED", "companion entry is malformed")
        path = _relative_path(item["path"], "companion path")
        if path in seen:
            raise _fail("DELETION_MANIFEST_MALFORMED", f"duplicate path {path}")
        seen.add(path)
    if not deletions and not companions:
        raise _fail("DELETION_MANIFEST_MALFORMED", "manifest authorizes nothing")
    return manifest


def verify_signature(
    section: Mapping[str, Any], manifest_bytes: bytes, signature_bytes: bytes
) -> dict[str, str]:
    """Verify an OpenSSH SSHSIG signature against the trusted signer list."""

    with tempfile.TemporaryDirectory(prefix="nexus-core-sshsig-") as tmp:
        directory = Path(tmp)
        signers = directory / "allowed_signers"
        signers.write_text("\n".join(section["allowed_signers"]) + "\n", encoding="utf-8")
        signature = directory / "manifest.sig"
        signature.write_bytes(signature_bytes)
        for line in section["allowed_signers"]:
            match = _SIGNER_RE.fullmatch(line)
            assert match is not None
            principal = match.group("principal")
            try:
                result = subprocess.run(
                    [
                        "ssh-keygen",
                        "-Y",
                        "verify",
                        "-f",
                        str(signers),
                        "-I",
                        principal,
                        "-n",
                        section["signature_namespace"],
                        "-s",
                        str(signature),
                    ],
                    input=manifest_bytes,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise _fail("DELETION_SIGNATURE_VERIFIER_UNAVAILABLE", str(exc)) from exc
            if result.returncode == 0:
                return {
                    "principal": principal,
                    "key": match.group("key"),
                    "verifier_output": result.stdout.decode("utf-8", "replace").strip(),
                }
    raise _fail(
        "DELETION_MANIFEST_SIGNATURE_INVALID",
        "signature does not verify for any trusted allowed_signers principal",
    )


def evaluate(
    *,
    section: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    read_blob: Callable[[str], bytes],
    tree_entry: Callable[[str, str], tuple[str, str] | None],
    is_ancestor_of_base: Callable[[str], bool],
    exempt_paths: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    """Return the receipt record for an authorized change, or None if not needed.

    ``entries`` is the exact Git change manifest. ``read_blob(oid)`` reads a blob
    from the candidate object store, ``tree_entry(commit, path)`` returns
    ``(mode, oid)`` or None, ``is_ancestor_of_base(commit)`` answers whether the
    commit is in the base commit's history. ``exempt_paths`` are protected paths
    whose change is already authorized elsewhere (material transitions).
    """

    deletes = [entry for entry in entries if entry["change_type"] == "DELETE"]
    protected = set(section["protected_paths"])
    touched_protected = sorted(
        entry["path"]
        for entry in entries
        if entry["path"] in protected and entry["path"] not in exempt_paths
    )
    prefix = section["manifest_dir"].rstrip("/") + "/"
    manifest_adds = [
        entry
        for entry in entries
        if entry["change_type"] == "ADD"
        and entry["path"].startswith(prefix)
        and entry["path"].endswith(".json")
        and "/" not in entry["path"][len(prefix) :]
    ]
    if not deletes and not touched_protected and not manifest_adds:
        return None
    if len(manifest_adds) != 1:
        code = (
            "FORBIDDEN_DELETION"
            if deletes and not manifest_adds
            else "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE"
            if not manifest_adds
            else "DELETION_MANIFEST_COUNT_INVALID"
        )
        detail = (
            ", ".join([entry["path"] for entry in deletes] + touched_protected)
            or f"{len(manifest_adds)} manifests"
        )
        raise _fail(code, detail)
    manifest_entry = manifest_adds[0]
    signature_path = manifest_entry["path"] + ".sig"
    by_path = {entry["path"]: entry for entry in entries}
    signature_entry = by_path.get(signature_path)
    if (
        signature_entry is None
        or signature_entry["change_type"] != "ADD"
        or signature_entry["after_mode"] != "100644"
        or manifest_entry["after_mode"] != "100644"
    ):
        raise _fail("DELETION_MANIFEST_SIGNATURE_MISSING", signature_path)
    manifest_bytes = read_blob(manifest_entry["after_oid"])
    signature_bytes = read_blob(signature_entry["after_oid"])
    manifest = _parse_manifest(manifest_bytes)
    if manifest_entry["path"] != f"{prefix}{manifest['id']}.json":
        raise _fail("DELETION_MANIFEST_MALFORMED", "manifest file name must be <id>.json")
    signer = verify_signature(section, manifest_bytes, signature_bytes)

    archive_commit = manifest["archive"]["commit"]
    if not is_ancestor_of_base(archive_commit):
        raise _fail(
            "DELETION_ARCHIVE_NOT_PRESERVED",
            f"archive commit {archive_commit} is not in the base commit's history",
        )
    listed_deletions = {item["path"]: item for item in manifest["deletions"]}
    listed_companions = {item["path"]: item for item in manifest["companion_changes"]}
    allowed_own = {manifest_entry["path"], signature_path}
    for entry in entries:
        path = entry["path"]
        if path in allowed_own:
            continue
        if entry["change_type"] == "DELETE":
            item = listed_deletions.get(path)
            if item is None:
                raise _fail("DELETION_NOT_IN_MANIFEST", path)
            if (
                item["before_oid"] != entry["before_oid"]
                or item["before_mode"] != entry["before_mode"]
            ):
                raise _fail("DELETION_MANIFEST_OID_MISMATCH", path)
            if tree_entry(archive_commit, path) is None:
                raise _fail("DELETION_ARCHIVE_NOT_PRESERVED", f"{path} not in {archive_commit}")
            continue
        companion = listed_companions.get(path)
        if companion is None:
            if path in exempt_paths:
                continue
            raise _fail("DELETION_PR_NOT_DEDICATED", path)
        if (
            companion["change_type"] != entry["change_type"]
            or companion["after_oid"] != entry["after_oid"]
        ):
            raise _fail("DELETION_MANIFEST_OID_MISMATCH", path)
    unused = sorted(
        set(listed_deletions) - {e["path"] for e in deletes}
        | (set(listed_companions) - set(by_path))
    )
    if unused:
        raise _fail("DELETION_MANIFEST_ENTRY_UNUSED", ", ".join(unused))
    return {
        "schema": RECORD_SCHEMA,
        "manifest_path": manifest_entry["path"],
        "manifest_sha256": _sha256(manifest_bytes),
        "signature_sha256": _sha256(signature_bytes),
        "manifest_base64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signature_base64": base64.b64encode(signature_bytes).decode("ascii"),
        "principal": signer["principal"],
        "signer_key": signer["key"],
        "archive": dict(manifest["archive"]),
        "deleted_paths": sorted(listed_deletions),
        "companion_paths": sorted(listed_companions),
    }


def revalidate_record(
    section: Mapping[str, Any], record: Any, entries: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Receipt-side re-verification from the embedded manifest and signature bytes."""

    if not isinstance(record, dict) or record.get("schema") != RECORD_SCHEMA:
        return ["DELETION_EXCEPTION_RECORD_MALFORMED"]
    try:
        manifest_bytes = base64.b64decode(record["manifest_base64"], validate=True)
        signature_bytes = base64.b64decode(record["signature_base64"], validate=True)
        if (
            _sha256(manifest_bytes) != record["manifest_sha256"]
            or _sha256(signature_bytes) != record["signature_sha256"]
        ):
            return ["DELETION_EXCEPTION_RECORD_MALFORMED"]
        manifest = _parse_manifest(manifest_bytes)
        signer = verify_signature(section, manifest_bytes, signature_bytes)
    except (KeyError, TypeError, ValueError):
        return ["DELETION_EXCEPTION_RECORD_MALFORMED"]
    except DeletionExceptionError as exc:
        return [exc.reason_code]
    reasons: list[str] = []
    if signer["principal"] != record.get("principal"):
        reasons.append("DELETION_MANIFEST_SIGNATURE_INVALID")
    listed = {item["path"]: item for item in manifest["deletions"]}
    deleted = {e["path"]: e for e in entries if e.get("change_type") == "DELETE"}
    if set(listed) != set(deleted) or any(
        listed[p]["before_oid"] != deleted[p].get("before_oid") for p in listed
    ):
        reasons.append("DELETION_NOT_IN_MANIFEST")
    return reasons
