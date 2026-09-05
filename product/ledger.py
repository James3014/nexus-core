"""Durable append-only SQLite ledger with replay fencing and recovery.

Core V1 TG-4 durable persistence boundary:
- Append-only WAL/full-sync SQLite receipt history.
- Idempotency fencing and generation CAS.
- Hash chaining and tamper/corruption fail-closed verification.
- Carried TG-3 EvidenceIdentityEnvelope and exact Completion Receipt.
- External Ed25519 signer and external head-anchor ports (public metadata only).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from product.evidence import _hash, canonical_json
from product.evidence.ingestion import IDENTITY_ENVELOPE_SCHEMA
from product.protocol import CERTIFICATION_RECEIPT_SCHEMA

LEDGER_SCHEMA_VERSION = "nexus.ledger-entry.v1"
GENESIS_PREVIOUS_HASH = "sha256:" + "0" * 64
DEFAULT_BUSY_TIMEOUT_MS = 5000
MAX_CONTENTION_ATTEMPTS = 5


class SecurityError(ValueError):
    """Raised when ledger storage security constraints are violated."""


class LedgerAppendStatus(str, Enum):
    APPENDED = "APPENDED"
    REPLAYED = "REPLAYED"
    STALE_GENERATION = "STALE_GENERATION"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    UNKNOWN_EFFECT = "UNKNOWN_EFFECT_RECONCILIATION_REQUIRED"
    BUSY_RETRY_EXHAUSTED = "LEDGER_BUSY_RECONCILIATION_REQUIRED"


class UnknownEffectError(RuntimeError):
    """Raised when an operation committed but the response could not be verified."""


@runtime_checkable
class ExternalSignerPort(Protocol):
    """External signing port. Receives only canonical digest; never private keys."""

    def sign_entry(self, digest: bytes) -> tuple[str, str, dict[str, object], bytes]:
        """Sign entry digest.

        Returns:
            (algorithm, key_id, public_metadata, signature_bytes)
        """
        ...


@runtime_checkable
class ExternalAnchorVerifierPort(Protocol):
    """External head anchor verifier port."""

    def verify_head_anchor(self, anchor: object, payload: bytes) -> str:
        """Verify the external head anchor.

        Returns:
            'VERIFIED', 'ANCHOR_UNAVAILABLE', or 'UNVERIFIABLE'
        """
        ...


@dataclass(frozen=True)
class LedgerAppendRequest:
    ledger_id: str
    request_id: str
    idempotency_key: str
    expected_generation: int
    attempt: int
    canonical_request: dict[str, object] | str
    identity_envelope_bytes: bytes
    completion_receipt_bytes: bytes
    source_snapshot_hash: str
    signer: ExternalSignerPort | None = None
    _failpoint: str | None = None


@dataclass(frozen=True)
class LedgerEntry:
    schema: str
    ledger_id: str
    sequence: int
    committed_generation: int
    expected_generation: int
    attempt: int
    request_id: str
    idempotency_key: str
    request_hash: str
    envelope_bytes: bytes
    envelope_hash: str
    receipt_bytes: bytes
    receipt_hash: str
    factual_disposition: str
    claim_ceiling: tuple[str, ...]
    source_snapshot_hash: str
    previous_entry_hash: str
    entry_hash: str
    signer_algorithm: str | None
    signer_key_id: str | None
    signer_public_metadata: dict[str, object] | None
    signature: bytes | None
    created_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "ledger_id": self.ledger_id,
            "sequence": self.sequence,
            "committed_generation": self.committed_generation,
            "expected_generation": self.expected_generation,
            "attempt": self.attempt,
            "request_id": self.request_id,
            "idempotency_key": self.idempotency_key,
            "request_hash": self.request_hash,
            "envelope_hash": self.envelope_hash,
            "receipt_hash": self.receipt_hash,
            "factual_disposition": self.factual_disposition,
            "claim_ceiling": list(self.claim_ceiling),
            "source_snapshot_hash": self.source_snapshot_hash,
            "previous_entry_hash": self.previous_entry_hash,
            "entry_hash": self.entry_hash,
            "signer_algorithm": self.signer_algorithm,
            "signer_key_id": self.signer_key_id,
            "signer_public_metadata": self.signer_public_metadata,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class LedgerAppendResult:
    status: LedgerAppendStatus
    entry: LedgerEntry | None
    is_replay: bool
    generation: int
    error_reason: str | None = None


@dataclass(frozen=True)
class LedgerReadResult:
    found: bool
    entry: LedgerEntry | None
    status: str


@dataclass(frozen=True)
class LedgerVerificationResult:
    valid: bool
    status: str
    entries_count: int
    head_sequence: int
    head_generation: int
    head_hash: str | None
    error_reason: str | None = None


@dataclass(frozen=True)
class AnchorVerificationResult:
    status: str
    head_hash: str | None
    reason: str | None = None


def resolve_ledger_path(override_path: Path | str | None = None) -> Path:
    """Resolve ledger SQLite path.

    Resolves override_path if given, else $XDG_STATE_HOME/nexus-core/ledger.sqlite3,
    falling back to ~/.local/state/nexus-core/ledger.sqlite3. Never uses cwd.
    """
    if override_path is not None:
        p = Path(override_path)
        if p.is_symlink():
            raise SecurityError(f"Ledger path {p} cannot be a symlink")
        return p.parent.resolve() / p.name

    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state and xdg_state.strip():
        base = Path(xdg_state).resolve()
    else:
        base = (Path.home() / ".local" / "state").resolve()
    return (base / "nexus-core" / "ledger.sqlite3").resolve()


def _ensure_secure_storage(db_path: Path) -> None:
    """Enforce filesystem security: mode 0700 dir, mode 0600 files, ownership."""
    if db_path.is_symlink():
        raise SecurityError(f"Ledger file {db_path} cannot be a symlink")

    parent = db_path.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        parent.chmod(0o700)
    except OSError:
        pass

    parent_stat = parent.stat()
    if parent_stat.st_uid != os.getuid():
        raise PermissionError(f"Directory {parent} is not owned by current UID")

    if db_path.exists():
        st = os.stat(db_path)
        if not stat.S_ISREG(st.st_mode):
            raise SecurityError(f"Ledger file {db_path} is not a regular file")
        if st.st_nlink > 1:
            raise SecurityError(f"Ledger file {db_path} has hard links ({st.st_nlink})")
        if st.st_uid != os.getuid():
            raise PermissionError(f"Ledger file {db_path} is not owned by current UID")
        try:
            db_path.chmod(0o600)
        except OSError:
            pass


def _secure_sidecars(db_path: Path) -> None:
    """Ensure WAL and SHM sidecars are mode 0600 and current UID."""
    for ext in ("", "-wal", "-shm"):
        target = Path(str(db_path) + ext) if ext else db_path
        if target.exists():
            st = os.stat(target)
            if target.is_symlink() or not stat.S_ISREG(st.st_mode):
                raise SecurityError(f"Ledger sidecar {target} is invalid")
            if st.st_uid != os.getuid():
                raise PermissionError(f"Ledger sidecar {target} is not owned by current UID")
            try:
                target.chmod(0o600)
            except OSError:
                pass


def _connect_ledger(db_path: Path) -> sqlite3.Connection:
    """Connect to SQLite with strict WAL, synchronous=FULL, foreign keys, and triggers."""
    _ensure_secure_storage(db_path)

    last_error: Exception | None = None
    for attempt in range(MAX_CONTENTION_ATTEMPTS):
        try:
            conn = sqlite3.connect(
                str(db_path),
                timeout=DEFAULT_BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None,  # Explicit transaction control
            )
            # Set busy_timeout first so pragmas wait if another process is initializing
            conn.execute(f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT_MS};")
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=FULL;")
            conn.execute("PRAGMA foreign_keys=ON;")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ledger_entries (
                    sequence INTEGER PRIMARY KEY,
                    committed_generation INTEGER NOT NULL,
                    expected_generation INTEGER NOT NULL,
                    attempt INTEGER NOT NULL,
                    ledger_id TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_hash TEXT NOT NULL,
                    envelope_bytes BLOB NOT NULL,
                    envelope_hash TEXT NOT NULL,
                    receipt_bytes BLOB NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    factual_disposition TEXT NOT NULL,
                    claim_ceiling TEXT NOT NULL,
                    source_snapshot_hash TEXT NOT NULL,
                    previous_entry_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    signer_algorithm TEXT,
                    signer_key_id TEXT,
                    signer_public_metadata TEXT,
                    signature BLOB,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ledger_idempotency ON ledger_entries(idempotency_key);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ledger_generation ON ledger_entries(committed_generation);"
            )

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_ledger_update
                BEFORE UPDATE ON ledger_entries
                BEGIN
                    SELECT RAISE(ABORT, 'LEDGER_IMMUTABLE: updates forbidden');
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_ledger_delete
                BEFORE DELETE ON ledger_entries
                BEGIN
                    SELECT RAISE(ABORT, 'LEDGER_IMMUTABLE: deletions forbidden');
                END;
            """)
            _secure_sidecars(db_path)
            return conn
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                time.sleep(0.02 * (2**attempt))
                continue
            raise

    if last_error:
        raise last_error
    raise sqlite3.OperationalError("Could not connect to ledger")


def compute_canonical_request_hash(canonical_request: dict[str, object] | str) -> str:
    """Compute deterministic SHA-256 hash for request payload."""
    if isinstance(canonical_request, str):
        if canonical_request.startswith("sha256:") and len(canonical_request) == 71:
            return canonical_request
        return "sha256:" + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    return _hash(canonical_request)


def compute_entry_hash(
    *,
    schema: str,
    ledger_id: str,
    sequence: int,
    committed_generation: int,
    request_id: str,
    idempotency_key: str,
    request_hash: str,
    envelope_hash: str,
    receipt_hash: str,
    factual_disposition: str,
    claim_ceiling: list[str] | tuple[str, ...],
    source_snapshot_hash: str,
    previous_entry_hash: str,
    signer_public_metadata: dict[str, object] | None,
) -> str:
    """Compute canonical hash for entry.

    Canonical domain: (schema, ledger_id, sequence, committed_generation, request_id,
    idempotency_key, request_hash, envelope_hash, receipt_hash, factual_disposition,
    claim_ceiling, source_snapshot_hash, previous_entry_hash, signer_public_metadata).
    """
    payload = (
        schema,
        ledger_id,
        sequence,
        committed_generation,
        request_id,
        idempotency_key,
        request_hash,
        envelope_hash,
        receipt_hash,
        factual_disposition,
        list(claim_ceiling),
        source_snapshot_hash,
        previous_entry_hash,
        signer_public_metadata,
    )
    return _hash(payload)


def _row_to_entry(row: tuple) -> LedgerEntry:
    (
        seq,
        com_gen,
        exp_gen,
        att,
        lid,
        rid,
        ikey,
        rhash,
        env_bytes,
        env_hash,
        rec_bytes,
        rec_hash,
        disp,
        claim_ceil_str,
        snap_hash,
        prev_hash,
        e_hash,
        s_algo,
        s_kid,
        s_meta_str,
        sig,
        created,
    ) = row

    s_meta = json.loads(s_meta_str) if s_meta_str else None
    claim_ceiling = tuple(json.loads(claim_ceil_str))
    return LedgerEntry(
        schema=LEDGER_SCHEMA_VERSION,
        ledger_id=lid,
        sequence=seq,
        committed_generation=com_gen,
        expected_generation=exp_gen,
        attempt=att,
        request_id=rid,
        idempotency_key=ikey,
        request_hash=rhash,
        envelope_bytes=env_bytes,
        envelope_hash=env_hash,
        receipt_bytes=rec_bytes,
        receipt_hash=rec_hash,
        factual_disposition=disp,
        claim_ceiling=claim_ceiling,
        source_snapshot_hash=snap_hash,
        previous_entry_hash=prev_hash,
        entry_hash=e_hash,
        signer_algorithm=s_algo,
        signer_key_id=s_kid,
        signer_public_metadata=s_meta,
        signature=sig,
        created_at=created,
    )


def append_or_replay(
    request: LedgerAppendRequest,
    *,
    db_path: Path | str | None = None,
) -> LedgerAppendResult:
    """Atomically append a new ledger entry or return idempotent replay.

    Enforces generation CAS, hash linking, immutability, and carried receipts.
    """
    target_path = resolve_ledger_path(db_path)
    req_hash = compute_canonical_request_hash(request.canonical_request)

    # Validate identity envelope
    try:
        env_dict = json.loads(request.identity_envelope_bytes.decode("utf-8"))
        if not isinstance(env_dict, dict) or env_dict.get("schema") != IDENTITY_ENVELOPE_SCHEMA:
            raise ValueError("invalid identity envelope schema")
        computed_env_hash = _hash(env_dict)
    except Exception as exc:
        raise ValueError(f"malformed identity envelope bytes: {exc}") from exc

    # Validate completion receipt
    try:
        rec_dict = json.loads(request.completion_receipt_bytes.decode("utf-8"))
        if (
            not isinstance(rec_dict, dict)
            or rec_dict.get("receipt_schema") != CERTIFICATION_RECEIPT_SCHEMA
        ):
            raise ValueError("invalid completion receipt schema")
        computed_rec_hash = rec_dict.get("receipt_hash")
        if not computed_rec_hash or not isinstance(computed_rec_hash, str):
            raise ValueError("completion receipt missing receipt_hash")
        factual_disposition = rec_dict["certification"]["disposition"]
        claim_ceiling = tuple(rec_dict["claim_ceiling"])
    except Exception as exc:
        raise ValueError(f"malformed completion receipt bytes: {exc}") from exc

    attempts = 0
    while attempts < MAX_CONTENTION_ATTEMPTS:
        attempts += 1
        try:
            conn = _connect_ledger(target_path)
        except sqlite3.OperationalError as exc:
            if "busy" in str(exc).lower() or "locked" in str(exc).lower():
                time.sleep(0.02 * (2 ** (attempts - 1)))
                continue
            raise

        try:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.cursor()

            # 1. Idempotency Check
            cur.execute(
                "SELECT sequence, committed_generation, expected_generation, attempt, ledger_id, "
                "request_id, idempotency_key, request_hash, envelope_bytes, envelope_hash, "
                "receipt_bytes, receipt_hash, factual_disposition, claim_ceiling, "
                "source_snapshot_hash, previous_entry_hash, entry_hash, signer_algorithm, "
                "signer_key_id, signer_public_metadata, signature, created_at "
                "FROM ledger_entries WHERE idempotency_key = ?;",
                (request.idempotency_key,),
            )
            existing_row = cur.fetchone()
            if existing_row:
                conn.execute("ROLLBACK;")
                stored_request_hash = existing_row[7]
                stored_entry = _row_to_entry(existing_row)
                if stored_request_hash != req_hash:
                    return LedgerAppendResult(
                        status=LedgerAppendStatus.IDEMPOTENCY_CONFLICT,
                        entry=None,
                        is_replay=False,
                        generation=stored_entry.committed_generation,
                        error_reason="idempotency key reused with different canonical request hash",
                    )
                return LedgerAppendResult(
                    status=LedgerAppendStatus.REPLAYED,
                    entry=stored_entry,
                    is_replay=True,
                    generation=stored_entry.committed_generation,
                )

            # Check request_id uniqueness under differing key
            cur.execute(
                "SELECT idempotency_key FROM ledger_entries WHERE request_id = ?;",
                (request.request_id,),
            )
            conflicting_req = cur.fetchone()
            if conflicting_req:
                conn.execute("ROLLBACK;")
                return LedgerAppendResult(
                    status=LedgerAppendStatus.IDEMPOTENCY_CONFLICT,
                    entry=None,
                    is_replay=False,
                    generation=0,
                    error_reason=f"request_id {request.request_id} already bound to another key",
                )

            # 2. Query current durable head
            cur.execute(
                "SELECT sequence, committed_generation, entry_hash FROM ledger_entries "
                "ORDER BY sequence DESC LIMIT 1;"
            )
            head_row = cur.fetchone()
            if head_row:
                current_sequence = head_row[0]
                current_generation = head_row[1]
                previous_hash = head_row[2]
            else:
                current_sequence = 0
                current_generation = 0
                previous_hash = GENESIS_PREVIOUS_HASH

            # 3. CAS Check
            if request.expected_generation != current_generation:
                conn.execute("ROLLBACK;")
                return LedgerAppendResult(
                    status=LedgerAppendStatus.STALE_GENERATION,
                    entry=None,
                    is_replay=False,
                    generation=current_generation,
                    error_reason=(
                        f"expected generation {request.expected_generation} != "
                        f"current generation {current_generation}"
                    ),
                )

            new_sequence = current_sequence + 1
            new_generation = current_generation + 1
            now_iso = datetime.now(timezone.utc).isoformat()

            # 4. Signing handling
            signer_algo = None
            signer_kid = None
            signer_meta = None
            signature_bytes = None

            if request.signer is not None:
                meta = getattr(request.signer, "public_metadata", {})
                if not isinstance(meta, dict):
                    meta = {}
                prelim_hash = compute_entry_hash(
                    schema=LEDGER_SCHEMA_VERSION,
                    ledger_id=request.ledger_id,
                    sequence=new_sequence,
                    committed_generation=new_generation,
                    request_id=request.request_id,
                    idempotency_key=request.idempotency_key,
                    request_hash=req_hash,
                    envelope_hash=computed_env_hash,
                    receipt_hash=computed_rec_hash,
                    factual_disposition=factual_disposition,
                    claim_ceiling=claim_ceiling,
                    source_snapshot_hash=request.source_snapshot_hash,
                    previous_entry_hash=previous_hash,
                    signer_public_metadata=meta or None,
                )
                sign_domain = (
                    "nexus.ledger-entry-signature.v1",
                    request.ledger_id,
                    new_sequence,
                    new_generation,
                    prelim_hash,
                    list(claim_ceiling),
                )
                digest = hashlib.sha256(canonical_json(sign_domain).encode("utf-8")).digest()
                signer_algo, signer_kid, res_meta, signature_bytes = request.signer.sign_entry(
                    digest
                )
                signer_meta = res_meta
                if signer_meta != meta:
                    # Final entry hash recomputation with signed metadata
                    entry_hash = compute_entry_hash(
                        schema=LEDGER_SCHEMA_VERSION,
                        ledger_id=request.ledger_id,
                        sequence=new_sequence,
                        committed_generation=new_generation,
                        request_id=request.request_id,
                        idempotency_key=request.idempotency_key,
                        request_hash=req_hash,
                        envelope_hash=computed_env_hash,
                        receipt_hash=computed_rec_hash,
                        factual_disposition=factual_disposition,
                        claim_ceiling=claim_ceiling,
                        source_snapshot_hash=request.source_snapshot_hash,
                        previous_entry_hash=previous_hash,
                        signer_public_metadata=signer_meta,
                    )
                else:
                    entry_hash = prelim_hash
            else:
                entry_hash = compute_entry_hash(
                    schema=LEDGER_SCHEMA_VERSION,
                    ledger_id=request.ledger_id,
                    sequence=new_sequence,
                    committed_generation=new_generation,
                    request_id=request.request_id,
                    idempotency_key=request.idempotency_key,
                    request_hash=req_hash,
                    envelope_hash=computed_env_hash,
                    receipt_hash=computed_rec_hash,
                    factual_disposition=factual_disposition,
                    claim_ceiling=claim_ceiling,
                    source_snapshot_hash=request.source_snapshot_hash,
                    previous_entry_hash=previous_hash,
                    signer_public_metadata=None,
                )

            # Failpoint before write
            if request._failpoint == "before_write":
                conn.execute("ROLLBACK;")
                raise RuntimeError("Failpoint: before_write")

            # 5. Insert row
            cur.execute(
                "INSERT INTO ledger_entries ("
                "sequence, committed_generation, expected_generation, attempt, ledger_id, "
                "request_id, idempotency_key, request_hash, envelope_bytes, envelope_hash, "
                "receipt_bytes, receipt_hash, factual_disposition, claim_ceiling, "
                "source_snapshot_hash, previous_entry_hash, entry_hash, signer_algorithm, "
                "signer_key_id, signer_public_metadata, signature, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    new_sequence,
                    new_generation,
                    request.expected_generation,
                    request.attempt,
                    request.ledger_id,
                    request.request_id,
                    request.idempotency_key,
                    req_hash,
                    request.identity_envelope_bytes,
                    computed_env_hash,
                    request.completion_receipt_bytes,
                    computed_rec_hash,
                    factual_disposition,
                    json.dumps(list(claim_ceiling)),
                    request.source_snapshot_hash,
                    previous_hash,
                    entry_hash,
                    signer_algo,
                    signer_kid,
                    json.dumps(signer_meta) if signer_meta is not None else None,
                    signature_bytes,
                    now_iso,
                ),
            )

            # Failpoint after write before commit
            if request._failpoint == "before_commit":
                conn.execute("ROLLBACK;")
                raise RuntimeError("Failpoint: before_commit")

            conn.execute("COMMIT;")
            _secure_sidecars(target_path)

            # Failpoint after commit before response
            if request._failpoint == "before_response":
                raise UnknownEffectError(LedgerAppendStatus.UNKNOWN_EFFECT.value)

            entry = LedgerEntry(
                schema=LEDGER_SCHEMA_VERSION,
                ledger_id=request.ledger_id,
                sequence=new_sequence,
                committed_generation=new_generation,
                expected_generation=request.expected_generation,
                attempt=request.attempt,
                request_id=request.request_id,
                idempotency_key=request.idempotency_key,
                request_hash=req_hash,
                envelope_bytes=request.identity_envelope_bytes,
                envelope_hash=computed_env_hash,
                receipt_bytes=request.completion_receipt_bytes,
                receipt_hash=computed_rec_hash,
                factual_disposition=factual_disposition,
                claim_ceiling=claim_ceiling,
                source_snapshot_hash=request.source_snapshot_hash,
                previous_entry_hash=previous_hash,
                entry_hash=entry_hash,
                signer_algorithm=signer_algo,
                signer_key_id=signer_kid,
                signer_public_metadata=signer_meta,
                signature=signature_bytes,
                created_at=now_iso,
            )

            return LedgerAppendResult(
                status=LedgerAppendStatus.APPENDED,
                entry=entry,
                is_replay=False,
                generation=new_generation,
            )

        except sqlite3.OperationalError as exc:
            try:
                conn.execute("ROLLBACK;")
            except Exception:
                pass
            if "busy" in str(exc).lower() or "locked" in str(exc).lower():
                time.sleep(0.02 * (2 ** (attempts - 1)))
                continue
            raise
        finally:
            conn.close()

    return LedgerAppendResult(
        status=LedgerAppendStatus.BUSY_RETRY_EXHAUSTED,
        entry=None,
        is_replay=False,
        generation=0,
        error_reason="SQLite busy contention retry exhausted",
    )


def get_by_request_id(
    request_id: str,
    *,
    db_path: Path | str | None = None,
) -> LedgerReadResult:
    """Retrieve ledger entry by request_id."""
    target_path = resolve_ledger_path(db_path)
    if not target_path.exists():
        return LedgerReadResult(found=False, entry=None, status="LEDGER_NOT_FOUND")

    conn = _connect_ledger(target_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT sequence, committed_generation, expected_generation, attempt, ledger_id, "
            "request_id, idempotency_key, request_hash, envelope_bytes, envelope_hash, "
            "receipt_bytes, receipt_hash, factual_disposition, claim_ceiling, "
            "source_snapshot_hash, previous_entry_hash, entry_hash, signer_algorithm, "
            "signer_key_id, signer_public_metadata, signature, created_at "
            "FROM ledger_entries WHERE request_id = ?;",
            (request_id,),
        )
        row = cur.fetchone()
        if not row:
            return LedgerReadResult(found=False, entry=None, status="NOT_FOUND")
        return LedgerReadResult(found=True, entry=_row_to_entry(row), status="FOUND")
    finally:
        conn.close()


def verify_chain(
    *,
    db_path: Path | str | None = None,
    expected_ledger_id: str | None = None,
) -> LedgerVerificationResult:
    """Verify hash chaining, contiguous sequence, generation monotonicity, and payloads.

    Fails closed on any corruption, truncation, gap, or tampering.
    """
    target_path = resolve_ledger_path(db_path)
    if not target_path.exists():
        return LedgerVerificationResult(
            valid=True,
            status="EMPTY",
            entries_count=0,
            head_sequence=0,
            head_generation=0,
            head_hash=None,
        )

    conn = _connect_ledger(target_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT sequence, committed_generation, expected_generation, attempt, ledger_id, "
            "request_id, idempotency_key, request_hash, envelope_bytes, envelope_hash, "
            "receipt_bytes, receipt_hash, factual_disposition, claim_ceiling, "
            "source_snapshot_hash, previous_entry_hash, entry_hash, signer_algorithm, "
            "signer_key_id, signer_public_metadata, signature, created_at "
            "FROM ledger_entries ORDER BY sequence ASC;"
        )
        rows = cur.fetchall()
        if not rows:
            return LedgerVerificationResult(
                valid=True,
                status="EMPTY",
                entries_count=0,
                head_sequence=0,
                head_generation=0,
                head_hash=None,
            )

        expected_sequence = 1
        previous_hash = GENESIS_PREVIOUS_HASH
        last_generation = 0
        last_hash = None

        for row in rows:
            entry = _row_to_entry(row)

            # Verify ledger_id
            if expected_ledger_id is not None and entry.ledger_id != expected_ledger_id:
                return LedgerVerificationResult(
                    valid=False,
                    status="LEDGER_ID_MISMATCH",
                    entries_count=len(rows),
                    head_sequence=entry.sequence,
                    head_generation=entry.committed_generation,
                    head_hash=entry.entry_hash,
                    error_reason=f"entry {entry.sequence} ledger_id {entry.ledger_id} != expected {expected_ledger_id}",
                )

            # Verify sequence contiguity
            if entry.sequence != expected_sequence:
                return LedgerVerificationResult(
                    valid=False,
                    status="SEQUENCE_GAP",
                    entries_count=len(rows),
                    head_sequence=entry.sequence,
                    head_generation=entry.committed_generation,
                    head_hash=entry.entry_hash,
                    error_reason=f"expected sequence {expected_sequence} got {entry.sequence}",
                )

            # Verify generation monotonicity
            if entry.committed_generation <= last_generation:
                return LedgerVerificationResult(
                    valid=False,
                    status="GENERATION_NON_MONOTONIC",
                    entries_count=len(rows),
                    head_sequence=entry.sequence,
                    head_generation=entry.committed_generation,
                    head_hash=entry.entry_hash,
                    error_reason=(
                        f"generation {entry.committed_generation} <= previous {last_generation}"
                    ),
                )

            # Verify previous hash link
            if entry.previous_entry_hash != previous_hash:
                return LedgerVerificationResult(
                    valid=False,
                    status="PREVIOUS_HASH_MISMATCH",
                    entries_count=len(rows),
                    head_sequence=entry.sequence,
                    head_generation=entry.committed_generation,
                    head_hash=entry.entry_hash,
                    error_reason=(
                        f"entry {entry.sequence} previous hash {entry.previous_entry_hash} != "
                        f"expected {previous_hash}"
                    ),
                )

            # Verify envelope bytes & hash
            try:
                env_dict = json.loads(entry.envelope_bytes.decode("utf-8"))
                recomputed_env_hash = _hash(env_dict)
                if recomputed_env_hash != entry.envelope_hash:
                    return LedgerVerificationResult(
                        valid=False,
                        status="ENVELOPE_TAMPERED",
                        entries_count=len(rows),
                        head_sequence=entry.sequence,
                        head_generation=entry.committed_generation,
                        head_hash=entry.entry_hash,
                        error_reason=f"envelope hash {entry.envelope_hash} tampered",
                    )
            except Exception as exc:
                return LedgerVerificationResult(
                    valid=False,
                    status="ENVELOPE_CORRUPT",
                    entries_count=len(rows),
                    head_sequence=entry.sequence,
                    head_generation=entry.committed_generation,
                    head_hash=entry.entry_hash,
                    error_reason=f"corrupt envelope: {exc}",
                )

            # Verify receipt bytes & hash
            try:
                rec_dict = json.loads(entry.receipt_bytes.decode("utf-8"))
                if rec_dict.get("receipt_hash") != entry.receipt_hash:
                    return LedgerVerificationResult(
                        valid=False,
                        status="RECEIPT_TAMPERED",
                        entries_count=len(rows),
                        head_sequence=entry.sequence,
                        head_generation=entry.committed_generation,
                        head_hash=entry.entry_hash,
                        error_reason=f"receipt hash {entry.receipt_hash} tampered",
                    )
            except Exception as exc:
                return LedgerVerificationResult(
                    valid=False,
                    status="RECEIPT_CORRUPT",
                    entries_count=len(rows),
                    head_sequence=entry.sequence,
                    head_generation=entry.committed_generation,
                    head_hash=entry.entry_hash,
                    error_reason=f"corrupt receipt: {exc}",
                )

            # Recompute entry hash
            recomputed_entry_hash = compute_entry_hash(
                schema=entry.schema,
                ledger_id=entry.ledger_id,
                sequence=entry.sequence,
                committed_generation=entry.committed_generation,
                request_id=entry.request_id,
                idempotency_key=entry.idempotency_key,
                request_hash=entry.request_hash,
                envelope_hash=entry.envelope_hash,
                receipt_hash=entry.receipt_hash,
                factual_disposition=entry.factual_disposition,
                claim_ceiling=entry.claim_ceiling,
                source_snapshot_hash=entry.source_snapshot_hash,
                previous_entry_hash=entry.previous_entry_hash,
                signer_public_metadata=entry.signer_public_metadata,
            )
            if recomputed_entry_hash != entry.entry_hash:
                return LedgerVerificationResult(
                    valid=False,
                    status="ENTRY_HASH_MISMATCH",
                    entries_count=len(rows),
                    head_sequence=entry.sequence,
                    head_generation=entry.committed_generation,
                    head_hash=entry.entry_hash,
                    error_reason=f"recomputed entry hash != stored entry_hash for sequence {entry.sequence}",
                )

            expected_sequence += 1
            previous_hash = entry.entry_hash
            last_generation = entry.committed_generation
            last_hash = entry.entry_hash

        return LedgerVerificationResult(
            valid=True,
            status="VALID",
            entries_count=len(rows),
            head_sequence=expected_sequence - 1,
            head_generation=last_generation,
            head_hash=last_hash,
        )
    finally:
        conn.close()


def verify_external_anchor(
    verifier: ExternalAnchorVerifierPort | None,
    anchor: object,
    *,
    db_path: Path | str | None = None,
    ledger_id: str | None = None,
) -> AnchorVerificationResult:
    """Verify external head anchor against the durable head.

    Without a valid verifier/anchor or on empty ledger, returns ANCHOR_UNAVAILABLE / UNVERIFIABLE.
    Rollback detection cannot be claimed without external verification.
    """
    if verifier is None or anchor is None:
        return AnchorVerificationResult(
            status="ANCHOR_UNAVAILABLE",
            head_hash=None,
            reason="verifier or anchor is missing",
        )

    target_path = resolve_ledger_path(db_path)
    if not target_path.exists():
        return AnchorVerificationResult(
            status="ANCHOR_UNAVAILABLE",
            head_hash=None,
            reason="ledger database does not exist",
        )

    conn = _connect_ledger(target_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT sequence, committed_generation, entry_hash, ledger_id FROM ledger_entries "
            "ORDER BY sequence DESC LIMIT 1;"
        )
        head_row = cur.fetchone()
        if not head_row:
            return AnchorVerificationResult(
                status="ANCHOR_UNAVAILABLE",
                head_hash=None,
                reason="ledger is empty; head anchor unavailable",
            )
        sequence, generation, head_hash, db_ledger_id = head_row
        target_ledger_id = ledger_id or db_ledger_id

        anchor_domain = (
            "nexus.ledger-head-anchor.v1",
            target_ledger_id,
            LEDGER_SCHEMA_VERSION,
            generation,
            sequence,
            head_hash,
        )
        payload = canonical_json(anchor_domain).encode("utf-8")
        status = verifier.verify_head_anchor(anchor, payload)
        if status not in {"VERIFIED", "ANCHOR_UNAVAILABLE", "UNVERIFIABLE"}:
            status = "UNVERIFIABLE"
        return AnchorVerificationResult(status=status, head_hash=head_hash)
    finally:
        conn.close()


__all__ = [
    "LEDGER_SCHEMA_VERSION",
    "GENESIS_PREVIOUS_HASH",
    "SecurityError",
    "LedgerAppendStatus",
    "ExternalSignerPort",
    "ExternalAnchorVerifierPort",
    "LedgerAppendRequest",
    "LedgerEntry",
    "LedgerAppendResult",
    "LedgerReadResult",
    "LedgerVerificationResult",
    "AnchorVerificationResult",
    "UnknownEffectError",
    "resolve_ledger_path",
    "compute_canonical_request_hash",
    "compute_entry_hash",
    "append_or_replay",
    "get_by_request_id",
    "verify_chain",
    "verify_external_anchor",
]
