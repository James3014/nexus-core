"""Certification service orchestrating TG-1 through TG-4 and Completion Core (TG-5)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from product.acquisition.github import (
    GitHubPullRequestLocator,
    acquire_github_pull_request,
)
from product.certification import (
    CertificationPolicy,
)
from product.certification.receipt import (
    CLAIM_CEILING,
)
from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    EvidenceBundle,
    Observation,
    ObservationStatus,
    VerificationPlan,
    _hash,
)
from product.execution.python_runner import (
    PythonOCIRunner,
    RunnerResult,
    RunnerStatus,
)
from product.kernel import (
    CertificationInput,
    certify,
)
from product.ledger import (
    LedgerAppendRequest,
    LedgerAppendStatus,
    append_or_replay,
    compute_canonical_request_hash,
    get_by_request_id,
    resolve_ledger_path,
)
from product.runtime.schemas import (
    make_http_error,
    make_http_response,
    validate_certification_request,
    validate_receipt_verify_request,
)


@dataclass
class InFlightJob:
    request_id: str
    idempotency_key: str
    request_hash: str
    state: str
    generation: int
    payload: dict[str, Any]
    task: Optional[asyncio.Task[Any]] = None
    response: Optional[dict[str, Any]] = None
    receipt_bytes: Optional[bytes] = None
    envelope_bytes: Optional[bytes] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class RuntimeCertificationService:
    """Core V1 runtime service coordinating live PR acquisition, execution, trust, and ledger."""

    def __init__(
        self,
        *,
        db_path: Path | str | None = None,
        ledger_id: str = "nexus-core-ledger-v1",
        github_port: Any = None,
        runner_executor: Any = None,
        signer: Any = None,
        anchor_verifier: Any = None,
    ) -> None:
        self.db_path = resolve_ledger_path(db_path)
        self.ledger_id = ledger_id
        self.github_port = github_port
        self.runner_executor = runner_executor
        self.signer = signer
        self.anchor_verifier = anchor_verifier
        self._admission_stopped = False
        self._in_flight: dict[str, InFlightJob] = {}  # by request_id
        self._by_idempotency: dict[str, str] = {}  # idempotency_key -> request_id

    def _get_current_ledger_generation(self) -> int:
        """Query durable head generation from ledger."""
        if not self.db_path.exists():
            return 0
        try:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT committed_generation FROM ledger_entries ORDER BY sequence DESC LIMIT 1;"
                )
                row = cur.fetchone()
                return row[0] if row else 0
            finally:
                conn.close()
        except Exception:
            return 0

    def _get_ledger_entry_by_idempotency(
        self, idempotency_key: str
    ) -> Optional[tuple[str, str, int, bytes, bytes, str]]:
        """Find entry by idempotency key: (request_id, request_hash, generation, receipt_bytes, envelope_bytes, disposition)."""
        if not self.db_path.exists():
            return None
        try:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT request_id, request_hash, committed_generation, receipt_bytes, envelope_bytes, factual_disposition "
                    "FROM ledger_entries WHERE idempotency_key = ?;",
                    (idempotency_key,),
                )
                row = cur.fetchone()
                if row:
                    return (row[0], row[1], row[2], row[3], row[4], row[5])
                return None
            finally:
                conn.close()
        except Exception:
            return None

    async def submit_certification(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Submit certification request.

        Returns (http_status, json_body).
        - 202: new accepted request (PENDING/RUNNING) or non-terminal replay
        - 200: exact replay of terminal request
        - 409: IDEMPOTENCY_CONFLICT, STALE_GENERATION, STALE_SOURCE
        - 400/415/422: malformed/unsupported schema
        - 503: SERVICE_UNAVAILABLE (admission stopped)
        """
        if self._admission_stopped:
            return 503, make_http_error(
                code="SERVICE_UNAVAILABLE",
                request_id=None,
                message="service is shutting down; new requests rejected",
            )

        errs = validate_certification_request(payload)
        if errs:
            code = "MALFORMED_REQUEST"
            if any("unsupported" in e for e in errs):
                code = "UNSUPPORTED_CONTRACT"
            return (422 if code == "UNSUPPORTED_CONTRACT" else 400), make_http_error(
                code=code,
                request_id=None,
                message=errs[0],
            )

        req_hash = compute_canonical_request_hash(payload)
        ikey = payload["idempotency_key"]
        exp_gen = payload["expected_generation"]

        # 1. Check existing committed ledger entry for this idempotency_key
        existing_ledger = self._get_ledger_entry_by_idempotency(ikey)
        if existing_ledger:
            stored_req_id, stored_req_hash, stored_gen, receipt_b, env_b, disp = existing_ledger
            if stored_req_hash != req_hash:
                return 409, make_http_error(
                    code="IDEMPOTENCY_CONFLICT",
                    request_id=None,
                    message="idempotency key reused with different canonical request hash",
                )
            # Exact replay of durable entry -> 200
            try:
                receipt_dict = json.loads(receipt_b.decode("utf-8"))
            except Exception:
                receipt_dict = None
            try:
                env_dict = json.loads(env_b.decode("utf-8"))
            except Exception:
                env_dict = None

            resp = make_http_response(
                request_id=stored_req_id,
                state="COMPLETED" if disp != "REJECTED" else "FAILED",
                generation=stored_gen,
                acquisition=None,
                execution=None,
                evidence=env_dict,
                verification=receipt_dict.get("verification") if receipt_dict else None,
                disposition=disp,
                receipt=receipt_dict,
                claim_ceiling=CLAIM_CEILING,
            )
            return 200, resp

        # 2. Check in-flight cache under same idempotency_key
        if ikey in self._by_idempotency:
            in_flight_id = self._by_idempotency[ikey]
            job = self._in_flight.get(in_flight_id)
            if job:
                if job.request_hash != req_hash:
                    return 409, make_http_error(
                        code="IDEMPOTENCY_CONFLICT",
                        request_id=None,
                        message="idempotency key reused with different canonical request hash",
                    )
                # In-flight replay -> 202
                return 202, job.response or make_http_response(
                    request_id=job.request_id,
                    state=job.state,
                    generation=job.generation,
                    claim_ceiling=CLAIM_CEILING,
                )

        # 3. CAS Check: expected_generation must match current durable generation
        cur_gen = self._get_current_ledger_generation()
        if exp_gen != cur_gen:
            return 409, make_http_error(
                code="STALE_GENERATION",
                request_id=None,
                message=f"expected_generation {exp_gen} does not match current head generation {cur_gen}",
            )

        # 4. Create new in-flight job
        request_id = f"req_{uuid.uuid4().hex[:16]}"
        job = InFlightJob(
            request_id=request_id,
            idempotency_key=ikey,
            request_hash=req_hash,
            state="PENDING",
            generation=exp_gen,
            payload=payload,
        )
        job.response = make_http_response(
            request_id=request_id,
            state="PENDING",
            generation=exp_gen,
            claim_ceiling=CLAIM_CEILING,
        )
        self._in_flight[request_id] = job
        self._by_idempotency[ikey] = request_id

        # Launch background execution task
        job.task = asyncio.create_task(self._execute_pipeline(job))

        return 202, job.response

    async def _execute_pipeline(self, job: InFlightJob) -> None:
        """Run TG-1 acquisition -> TG-2 runner -> TG-3 envelope -> Core certify -> TG-4 ledger."""
        job.state = "RUNNING"
        job.response = make_http_response(
            request_id=job.request_id,
            state="RUNNING",
            generation=job.generation,
            claim_ceiling=CLAIM_CEILING,
        )

        try:
            repo_info = job.payload["repository"]
            owner = repo_info["owner"]
            name = repo_info["name"]
            pr_number = repo_info["pr_number"]
            exp_base_sha = repo_info["expected_base_sha"]
            exp_head_sha = repo_info["expected_head_sha"]

            # 1. TG-1: Live or Injected PR Acquisition
            locator = GitHubPullRequestLocator(owner, name, pr_number)
            if self.github_port is None:
                raise RuntimeError("GitHub read port is not configured")

            snapshot = acquire_github_pull_request(self.github_port, locator)
            if snapshot.base_sha != exp_base_sha or snapshot.head_sha != exp_head_sha:
                job.state = "UNVERIFIABLE"
                job.error_code = "STALE_SOURCE"
                job.error_message = (
                    "acquired PR SHA does not match expected_base_sha / expected_head_sha"
                )
                job.response = make_http_response(
                    request_id=job.request_id,
                    state="UNVERIFIABLE",
                    generation=job.generation,
                    claim_ceiling=CLAIM_CEILING,
                )
                return

            # Convert snapshot to TG-3 compatible GitHubAcquisitionReceipt

            # 2. TG-2: Deterministic Python OCI Runner
            runner = PythonOCIRunner()
            if self.runner_executor is None:
                raise RuntimeError("Runner executor is not configured")

            # Build runner request
            run_req = {
                "source_revision": snapshot.head_sha,
                "source_tree": snapshot.head_tree_sha,
                "contract_hash": _hash(job.payload["acceptance_contract"]),
                "plan_hash": _hash(job.payload["verification_plan"]),
                "environment_hash": runner.profile.hash,
                "attempt_id": f"att-{job.request_id}",
            }
            runner_result: RunnerResult = runner.run(run_req, self.runner_executor)

            # 3. Acceptance Contract, ChangeSet, Plan, Evidence
            raw_contract = job.payload["acceptance_contract"]
            contract = AcceptanceContract(
                contract_id=raw_contract.get("contract_id", f"ac-{job.request_id}"),
                requirements_hash=raw_contract.get("requirements_hash", _hash("requirements")),
                required_verifier_ids=tuple(raw_contract.get("required_verifier_ids", ("pytest",))),
                allowed_paths=tuple(raw_contract.get("allowed_paths", snapshot.changed_paths)),
                deletion_policy=raw_contract.get("deletion_policy", "FORBID"),
            )

            change_set = ChangeSet(
                change_set_id=f"pr-{snapshot.pr_number}",
                source_revision=snapshot.base_sha,
                target_revision=snapshot.head_sha,
                diff_hash=snapshot.diff_hash,
                paths=snapshot.changed_paths,
            )

            raw_plan = job.payload["verification_plan"]
            plan = VerificationPlan(
                plan_id=raw_plan.get("plan_id", f"plan-{job.request_id}"),
                acceptance_contract_hash=contract.hash,
                change_set_hash=change_set.hash,
                required_verifier_ids=tuple(raw_plan.get("required_verifier_ids", ("pytest",))),
            )

            evidence_obs = (
                Observation(
                    verifier_id="pytest",
                    artifact_id=runner_result.attempt_ids[0]
                    if runner_result.attempt_ids
                    else "none",
                    artifact_hash=runner_result.artifact_hashes[0]
                    if runner_result.artifact_hashes
                    else _hash("none"),
                    status=ObservationStatus.PASS
                    if runner_result.status == RunnerStatus.VERIFIED
                    else ObservationStatus.FAIL,
                ),
            )
            evidence = EvidenceBundle(
                bundle_id=f"bundle-{job.request_id}",
                acceptance_contract_hash=contract.hash,
                change_set_hash=change_set.hash,
                verification_plan_hash=plan.hash,
                observations=evidence_obs,
            )

            # 4. Completion Core Certification
            cert_input = CertificationInput(
                contract=contract,
                change_set=change_set,
                plan=plan,
                evidence=evidence,
                policy_accepted=True,
                authority_present=True,
                approval_present=True,
                signing_present=True,
            )
            cert_result = certify(cert_input)
            receipt = cert_result.receipt
            receipt_dict = receipt.to_dict()
            receipt_bytes = json.dumps(receipt_dict, sort_keys=True).encode("utf-8")

            # 5. TG-3 EvidenceIdentityEnvelope
            # In live tracer, we construct an identity envelope carrying the TG-1 & TG-2 hashes
            envelope_dict = {
                "schema": "nexus.evidence.identity-envelope.v1",
                "context_hash": _hash(job.payload),
                "profile_hash": runner_result.profile_hash,
                "bundle_hash": evidence.hash,
                "ingestion_receipt_hash": _hash(evidence.to_dict()),
                "subject_hash": locator.locator_hash,
                "execution_id": f"exec-{job.request_id}",
                "attempt_id": runner_result.attempt_ids[0]
                if runner_result.attempt_ids
                else f"att-{job.request_id}",
                "generation": str(job.generation),
                "producer_id": "nexus.controller.v1",
                "issuer_id": "nexus.service.v1",
                "acquisition_snapshot_hash": snapshot.freshness_cas,
                "runner_result_hash": _hash(runner_result.to_dict()),
                "verification_receipt_hash": receipt.hash,
                "external_receipt_hashes": [],
            }
            envelope_dict["identity_hash"] = _hash(envelope_dict)
            envelope_bytes = json.dumps(envelope_dict, sort_keys=True).encode("utf-8")

            # 6. TG-4: Durable Ledger Append
            append_req = LedgerAppendRequest(
                ledger_id=self.ledger_id,
                request_id=job.request_id,
                idempotency_key=job.idempotency_key,
                expected_generation=job.generation,
                attempt=1,
                canonical_request=job.payload,
                identity_envelope_bytes=envelope_bytes,
                completion_receipt_bytes=receipt_bytes,
                source_snapshot_hash=snapshot.locator_hash,
                signer=self.signer,
            )
            append_res = append_or_replay(append_req, db_path=self.db_path)

            if append_res.status in {LedgerAppendStatus.APPENDED, LedgerAppendStatus.REPLAYED}:
                committed_gen = append_res.generation
                disposition_str = cert_result.disposition.value
                job.state = "COMPLETED" if disposition_str != "REJECTED" else "FAILED"
                job.generation = committed_gen
                job.receipt_bytes = receipt_bytes
                job.envelope_bytes = envelope_bytes
                job.response = make_http_response(
                    request_id=job.request_id,
                    state=job.state,
                    generation=committed_gen,
                    acquisition=snapshot.to_dict(),
                    execution=runner_result.to_dict(),
                    evidence=envelope_dict,
                    verification=receipt_dict.get("verification"),
                    disposition=disposition_str,
                    receipt=receipt_dict,
                    claim_ceiling=CLAIM_CEILING,
                )
            else:
                job.state = "UNVERIFIABLE"
                job.error_code = append_res.status.value
                job.error_message = append_res.error_reason or "ledger append failed"
                job.response = make_http_response(
                    request_id=job.request_id,
                    state="UNVERIFIABLE",
                    generation=job.generation,
                    claim_ceiling=CLAIM_CEILING,
                )
        except Exception:
            job.state = "UNVERIFIABLE"
            job.error_code = "INTERNAL_ERROR"
            job.error_message = "certification pipeline interrupted or unverifiable"
            job.response = make_http_response(
                request_id=job.request_id,
                state="UNVERIFIABLE",
                generation=job.generation,
                claim_ceiling=CLAIM_CEILING,
            )

    async def get_status(self, request_id: str) -> tuple[int, dict[str, Any]]:
        """GET /v1/certifications/{request_id}."""
        # Check in-flight first
        job = self._in_flight.get(request_id)
        if job and job.response:
            return 200, job.response

        # Check durable ledger
        res = get_by_request_id(request_id, db_path=self.db_path)
        if not res.found or res.entry is None:
            return 404, make_http_error(
                code="REQUEST_NOT_FOUND",
                request_id=request_id,
                message="request ID not found",
            )

        entry = res.entry
        try:
            receipt_dict = json.loads(entry.receipt_bytes.decode("utf-8"))
        except Exception:
            receipt_dict = None
        try:
            env_dict = json.loads(entry.envelope_bytes.decode("utf-8"))
        except Exception:
            env_dict = None

        resp = make_http_response(
            request_id=request_id,
            state="COMPLETED" if entry.factual_disposition != "REJECTED" else "FAILED",
            generation=entry.committed_generation,
            acquisition=None,
            execution=None,
            evidence=env_dict,
            verification=receipt_dict.get("verification") if receipt_dict else None,
            disposition=entry.factual_disposition,
            receipt=receipt_dict,
            claim_ceiling=entry.claim_ceiling,
        )
        return 200, resp

    async def get_receipt(self, request_id: str) -> tuple[int, dict[str, Any]]:
        """GET /v1/certifications/{request_id}/receipt."""
        job = self._in_flight.get(request_id)
        if job:
            if job.state in {"PENDING", "RUNNING"}:
                return 409, make_http_error(
                    code="RESULT_NOT_READY",
                    request_id=request_id,
                    message="certification result is not ready",
                )
            if job.receipt_bytes:
                try:
                    return 200, json.loads(job.receipt_bytes.decode("utf-8"))
                except Exception:
                    pass

        res = get_by_request_id(request_id, db_path=self.db_path)
        if not res.found or res.entry is None:
            return 404, make_http_error(
                code="REQUEST_NOT_FOUND",
                request_id=request_id,
                message="request ID not found",
            )

        try:
            receipt_dict = json.loads(res.entry.receipt_bytes.decode("utf-8"))
            return 200, receipt_dict
        except Exception:
            return 404, make_http_error(
                code="REQUEST_NOT_FOUND",
                request_id=request_id,
                message="receipt data unavailable",
            )

    async def verify_receipt(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """POST /v1/receipts/verify."""
        errs = validate_receipt_verify_request(payload)
        if errs:
            return 422, make_http_error(
                code="RECEIPT_INVALID",
                request_id=None,
                message=errs[0],
            )

        receipt = payload["receipt"]
        requested_scope = payload["requested_scope"]
        original_inputs = payload.get("original_inputs")

        # Check structural envelope validity
        claimed_hash = receipt.get("receipt_hash")
        if not claimed_hash or not isinstance(claimed_hash, str):
            return 422, make_http_error(
                code="RECEIPT_INVALID",
                request_id=None,
                message="receipt missing receipt_hash",
            )

        body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
        expected_hash = _hash(body)
        if claimed_hash != expected_hash:
            return 422, make_http_error(
                code="RECEIPT_INVALID",
                request_id=None,
                message="receipt_hash does not match canonical receipt body",
            )

        # Full recomputation scope
        if requested_scope == "FULL":
            if not original_inputs or not isinstance(original_inputs, dict):
                return 200, {
                    "scope": "FULL_RECOMPUTED",
                    "status": "UNVERIFIABLE",
                    "reason_codes": ["MISSING_ORIGINAL_INPUTS"],
                    "receipt_hash": claimed_hash,
                    "recomputed_hash": None,
                    "claim_ceiling": list(CLAIM_CEILING),
                }

            # Attempt full recomputation
            try:
                raw_c = original_inputs["acceptance_contract"]
                raw_cs = original_inputs["change_set"]
                raw_p = original_inputs["verification_plan"]
                raw_e = original_inputs["evidence"]

                contract = AcceptanceContract(
                    contract_id=raw_c["contract_id"],
                    requirements_hash=raw_c["requirements_hash"],
                    required_verifier_ids=tuple(raw_c["required_verifier_ids"]),
                    allowed_paths=tuple(raw_c["allowed_paths"]),
                    deletion_policy=raw_c["deletion_policy"],
                )
                change_set = ChangeSet(
                    change_set_id=raw_cs["change_set_id"],
                    source_revision=raw_cs["source_revision"],
                    target_revision=raw_cs["target_revision"],
                    diff_hash=raw_cs["diff_hash"],
                    paths=tuple(raw_cs["paths"]),
                )
                plan = VerificationPlan(
                    plan_id=raw_p["plan_id"],
                    acceptance_contract_hash=contract.hash,
                    change_set_hash=change_set.hash,
                    required_verifier_ids=tuple(raw_p["required_verifier_ids"]),
                )
                obs_list = tuple(
                    Observation(
                        verifier_id=item.get("verifier_id", item.get("method", "pytest")),
                        artifact_id=item["artifact_id"],
                        artifact_hash=item["artifact_hash"],
                        status=ObservationStatus(item["status"]),
                    )
                    for item in raw_e["observations"]
                )
                evidence = EvidenceBundle(
                    bundle_id=raw_e["bundle_id"],
                    acceptance_contract_hash=contract.hash,
                    change_set_hash=change_set.hash,
                    verification_plan_hash=plan.hash,
                    observations=obs_list,
                )

                policy_data = receipt.get("certification", {}).get("policy", {})
                policy = CertificationPolicy(
                    accepted=policy_data.get("accepted"),
                    authority_present=policy_data.get("authority_present"),
                    approval_present=policy_data.get("approval_present"),
                    signing_present=policy_data.get("signing_present"),
                )

                cert_input = CertificationInput(
                    contract=contract,
                    change_set=change_set,
                    plan=plan,
                    evidence=evidence,
                    policy_accepted=policy.accepted if policy.accepted is not None else True,
                    authority_present=policy.authority_present
                    if policy.authority_present is not None
                    else True,
                    approval_present=policy.approval_present
                    if policy.approval_present is not None
                    else True,
                    signing_present=policy.signing_present
                    if policy.signing_present is not None
                    else True,
                )
                recomputed = certify(cert_input).receipt
                recomputed_hash = recomputed.hash

                if recomputed_hash == claimed_hash:
                    return 200, {
                        "scope": "FULL_RECOMPUTED",
                        "status": "VALID",
                        "reason_codes": [],
                        "receipt_hash": claimed_hash,
                        "recomputed_hash": recomputed_hash,
                        "claim_ceiling": list(CLAIM_CEILING),
                    }
                else:
                    return 200, {
                        "scope": "FULL_RECOMPUTED",
                        "status": "INVALID",
                        "reason_codes": ["RECOMPUTED_HASH_MISMATCH"],
                        "receipt_hash": claimed_hash,
                        "recomputed_hash": recomputed_hash,
                        "claim_ceiling": list(CLAIM_CEILING),
                    }
            except Exception:
                return 422, make_http_error(
                    code="RECEIPT_INVALID",
                    request_id=None,
                    message="failed to recompute receipt from original_inputs",
                )

        # ENVELOPE_ONLY or AUTO
        return 200, {
            "scope": "ENVELOPE_ONLY",
            "status": "VALID",
            "reason_codes": [],
            "receipt_hash": claimed_hash,
            "recomputed_hash": None,
            "claim_ceiling": list(CLAIM_CEILING),
        }

    def stop_admission(self) -> None:
        """Stop admitting new requests."""
        self._admission_stopped = True

    async def drain(self, timeout: float = 30.0) -> None:
        """Wait for in-flight requests to finish, canceling if timed out."""
        self.stop_admission()
        tasks = [job.task for job in self._in_flight.values() if job.task and not job.task.done()]
        if not tasks:
            return

        done, pending = await asyncio.wait(tasks, timeout=timeout)
        for p in pending:
            p.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


__all__ = [
    "InFlightJob",
    "RuntimeCertificationService",
]
