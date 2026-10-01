# Nexus Verify Product Page Copy

Status: source copy for the future required HTTPS website URL.

## Nexus Verify

Verify whether an AI- or human-generated code-change completion claim is backed by evidence that is still valid for the exact current pull request.

Nexus Verify is read-only. It checks evidence integrity and applicability; it does not review code quality, execute repository code, write to GitHub, approve merges, release software, or deploy to production.

### Public v0

The initial public profile is intentionally limited to public GitHub pull requests and optional caller-supplied Nexus verification receipts.

Typical questions:

- “The agent says this PR is done. Is the verification evidence still current?”
- “Does this receipt apply to the current PR head?”
- “CI is green. Is there Nexus evidence that actually applies to this exact code state?”

### Result boundary

Nexus Verify may report evidence such as `VERIFIED`, `STALE_TARGET`, `TAMPERED`, `SUBJECT_MISMATCH`, or `UNVERIFIABLE`.

`VERIFIED` never means merge approval, release approval, deployment approval, general correctness, or security certification.

### Open source

Nexus Core is available at:

`https://github.com/James3014/nexus-core`

License: Apache-2.0.

The final production page must link to the final HTTPS support, privacy-policy, and terms URLs before submission.
