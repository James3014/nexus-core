# Nexus Verify Public Review Readiness

Status: **G4A internal review package**. This document is not evidence of public deployment or OpenAI approval.

## Product boundary

Nexus Verify exposes one read-only MCP tool:

`verify_code_change_evidence`

Its job is to answer a narrow question: whether supplied Nexus verification evidence is internally valid, authenticated as CI-produced, and still applies to the exact current GitHub pull-request state.

The public-review v0 profile is intentionally limited to:

- public GitHub pull requests;
- caller-supplied Nexus receipt data when available, with the receipt's Sigstore bundle;
- read-only GitHub acquisition;
- receipt authentication, evidence integrity and applicability readback.

It does not:

- execute repository code;
- review code quality or security;
- write to GitHub;
- approve or merge a pull request;
- release or deploy software;
- trust a receipt without its CI signature: a receipt with no Sigstore bundle, or one whose bundle does not verify, is `UNVERIFIABLE` (see Receipt authentication);
- support private repositories;
- accept user passwords, API keys, GitHub tokens, MFA codes, or other authentication secrets.

`VERIFIED` is evidence status, not merge, release, deployment, or production authority.

## Authentication model

The v0 public tool is anonymous (`noauth`) because it serves public GitHub data plus explicit caller-supplied receipt bytes.

Private-repository support is deliberately deferred. Adding it requires a separate OAuth 2.1 design and review. The production public host must use a dedicated service-side GitHub credential through `NEXUS_VERIFY_PUBLIC_GITHUB_TOKEN` for API capacity while keeping the user-facing tool `noauth`. The adapter verifies repository visibility before reading PR data and never falls back to developer or generic `GITHUB_TOKEN` variables.

## Receipt authentication

A receipt's `receipt_hash` is an unkeyed SHA-256, so it only shows the receipt is self-consistent. Since #231 the tool also checks authenticity. The caller supplies the CI receipt's exact bytes and its Sigstore bundle in `receipt_signature`:

```json
{"receipt_base64": "<base64 of <receipt>.json>", "sigstore_bundle": {"...": "<contents of <receipt>.json.sigstore.json>"}}
```

The service verifies the bundle the way the `receipt-verify` action does (`sigstore verify github`). The OIDC issuer must be GitHub Actions. The certificate identity must be the subject repository's `nexus-core-issue-completion.yml` workflow on `refs/heads/main`. The workflow-repository extension must be that same repository. The signature, certificate chain and Rekor entry must verify for the exact receipt bytes, and those bytes must decode to the supplied `receipt` object. The tool caller cannot choose the signer; a host can configure a different workflow file of the same repository.

Only an authenticated receipt can produce `APPLIES` or `VERIFIED`. Otherwise the result is `UNVERIFIABLE` / `NOT_AVAILABLE` with one of these reason codes:

- `RECEIPT_NOT_AUTHENTICATED`: no bundle; malformed bundle or bytes; bytes that are not the supplied receipt; or a signature from another identity, repository or content.
- `RECEIPT_AUTHENTICATION_UNAVAILABLE`: the optional `sigstore` package (`pip install 'sigstore>=4.5,<5'`; not a core dependency) or the Sigstore trust root is unavailable, so authentication could not run.

Authentication proves which workflow identity produced the receipt bytes. It does not prove the verifier is sufficient or that the Issue is semantically complete. The input and output schema ids are `nexus.verify-code-change-evidence.input.v2` / `.output.v2`.

## Tool contract

The public-review profile preserves the G3 tool name, input schema, output schema, and claim ceiling.

Required annotations:

- `readOnlyHint=true`
- `destructiveHint=false`
- `idempotentHint=true`
- `openWorldHint=true`

Required compatibility metadata:

- `securitySchemes=[{"type":"noauth"}]`
- bounded invocation status strings
- no UI resource
- no screenshots

## Listing package

Public submission ultimately requires externally hosted HTTPS URLs for:

- product website;
- support page;
- privacy policy;
- terms of service.

The source drafts live in this directory. G4A does not invent or reserve production URLs.

The submission pack also contains:

- exactly five positive review cases;
- exactly three negative review cases;
- release notes;
- a demo-recording plan;
- no screenshots because v0 has no custom UI.

## External activation gates

The following are deliberately not claimed by G4A:

- dedicated least-privilege service-side GitHub credential;
- stable public HTTPS `/mcp` endpoint;
- OpenAI individual/business publisher verification;
- `api.apps.write` and `api.apps.read` permission evidence;
- production domain ownership/verification;
- final website/support/privacy/terms HTTPS URLs;
- current portal tool scan;
- demo recording URL;
- plugin submission/review/publication.

Those belong to G4B external activation and require fresh observations and, where applicable, separate external-side-effect authorization.
