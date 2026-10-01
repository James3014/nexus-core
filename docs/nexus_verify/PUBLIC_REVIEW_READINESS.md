# Nexus Verify Public Review Readiness

Status: **G4A internal review package**. This document is not evidence of public deployment or OpenAI approval.

## Product boundary

Nexus Verify exposes one read-only MCP tool:

`verify_code_change_evidence`

Its job is to answer a narrow question: whether supplied Nexus verification evidence is internally valid and still applies to the exact current GitHub pull-request state.

The public-review v0 profile is intentionally limited to:

- public GitHub pull requests;
- caller-supplied Nexus receipt data when available;
- read-only GitHub acquisition;
- evidence integrity/applicability readback.

It does not:

- execute repository code;
- review code quality or security;
- write to GitHub;
- approve or merge a pull request;
- release or deploy software;
- support private repositories;
- accept user passwords, API keys, GitHub tokens, MFA codes, or other authentication secrets.

`VERIFIED` is evidence status, not merge, release, deployment, or production authority.

## Authentication model

The v0 public tool is anonymous (`noauth`) because it serves public GitHub data plus explicit caller-supplied receipt bytes.

Private-repository support is deliberately deferred. Adding it requires a separate OAuth 2.1 design and review. The production public host must use a dedicated service-side GitHub credential through `NEXUS_VERIFY_PUBLIC_GITHUB_TOKEN` for API capacity while keeping the user-facing tool `noauth`. The adapter verifies repository visibility before reading PR data and never falls back to developer or generic `GITHUB_TOKEN` variables.

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
