# Nexus Verify Public Operations Policy

Status: G4A operating contract. External enforcement must be proven after deployment in G4B.

## Hosting boundary

Production/public hosting is not owned by Nexus Core truth authorities. The hosting plane may provide TLS termination, service credentials, rate limiting, redacted logs, metrics, health checks, and rollback. It must not add verification or completion semantics.

The production MCP endpoint must use stable HTTPS and Streamable HTTP at a stable `/mcp` URL. Temporary tunnels do not satisfy public-review readiness.

## Authentication and GitHub access

v0 is anonymous to the end user and public-repository-only.

If a service credential is used to increase GitHub API capacity:

- use only `NEXUS_VERIFY_PUBLIC_GITHUB_TOKEN`;
- never fall back to `GITHUB_TOKEN` or `NEXUS_VERIFY_GITHUB_TOKEN`;
- use a dedicated service identity with no intended private-repository access;
- verify repository visibility is public before pull-request acquisition;
- never return or log the credential.

Private repository access requires a later OAuth 2.1 design and is not enabled by v0.

## Abuse and rate limiting

The initial public host must enforce all of the following before G4B can be considered ready:

- per-client or anonymized-subject request limiting where a stable host-provided subject is available;
- source-IP fallback limiting at the edge;
- bounded concurrent MCP tool calls;
- upstream GitHub timeout and total request timeout;
- 429 responses or bounded tool errors when limits are exceeded;
- no automatic retry loop that can multiply GitHub reads after an uncertain result.

Target initial limits for a limited pilot:

- 10 tool calls per minute per client subject;
- burst of 5 concurrent tool calls per subject;
- 60 tool calls per minute service-wide before explicit capacity review.

These are operating defaults, not user entitlements or an SLA.

## Logging

Allowed operational log fields:

- timestamp;
- result class/status;
- latency bucket;
- HTTP/MCP status class;
- redacted repository locator or one-way locator hash;
- anonymized client subject hash when available;
- deployment revision.

Do not write to normal application logs:

- raw Nexus receipts;
- raw diff bodies;
- GitHub authorization headers/tokens;
- MCP authorization headers;
- full ChatGPT conversation content;
- arbitrary tool input/result payloads.

Production logs must apply structured redaction before emission.

## Retention

Default operational log retention is at most 7 days.

Longer security-incident retention requires a documented incident reason and restricted access.

## Monitoring

Production monitoring should cover:

- failed MCP initialization;
- tool-call error rate;
- GitHub 401/403/404/429/5xx classes;
- latency and timeout rate;
- rate-limit denials;
- unexpected private-repository attempts;
- schema/tool-definition drift.

Metrics must not embed receipt bodies, raw diffs, credentials, or full prompts.

## Rollback and removal

Every production deployment must retain an exact previous known-good revision and support bounded rollback.

Rollback triggers include:

- accidental private-data exposure;
- authentication/authorization regression;
- tool schema drift not reflected in review;
- incorrect mutation capability;
- claim-ceiling violation;
- sustained error/timeout rate above the pilot's operating threshold;
- OpenAI review or policy request.

Emergency response order:

1. disable/remove public routing to the MCP endpoint;
2. preserve minimal redacted incident evidence;
3. rotate affected service credentials if relevant;
4. roll back to the last known-good version only if safe;
5. refresh the plugin/tool definition before re-enabling.

Removal of the plugin or endpoint does not authorize deletion of unrelated repository evidence.
