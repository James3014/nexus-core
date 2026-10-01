# Nexus Verify Privacy Policy Draft

Status: source draft for G4A. Publish only after final legal/domain review.

## Scope

This draft covers the proposed public Nexus Verify v0 MCP service. The v0 service is designed for public GitHub pull requests and caller-supplied Nexus verification receipts. It does not support private repositories or user-account linking.

## Data we process

### Tool inputs

The service may receive:

- GitHub repository owner;
- GitHub repository name;
- pull-request number;
- an optional Nexus verification receipt supplied by the caller.

The tool does not request passwords, API keys, access tokens, MFA/OTP codes, payment-card information, health information, government identifiers, precise location, or a full chat transcript.

### Public GitHub data

To answer the request, the service reads public GitHub API data required for evidence binding, including:

- pull-request base/head commit identity;
- Git tree identity;
- pull-request diff bytes used to derive a hash;
- changed and deleted paths;
- check-run identity and status metadata;
- repository visibility.

### Operational metadata

The production hosting layer may process limited operational metadata needed for abuse prevention, availability, and incident response, such as coarse request timing, status class, latency, and an anonymized client subject when the host provides one.

## Why we process data

We process the above data only to:

1. verify receipt integrity;
2. compare evidence with the exact current pull-request state;
3. return a bounded factual result;
4. protect service availability and investigate operational failures.

We do not use tool inputs or results to train models, build advertising profiles, or sell personal data.

## Recipients and subprocessors

The service sends the public repository locator to GitHub's official API to retrieve public repository data.

The hosted service may use infrastructure providers for compute, networking, logs, and monitoring. Final production subprocessors must be listed on the published policy before launch.

OpenAI/ChatGPT or Codex may transmit tool arguments to the MCP service as the client selected by the user; OpenAI's own handling is governed by its policies.

## Retention

The v0 production policy is:

- raw Nexus receipt bodies: not written to durable application logs;
- raw GitHub diff bodies: not written to durable application logs;
- tool inputs/results: not persisted as application records after the request completes;
- operational logs: retain only redacted metadata for at most **7 days**, then delete automatically;
- security/incident records: may be retained longer only when necessary to investigate a documented security incident or meet legal obligations, with access restricted to the minimum required personnel.

G4A defines this policy but does not claim external-host enforcement until G4B deployment evidence exists.

## User controls

Because v0 has no user account and no durable tool-result store, most request data expires with the request or log-retention window.

For a privacy or deletion request about retained operational data, contact the support route listed in `SUPPORT.md`. Requests must include enough non-secret information to identify the relevant interaction without sending passwords or access tokens.

## Security

The v0 service is read-only and public-repository-only. It validates tool inputs server-side, rejects private repositories in the public-review profile, and does not execute repository code.

Security vulnerabilities should be reported through the repository's private vulnerability-reporting route described in the root `SECURITY.md`.

## Changes

Material changes to data categories, purposes, recipients, retention, authentication, or private-repository support require an updated policy and a new review of the affected MCP tool definition.
