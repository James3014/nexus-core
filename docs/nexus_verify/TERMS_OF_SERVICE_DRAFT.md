# Nexus Verify Terms of Service Draft

Status: source draft for G4A. Publish only after final legal/domain review.

## Service

Nexus Verify is a read-only evidence-applicability service. It can compare an optional Nexus verification receipt with the exact current state of a public GitHub pull request.

The service is not a general code reviewer, security scanner, test generator, merge approver, release system, deployment system, or production certification authority.

## Public-repository-only v0

The proposed public v0 supports public GitHub repositories only. Do not submit private repository content, credentials, authentication secrets, personal secrets, regulated data, or data you are not authorized to process.

## Verification claim boundary

A `VERIFIED` result means the supplied evidence passed Nexus's defined integrity/applicability checks for the exact represented subject. It does not mean the code is bug-free, secure, approved for merge, approved for release, deployed, production-ready, or suitable for any particular purpose.

Users remain responsible for their own engineering, security, review, release, and deployment decisions.

## Acceptable use

Do not use the service to:

- access data you are not authorized to access;
- evade GitHub or OpenAI access controls or rate limits;
- submit credentials or secrets;
- overload, probe, or disrupt the service;
- misrepresent Nexus verification as a merge/release/deployment approval.

## Availability and changes

The service may be changed, rate-limited, suspended, or removed to protect security, reliability, legal compliance, or review requirements. Early public pilots may have limited capacity and no uptime SLA.

## Privacy

Data handling is described in `PRIVACY_POLICY_DRAFT.md`. The final published Terms must link to the final HTTPS privacy-policy URL.

## Warranty and liability

The service is provided on an as-available basis without a guarantee that evidence or tests capture all defects. Any final legal warranty/liability language must be reviewed before public launch.

## Contact

Use the support route defined in `SUPPORT.md`.
