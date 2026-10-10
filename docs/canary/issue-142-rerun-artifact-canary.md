# Nexus Core Issue #142 live artifact rerun canary

This PR exists only to exercise the default-branch-owned issue-gate and
receipt-verify GitHub Actions with the merged exact artifact-ID selection fix.

The canary contract checks both rerun all jobs and rerun only the verify job
against the same workflow run ID. It must preserve the exact producer artifact
identity across attempts and reject any stale or substituted artifact.

This fixture PR is not intended for merging. Preserve its GitHub Actions run
and artifact evidence, then close the fixture PR without merging.
