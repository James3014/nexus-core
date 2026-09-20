# GitHub Repository Golden Path (G2)

G2 exposes one repository-level GitHub Actions path over the existing local
Golden Path. It runs the verifier configured in `.nexus-core/config.toml`, derives
facts from the physical checked-out Git repository, calls the canonical Core
adapter through `check_repository()`, and writes the same durable local
verification receipt. Users do not author canonical protocol JSON and do not
install another Nexus repository.

This is a self-hosted-runner path only. It does not support GitHub-hosted runners.
Running repository verifier code on a self-hosted machine is appropriate only for
trusted repository contributors and trusted branches. Public or otherwise
untrusted fork pull-request verification is unsupported in G2; do not remove the
workflow guard or weaken the admission checks to enable it. Use a separately
designed sandbox/security boundary for that future use case.

Copy [`examples/github-repository-check.yml`](examples/github-repository-check.yml)
to the consuming repository's `.github/workflows/` directory. The self-hosted
runner must already have the candidate `nexus-core` package and the repository's
verifier dependencies installed. G2 makes no public package release or GitHub
Marketplace claim.

Before checkout, the example job condition skips fork pull requests. At process
entry, repository mode independently fails closed unless all of these are true:

- `RUNNER_ENVIRONMENT` is exactly `self-hosted`;
- `GITHUB_REPOSITORY` is a single unambiguous `owner/name` identity;
- `GITHUB_EVENT_PATH` is readable JSON whose repository identity exactly matches
  `GITHUB_REPOSITORY`;
- the event is `push`, or it is `pull_request` with matching base and head
  repositories and an explicit non-fork head.

Admission happens before `check_repository()` starts the verifier. Repository mode
does not accept `--token-file`, does not read a token or secret, and does not use
the HTTP runtime. GitHub environment and event identities are admission and output
metadata only. The physical checkout and canonical Core adapter remain the source
of factual verification truth.

The action outputs are `verification-status`, `receipt-file`, `certification`,
`github-repository`, and `github-event-name`. `certification` is always `null` in
this mode. A successful result is `VERIFIED (not CERTIFIED)`; it is not approval,
Candidate acceptance, merge authority, release authority, or a production claim.

The older request-file mode remains available for existing consumers:

```bash
python -m product.clients.github_action \
  --request-file request.json \
  --token-file /protected/path/token \
  --service-url http://127.0.0.1:8767
```

That mode retains its self-hosted-runner requirement, loopback service URL
requirement, protected token read, and canonical HTTP behavior. The two modes are
mutually exclusive.
