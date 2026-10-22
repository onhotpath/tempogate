# Security Policy

## Supported versions

`tempogate` is pre-1.0. We support fixes against the latest tagged release on `main`. Older lines are not patched until 1.0.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Report privately through GitHub's private vulnerability reporting:

1. Sign in to GitHub.
2. Open <https://github.com/onhotpath/tempogate/security/advisories/new> (or the repository's **Security** tab, then **Report a vulnerability**).
3. Fill in the form and submit it. Only you and the maintainers can see the report.

Include:

- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal proof-of-concept.
- Affected versions or commits.
- Any mitigations you're aware of.

We aim to:

- Acknowledge within **3 business days**.
- Provide an initial assessment within **7 business days**.
- Coordinate a fix and a disclosure timeline with you.

If the form is not available, or you don't get a response, open a *non-sensitive* GitHub issue asking the maintainers for a private reporting channel or to check the advisory inbox.
Do not include any vulnerability details in that issue.

## Scope

In scope:

- The `tempogate` binary and its published container images.
- The Helm chart under `charts/` and the artifacts under `examples/`.
- CI/CD pipeline configurations in this repo.

Out of scope:

- Vulnerabilities in third-party dependencies — please report those upstream. We will of course bump pinned versions when fixes land.
- Issues in your operator-supplied configuration (TLS termination, ingress rules, secrets management, etc.).
- Self-hosted Temporal itself — report those to the [Temporal project](https://github.com/temporalio/temporal/security).
