# Security Policy

## Supported versions

`tempogate` is pre-1.0. We support fixes against the latest tagged release on `main`. Older lines are not patched until 1.0.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Use [GitHub Security Advisories](https://github.com/onhotpath/tempogate/security/advisories/new) for private, coordinated disclosure. Include:

- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal proof-of-concept.
- Affected versions or commits.
- Any mitigations you're aware of.

We aim to:

- Acknowledge within **3 business days**.
- Provide an initial assessment within **7 business days**.
- Coordinate a fix and a disclosure timeline with you.

If you don't get a response, please escalate by opening a *non-sensitive* GitHub issue asking us to check the advisory inbox — without disclosing details.

## Scope

In scope:

- The `tempogate` binary and its published container images.
- The Helm chart and other artifacts under `examples/`.
- CI/CD pipeline configurations in this repo.

Out of scope:

- Vulnerabilities in third-party dependencies — please report those upstream. We will of course bump pinned versions when fixes land.
- Issues in your operator-supplied configuration (TLS termination, ingress rules, secrets management, etc.).
- Self-hosted Temporal itself — report those to the [Temporal project](https://github.com/temporalio/temporal/security).
