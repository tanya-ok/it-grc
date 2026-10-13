# Security policy

## Supported versions

Only the latest commit on `main` is supported. The current version is 0.2.0. There are no
release branches and no backports.

## Reporting a vulnerability

Report privately through GitHub Security Advisories: open the Security tab of this
repository and use **Report a vulnerability**. Please do not open a public issue, pull
request or discussion for a security report.

Use synthetic reproductions only. Never include real patient data, credentials or other
secret values in a report.

Expect an acknowledgement within seven days. If a fix is needed, the advisory stays private
until the fix is on `main`.

## Scope

In scope:

- The bridge in `src/it_grc`: the REST client, bootstrap and token handling, the mapping,
  push, verify and the local ledger, and the lab-report validator.
- The lifecycle script `scripts/grc_lab.py`, the VM profile and Helm values in `deploy/`,
  and the mapping contract check.
- The GitHub Actions workflows.

Threat model notes:

- CISO Assistant Community edition runs unmodified in the dedicated `it-grc` Lima VM and is
  reached only through `https://localhost:18443` on host loopback. The client trusts only
  `deploy/.data/ca.pem`, sends no request through a proxy and follows no redirect.
- Secrets (administrator and bridge passwords, the bridge token, the Django key) live only in
  owner-only files under the git-ignored `deploy/.data/`. They are never printed, logged,
  placed on a command line or written to the ledger.
- The bridge token belongs to a user in the Analyst group of one dedicated domain. CE cannot
  narrow that role: the token itself could approve evidence, lock or delete audits. The
  bridge refuses such writes through an allowlist and caps results at `partially_compliant`
  with status `in_review`. The ledger makes later changes visible; it is unsigned and does
  not resist someone who controls the host.
- Lab reports are untrusted input. Only validated fields reach CISO Assistant; free text in a
  report is never uploaded.

Out of scope: attacks that require an already compromised local account, vulnerabilities in
CISO Assistant, Lima, k3s, Helm, Caddy or sibling repositories, and the synthetic content of
the lab report. This project does not establish HIPAA compliance.

This project has no telemetry.
