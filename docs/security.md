# Security model

IT GRC is a local proof of concept. It moves synthetic lab evidence from a host into CISO Assistant Community edition (CE) in a dedicated VM. This page lists its trust boundaries, the controls on each and what they do not cover. Report vulnerabilities privately as described in the repository's [security policy](https://github.com/tanya-ok/it-grc/blob/main/SECURITY.md).

## Boundaries and controls

| Boundary | Control | Details |
|---|---|---|
| Host to VM | One port forward, host `127.0.0.1:18443` to guest loopback; no host mounts, no SSH agent forwarding, no kubeconfig on the host | [Deployment](deployment.md#security-controls) |
| TLS | The client trusts only `deploy/.data/ca.pem`, verifies the host name, requires TLS 1.2 or newer, uses no proxy and follows no redirect | [Bridge](bridge.md#client-safety-rules) |
| Secrets | Owner-only files in the git-ignored `deploy/.data/` (0700). Never printed, logged, placed on a command line or in a Helm `--set`; Secrets reach the cluster on stdin only. Every printed line passes a redactor that knows every secret the run has read | [Bridge](bridge.md#secret-files) |
| Identity | A dedicated bridge user in the Analyst group of one domain, with a one-day personal access token; bootstrap refuses a superuser, an inactive user or any role other than Analyst | [Bridge](bridge.md#roles-why-analyst) |
| Writes | An allowlist of six routes and their fields. Results above `partially_compliant`, statuses above `in_review`, evidence approval, locking and every DELETE raise before a request is sent | [Mapping](mapping.md#result-ceiling) |
| Lookups | One-object lookups assert exactly one match; requirement lookups also assert the exact URN and an assessable node, because CE ignores unknown filters | [Bridge](bridge.md#lookups) |
| Input | The lab report passes a strict validator; only validated fields reach CE, free text is never uploaded | [Lab report digests](evidence-digests.md) |
| After the push | A local hash-chained ledger and checkpoint; `verify` reports drift and lists human decisions as `HELD` | [Ledger and verification](bridge.md#ledger-and-verification) |
| Supply chain | VM image, k3s, Helm, chart and container images pinned by digest and re-verified on every `make grc-up`; CI actions pinned by commit SHA; gitleaks over the full history | [Deployment](deployment.md#pins), [CI](publication-readiness.md#continuous-integration) |

## What the controls do not cover

- The Analyst role can approve evidence, lock audits and delete audits, and CE cannot narrow it. The bridge refuses those writes; the token itself could still make them. The ledger makes such changes visible to `verify` but cannot prevent them.
- The ledger and its checkpoint are unsigned and sit in the same directory. Anyone who can rewrite both files rewrites the history without detection.
- Anyone who can read `deploy/.data/` acts as the bridge user, and with the administrator password as the administrator.
- `verify` cannot tell a reviewer from someone who uses the Analyst token. Review every `HELD` line in CE.
- One node, one replica and SQLite. No high availability and no automated backup.

## Claims discipline

- Lab evidence on synthetic data is not HIPAA compliance. NIST SP 800-66 rev2 is guidance for implementing the HIPAA Security Rule, not the rule itself.
- `partially_compliant` means lab evidence exists for part of a key activity, nothing more. `compliant`, `not_applicable` and `done` are human decisions.
- Missing evidence stays `not_verified`. A proven lab failure is the only source of `non_compliant`.
- Saved lab reports are dated evidence, not proof of the current cluster state.

See [independent provenance](provenance.md) for the permitted inputs and the license boundary with CE.
