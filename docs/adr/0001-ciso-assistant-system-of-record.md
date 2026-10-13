# ADR 0001: CISO Assistant Community edition as the GRC system of record

- Status: Accepted
- Date: 2026-10-13
- Deciders: Tanya Babitskaya

## Context

The prototype (tag `v0.1.1-prototype`) reimplemented a small GRC tool: its own
control catalog, findings model, review states, report export and web UI. That was
a mistake. A GRC system of record needs framework libraries, audits, evidence
revisions, applied controls, roles and an audit trail. Rebuilding those adds no
value to the evidence that the security lab actually produces, and a homemade
catalog is harder to trust than a maintained public one.

The useful part of the project is the bridge: executed lab scenarios with capture
time, producer revisions and digests. A spike on 2026-10-13 against CISO Assistant
Community edition (CE) v4.1.1 confirmed that its REST API can hold that evidence:
personal access tokens, domains, perimeters, audits, requirement assessments,
evidence revisions with server-side SHA-256 hashes and applied controls.

## Decision

- Use the intuitem CISO Assistant Community edition v4.1.1 as the GRC system of
  record. Run the unmodified upstream images, pinned by digest:
    - backend `ghcr.io/intuitem/ciso-assistant-community/backend@sha256:15f31d4eacd3b60e4c08dca206f608adb6db44fc8a0a1f9ad81bf7edc9f2e410`
    - frontend `ghcr.io/intuitem/ciso-assistant-community/frontend@sha256:4a0bd757b9eb5d05555a048f498401d3bde6f8bead554fa12d17fbc099907a7b`
- Deploy it in a dedicated Lima VM named `it-grc` with k3s and the official Helm
  chart `oci://ghcr.io/intuitem/helm-charts/ce/ciso-assistant`, version 0.13.3.
  The shared `security-lab` VM stays separate.
- Assess against the public NIST SP 800-66 rev2 (HIPAA) framework from the upstream
  library `urn:intuitem:risk:library:nist-sp-800-66-rev2`, loaded through the API.
- IT GRC talks to CISO Assistant only over its REST API. It authenticates with a
  personal access token of a dedicated user in the Analyst group of a dedicated
  domain that holds only synthetic lab evidence.

## Consequences

### License boundary

- CISO Assistant CE is AGPL-3.0-or-later. IT GRC runs it unmodified as an external
  service and exchanges data over HTTP only.
- No upstream source code, serializers, API schemas or library YAML are copied into
  this repository. It stays Apache-2.0.
- Modifying CISO Assistant would bring AGPL source-offer duties. This decision
  avoids modifying it.

### Least privilege within CE limits

CE has no service accounts (`/iam/service-accounts/` answers "This feature is not
enabled") and no custom roles. The Analyst role can approve evidence, lock audits
and delete audits. Mitigations:

- A dedicated domain, so the token cannot reach other domains.
- Short-lived tokens (one day by default), created per run.
- A local append-only ledger of every write the bridge makes, so a later
  deletion or edit in CISO Assistant is detectable.
- Tests that the bridge never approves evidence, never locks or deletes audits and
  never sets a result above its ceiling.

### API lookups

Unknown query filters are silently ignored. In the spike,
`requirement=<urn>` returned all 179 requirement assessments of an audit, and a
write landed on a non-assessable node. Only `requirement__urn` filtered correctly.
Every lookup therefore asserts exactly one match, that the match is assessable and
that its URN equals the expected URN, before any write.

### Result ceiling

The bridge sets at most result `partially_compliant` with status `in_review`.
`compliant` and `done` are human decisions made in CISO Assistant. Evidence stays
unapproved until a human reviews it.

### Secrets

Secrets (admin password, database password, Django secret key, access tokens) are
read only from owner-only files. They never appear in compose `environment`
blocks, Helm `--set` arguments, process command lines or shell history.

### Prototype code

The prototype UI, rules and model code stay in the repository until phases 2 to 4
replace them. Dated evidence records from the prototype are kept unchanged.

## Alternatives considered

| Option | Outcome |
|---|---|
| Keep extending the prototype | Rejected: rebuilds a GRC tool instead of using one |
| Fork or modify CISO Assistant | Rejected: AGPL duties and upstream drift |
| CISO Assistant Enterprise edition | Not used: service accounts and custom roles would help, but CE is sufficient with the mitigations above |
| Run CISO Assistant inside `security-lab` | Rejected: mixes the GRC system of record with the system under test |

## Status update

2026-10-13, phase 5: the prototype was removed from the branch. This covers its web UI
and HTTP server, the local model client and model evaluation, review-state recovery, the
rule-based assessment engine with its HIPAA fixtures and control catalog, the Kubernetes
profile and container image, the packaging and install-verification scripts, and the
dated prototype records (`artifacts/demo/`, the acceptance and evaluation pages). All of
it stays available at the local tag `v0.1.1-prototype`. The strict lab-report validator
(`import_lab`) was kept as `it_grc.lab_report`; every push runs it before any request to
CISO Assistant. The decision above is unchanged.
