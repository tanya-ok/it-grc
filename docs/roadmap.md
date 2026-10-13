# Development milestones

## IT GRC rework

IT GRC pushes executed lab evidence into CISO Assistant Community edition as the GRC system of record. See [ADR 0001](adr/0001-ciso-assistant-system-of-record.md).

- [x] 0. Record the decision, rename the project and rewrite the license notice.
- [x] 1. Deploy: CISO Assistant CE v4.1.1 in the dedicated `it-grc` Lima VM with k3s and the official Helm chart, images pinned by digest. Verified on 2026-10-13; see [Deployment](deployment.md).
- [x] 2. Client and bootstrap: REST client, dedicated domain, Analyst-group user, short-lived token, NIST SP 800-66 rev2 library loaded by URN, administrator password rotation. Verified on 2026-10-13; see [Bridge](bridge.md).
- [x] 3. Mapping and push: lab scenarios mapped to requirement URNs; evidence revisions, applied controls and capped results pushed. Verified on 2026-10-13; see [Mapping and push](mapping.md).
- [x] 4. Verify and ledger: every push read back and recorded in a local hash-chained ledger with a checkpoint; later deletions or edits detected. Verified on 2026-10-13; see [Ledger and verification](bridge.md#ledger-and-verification).
- [x] 5. Demo and docs: prototype removed (retained at the local tag `v0.1.1-prototype`), `make grc-demo` and `it-grc summary`, the [demo walkthrough](demo.md) with CISO Assistant screenshots, and documentation rewritten for publication. Verified on 2026-10-13.
- [x] 6. CI: lint, strict types, offline tests including the result ceiling and lookup assertions, gitleaks, and the mapping contract against the pinned upstream library. Checked with actionlint on 2026-10-13; no remote run yet. See [Continuous integration](publication-readiness.md#continuous-integration).

## Prototype

The prototype (version 0.1.1, local tag `v0.1.1-prototype`) built a standalone review UI with its own rules, a synthetic HIPAA-oriented case, local model drafts and an optional Kubernetes profile. Its milestones were completed on 2026-10-06 and 2026-10-07. ADR 0001 replaced it with CISO Assistant as the system of record, and phase 5 removed its code and dated records from the branch; they remain at the tag.
