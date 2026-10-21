# Proposed AI Assurance profile

**Pending maintainer review. No installation or execution evidence is included.**

Scope: Offline synthetic lab-report ingestion, evidence ledger and CISO Assistant API contract; no live CE verification or compliance certification.

Prepared base: `38b10a9efc6a1c4cf977a616e7b3799be300f2b2`.
This base revision is not published; verify its remote availability before opening.
Candidate source: AI Assurance 0.2.1, commit
`353d374a00b43479870a6dee300dd200529cc60c`, verified locally against an immutable Git bundle.
This source revision is not published; remote availability must be checked before adoption.
The source checkout and CLI must be trusted separately from a target lock.

| Control | Proposed bounded claim | Existing evidence surface |
|---|---|---|
| access-boundary | API operations use explicit scoped configuration and refuse unsafe prerequisites. | `tests/test_grc_client.py`, `tests/test_grc_ops.py` |
| data-exposure | CLI and report validation do not include private credentials in assessment output. | `tests/test_cli.py`, `tests/test_lab_report.py` |
| untrusted-instructions | Imported report content is validated as evidence and never grants execution authority. | `tests/test_lab_report.py`, `tests/test_grc_push.py` |
| consequential-actions | The push bridge preserves its review/result ceiling and does not auto-approve evidence. | `tests/test_grc_push.py`, `tests/test_grc_mapping.py` |
| evidence-lineage | Ledger tampering is checked against retained evidence and checkpoint contracts. | `tests/test_grc_ledger.py` |
| bounded-claims | Mapping and repository checks distinguish missing evidence from failure and retain scope limits. | `tests/test_grc_mapping.py`, `tests/test_validate_repository.py` |

CI workflow: `.github/workflows/ci.yml`. Candidate checks: `test (3.12)`, `test (3.13)`, `test (3.14)`.
These names come from workflow definitions. Before accepting records, match the
actual provider job names, exact project commit, completed job conclusion and
run URL. A CI suite's success is coarse evidence; it cannot establish untested
claims or substitute for review of individual test coverage.

All six controls are proposed for scoped review, with missing proof retained as
`not_verified`. This is not an accepted applicability decision. Only a maintainer
may approve or change applicability. Any future exclusion needs rationale and
`decided_by`. Agents must not manufacture executed records or approve exclusions.

Private repository: the current public-only installer cannot verify its CI and must refuse installation. A separately reviewed private CI collector is required. Offline fake API tests are not live CISO Assistant acceptance.

## Adoption gate

1. Review claims and approve the project-specific profile; keep limitations.
2. Use a trusted collector to select real CI evidence for an existing full
   40-hex project commit, a non-future timestamp, and a run URL or artifact hash.
   The current installer also requires publicly verifiable GitHub run/job metadata.
3. Keep records outside this proposal until independently collected. There are
   no empty evidence arrays or fabricated execution outcomes here.
4. Obtain explicit installation approval. Then use the separately reviewed CLI,
   source commit and approved candidate. Do not install by copying this directory.

`proposal.json` is a review envelope, deliberately not an installer input.
No `.ai-assurance/` directory, managed AGENTS block, workflow, dependency, tracker
integration or model call is added. No publication, deployment or certification
is implied. Linear and other trackers remain optional adapters.
