# Mapping and push

Phase 3 maps the 18 executed lab scenarios to NIST SP 800-66 rev2 requirement nodes and pushes them into CISO Assistant as an audit with evidence revisions, one applied control and capped requirement results. The mapping is a versioned JSON file, `mappings/hipaa-800-66r2.json`, read with the Python standard library. See [ADR 0001](adr/0001-ciso-assistant-system-of-record.md) and [Bridge](bridge.md).

!!! warning "Claims discipline"
    Lab evidence on synthetic data is not HIPAA compliance. NIST SP 800-66 rev2 is guidance for implementing the HIPAA Security Rule, not the rule itself. A `partially_compliant` result means "lab evidence exists for part of this key activity", nothing more. `compliant`, `not_applicable` and `done` are human decisions in CISO Assistant.

## Commands

| Command | Make target | Effect |
|---|---|---|
| `it-grc push --report <path> --dry-run` | `make grc-push-dry-run` | Validates, reads CISO Assistant and lists the planned changes; writes nothing |
| `it-grc push --report <path>` | `make grc-push` | Applies the plan with the bridge token, then appends a record to the local ledger |
| `it-grc verify` | `make grc-push-verify` | Reads the audit back and compares it with the latest ledger record; exit 1 on drift |
| `it-grc summary` | `make grc-summary` | Read only: result and status counts, evidence coverage, evidence status and the applied control |
| all of the above in order | `make grc-demo` | Dry run, push, verify, ledger verify and summary; see [Demo](demo.md) |

The make targets read `REPORT`, which defaults to the retained fixture `fixtures/lab/demo-report-2026-10-13.json`. Pass `REPORT=../mcp-svid-auth/deploy/.data/demo-report.json` to push a fresh lab report. All writes use the bridge token (Analyst role). The administrator is not used.

## What push does

1. Validates the report with the strict lab-report validator (`import_lab`): 18 unique scenarios, a consistent verdict, a supported backend and a past capture time. It prints the canonical record digest (`json-sort-keys-compact-ascii-v1`).
2. Validates the mapping: schema, URN format, known references, every scenario covered and the result ceiling.
3. Checks the bridge token: user `bridge@example.org`, Analyst role only.
4. Resolves the domain `IT GRC Lab`, the perimeter `ITGRC-LAB` and the framework, each as exactly one match.
5. Looks up every mapped URN through `/requirement-nodes/?urn=`: exactly one row, URN equal, assessable, and name and section equal to the mapping. A changed library stops the push before any write.
6. Ensures the objects below, each found by its key before anything is created.
7. Sets result, status, observation, extended result and links on the mapped requirement assessments, then reads each one back.

| Object | Key | Created with |
|---|---|---|
| Audit | ref_id `ITGRC-800-66R2`, in the lab domain, perimeter and framework | status `in_progress`, never locked |
| Evidence, one per scenario group | exact name, which starts with the ref id (CE v4.1.1 evidence has no ref_id field) | name and description, no status |
| Evidence revision | SHA-256 of the group's JSON extract | uploaded only when it differs from the latest revision's stored `attachment_hash`, then checked against it |
| Applied control | ref_id `ITGRC-AC-KEY-ROTATION` | category, CSF function and evidence link, no status |
| Requirement assessment | audit id and `requirement__urn`, asserted as one assessable row with the exact URN | values from the mapping |

Each extract holds only validated fields: report digests, capture time, backend, producer revisions and the scenario ids, titles and outcomes of its group. Free text from the report is not uploaded. The same report always yields the same bytes, so a second push changes nothing and a new report adds one revision per group.

A failed basis scenario lowers that requirement to `non_compliant`, a proven lab failure rather than missing evidence. A failed supporting scenario is listed in the observation without changing the result.

## Result ceiling

| Rule | Enforcement |
|---|---|
| Results the bridge may set | `not_assessed`, `non_compliant`, `partially_compliant` |
| Statuses the bridge may set | `to_do`, `in_review` |
| Refused in the mapping | `compliant`, `not_applicable`, `done`, `in_progress`, and any ceiling other than `partially_compliant` / `in_review` |
| Refused on every write | an allowlist of six routes and their fields; anything else, including `is_locked`, `review_state`, evidence or applied control `status` and every DELETE, raises before a request is sent |
| Human decisions | a row that is locked, `compliant`, `not_applicable`, `in_progress`, `done` or review `accepted` is left unchanged and reported as `HELD` |
| Evidence | never approved. CE moves evidence to In review when a revision is uploaded |

The Analyst role itself can still approve, lock and delete. These rules limit the bridge, not the token. The local ledger makes later changes visible; see [Ledger and verification](bridge.md#ledger-and-verification).

## Evidence groups

| Evidence | Scenarios | What the lab shows |
|---|---|---|
| `ITGRC-EV-ACCESS` | S1, S2, S10 | Allowlisted workload identities call tools within their granted scopes (S1), a tool outside the granted scope is denied (S2) and a granted write succeeds (S10). |
| `ITGRC-EV-IDENTITY` | S3, S5, S8 | An unlisted SPIFFE identity is denied (S3), copied pod labels do not impersonate another ServiceAccount (S5) and the gateway calls upstream services with its own identity (S8). |
| `ITGRC-EV-ASSERTION` | S4, S6, S12, S13 | A cross-resource replay is denied (S4), an untrusted issuer is refused (S6), an expired assertion is refused after SVID renewal (S12) and strict mode rejects a reused assertion (S13). |
| `ITGRC-EV-FHIR-MTLS` | S15, S16, S17 | The FHIR gateway accepts the allowed SPIRE identity over mutual TLS with OAuth (S15) and refuses a disallowed identity (S16) and a client without a certificate (S17). |
| `ITGRC-EV-REVOCATION` | S9 | New tokens are denied after the grant is removed from the policy (S9). |
| `ITGRC-EV-KEY-ROTATION` | S11 | After a restart the new signing key is accepted, and a planned overlap keeps tokens signed with the old and the new key verifiable (S11). |
| `ITGRC-EV-AUDIT-CHAIN` | S14 | Audit record links verify and the checkpoint detects deletion of the log tail (S14). |
| `ITGRC-EV-FHIR-AUDIT` | S18 | FHIR audit records name the calling workload and keep patient ids only as HMAC values (S18). |
| `ITGRC-EV-IDENTITY-LIMITS` | S7, S10 | In explicit reuse mode a cached SVID is reused within its lifetime (S7), and a valid identity with a granted scope cannot prove the intent of a write (S10). |

## Mapped requirements

All 20 nodes are set to `partially_compliant` with status `in_review`. Node URNs are `urn:intuitem:risk:req_node:nist-sp-800-66-rev2:<node>`. Basis evidence decides the result; supporting evidence is linked only.

| Node | CFR | Key activity | Evidence (basis; supporting) | Extended result |
|---|---|---|---|---|
| `node211` | 164.312(a)(1) | 5. Implement Access Control Procedures Using Selected Hardware and Software | ACCESS; IDENTITY-LIMITS | observation_sensitive_point |
| `node57` | 164.308(a)(4)(ii)(B) | 2. Implement Policies and Procedures for Authorizing Access | ACCESS | |
| `node59` | 164.308(a)(4)(ii)(B) | Implementation Specification (Addressable) | ACCESS | |
| `node205` | 164.312(a)(2)(i) | 3. Ensure that All System Users Have Been Assigned a Unique Identifier | IDENTITY | |
| `node207` | 164.312(a)(2)(i) | Implementation Specification (Required) | IDENTITY | |
| `node258` | 164.312(d) | 3. Select and Implement Authentication Options | ASSERTION, FHIR-MTLS; KEY-ROTATION, IDENTITY-LIMITS | observation_sensitive_point |
| `node265` | 164.312(e)(2)(i) | 3. Implement Integrity Controls | FHIR-MTLS; KEY-ROTATION | |
| `node267` | 164.312(e)(2)(i) | Implementation Specification (Addressable) | FHIR-MTLS | |
| `node269` | 164.312(e)(2)(ii) | 4. Implement Encryption | FHIR-MTLS | |
| `node271` | 164.312(e)(2)(ii) | Implementation Specification (Addressable) | FHIR-MTLS | |
| `node225` | 164.312(a)(1) | 9. Terminate Access if it is No Longer Required | REVOCATION | |
| `node213` | 164.312(a)(1) | 6. Review and Update Access for Users and Processes | REVOCATION | |
| `node61` | 164.308(a)(4)(ii)(C) | 3. Implement Policies and Procedures for Access Establishment and Modification | REVOCATION | |
| `node63` | 164.308(a)(4)(ii)(C) | Implementation Specification (Addressable) | REVOCATION | |
| `node236` | 164.312(b) | 5. Implement the Audit/System Activity Review Process | AUDIT-CHAIN, FHIR-AUDIT | |
| `node230` | 164.312(b) | 2. Select the Tools that Will Be Deployed for Auditing and System Activity Reviews | AUDIT-CHAIN | |
| `node24` | 164.308(a)(1)(ii)(D) | Implementation Specification (Required) | AUDIT-CHAIN | |
| `node247` | 164.312(c)(2) | 5. Implement a Mechanism to Authenticate ePHI | AUDIT-CHAIN | |
| `node249` | 164.312(c)(2) | Implementation Specification (Addressable) | AUDIT-CHAIN | |
| `node228` | 164.312(b) | 1. Determine the Activities that Will Be Tracked or Audited | FHIR-AUDIT | |

The applied control `ITGRC-AC-KEY-ROTATION` "Signing key rotation with overlap" carries the S11 evidence and is linked to `node258` and `node265`. On its own it changes no result.

### Rationale and limits

Each entry carries a short rationale and limits text; the bridge writes both into the observation, with the mapping version and the CFR reference. The limits that matter most:

| Area | Limit written into the observation |
|---|---|
| Access control and unique identification | Workload identities and lab tools only; no person users, no documented authorization procedure, no workforce process |
| Authentication (164.312(d)) | Workload authentication only; person authentication and SMART on FHIR are not implemented |
| Transmission security | Lab SPIRE CA and a sandbox FHIR server; no transmission inventory, certificate lifecycle or production network |
| Revocation | Tokens issued before a revocation stay valid for up to 300 seconds |
| Audit controls and integrity | Audit records only, not ePHI; the checkpoint sits beside the log; no retention and no review process |
| FHIR audit | HMAC patient ids are pseudonymization, not de-identification |
| Sensitive points (S7, S10) | `observation_sensitive_point` on `node211` and `node258`: a cached SVID can be reused within its lifetime, and identity cannot prove intent |

## What stays not_verified

These 97 nodes keep result `not_assessed` and status `to_do`. Their observation starts with `not_verified:` so that missing evidence is visible and is not mistaken for a failure. The other 35 assessable nodes are not touched and stay at the CISO Assistant defaults.

| Gap | CFR | Nodes | Observation after `not_verified:` |
|---|---|---|---|
| physical-safeguards | 164.310 | 24 | physical safeguards are outside the lab; no facility, workstation, device or media evidence. |
| risk-analysis | 164.308(a)(1)(ii)(A) | 2 | no risk analysis was performed or supplied for the lab. |
| workforce-security | 164.308(a)(3) | 8 | no workforce authorization, clearance or termination procedure is evidenced. |
| security-awareness-training | 164.308(a)(5) | 11 | no security awareness or training evidence. |
| security-incident-procedures | 164.308(a)(6) | 5 | no incident response procedure or exercise is evidenced. |
| contingency-plan | 164.308(a)(7) | 12 | no backup, disaster recovery, emergency mode or contingency test evidence. |
| evaluation | 164.308(a)(8) | 5 | no periodic technical and nontechnical evaluation is evidenced. |
| business-associate-contracts | 164.308(b)(1) | 4 | no business associate contracts or other arrangements are evidenced. |
| emergency-access | 164.312(a)(2)(ii) | 2 | no emergency access procedure is evidenced. |
| automatic-logoff-and-encryption-at-rest | 164.312(a)(2)(iii), 164.312(a)(2)(iv) | 3 | automatic logoff and encryption at rest are not evidenced; the lab tests encryption in transit only. |
| transmission-inventory | 164.312(e)(1) | 1 | no inventory of ePHI transmission pathways; only the lab FHIR gateway path is tested. |
| organizational-requirements | 164.314 | 18 | business associate contract and group health plan requirements are not evidenced. |
| documentation-retention | 164.316(b)(2)(i) | 2 | no six-year documentation retention; lab reports have no retention policy. |

The lab is a technical test bed. Administrative, physical and organizational safeguards need documents, people and facilities that it does not have.

## URN verification

On 2026-10-13 every one of the 117 URNs was looked up against CE v4.1.1 with `GET /api/requirement-nodes/?urn=<urn>`. Each returned exactly one row with an equal URN and `assessable` true; the name and parent section were recorded in the mapping. No URN from the proposal needed a correction. The push repeats this check on every run.

## Verify and drift

Since phase 4 every push appends a record to the local ledger `deploy/.data/grc-ledger.jsonl`: the mapping digest, the validated report summary, the server ids of the audit, evidence objects, revisions and applied control, and the planned and observed result and status of every mapped requirement. `it-grc verify` rebuilds the plan from the latest complete record and the current mapping, then reports as drift:

- a missing or replaced audit, evidence object or applied control;
- a recorded revision that is missing or changed, a revision the ledger does not record, and a latest revision whose stored `attachment_hash` differs from the extract's SHA-256;
- a mapped requirement whose result, status, observation or extended result differs, or that lost an evidence or control link;
- an applied control that lost its evidence link;
- a mapping file that changed since the push, and a failed push after the latest complete one.

A mapped requirement held by a human decision (locked, `compliant`, `not_applicable`, `in_progress`, `done` or review `accepted`) is listed as `HELD`, not as drift. From the bridge's side, an edit by a reviewer and an edit made with the Analyst token look the same, so the HELD lines need a human review. Verify also prints result and status counts and the `evidence_coverage` summary of the audit. The ledger format, chain and checkpoint are described in [Ledger and verification](bridge.md#ledger-and-verification).

## Live run

2026-10-13, CE v4.1.1 in the `it-grc` VM, report captured 2026-10-13T07:51:16Z, record SHA-256 `de28b5bd...8b25`, mapping `2026-10-13.1`.

| Step | Result |
|---|---|
| `push --dry-run` | 137 planned changes: audit, 9 evidence objects, 9 revisions, 1 applied control, 117 requirement assessments; nothing written |
| `push`, first run | 138 changes: the 137 above plus one redundant evidence link on the applied control |
| `push`, second run | 1 change: the same link again. CE omits evidence links from applied-control list rows; the push now reads the control detail (fix commit) |
| `push`, after the fix | No changes |
| `verify` | Clean: audit, 9 evidence hashes, 1 applied control and 117 requirements match |
| Final `push --dry-run`, `push`, `verify` | 0 planned changes, no changes, clean |

| Measure | Value |
|---|---|
| Results (152 assessable) | partially_compliant 20, not_assessed 132 |
| Statuses | in_review 20, to_do 132 |
| Evidence coverage | with evidence 20 (direct only 18, direct and through the applied control 2), without evidence 132, 13.2 percent |
| Evidence status | 9 In review, none approved |
| Attachment check | Stored hashes equal the local SHA-256 for all 9 revisions; a download of one attachment hashed to the same value |

## Tests

`make check` runs the offline tests in `tests/test_grc_mapping.py` and `tests/test_grc_push.py` against the in-memory CE stand-in: mapping schema and URN format, refusal of `compliant` and `done` in the mapping and on every write, idempotency, a new revision only for a changed report, stored hash mismatch, wrong targets (an audit with the ref id in another perimeter, ignored filters, a changed library node, a locked audit, a token with a wider role), dry run without writes, held human decisions, drift detection including a deleted audit or evidence, a read-only `summary` that counts missing objects, and no secret in any output. `tests/test_cli.py` checks that `make grc-demo` runs the documented five steps on the fixture. The ledger tests are listed in [Bridge](bridge.md#tests).

## Fixture

`fixtures/lab/demo-report-2026-10-13.json` is a byte-for-byte copy of the 18-scenario lab report from 2026-10-13 (SHA-256 `733de041...a4bb`). It holds only scenario numbers, outcomes, short descriptions, the SPIRE version, the SVID lifetime and the backend name: synthetic lab data without patient data, hosts or credentials.

## Limits

- The mapping is one engineer's reading of NIST SP 800-66 rev2 against a lab. A reviewer should check every row before relying on it.
- The bridge does not set applied control status, evidence status or audit progress beyond `in_progress`.
- The ledger is local and unsigned; see [Ledger and verification](bridge.md#ledger-and-verification) for what it detects and what it does not.
- Evidence objects are keyed by exact name because CE v4.1.1 evidence has no ref_id; renaming one in the UI makes the next push create a new object.
