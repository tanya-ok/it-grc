# Lab evidence belongs in a GRC system of record

The first version of this project was a small GRC tool of its own: a control catalog, a findings model, review states, a Markdown export and a web UI, all around a synthetic healthcare case. It worked as a demonstration. It was also the wrong thing to build. A system of record needs framework libraries, audits, evidence revisions, applied controls, roles and an audit trail, and a homemade catalog is harder to trust than a maintained public one.

The useful part was never the UI. It was the evidence: a security lab that executes 18 scenarios around workload identity, token exchange, mutual TLS and audit logging, and records when it ran and what each scenario showed. IT GRC is now only the bridge that puts that evidence into [CISO Assistant Community edition](https://github.com/intuitem/ciso-assistant-community) and checks later that it is still there. [ADR 0001](adr/0001-ciso-assistant-system-of-record.md) records the decision.

## Running CISO Assistant as an external service

CISO Assistant CE v4.1.1 runs unmodified from its upstream images, pinned by digest, in a dedicated Lima VM with k3s and the official Helm chart. A lifecycle script re-verifies every pin before it changes anything, keeps generated secrets in owner-only files on the host and sends them to the cluster on stdin only. The VM exposes one port on host loopback, behind a Caddy proxy with an internal CA. CE is AGPL-3.0-or-later; IT GRC is Apache-2.0 and only exchanges HTTP requests with it. No upstream source, API schemas or library files are copied into the repository.

## Least privilege inside the limits of CE

CE Community edition has no service accounts and no custom roles. The smallest built-in role that can create evidence and update requirement assessments is Analyst, and in a spike that role could also approve evidence, lock audits and delete them. The bridge therefore uses a dedicated user in the Analyst group of one dedicated domain that holds only synthetic lab evidence, with personal access tokens that live one day.

The remaining power of the token is limited on the client side. Every write passes an allowlist of six routes and their fields. A result above `partially_compliant`, a status above `in_review`, evidence approval, locking and every delete raise an error before a request is sent. `compliant` and `done` stay human decisions.

## Lookups that check their own answers

The spike produced the most important rule. CE ignores unknown query filters without an error. A lookup with `requirement=<urn>` returned all 179 requirement assessments of the audit, and a write landed on a node that is not assessable. Only `requirement__urn` filtered correctly. Every lookup in the bridge now checks the rows it gets back: every row must carry the filtered values, a lookup for one object must find exactly one, and a requirement must be assessable with an exactly equal URN. A changed library stops the push before its first write.

## What the push writes

A versioned mapping file assigns the 18 scenarios to 9 evidence groups and 20 requirement nodes of the public NIST SP 800-66 rev2 framework. Each mapped node gets `partially_compliant` with status `in_review` and an observation with the mapping version, the CFR reference, the rationale and the limits. Two nodes also carry a sensitive point: a cached workload identity can be reused within its lifetime, and a valid identity cannot prove the intent of a write. Another 97 nodes are listed as gaps and keep `not_assessed` with an observation that starts with `not_verified:`. Physical, administrative and organizational safeguards need documents, people and facilities that a lab does not have, and saying so is part of the result.

Each evidence revision is a deterministic JSON extract of validated report fields, so the same report always yields the same bytes. After every upload the bridge compares the hash CE stores with its own SHA-256. The live run on 2026-10-13 ended with 20 requirements partially compliant, 132 not assessed, evidence coverage of 13.2 percent and 9 evidence objects in review, none approved.

The first live push also found something the in-memory test stand-in had not modeled: CE omits evidence links from applied-control list rows, so every push re-sent a link that already existed. The bridge now reads the control's detail endpoint, the stand-in behaves the same way, and a second push changes nothing.

## Verifying later

Because the token could still change what the bridge wrote, every push appends a record to a local ledger: canonical JSON lines chained by SHA-256, with a checkpoint that detects a truncated tail. `it-grc verify` compares CE with the latest record and reports deleted objects, changed hashes, unrecorded revisions and changed results as drift. A requirement that a human has taken over is listed as `HELD`, not as drift. The ledger is unsigned and sits beside its checkpoint, so it detects accidental and partial changes, not a determined attacker on the host.

## What it leaves open

Lab evidence on synthetic data is not HIPAA compliance, and NIST SP 800-66 rev2 is guidance for the Security Rule, not the rule itself. The mapping is one engineer's reading and needs review row by row. A saved lab report is dated evidence, not the current state of a cluster. Within those limits, the bridge does one thing: it puts executed evidence into a real system of record, at the strength the evidence supports, and makes later changes visible.
