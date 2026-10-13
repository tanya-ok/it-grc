# Bridge client and bootstrap

Phase 2 gives IT GRC a REST client for CISO Assistant Community edition (CE) and the commands that prepare it for the bridge: a dedicated domain, a perimeter, a bridge user in the domain's Analyst group, a short-lived token and the public NIST SP 800-66 rev2 framework loaded by URN. Phase 3 pushes lab evidence with this client; see [Mapping and push](mapping.md). Phase 4 records every push in a local hash-chained ledger; see [Ledger and verification](#ledger-and-verification). See [ADR 0001](adr/0001-ciso-assistant-system-of-record.md) and [Deployment](deployment.md).

## Commands

All commands run from the repository checkout against `https://localhost:18443` and trust only `deploy/.data/ca.pem`. Nothing secret is printed.

| Command | Make target | Acts as | Effect |
|---|---|---|---|
| `it-grc rotate-admin` | `make grc-rotate-admin` | administrator | New administrator password, all administrator tokens revoked, Secret updated |
| `it-grc bootstrap` | `make grc-bootstrap` | administrator, then bridge | Library, domain, perimeter, bridge user, bridge password and token; idempotent |
| `it-grc token-refresh` | `make grc-token-refresh` | bridge | New 1-day token; every other bridge token revoked |
| `it-grc bridge-check` | `make grc-bridge-check` | bridge token | Read checks and two writes that must answer 403 |
| `scripts/grc_lab.py sync-admin-secret` | `make grc-admin-secret` | VM operator | Copies the administrator password file into the bootstrap Secret over stdin |

### What bootstrap creates

| Object | Value | Lookup before create |
|---|---|---|
| Library | `urn:intuitem:risk:library:nist-sp-800-66-rev2`, loaded only if `is_loaded` is false | `stored-libraries?urn=`, exactly one, URN equal |
| Framework | `urn:intuitem:risk:framework:nist-sp-800-66-rev2` | full list, exactly one with that URN (the endpoint has no URN filter) |
| Domain | `IT GRC Lab` under Global, created with its IAM groups | `folders?name=&parent_folder=`, every row checked, at most one |
| Perimeter | `Security lab`, ref_id `ITGRC-LAB` | `perimeters?folder=`, then ref_id selected locally (no ref_id filter) |
| User | `bridge@example.org`, groups set to exactly `IT GRC Lab - Analyst` | `users?email=`, every row checked, at most one |
| Password | generated, stored in `deploy/.data/bridge-password`, set by the administrator | login attempt with the stored file |
| Token | 1-day personal access token in `deploy/.data/bridge-token` | `iam/current-user` with the stored token |

A second run with nothing missing makes no change: it only reads, verifies the bridge login and logs both sessions out. Bootstrap refuses to continue if the bridge user is a superuser or inactive, or if the token's user holds any role other than Analyst (`BI-RL-ANA`). If someone added the bridge user to another group, bootstrap removes it and reports the change.

## Client safety rules

`src/it_grc/grc_client.py` uses only the Python standard library.

| Rule | Implementation |
|---|---|
| TLS | `SSLContext` from `deploy/.data/ca.pem` only, `CERT_REQUIRED`, host name verification, TLS 1.2 minimum. A missing or invalid CA file stops the client before any connection |
| Origin | `https://<host>:<port>` only; plain HTTP has no handler |
| No proxies | The opener has no proxy handler; proxy environment variables are ignored |
| No redirects | The opener has no redirect handler; any 3xx raises an error and the target is never requested |
| JSON only | Requests send JSON; non-JSON or invalid JSON responses raise an error |
| Bounded responses | 4 MiB limit, checked against `Content-Length` and while reading |
| Timeouts | 30 seconds per request; 300 seconds for a library import |
| Retries | GET, PUT and DELETE only, on HTTP 5xx or a connection reset, after 0.5, 1 and 2 seconds. POST and PATCH are never repeated, so a create never runs twice |
| Pagination | Offsets are computed by the client. `next` links are ignored, so a page cannot send the token to another origin. Page counts must stay consistent |
| Errors | Typed errors (`GrcAuthError`, `GrcPermissionError`, `GrcLookupError` and others) with fixed text: method, a route with ids replaced by `{id}`, and the status. Never a response body, token or password |
| Sessions | `logout` deletes the access token in use and ends the headless login session. For a personal access token, logout revokes the token |

### Lookups

CE ignores unknown query filters without an error. In the spike, `requirement=<urn>` returned all 179 requirement assessments of an audit and a write landed on a non-assessable node. Every lookup therefore checks the returned rows itself:

- Every returned row must carry the filtered values. A row outside the filter means the filter was ignored, and the lookup fails before any write.
- A lookup that targets one object asserts exactly one match.
- A requirement node lookup also requires `assessable` to be true and the URN to be equal, not a prefix.
- A requirement assessment lookup uses `requirement__urn`, the filter that works, and asserts the audit id, the nested `requirement.urn` and that the row and its requirement are assessable.

## Roles: why Analyst

CE has no service accounts (`/iam/service-accounts/` answers "This feature is not enabled") and no custom roles. The bridge needs to read the framework and, from phase 3, create evidence and applied controls and update requirement assessments in its own domain.

| Built-in role | Behavior | Fit |
|---|---|---|
| Reader | Read only | Cannot write evidence |
| Respondent | In the spike it listed no requirement assessments of the audit (count 0) | Cannot do the job |
| Analyst | In the spike it created evidence and applied controls and updated requirement assessments. It cannot load libraries or create root domains (403, verified again on 2026-10-13) | Smallest role that works |
| Approver | Approves evidence by design | Would make the bridge the human reviewer |
| Domain manager | Manages the domain, including its users | More than needed |

The bridge user is a member of exactly one group, `IT GRC Lab - Analyst`. It sees only the Global folder (shared frameworks and libraries) and the lab domain.

## Token lifetime and rotation

- Bridge tokens live one day. `token-refresh` logs in as the bridge user with `deploy/.data/bridge-password`, creates a new token, stores it, revokes every other bridge token and confirms the previous token is rejected. CE allows five active tokens per user; at that limit the refresh revokes all of them first.
- `bootstrap` issues a token only when the stored one no longer works.
- `rotate-admin` rotates the administrator password:
    1. It writes the new password to `deploy/.data/admin-password.pending` before changing anything.
    2. It changes the password through the API (`/iam/change-password/`), confirms the new password logs in and only then replaces `deploy/.data/admin-password`.
    3. It calls `/iam/logoutall/`, which deletes every administrator access token, personal access tokens included, because any of them may stem from the old password.
    4. It confirms the old password is rejected and no administrator token is left.
    5. It runs `scripts/grc_lab.py sync-admin-secret`, which writes the password file into the Secret `it-grc-bootstrap` over stdin and verifies it by comparing hashes.
- If a rotation stops midway, the next run finds the pending file and either finishes the rotation (the server accepts the pending password) or discards it (the server still accepts the old one).
- The upstream startup script reads the Secret only to create a missing administrator, so the Secret matters when the database is recreated. The running backend keeps the previous value in its environment until it restarts; the database no longer accepts it.

## Secret files

All files live in the git-ignored `deploy/.data/` directory (mode 0700). Each file is mode 0600, written through an exclusive create or an atomic replace, and read only by the commands above.

| File | Content | Written by |
|---|---|---|
| `admin-password` | Administrator password | `grc_lab.py bootstrap-admin`, `it-grc rotate-admin` |
| `admin-password.pending` | New password during a rotation only | `it-grc rotate-admin` |
| `bridge-password` | Bridge user password | `it-grc bootstrap` |
| `bridge-token` | Bridge personal access token, 1 day | `it-grc bootstrap`, `it-grc token-refresh` |
| `ca.pem` | Internal CA certificate (not secret) | `grc_lab.py up` |
| `grc-ledger.jsonl` | Push ledger, one record per push (no secrets) | `it-grc push` |
| `grc-ledger.checkpoint` | Ledger record count and last record hash (no secrets) | `it-grc push` |

## Limits and mitigations

- The Analyst role can approve evidence, lock audits and delete audits; the spike confirmed all three. CE cannot narrow it. Mitigations: a dedicated domain that holds only synthetic lab evidence, one-day tokens, a local append-only ledger of every bridge push so a later deletion or edit is detectable (see [Ledger and verification](#ledger-and-verification)), and a write allowlist with tests that the bridge never approves evidence, locks or deletes anything or sets a result above its ceiling (phase 3, see [Mapping and push](mapping.md)).
- The bridge password stays on the host so that tokens can be renewed. Anyone who can read `deploy/.data` acts as the bridge user.
- Bootstrap and rotation need the administrator password. The bridge itself never uses it.
- Tokens are not renewed automatically. Run `make grc-token-refresh` before work on a new day.
- `bridge-check` sends two writes that must fail with 403. If one succeeds, the check fails and names it; a probe domain `IT GRC bridge permission probe` would then need manual deletion.
- The phase 1 `grc_lab.py` login helpers log out the access token only; their headless login session expires on its own.

## Verification

Live run on 2026-10-13 against CE v4.1.1 in the `it-grc` VM:

| Step | Result |
|---|---|
| `it-grc rotate-admin` | New password stored; old password rejected; no administrator token left; Secret updated and verified |
| `it-grc bootstrap`, first run | 7 changes: library loaded, domain with IAM groups, perimeter, user, Analyst group, password, token |
| `it-grc bootstrap`, second run | No changes |
| `it-grc bridge-check` | Analyst role only; folders Global and IT GRC Lab; 179 requirement nodes, 152 assessable; library load 403; domain creation 403 |
| `it-grc token-refresh` | New token stored, 1 previous token revoked and rejected |

Offline tests (`make check`) cover the client against loopback HTTPS servers with a throwaway CA: single-match failures (0 and 2 results, not assessable, URN mismatch, ignored filters), the CA file requirement, host name and CA verification, refused redirects, ignored proxy variables, bounded JSON responses, retry rules, error messages without body or secret, 0600 files, and bootstrap idempotency, rotation, token refresh and the bridge check against an in-memory CE stand-in.

## Ledger and verification

Phase 4 records every push in a local append-only ledger and reconciles CISO Assistant against it. The Analyst token can still delete or edit what the bridge wrote, and CE cannot narrow that role (see [Limits and mitigations](#limits-and-mitigations)). The ledger makes such changes visible to `it-grc verify`.

### Commands

| Command | Make target | Needs CISO Assistant | Effect |
|---|---|---|---|
| `it-grc push --report <path>` | `make grc-push` | Yes | Checks the ledger first, then appends one record after the writes |
| `it-grc ledger verify` | `make grc-ledger-verify` | No | Recomputes the chain and checks the checkpoint; exit 1 on any failure |
| `it-grc verify` | `make grc-push-verify` | Yes | Checks the ledger, then compares CISO Assistant with the latest complete record; exit 1 on drift |

A dry run reads the ledger but never writes it. A push that fails after it sent a write appends a record with outcome `failed`; a push that fails before its first write adds none.

### Files

| File | Mode | Written |
|---|---|---|
| `deploy/.data/grc-ledger.jsonl` | 0600 | Opened append-only under an exclusive lock; the chain and checkpoint are checked again before the line is added and synced |
| `deploy/.data/grc-ledger.checkpoint` | 0600 | Replaced atomically after each append: record count and last `record_hash` |

Both files are git-ignored. Every read requires an owner-only regular file and refuses symbolic links. The previous `deploy/.data/grc-push-record.json` is no longer read.

### Record fields

| Field | Content |
|---|---|
| `seq`, `time` | Position from 1 and UTC time of the append |
| `outcome` | `complete`, or `failed` for a push that sent writes and then stopped |
| `ce_version` | `version` from `GET /api/build/`, read with the bridge token |
| `actor` | `bridge@example.org` |
| `mapping` | Mapping version and file SHA-256 |
| `report` | Validated lab report summary: raw file SHA-256, canonical record SHA-256, capture time, producer revisions and scenario outcomes |
| `audit` | Audit id and ref_id `ITGRC-800-66R2` |
| `evidence` | Per group: evidence id, extract SHA-256 and every revision with its id, version and stored `attachment_hash` |
| `controls` | Applied control id and its linked evidence ids |
| `requirements` | Per mapped URN: planned and observed result and status, and the reason if a human holds it |
| `writes` | Writes the push sent, in order; empty when nothing changed. In a failed record the last one may not have applied |
| `error` | Failed records only: the fixed error text |
| `prev_hash`, `record_hash` | Chain fields |

Failed records carry no audit, evidence, control or requirement fields. Records never hold tokens, passwords or response bodies: before a line is written, it is compared with every secret the run has read, and a match refuses the write.

### Chain

- A line is the canonical JSON of its record: sorted keys, compact separators, ASCII (`json-sort-keys-compact-ascii-v1`).
- `record_hash` is the SHA-256 of the canonical JSON of the record without `record_hash`, so it covers `prev_hash`. The first record's `prev_hash` is 64 zeros.
- `ledger verify`, `push` and `verify` check every line from the first: valid JSON without duplicate keys, canonical form, `seq` equal to the line number, `prev_hash` equal to the previous `record_hash`, and `record_hash` recomputed.

| Change to the files | Detected by |
|---|---|
| A field edited, hash left as it was | Recomputed `record_hash` |
| A record edited and its hash recomputed | `prev_hash` of the next record |
| Whitespace or key order changed | Canonical form check |
| Records reordered, or removed from the start or the middle | `seq` and `prev_hash` |
| Records removed from the end | Checkpoint count |
| Last record edited and its hash recomputed | Checkpoint hash |
| A partly written last line | Missing line end |
| Checkpoint removed while records exist | Missing checkpoint |
| Ledger and checkpoint rewritten together | Not detected |

A broken ledger stops `push` before it contacts CISO Assistant, and it stops `verify`. If the checkpoint covers fewer records than the ledger (a push stopped between the two writes), both commands print a warning and continue; the next append updates the checkpoint. To start a new ledger after a failure, move both files aside and keep them as evidence.

!!! warning "Not tamper-proof"
    The checkpoint sits beside the ledger in the same directory. Anyone who can rewrite both files, for example by truncating the ledger and writing a matching checkpoint, rewrites the history without detection. Neither file is signed, and the hashes need no key. The ledger detects accidental damage and partial edits of the local files, and it lets `verify` see what changed in CISO Assistant. It is not evidence against someone who controls the host.

### Verify against the ledger

`it-grc verify` reads the latest complete record and reports as drift:

- a failed push recorded after it;
- a mapping file that changed since that push;
- a missing or replaced audit, evidence object or applied control;
- a recorded evidence revision that is missing or whose version or stored hash changed, and a revision the ledger does not record;
- a latest revision whose stored hash differs from the extract SHA-256;
- an applied control that lost its evidence link;
- a mapped requirement whose result, status, observation or extended result differs from the plan, or that lost a link, unless a human holds it.

A mapped requirement that is locked, `compliant`, `not_applicable`, `in_progress`, `done` or review `accepted` is reported as `HELD`, not as drift, with "recorded at the push" when the ledger already shows that state and "a human decision since the push" otherwise. Verify cannot tell a reviewer from someone who uses the Analyst token; review the HELD lines in CISO Assistant. A different CE version is printed as a note.

### Limits

- One record is about 27 KB. The ledger is read whole on every check and refused above 64 MiB, about 2,400 pushes. Rotation is not implemented.
- The ledger records what the bridge did and saw. It does not record changes made in CISO Assistant between pushes; `verify` finds those by comparison.

### Live run

2026-10-13, CE v4.1.1 in the `it-grc` VM, report `fixtures/lab/demo-report-2026-10-13.json` (SHA-256 `733de041...a4bb`), mapping `2026-10-13.1`:

| Step | Result |
|---|---|
| `push --dry-run` | Ledger with 0 records verified; 0 planned changes |
| `push` | No server changes; record 1 appended: outcome `complete`, `ce_version` v4.1.1, 0 writes, 9 evidence objects with 1 revision each, 117 requirements observed as planned, none held; `record_hash` `2bc64bd4...0cc1` |
| `ledger verify` | 1 record chained from the genesis hash; checkpoint matches |
| `verify` | Clean against record 1: partially_compliant 20, not_assessed 132; evidence coverage 13.2 percent |
| Secret check | No password, token or key from `deploy/.data` in either file |

### Tests

`make check` runs `tests/test_grc_ledger.py` offline: chain and file modes, an independent recomputation of `record_hash`, detection of edited, re-hashed, non-canonical, reordered and deleted records, tail truncation through the checkpoint, the undetected rewrite of both files, missing, malformed and lagging checkpoints, incomplete lines, loose permissions and symbolic links, refusal to append to a broken ledger, to write a known secret or to set chain fields. Against the in-memory CE stand-in: one record per real push and none for a dry run, no secret in either file, held decisions recorded and not reported as drift, a changed result that no human holds, missing and unrecorded revisions, a failed push recorded and reported by verify, and a broken ledger that stops push and verify before any write.
