# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

The rework replaces the prototype's own GRC tool with CISO Assistant Community edition (CE)
as the system of record and keeps only the bridge. See
`docs/adr/0001-ciso-assistant-system-of-record.md`.

### Added

- ADR 0001: CE v4.1.1 as the GRC system of record, run unmodified and used only over its
  REST API.
- Deployment: `scripts/grc_lab.py` and `make grc-*` targets run CE from its official chart
  0.13.3 in a dedicated `it-grc` Lima VM with k3s. Pins live in `deploy/upstream.json` and
  are re-verified before use; secrets stay in owner-only files under `deploy/.data`. See
  `docs/deployment.md`.
- Bridge client and bootstrap: `it_grc.grc_client`, a standard-library REST client (CA-pinned
  TLS, no proxies or redirects, bounded JSON, limited retries, single-match lookups with URN
  and assessable checks, fixed error text), and the commands `bootstrap`, `rotate-admin`,
  `token-refresh` and `bridge-check` with a dedicated domain, an Analyst-group bridge user
  and one-day tokens. See `docs/bridge.md`.
- Mapping and push: `mappings/hipaa-800-66r2.json` maps the 18 lab scenarios to 20 NIST SP
  800-66 rev2 nodes capped at `partially_compliant` and lists 97 gaps as `not_verified`,
  every URN verified live. `it-grc push` (with `--dry-run`) uploads evidence revisions with
  stored hash checks and refuses any write outside an allowlist. The lab report fixture
  `fixtures/lab/demo-report-2026-10-13.json` is retained. See `docs/mapping.md`.
- Ledger and verification: every push appends a canonical JSON record to a hash-chained
  local ledger with a checkpoint. `it-grc ledger verify` checks it offline; `it-grc verify`
  reconciles CE with the latest complete record, reports drift and lists human decisions as
  `HELD`.
- Demo: `it-grc summary` and `make grc-summary` print result and status counts, evidence
  coverage, evidence status and the applied control. `make grc-demo` runs dry run, push,
  verify, ledger verify and summary on the fixture or on `REPORT=<path>`. `docs/demo.md`
  walks through a live run with four CE screenshots.
- `it-grc --version`.
- Separate raw-artifact and canonical-record digests for lab reports. See
  `docs/evidence-digests.md`.
- CI: lint, `mypy --strict src scripts`, offline tests on Python 3.12 to 3.14, gitleaks over
  the full history and a mapping contract job (`make mapping-contract`) that reads the pinned
  upstream library into memory only. Dependabot updates with a seven-day cooldown.
- Documentation for publication: overview, demo, security model, article, light and dark
  palettes. Security policy, contribution guide, changelog, code owners, editor settings,
  and pull request and issue templates.

### Changed

- Renamed the project to IT GRC: distribution and CLI `it-grc`, package `it_grc` and URLs
  under `tanya-ok/it-grc`.
- Licensed under Apache-2.0. `NOTICE` describes the service boundary with AGPL CE.
- The strict lab-report validator moved to `it_grc.lab_report`. Its artifact digest always
  covers the raw file bytes.
- The push targets read `REPORT`, which defaults to the retained fixture, instead of
  `LAB_REPORT`.
- Package metadata, pinned ruff and mypy in a dev group, and wider lint rules. The
  repository check also covers YAML files, and scripts raise explicit errors instead of
  using `assert`.

### Removed

- The prototype, retained at the local tag `v0.1.1-prototype`: the web UI and loopback HTTP
  server, the local model client and model evaluation, review-state backup and restore, the
  rule-based assessment engine with its HIPAA fixtures and `references/controls.json`, the
  Kubernetes profile and container image, the packaging and install-verification scripts,
  `artifacts/demo/` and the prototype documentation pages.
- The CLI commands `serve`, `demo`, `assess`, `evaluate`, `import-lab`, `backup-state` and
  `restore-state`, the variables `IT_GRC_DATA`, `IT_GRC_MODEL`, `IT_GRC_MODEL_URL` and
  `IT_GRC_TRUSTED_HOSTS`, and the make targets `demo`, `serve`, `assess`, `evaluate`,
  `lab-*` and `package`.
- Prototype changes made after 0.1.1 and never released (review-state backup, installed-CLI
  verification, the container-only bind option, export fencing and credential-shape input
  filters) went with it.

### Security

- Secrets never appear on command lines, in Helm `--set` arguments, in output or in the
  ledger; every printed line passes a redactor that knows every secret the run has read.
- The bridge never approves evidence, locks or deletes anything, or sets a result above
  `partially_compliant` with status `in_review`.

## [0.1.1] - 2026-10-06

### Fixed

- Bounded input fields and tolerated cold local model starts.
- Restored lab workload identity and closed port forwarding cleanly.
- Synchronized the reported application version across backend, UI and container.

## [0.1.0] - 2026-10-06

### Added

- Local evidence review demo with a synthetic HIPAA-oriented healthcare case and before and
  after snapshots.
- Rule-based assessment that separates observed gaps, open evidence questions and supported
  checks, with public HHS references and scope limits.
- Human review of findings, Markdown export and untrusted Markdown context documents.
- Optional local model executive summary with reference and uncertainty validation.
- Loopback web UI and an optional Kubernetes profile alongside the shared security lab.
