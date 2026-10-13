# Publication and demonstration gates

This page defines acceptance criteria, not an approval badge. Publication stays
separate from local preparation. No remote deployment is implied by a successful
local documentation build.

## Reproduce the project

Run from a fresh checkout with the documented runtime and package manager:

```sh
make check
make grc-up
make grc-admin
make grc-bootstrap
make grc-demo
make grc-stop
```

Follow the [demo walkthrough](demo.md) for the UI checks. Capture the source revision,
environment, command, observed positive and negative outcomes and cleanup result. Saved
screenshots or an older report must identify their capture date. Re-run an applicable
integration check after changing the behavior it exercises. Lab evidence on synthetic
data does not establish HIPAA compliance.

## Build the documentation

Documentation tooling is separate from the application runtime:

```sh
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r requirements-docs.txt
.venv-docs/bin/zensical build --strict --clean
.venv-docs/bin/zensical serve --dev-addr 127.0.0.1:8000
```

The pinned generator produces `site/`. Check navigation, code blocks, diagrams,
search and project-subpath asset URLs in a browser. Never add private overlays,
state databases, credentials or private vaults to documentation sources.

## Continuous integration

`.github/workflows/ci.yml` runs on pull requests and on pushes to `main`. Every action is pinned by commit SHA, the workflow token is read-only (`contents: read`), checkouts do not persist credentials and every job stops after 10 minutes.

| Job | Checks | Network |
|---|---|---|
| `lint` | `ruff check`, `ruff format --check`, `mypy --strict src scripts` | Package install from `uv.lock` |
| `test` | `make check` on Python 3.12, 3.13 and 3.14: offline unit tests, the bridge and ledger tests against the in-memory CISO Assistant stand-in on loopback HTTPS, the mapping contract tests on synthetic library files, and the repository hygiene check | Package install from `uv.lock` |
| `mapping-contract` | `scripts/check_mapping_contract.py --download` | One HTTPS read of the pinned library file |
| `gitleaks` | Checksum-verified gitleaks 8.30.1 over the full history | Release download |

- No job starts CISO Assistant, a Lima VM or Kubernetes. Live pushes, `verify` and the ledger run only on a maintainer machine; see [Ledger and verification](bridge.md#ledger-and-verification).
- The mapping contract job reads `backend/library/libraries/nist-sp-800-66-rev2.yaml` from upstream commit `7a7a5babbdf9dffa10cafb454ff194be401e1aa0` (tag v4.1.1) into memory and refuses it unless its SHA-256 equals the pin in `deploy/upstream.json`, `1834c999eadbb51c4d12854c9975f23dd1205c9bb909215dff99d43f73753c4e`. It then requires the library and framework URNs, 179 requirement nodes with 152 assessable, and for each of the 117 mapped URNs one node that is assessable at depth 3 and carries the mapped name and parent section.
- The library file is AGPL-3.0-or-later. It is never written to the workspace or committed, and a test fails if a library file appears in the repository. The reader uses the Python standard library and refuses YAML constructs outside the subset the library uses. On 2026-10-13 it matched PyYAML on all 179 nodes in a one-off comparison outside the repository.
- Run the same check locally with `make mapping-contract` (needs network).
- To move to a new CISO Assistant release, change the commit, source and sha256 of the library pin together, then rerun the contract and the live [URN verification](mapping.md#urn-verification).
- `actionlint` passed on 2026-10-13. No remote run has been observed: the repository has no remote and nothing was pushed.

## GitHub Pages handoff

The prepared workflow builds on pull requests and publishes only from `main`
after an authorized push or explicit workflow dispatch. It uploads the static
`site/` directory and uses the GitHub Pages environment with job-scoped
`pages: write` and `id-token: write`; no long-lived deploy key is required.
The repository owner must select GitHub Actions as the Pages source before the
first deployment. Preparing this file does not enable Pages or execute a deploy.

Before publication, inspect the exact staged diff and distributable contents,
run the repository privacy/secret gates, reproduce the demo from a clean checkout,
verify the strict docs build and retain its evidence. Remote CI and the resulting
Pages URL still need verification after publication is explicitly authorized.

Generator behavior and configuration follow the
[official Zensical guide](https://zensical.org/docs/create-your-site/).

## Prototype records

The prototype's installed-package verification (2026-10-07), acceptance and evaluation
records were removed with its code in phase 5. They remain at the local tag
`v0.1.1-prototype` and describe that prototype only.

The project is licensed under Apache-2.0; `LICENSE` holds the text and `NOTICE` the
attribution that redistributions must keep. The prepared Pages workflow does not
authorize a remote upload.
