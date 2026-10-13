# Contributing

This is a small proof of concept. Issues and focused pull requests are welcome.

## Ground rules

- Build from public standards and this repository's own materials only.
- Fixtures use fictional organizations, synthetic data and `example.org` domains. Never add
  real patient data, credentials or secret values.
- Keep missing evidence distinct from a proven control failure, and do not describe simulated
  evidence as an executed check.
- Write in English. Use plain hyphens, not em dashes or en dashes.
- Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Development

Requires Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

```sh
uv sync --locked
uv run make check
uv run ruff check
uv run ruff format --check
uv run mypy
```

For documentation changes, also run:

```sh
uvx --from zensical==0.0.65 zensical build --strict
```

## Commits and pull requests

- Commit subjects use `type: Capitalized subject` without a trailing period. Types: `feat`,
  `fix`, `docs`, `ci`, `chore`, `refactor`, `test`, `security`, `perf`.
- Keep each pull request focused and fill in the template checklist.
- Do not bypass hooks.

Contributions are licensed under the [Apache License, Version 2.0](LICENSE).
