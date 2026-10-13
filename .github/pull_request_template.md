## Summary

What changed and why.

## Verification

- [ ] `make check`
- [ ] `uv run ruff check`, `uv run ruff format --check` and `uv run mypy`
- [ ] `uvx --from zensical==0.0.65 zensical build --strict` when docs changed

## Boundaries

- [ ] Fixtures and examples use fictional organizations, synthetic data and `example.org` only
- [ ] No real patient data, credentials or secret values
- [ ] Missing evidence stays distinct from a proven control failure
- [ ] Dated evidence records are unchanged, or the change is explained
