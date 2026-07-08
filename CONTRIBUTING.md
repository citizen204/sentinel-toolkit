# Contributing to Sentinel

Thanks for your interest! Issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/citizen204/sentinel-toolkit.git
cd sentinel-toolkit
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Checks to run before opening a PR

```bash
pytest -q            # tests (fully offline; AWS via moto, HTTP via responses)
ruff check .         # lint

cd dashboard
npm ci
npm run lint         # eslint
npm run build        # next build
```

CI runs all of the above on every push and pull request.

## Adding a scanner module

1. Create `sentinel/modules/<name>/` with a `scanner.py` defining a `BaseScanner` subclass
   (set `name` so it auto-registers) and a `checks/` package of pure functions.
2. Register the module in `sentinel/modules/__init__.py`.
3. Add tests under `tests/`.

## Adding a rule

Rules live in each module's `rules.py`. Register a `Rule` (id, title, severity, category,
references, confidence) and emit findings with `build_finding(rule_id, ...)` so metadata stays
in one place. Bind each finding to a structured `Asset` where possible.

## Style

- Keep checks pure and independently testable.
- Every finding must carry a concrete `remediation`.
- Follow the existing file layout; keep files small and focused.
