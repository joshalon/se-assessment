# Meridian SE Assessment

Phase 1 scaffolding for the Meridian SE Assessment.

This repository hosts the HTTP client and submission CLI used to interact
with the assessment API, along with the discovery notes and audit trail
required by the assessment workflow.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `assessment/` | Python package: HTTP client (`client.py`) and submission CLI (`submit.py`). |
| `tests/` | Pytest suite. All HTTP is mocked; no live network access in CI. |
| `tests/fixtures/` | Hand-crafted JSON fixtures that mirror real API response shapes. |
| `discovery/` | Phase 1 endpoint map produced by the unauthenticated discovery track. |
| `audit/` | Audit signoff files. The submission CLI refuses to submit without a `PASS` verdict. |
| `logs/` | Runtime-only directory (gitignored). The client writes one JSON record per call. |

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Lint and format
ruff check .
black --check .

# Tests with coverage gate
pytest --cov=assessment --cov-report=term --cov-fail-under=90
```

## Environment

Copy `.env.example` to `.env` and fill in `API_KEY` once available. The
assessment clock starts on the first authenticated request, so do **not**
populate `API_KEY` until you are ready to start the timed portion.

## Notes

- Phase 1 is pre-clock. No live HTTP requests are made during development
  or test runs.
- The client never logs the API key value: any `Authorization` header is
  rewritten to `Bearer ***REDACTED***` before reaching stdout or disk.
- See `assessment/README.md` for package-level usage details.
