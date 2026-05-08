# `assessment` package

HTTP client and submission CLI for the SE Assessment.

## Installation

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Environment Setup

Copy the template and fill in your key when you are ready to start the
3-hour clock:

```bash
cp .env.example .env
# then edit .env and set API_KEY=...
```

The client reads `BASE_URL` and `API_KEY` from the process environment at
call time, not at import time. If `API_KEY` is unset or empty, no
`Authorization` header is sent.

## Client Usage

```python
import os

os.environ["BASE_URL"] = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"
os.environ["API_KEY"] = "..."  # only set this when you are ready to start the clock

from assessment.client import make_request

response = make_request("GET", "/api/v1/health")
print(response.status_code, response.json())
```

Each call writes a JSON record to `logs/<timestamp>-<METHOD>-<path-slug>.json`
and a human-readable summary to stdout. The API key is redacted from both
sinks (it is rewritten to `Bearer ***REDACTED***`).

The function returns the `httpx.Response` regardless of status; non-2xx
responses are not raised. Transport-level errors (DNS, timeout, connection
refused) propagate as `httpx.RequestError`.

## CLI Usage

The submission CLI requires an audit signoff file under `audit/` named
`audit-report-<type>-attempt-<N>.md` containing a line of the form
`Overall Verdict: PASS`. The highest-numbered attempt for the given type
is consulted.

### Happy path (PASS verdict)

```bash
python -m assessment.submit --type layer-1 --value "0xdeadbeef" --notes "Hash of decrypted blob"
# prints the pending block, then prompts:
#   Confirm submit? [y/N]:
# answer 'y' to POST /api/v1/submit
```

### Dry-run (no HTTP, no signoff check)

```bash
python -m assessment.submit --type layer-2 --value "candidate-answer" --dry-run
# prints the pending block, then exits with "DRY RUN - not submitting"
```

### Refusal (FAIL or MISSING verdict)

```bash
python -m assessment.submit --type layer-3 --value "x"
# exits with code 2 and a message such as:
#   Refusing to submit: no audit signoff file found for this type.
#   Refusing to submit: audit signoff is FAIL.
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Submitted successfully (HTTP 2xx), aborted by user, or dry-run completed. |
| 1 | HTTP submission completed but returned non-2xx. |
| 2 | Audit signoff was `FAIL` or `MISSING`; no HTTP call was made. |
