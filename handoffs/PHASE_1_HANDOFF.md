# Phase 1 Handoff — Meridian SE Assessment

> Synthesized: 2026-05-08 (Fri 00:59 UTC) / 2026-05-07 evening ET
> Phase: 1 (pre-clock)
> Authenticated requests made: **0** (clock not started)
> Commits made: **0** (Shua commits manually)

## Summary

Two parallel tracks completed and independently audited. Both passed.

| Track | Working Deliverable | Audit Verdict |
|---|---|---|
| A — Discovery | `discovery/endpoint-map.md` (198 lines) | **PASS** — 32 of 32 probe claims independently re-verified |
| B — Infra | `assessment/` package + tests | **PASS** — 25/25 tests, 93.10% coverage, redaction + gates verified empirically |

---

## Track A — Discovery (Endpoint Surface)

### Confirmed routes (5 paths, 7 probe variants)

| Method | Path | Status | Notes |
|---|---|---|---|
| GET | `/api/v1/health` | 200 | Body `{"service":"assessment-api","status":"ok"}` |
| GET | `/api/v1/submit` | 401 | Standard error envelope |
| GET | `/api/v1/dataset` | 401 | |
| GET | `/api/v1/dataset/{id}` | 401 | Path-param accepted (probed with `/dataset/test`) |
| GET | `/api/v1/challenges` | 401 | Returns `allow: OPTIONS` — see anomaly below |
| OPTIONS | `/api/v1/submit` | 401 | `allow: POST` — confirms POST is the submission verb |
| OPTIONS | `/api/v1/dataset` | 401 | No `allow:` header observed |

### Confirmed 404s (24 paths)

All 16 prescribed paths plus 3 prescribed extras (`/api/v1/`, `/api/v1`, `/api/v1/v1`) plus all 5 speculative probes (`submissions`, `keys`, `datasets`, `proofs`, `answers`). **No new real routes surfaced from speculation.**

### Routing/auth inference
401 = real route, 404 = no route registered. The platform layer returns 404s without the application's security-header bundle, which itself is diagnostic of where the routing decision is made.

### Anomalies worth flagging
1. **`GET /api/v1/challenges` returns `allow: OPTIONS`** — implies GET is NOT in the allow list for `/challenges` and the endpoint may be POST-only (or some other verb). Verify post-clock with the appropriate verb.
2. `OPTIONS /api/v1/dataset` and `OPTIONS /api/v1/challenges` return no `allow:` header at all, while `OPTIONS /api/v1/submit` does (`allow: POST`). Inconsistent OPTIONS handling across endpoints.
3. 404 envelopes lack the security-header bundle that 401s carry — different layer.
4. No `server:` header anywhere; no `cache-control` anywhere; HSTS without `preload`.

---

## Track B — Infrastructure (Client + Submit CLI)

### Package layout
```
assessment/__init__.py
assessment/client.py        # make_request(method, path, *, json, params) -> httpx.Response
assessment/submit.py        # python -m assessment.submit --type X --value Y [--notes ...] [--dry-run]
assessment/README.md
tests/test_client.py        # 14 tests
tests/test_submit.py        # 11 tests
tests/fixtures/response_{200,401}.json
pyproject.toml              # httpx, pytest, pytest-cov, ruff, black; coverage gate 90%
.env.example                # template only — no real key
.gitignore
README.md
```

### Verification results (independently re-run by audit agent)

- **Tests:** 25 passed / 0 failed. Coverage **93.10%** (gate 90%, client 95%, submit 91%).
- **Lint:** `ruff check .` clean.
- **Format:** `black --check` clean (audit ran it scoped to `assessment/ tests/` to avoid descending into `.venv-audit/`; not a working-agent issue, but see "Note" below).
- **Redaction:** Empirical canary key `AUDIT_CANARY_KEY_xyz_99887766` set; canary did NOT appear in stdout or in any JSON log file. `***REDACTED***` did appear in both. Verified.
- **Submit CLI gates** (all 4 scenarios PASS):
  - MISSING signoff → exit 2, no HTTP call
  - PASS signoff + `n` input → prompt shown, exit 0, no HTTP call
  - FAIL signoff → exit 2, no HTTP call
  - DRY-RUN (any state) → exit 0, no HTTP call, gate bypassed per spec
- **Credential leakage:** zero API-key-shaped strings in tracked files. `.env` and `logs/` confirmed gitignored via `git check-ignore`.
- **Commit state:** `git log` shows zero commits.
- **Scope:** no layer logic, no hash, no decrypt, no pagination, no live HTTP in tests.

### Note (minor, non-blocking)
The Track B working agent's `pyproject.toml` configures black with default excludes (`.venv/`, etc.). The audit's separate `.venv-audit/` directory does NOT match those default excludes, so running `black --check .` from the repo root would attempt to format the audit venv. The orchestrator added `.venv*/` to `.gitignore`, but black has its own `extend-exclude` mechanism — *not a blocker for Phase 1*, but if you run lint locally with a `.venv-audit`-style scratch venv in the future, scope black to `assessment/ tests/` or extend its excludes.

---

## Known Unknowns (carried into Phase 2)

These cannot be answered without authenticated requests and so are explicitly deferred:

1. **Decryption-key location** — no unauthenticated route hints at it. Hypotheses: response header on the first authenticated call, or embedded in an authenticated `/dataset` or `/challenges` response.
2. **Time-remaining mechanism** — `/time-remaining`, `/timer`, `/clock` all 404. Hypotheses: a header (`x-time-remaining: ...`) on every authenticated response, or a field on `/dataset` / `/challenges` payloads.
3. **Dataset structure** — paginated, indexed, or single-shot? `/dataset` (401) and `/dataset/{id}` (401) suggest both forms are accepted; behavior is unknown until authenticated.
4. **`/challenges` verb** — `allow: OPTIONS` on GET strongly suggests it's not a GET endpoint. Likely POST. Phase 2 should probe carefully (one authenticated call costs ~no clock time individually, but the first call STARTS the 3-hour clock).
5. **Submission response shape** — POST `/api/v1/submit` was not probed (would require auth and a body). Unknown whether responses are immediate verdicts, async, or carry next-layer hints.

---

## Open Items for Shua Before Phase 2

1. **Review and approve the commit plan below.** Nothing is committed yet.
2. **Decide on the Phase 2 scoping prompt with Kael** — Phase 2 starts the 3-hour clock on its first authenticated call, so the prompt needs to be crisp.
3. **Confirm where the API key will live** at Phase 2 start (presumably `.env` locally; never in repo).
4. **Optional:** if you want an `audit/` directory pre-created and tracked with a `.gitkeep`, say the word. Currently absent (the submit CLI tolerates it being missing — that's the MISSING signoff path).

---

## Phase 2 Readiness Recommendation

**READY.** Both audit verdicts are PASS. Infrastructure is hermetic (no live HTTP in tests, redaction empirically verified, gates working). Endpoint surface is mapped to the limit of what unauthenticated probing can reveal.

Recommend Kael scope a Phase 2 orchestrator prompt that begins with the first authenticated probe — most likely `OPTIONS /api/v1/dataset` or a single small `GET /api/v1/dataset` to learn the response shape. Every subsequent call is on the clock.

---

## Commit Plan (for Shua to execute)

All 16 deliverable files are currently staged on `main` (`git status` clean). Suggested groupings — feel free to rewrite messages or rebundle:

### Option A: 6 logical commits

```
# 1. Repo scaffolding
git reset
git add .gitignore README.md pyproject.toml .env.example
git commit -m "chore: initialize repo and project scaffolding"

# 2. HTTP client wrapper
git add assessment/__init__.py assessment/client.py tests/__init__.py tests/test_client.py tests/fixtures/
git commit -m "feat: add httpx-based client wrapper with redacted logging"

# 3. Submit CLI
git add assessment/submit.py tests/test_submit.py
git commit -m "feat: add submission CLI gated on audit signoff"

# 4. Package README
git add assessment/README.md
git commit -m "docs: add assessment package usage guide"

# 5. Phase 1 discovery + audits
git add discovery/endpoint-map.md discovery/audit-report-discovery.md assessment/audit-report-infra.md
git commit -m "docs: phase 1 endpoint discovery and audit reports"

# 6. Phase 1 handoff
git add handoffs/PHASE_1_HANDOFF.md
git commit -m "docs: phase 1 handoff and commit plan"
```

### Option B: 1 single commit

```
git commit -m "feat: phase 1 scaffolding — client, submit CLI, endpoint discovery"
```

### Option C: 3 commits (medium granularity)

```
# 1. Scaffolding + package code
git add .gitignore README.md pyproject.toml .env.example assessment/__init__.py assessment/client.py assessment/submit.py assessment/README.md tests/
git commit -m "feat: phase 1 scaffolding with client and submit CLI"

# 2. Discovery
git add discovery/
git commit -m "docs: phase 1 endpoint discovery and audit"

# 3. Audits + handoff
git add assessment/audit-report-infra.md handoffs/PHASE_1_HANDOFF.md
git commit -m "docs: phase 1 infra audit and handoff"
```

---

## Final Artifact Inventory (all staged, none committed)

```
.env.example
.gitignore
README.md
pyproject.toml
assessment/__init__.py
assessment/README.md
assessment/audit-report-infra.md
assessment/client.py
assessment/submit.py
discovery/audit-report-discovery.md
discovery/endpoint-map.md
tests/__init__.py
tests/fixtures/response_200.json
tests/fixtures/response_401.json
tests/test_client.py
tests/test_submit.py
handoffs/PHASE_1_HANDOFF.md (this file)
```

End of Phase 1.
