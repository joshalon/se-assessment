# Discovery Track Audit Report

> Audit performed: 2026-05-07 via `bash date`
> Auditor independently re-ran all probes against BASE_URL with NO Authorization header.

## Verification Results

| Claim | Method | Path | Re-run Status | Re-run Body Snippet | Match? | Notes |
|---|---|---|---|---|---|---|
| Confirmed route, 200 | GET | /api/v1/health | 200 | `{"service":"assessment-api","status":"ok"}` | yes | Body identical, content-length 42 |
| Confirmed route, 401 | GET | /api/v1/submit | 401 | `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}` | yes | `allow: POST` present as claimed |
| Confirmed route, 401 | GET | /api/v1/dataset | 401 | `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}` | yes | No `allow:` header, as claimed |
| Confirmed route, 401 (path-param) | GET | /api/v1/dataset/test | 401 | `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}` | yes | Confirms path-parameterized route |
| Confirmed route, 401 | GET | /api/v1/challenges | 401 | `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}` | yes | `allow: OPTIONS` present (anomaly confirmed) |
| Confirmed route, 401 | OPTIONS | /api/v1/submit | 401 | `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}` | yes | `allow: POST` present as claimed |
| Confirmed route, 401 | OPTIONS | /api/v1/dataset | 401 | `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}` | yes | No `allow:` header, as claimed |
| Confirmed route, 401 | OPTIONS | /api/v1/challenges | 401 | `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}` | yes | No `allow:` header, as claimed |
| 404 | GET | /api/v1/data | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/challenge | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/key | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/decrypt | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/time-remaining | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/timer | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/clock | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/openapi.json | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/docs | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/redoc | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/me | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/types | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/layers | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/status | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/info | 404 | (empty) | yes | CORS-only envelope |
| 404 | GET | /api/v1/sessions | 404 | (empty) | yes | CORS-only envelope |
| Speculative (prescribed), 404 | GET | /api/v1/ | 404 | (empty) | yes | CORS-only envelope |
| Speculative (prescribed), 404 | GET | /api/v1 | 404 | (empty) | yes | CORS-only envelope |
| Speculative (prescribed), 404 | GET | /api/v1/v1 | 404 | (empty) | yes | CORS-only envelope |
| Speculative, 404 | GET | /api/v1/submissions | 404 | (empty) | yes | CORS-only envelope |
| Speculative, 404 | GET | /api/v1/keys | 404 | (empty) | yes | CORS-only envelope |
| Speculative, 404 | GET | /api/v1/datasets | 404 | (empty) | yes | CORS-only envelope |
| Speculative, 404 | GET | /api/v1/proofs | 404 | (empty) | yes | CORS-only envelope |
| Speculative, 404 | GET | /api/v1/answers | 404 | (empty) | yes | CORS-only envelope |

Total probes re-run: 32. All 32 results match the working agent's claims.

## Header Verification

For each confirmed (non-404) route, the working agent claimed a "full security-header bundle" comprising:
`content-security-policy`, `strict-transport-security`, `x-frame-options: DENY`, `x-content-type-options: nosniff`, `referrer-policy: no-referrer`, `cross-origin-opener-policy: same-origin`, `cross-origin-embedder-policy: require-corp`, `cross-origin-resource-policy: same-origin`, plus `content-type: application/json`.

My re-runs observed the exact same headers (case-insensitive name match, identical values) on:
- GET /api/v1/health (200)
- GET /api/v1/submit (401, with `allow: POST`)
- GET /api/v1/dataset (401, no `allow:`)
- GET /api/v1/dataset/test (401, no `allow:`)
- GET /api/v1/challenges (401, with `allow: OPTIONS` — anomaly reproduced)
- OPTIONS /api/v1/submit (401, with `allow: POST`)
- OPTIONS /api/v1/dataset (401, no `allow:`)
- OPTIONS /api/v1/challenges (401, no `allow:`)

CSP value verified: `base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'`.
HSTS value verified: `max-age=31536000; includeSubDomains` (no `preload`, as claimed).

For the 404 envelopes, the working agent claimed an empty body, `content-length: 0`, and CORS headers `vary: origin, access-control-request-method, access-control-request-headers`, `access-control-allow-origin: *`, `access-control-expose-headers: *`, with the security bundle absent. All re-runs match exactly.

`date:` and `request-id:` differences across runs are expected variance. (No `request-id:` was actually emitted in either set of runs — the working agent did not claim one.) No header divergences observed.

## Fabrication Flags

None observed. Every claim in the deliverable is supported by my independent re-run.

## Scope Violations

None observed. The working agent's deliverable contains no evidence of authenticated requests:
- No `Authorization` header is mentioned in any probe description (only quoted in the 401 error body that the server returns).
- POST /submit was explicitly NOT probed; this is acknowledged in the "Known Unknowns" section.
- No 200 responses appear on any non-`/health` endpoint.
- All confirmed routes (other than `/health`) returned 401, which is the expected unauthenticated response. No probe is described that would have required an API key.

I also performed all my own re-run probes with NO `Authorization` header.

## Format Compliance

The deliverable contains all required sections in the prescribed order: Confirmed Routes, Confirmed Non-Routes, Speculative Probes, Inferences, Known Unknowns. Each entry includes status, body, and notable headers as expected.

Speculative probe count: the section lists 8 entries, but 3 are explicitly labeled "(prescribed)" by the orchestrator (`/api/v1/`, `/api/v1`, `/api/v1/v1`). The remaining 5 newly-introduced speculative probes (`/submissions`, `/keys`, `/datasets`, `/proofs`, `/answers`) meet the ≤5 constraint. Each carries a clearly written justification grounded in the observed naming convention (plural-collection pattern, pairing with `/submit` or `/challenges`). Justifications are reasonable.

## Inferences Sanity Check

- **Routing-vs-Auth distinction (401 vs 404):** Strongly supported. All 8 confirmed routes returned 401 with the security-header bundle; all 21 non-routes returned 404 with only CORS headers. The middleware-ordering inference (auth runs behind security-headers; 404 emitted by an outer ingress before app middleware) is well-supported by the header pattern and is a reasonable architectural read.
- **Naming convention:** Consistent with the data. Plural collections (`/challenges`), singular action verbs (`/submit`), singular resources (`/dataset`, `/dataset/{id}`), no synonyms registered (`/data` 404, `/sessions` 404, `/info` 404). No introspection (`/openapi.json`, `/docs`, `/redoc` all 404). Supported.
- **Security posture:** Header bundle correctly enumerated. Observations about the missing `server:` header, missing `cache-control`, and HSTS without `preload` are accurate.
- **OPTIONS / `allow:` anomaly on `/challenges`:** The claim that `GET /api/v1/challenges` returns `allow: OPTIONS` is reproduced in my re-run. The hypothesis that `/challenges` may be POST-only (or otherwise non-GET) is reasonable but explicitly framed as a hypothesis to verify post-clock, not a confirmed fact. No logical overreach.
- **Known Unknowns:** Each item is grounded in either a 404 result or a missing header signature. No unsupported leaps.

No logical gaps observed.

## Overall Verdict: PASS

All 32 probes independently verified, all headers match, no scope violations, no fabrications, format compliant; the deliverable accurately documents the unauthenticated route surface.
