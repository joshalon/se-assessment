# Endpoint Discovery Map

> Method: 401 = real route exists, 404 = no route registered.
> All probes are UNAUTHENTICATED (no Authorization header). Phase 1 is pre-clock.
> BASE_URL: https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io
> Captured: 2026-05-07 via `bash date` (Thu May  7 20:45:18 EDT 2026)

## Confirmed Routes

### `GET /api/v1/health`
- Status: 200
- Body: `{"service":"assessment-api","status":"ok"}`
- Notable headers:
  - `content-type: application/json`
  - `content-security-policy: base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'`
  - `strict-transport-security: max-age=31536000; includeSubDomains`
  - `x-frame-options: DENY`
  - `x-content-type-options: nosniff`
  - `referrer-policy: no-referrer`
  - `cross-origin-opener-policy: same-origin`
  - `cross-origin-embedder-policy: require-corp`
  - `cross-origin-resource-policy: same-origin`

### `GET /api/v1/submit`
- Status: 401
- Body: `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`
- Notable headers:
  - `content-type: application/json`
  - `allow: POST`  (a `GET` to a POST-only endpoint still gets the auth-gate first; the `allow` header is present even on the auth error)
  - Full security-header bundle (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, COOP, COEP, CORP) — same as `/health`.

### `GET /api/v1/dataset`
- Status: 401
- Body: `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`
- Notable headers:
  - `content-type: application/json`
  - No `allow:` header observed.
  - Full security-header bundle.

### `GET /api/v1/dataset/test`  (path-param probe)
- Status: 401
- Body: `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`
- Notable headers:
  - `content-type: application/json`
  - No `allow:` header.
  - Full security-header bundle.
- Note: 401 (not 404) for an arbitrary `{any-segment}` strongly implies `/api/v1/dataset/{id}` is a path-parameterized route, not a literal segment.

### `GET /api/v1/challenges`
- Status: 401
- Body: `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`
- Notable headers:
  - `content-type: application/json`
  - `allow: OPTIONS`  **(anomaly — see Inferences/OPTIONS Behavior)**
  - Full security-header bundle.

### `OPTIONS /api/v1/submit`
- Status: 401
- Body: `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`
- Notable headers:
  - `allow: POST`
  - Full security-header bundle.

### `OPTIONS /api/v1/dataset`
- Status: 401
- Body: `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`
- Notable headers:
  - No `allow:` header observed.
  - Full security-header bundle.

### `OPTIONS /api/v1/challenges`  (prescribed probe)
- Status: 401
- Body: `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`
- Notable headers:
  - No `allow:` header observed (note: `GET /api/v1/challenges` returned `allow: OPTIONS`, but the `OPTIONS` request itself gets no `allow:` back).
  - Full security-header bundle.

## Confirmed Non-Routes (404)

All 404 responses share the same envelope: HTTP/2 404, empty body, `content-length: 0`, and CORS headers (`vary: origin, access-control-request-method, access-control-request-headers`, `access-control-allow-origin: *`, `access-control-expose-headers: *`). No security-header bundle (CSP/HSTS/etc.) on 404s — that fingerprint is itself diagnostic; see Inferences.

- `GET /api/v1/data` — 404
- `GET /api/v1/challenge` — 404
- `GET /api/v1/key` — 404
- `GET /api/v1/decrypt` — 404
- `GET /api/v1/time-remaining` — 404
- `GET /api/v1/timer` — 404
- `GET /api/v1/clock` — 404
- `GET /api/v1/openapi.json` — 404
- `GET /api/v1/docs` — 404
- `GET /api/v1/redoc` — 404
- `GET /api/v1/me` — 404
- `GET /api/v1/types` — 404
- `GET /api/v1/layers` — 404
- `GET /api/v1/status` — 404
- `GET /api/v1/info` — 404
- `GET /api/v1/sessions` — 404

## Speculative Probes (newly attempted)

### `GET /api/v1/` (prescribed — trailing slash)
- Justification: Prescribed by orchestrator. Tests whether router treats `/api/v1/` as a directory index.
- Status: 404
- Body: empty (CORS-headers envelope)
- Result: not registered

### `GET /api/v1` (prescribed — no trailing slash)
- Justification: Prescribed by orchestrator. Tests whether router exposes a version landing page.
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/v1` (prescribed)
- Justification: Prescribed by orchestrator. Sanity check for a doubled-prefix routing bug.
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/submissions`
- Justification: Confirmed routes use full plural words for collections (`challenges`). The action endpoint is the singular verb `/submit`, so a separate plural `/submissions` collection (history of past POSTs) was a natural guess.
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/keys`
- Justification: Plural-collection naming pattern (`/challenges`, `/dataset`). If the assessment exposes a key-management surface, plural `/keys` would match the convention.
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/datasets`
- Justification: `/dataset` (singular) returned 401, and `/dataset/{id}` also returned 401. Worth checking whether a plural-collection alias `/datasets` was registered for parity with `/challenges`.
- Status: 404
- Body: empty
- Result: not registered (singular `/dataset` is the only form registered)

### `GET /api/v1/proofs`
- Justification: Plural-collection naming. `submit` could be paired with a `/proofs` collection if the workflow includes verifiable proofs of computation/decryption.
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/answers`
- Justification: Plural-collection naming. The `/challenges` + `/submit` pairing might also expose a read-side `/answers` collection (e.g., past answers, scoring).
- Status: 404
- Body: empty
- Result: not registered

## Inferences

### Routing-vs-Auth
The API consistently distinguishes two failure modes by status code:
- **401** (Unauthorized): the path matched a registered route, but the request lacked credentials. Body is the JSON `{"error":"Missing or invalid Authorization header. Use: Bearer <api-key>"}`. The full security-header bundle (CSP/HSTS/COOP/etc.) is attached because the auth middleware sits *behind* the security-headers middleware.
- **404** (Not Found): no route is registered for this path. Body is empty, only CORS headers are attached, and the security bundle is absent — strongly suggesting 404s are emitted by an outer ingress/router layer that runs *before* the application's middleware stack.

This binary lets us enumerate the full route surface without ever authenticating: every path that returns 401 is a real, registered handler.

### Naming Convention
Confirmed routes use **full English words** (no abbreviations) and lowercase ASCII with no separators within a segment:
- Collections: plural noun (`/challenges`).
- Actions / commands: singular verb (`/submit`).
- Resources / lookups: singular noun, optionally with a path parameter (`/dataset`, `/dataset/{id}`).
- Health: standard convention (`/health`).

The 404 results on `/data`, `/challenge`, `/key`, `/timer`, `/clock`, `/sessions`, `/me`, `/info`, `/status` reinforce that the API does NOT register both singular/plural variants and does NOT use generic English synonyms (e.g., `/data` is rejected even though `/dataset` exists). It also explicitly does NOT expose introspection (`/openapi.json`, `/docs`, `/redoc`).

### Security Posture
All 401 responses (i.e., real route hits) carry a strong security-header bundle:
- `content-security-policy: base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'`
- `strict-transport-security: max-age=31536000; includeSubDomains` (no `preload`)
- `x-frame-options: DENY`
- `x-content-type-options: nosniff`
- `referrer-policy: no-referrer`
- `cross-origin-opener-policy: same-origin`
- `cross-origin-embedder-policy: require-corp`
- `cross-origin-resource-policy: same-origin`

Notably absent / observations:
- No `server:` header at all — the server software is not advertised.
- No `cache-control` on any response (neither 200, 401, nor 404). For an API that returns auth errors and a health check, this is acceptable but worth flagging — clients/intermediaries are free to apply default caching to the JSON 401 envelope.
- HSTS does NOT include `preload`.
- 404 envelopes lack the security bundle entirely (only CORS headers). This is consistent with a platform-emitted 404 rather than an app-emitted 404.

### OPTIONS Behavior
- `OPTIONS /api/v1/submit` → 401 with `allow: POST`. The handler advertises the canonical method (POST), confirming `/submit` is POST-only and matching the assessment description.
- `OPTIONS /api/v1/dataset` → 401 with NO `allow:` header. Either the handler doesn't list allowed methods, or `OPTIONS` is itself the only registered method on this path beyond the implicit GET. We can still infer `GET /api/v1/dataset` works because the GET probe returned 401 (route exists).
- `OPTIONS /api/v1/challenges` → 401 with NO `allow:` header.
- **Anomaly:** `GET /api/v1/challenges` returned `allow: OPTIONS` — i.e., the response is telling us GET is *not* in the allowed-methods list for this path. Combined with the `OPTIONS` probe getting no `allow:` header, this hints `/challenges` may only respond to a non-GET method (perhaps POST). If `/challenges` is POST-only, the assessment workflow may be: POST to `/challenges` to create/request a challenge, retrieve dataset via `/dataset`(`/{id}`), then POST to `/submit`. This is a hypothesis to verify post-clock.

The `allow:` header is only emitted by the application's auth-gated handlers (it appears on 401s for `/submit` GET, `/submit` OPTIONS, and `/challenges` GET). Its presence further confirms which paths are real.

## Speculative Probes (Phase 2A — unauthenticated, pre-clock)

Probed Fri May  8 02:16:31–34 UTC 2026. No `Authorization` header sent; `request_headers: {}` confirmed in all five log files.

### `GET /api/v1/window`
- Status: 404
- Body: empty (CORS-headers envelope only)
- Result: not registered

### `GET /api/v1/budget`
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/quota`
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/expires`
- Status: 404
- Body: empty
- Result: not registered

### `GET /api/v1/deadline`
- Status: 404
- Body: empty
- Result: not registered

All five return the same 404 envelope (CORS headers, no security bundle, empty body) as the Phase 1 confirmed non-routes. None is a registered route; the time-remaining mechanism is not exposed via a dedicated path. Confirmed via `/api/v1/stats` in Phase 2B (see dataset-response-analysis.md).

---

## Phase 2B — Authenticated Routes Discovered

These routes were unknown until the first authenticated call started the clock.

### `GET /api/v1/dataset` (authenticated — Phase 2B primary call)
- Status: 200
- T0: 2026-05-08T02:16:44Z (log file: `logs/20260508T021644Z-GET-api-v1-dataset.json`)
- Body: paginated JSON envelope — `data` (array of 25 base64 strings), `has_more: true`, `page: 1`, `page_size: 25`, `total: 500`
- Notable headers:
  - `link: </api/v1/dataset?batch=true&range=0-99>; rel="batch", </api/v1/stats>; rel="related"` — reveals batch mode and `/stats` route
  - `ratelimit-limit: 5`, `ratelimit-remaining: 4`, `ratelimit-reset: 1`
  - `etag: W/"bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf"` (64-char hex, SHA-256 width)
  - `cache-control: private, max-age=60, stale-while-revalidate=60`
  - Full security-header bundle
- See `discovery/dataset-response-analysis.md` for full header and body catalog.

### `GET /api/v1/stats` (authenticated — Phase 2D follow-up call)
- Status: 200
- Log file: `logs/20260508T021837Z-GET-api-v1-stats.json`
- Discovered via: `link: rel="related"` header on `/dataset` response
- Body: live assessment timer — `api_requests`, `assessment_expires_at`, `assessment_started_at`, `dataset_records`, `elapsed_seconds`, `remaining_seconds`
- Notable headers: full security-header bundle; no `ratelimit-*`, no `link`, no `etag`, no `cache-control`
- Note: `api_requests` counter increments on dataset fetches only; stats calls are not counted.

### `GET /api/v1/dataset?batch=true&range=0-99` (not yet called)
- Discovered via: `link: rel="batch"` header on `/dataset` response
- Expected: 100 records per call; 5 calls required for full 500-record dataset
- Status: unknown (not yet probed — Phase 3 action)

---

## Known Unknowns (post-clock discovery items)

Updated after Phase 2B/2C/2D. Items resolved in Phase 2 are marked.

- **Decryption key location:** UNRESOLVED. The `/dataset` response body contains no key material and no `x-*` key header was observed. Most likely delivered via POST `/api/v1/challenges`. See Hypothesis 2 in `discovery/dataset-response-analysis.md`.
- **Time-remaining mechanism:** RESOLVED (Phase 2D). Exposed via `/api/v1/stats` body fields `elapsed_seconds`, `remaining_seconds`, `assessment_started_at`, `assessment_expires_at`. No per-response `x-*` timing header observed.
- **Dataset structure (paginated vs indexed vs single):** RESOLVED (Phase 2B). `/dataset` returns a paginated envelope: 25 items per default page, 500 total records, `has_more: true` on page 1. A batch mode (`?batch=true&range=0-99`) is advertised via the `link` header for 100-item fetches. Records are positionally addressed (bare base64 strings in an array — no per-record ID field).
- **Submission response shape:** UNRESOLVED. `POST /submit` not yet probed. Unknown response format.
- **`/challenges` verb:** UNRESOLVED. Still inferred as POST-only from Phase 1 `allow: OPTIONS` anomaly. Not probed in Phase 2.
- **ETag integrity proof input:** UNRESOLVED. The 64-char hex ETag is present; its hash input (raw bytes, JSON, decoded records) is unknown. Phase 3 should verify.
- **Batch range semantics:** UNRESOLVED. Whether `range=0-99` is inclusive or exclusive at both ends needs empirical confirmation in Phase 3.
