# Dataset Response Analysis

> Phase: 2B/2C
> Authenticated calls made: 2 of 3 allowed (1 primary + 1 justified follow-up)
> Captured: Fri May  8 02:18:00 UTC 2026

---

## Call Metadata

- T0 (UTC): 2026-05-08T02:16:44Z
- Operational deadline (T0 + 2h50m, UTC): 2026-05-08T05:06:44Z
- Server-reported assessment_expires_at: 2026-05-08T05:16:44.027507+00:00 (T0 + 3h exactly)
- Response status: 200
- Response size (content-length header): 8737 bytes
- Response body JSON-serialized length: 8770 characters
- Time to first byte (elapsed_ms from log): 691 ms

---

## Full Header Catalog

All headers present in `logs/20260508T021644Z-GET-api-v1-dataset.json`.

| Header Name | Value | Notes / Hypothesis |
|---|---|---|
| `content-type` | `application/json` | Standard JSON body |
| `link` | `</api/v1/dataset?batch=true&range=0-99>; rel="batch", </api/v1/stats>; rel="related"` | Reveals batch fetch mode and /api/v1/stats endpoint — neither was known in Phase 1 |
| `ratelimit-limit` | `5` | Max 5 authenticated requests per window |
| `ratelimit-remaining` | `4` | 4 remaining after this call (1 used) |
| `ratelimit-reset` | `1` | Seconds until window resets |
| `etag` | `W/"bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf"` | Weak ETag; SHA-256-length hex (64 chars) — likely a hash of the current page content or the full dataset |
| `cache-control` | `private, max-age=60, stale-while-revalidate=60` | Client-side cache only (private); 60-second freshness; not present on unauthenticated 401 responses |
| `content-security-policy` | `base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'` | Same security bundle as all authenticated endpoints |
| `strict-transport-security` | `max-age=31536000; includeSubDomains` | No `preload` — consistent with Phase 1 observation |
| `x-frame-options` | `DENY` | Standard clickjacking prevention |
| `x-content-type-options` | `nosniff` | Standard MIME-type enforcement |
| `referrer-policy` | `no-referrer` | No referrer leakage |
| `cross-origin-opener-policy` | `same-origin` | COOP isolation |
| `cross-origin-embedder-policy` | `require-corp` | COEP isolation |
| `cross-origin-resource-policy` | `same-origin` | CORP isolation |
| `content-length` | `8737` | Body size in bytes |
| `date` | `Fri, 08 May 2026 02:16:44 GMT` | Server timestamp; confirms T0 |

---

## Body Structure

- Top-level type: object
- Top-level keys: `data`, `has_more`, `page`, `page_size`, `total`
- Body shape inference: paginated — standard page/page_size/has_more envelope with a flat array of records under `data`
- Record count (this page): 25
- Total records: 500
- Page: 1 of 20 (25 items/page) or 1 of 5 (100 items/batch, via batch mode)

Sample record (structure only — first element of `data`):
```
"K7IUPBR4PweWVZcQw3/f+4b8OSbc93SBvW7zjLNQMrZsgrQDOTNWL1M9..." (344 chars)
```
- Each record is a plain base64 string (no wrapping object, no fields, no ID)
- Decoded byte length: exactly 256 bytes for every record examined
- All records end with `==` (base64 padding consistent with 256-byte payloads)

---

## Body — Full Field Catalog

The body is a single flat JSON object. There is no additional nesting beyond the `data` array.

| Field | Type | Value (page 1) | Notes |
|---|---|---|---|
| `data` | array of string | 25 elements | Each element is a standard base64-encoded binary blob, 344 chars / 256 decoded bytes |
| `has_more` | boolean | `true` | Pages 2–20 not yet fetched |
| `page` | integer | `1` | 1-indexed page number |
| `page_size` | integer | `25` | Items per default page |
| `total` | integer | `500` | Total record count across all pages |

No record-level fields exist: the array elements are bare strings, not objects. There is no `id`, `index`, `checksum`, or metadata field per record. The identity of each ciphertext is positional (array index 0–499).

---

## Hypothesis 1: Integrity Proof Format (Layer 1)

- **Hypothesis:** The integrity proof mechanism is the `etag` header combined with a SHA-256 (or HMAC-SHA-256) hash over the full dataset or the current page content. The ETag value (`W/"bf08cec00..."`) is a 64-hex-character string — the correct length for a SHA-256 digest — and is present on the authenticated response. The intent is likely for the solver to verify that the retrieved records have not been tampered with, using a known-or-derivable hash over the concatenated (or JSON-serialized) ciphertext array.
- **Evidence:** `etag: W/"bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf"` (64 hex chars = 256 bits = SHA-256 width). Standard SHA-256 integrity check over `data` array contents is consistent with this length.
- **Confidence:** medium — the ETag is strongly suggestive but its exact input (full dataset vs. page vs. decoded bytes vs. serialized JSON) is not yet known. The challenges endpoint (Phase 3 concern) may clarify the expected proof format.
- **Alternative hypotheses worth holding:**
  1. ETag is a server-side cache key computed from internal state, not intended as a solver-facing integrity proof. The real proof mechanism lives in the `/api/v1/challenges` response.
  2. Each record carries an implicit HMAC in its last N bytes (after decryption), not at the envelope level.
  3. The hash input is the concatenation of all 500 decoded 256-byte blobs, not the page JSON.

---

## Hypothesis 2: Decryption Key Location (Layer 2)

- **Hypothesis:** The decryption key is delivered via the `/api/v1/challenges` endpoint (likely a POST response), not inline in the `/api/v1/dataset` response. The dataset body contains no key field, no `x-*` decryption-key header, and no embedded key material. The separation of dataset (ciphertexts) from key (presumably in `/challenges`) is consistent with an assessment workflow where solving the challenge grants the key. Each ciphertext is 256 bytes — the exact output size of RSA-2048 encryption — which would require an asymmetric key for decryption.
- **Evidence:** No `x-decryption-key`, `x-key`, or similar header on the dataset response. No `key`, `iv`, `nonce`, or encryption-metadata field in the body. All 500 records are fixed 256-byte blobs (RSA-2048 output width). The workflow implied by Phase 1 (`/challenges` + `/submit`) suggests the key is gated behind challenge completion.
- **Confidence:** medium — the absence of a key in `/dataset` is strong evidence it's elsewhere, but the delivery endpoint (challenges vs. a different mechanism) remains unconfirmed. RSA-2048 inference is probabilistic (AES with padding could also produce 256-byte outputs in some configurations, but uniform fixed-length records strongly favor RSA block cipher behavior).
- **Alternatives:**
  1. The key is in the `/api/v1/stats` response body (not observed — stats body has only timing and count fields).
  2. The key is derived from the API key itself via a KDF; no separate endpoint needed.
  3. The key is returned in the response header of a POST to `/api/v1/challenges`.

---

## Hypothesis 3: Time-Remaining Mechanism

- **Hypothesis:** Time-remaining is exposed exclusively via the `/api/v1/stats` endpoint body, not via a per-response header. The `stats` response provides `elapsed_seconds`, `remaining_seconds`, `assessment_started_at`, and `assessment_expires_at`. The dataset response has no `x-time-remaining` or similar header. Phase 1 confirmed no standalone `/time-remaining`, `/timer`, or `/clock` route exists.
- **Evidence:** `/api/v1/stats` body fields: `elapsed_seconds: 113`, `remaining_seconds: 10686`, `assessment_started_at: 2026-05-08T02:16:44.027507+00:00`, `assessment_expires_at: 2026-05-08T05:16:44.027507+00:00`. Dataset response headers have no timing `x-*` field. Stats endpoint was discovered via the `link: rel="related"` header on the dataset response.
- **Confidence:** high — `stats` provides exact and precise timer state. No per-response timing header was observed. The relationship between `/dataset` and `/stats` via `rel="related"` link confirms `/stats` is the designated metadata companion.
- **Alternatives:**
  1. Timer is also mirrored as an `x-*` header on other authenticated endpoints not yet called (e.g., `/challenges`). Possible but additive, not contradictory.

---

## Hypothesis 4: Dataset Fetch Strategy (Layer 1)

- **Hypothesis:** A batch fetch strategy using the `link: rel="batch"` hint is the correct approach. The default page (`page_size=25`) requires 20 calls to retrieve all 500 records. The `link` header advertises `</api/v1/dataset?batch=true&range=0-99>; rel="batch"`, implying a range-based batch mode fetching 100 records per call — requiring only 5 calls for the full dataset (ranges `0-99`, `100-199`, `200-299`, `300-399`, `400-499`). Given the `ratelimit-limit: 5` per window, this is almost certainly intentional: the batch mode is sized precisely to complete the full retrieval within one rate-limit window of 5 calls.
- **Evidence:** `link` header reveals `batch=true&range=0-99` as an advertised fetch pattern. `ratelimit-limit: 5`. `total: 500`. 500 / 100 per batch = 5 calls = exactly the rate limit. Default pagination would require 20 calls and 4 rate-limit windows.
- **Confidence:** high — the numerical alignment (5 batch calls = 5 rate-limit allowance) is too precise to be coincidental. The `link` header is the server's explicit hint for the intended fetch pattern.
- **Estimated number of additional fetches needed:** 5 (ranges 0-99 through 400-499), consuming the full rate-limit window.

---

## Phase 2D — Follow-up Call: GET /api/v1/stats

**Justification (written before the call):** The `link` header on `/dataset` referenced `/api/v1/stats` as `rel="related"`. This endpoint was not in Phase 1's surface map. A single call resolves Hypothesis 3 (time-remaining mechanism) definitively and may reveal additional metadata (key hints, record-count confirmation). This is a legitimate disambiguation call within the 2-follow-up budget.

**Log file:** `logs/20260508T021837Z-GET-api-v1-stats.json`

### Stats Response Headers

| Header Name | Value | Notes |
|---|---|---|
| `content-type` | `application/json` | |
| `content-security-policy` | `base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'` | Same security bundle |
| `strict-transport-security` | `max-age=31536000; includeSubDomains` | |
| `x-frame-options` | `DENY` | |
| `x-content-type-options` | `nosniff` | |
| `referrer-policy` | `no-referrer` | |
| `cross-origin-opener-policy` | `same-origin` | |
| `cross-origin-embedder-policy` | `require-corp` | |
| `cross-origin-resource-policy` | `same-origin` | |
| `content-length` | `206` | |
| `date` | `Fri, 08 May 2026 02:18:37 GMT` | 113 seconds after T0 |

Notable: no `ratelimit-*` headers, no `link` header, no `etag`, no `cache-control` on `/stats`. Stats is a live-computed endpoint, not a cached resource.

### Stats Response Body Fields

| Field | Type | Value | Notes |
|---|---|---|---|
| `api_requests` | integer | `1` | Counts authenticated dataset calls (not stats calls) |
| `assessment_expires_at` | string (ISO-8601) | `2026-05-08T05:16:44.027507+00:00` | Exactly T0 + 3h |
| `assessment_started_at` | string (ISO-8601) | `2026-05-08T02:16:44.027507+00:00` | Matches T0 |
| `dataset_records` | integer | `500` | Confirms total |
| `elapsed_seconds` | integer | `113` | Live elapsed time at call moment |
| `remaining_seconds` | integer | `10686` | Live remaining time at call moment |

**What this confirmed:** Hypothesis 3 is resolved. Time-remaining is a body field on `/stats`, not a response header on `/dataset`. The clock is server-side, accurate to the second, and the window is exactly 3 hours (not 2h50m — the 2h50m operational deadline is a safety margin). The `api_requests: 1` counter tracks dataset fetches, which is relevant for rate-limit planning.

---

## Anomalies and Surprises

1. **`link` header reveals two undiscovered routes.** `/api/v1/stats` and the `batch=true&range=...` query-parameter mode were not discoverable via Phase 1 unauthenticated probing. The link header is the API's primary discovery mechanism for these.
2. **Rate limit of 5 matches batch call count exactly.** Fetching 500 records in batches of 100 requires exactly 5 calls, which equals `ratelimit-limit: 5`. This strongly implies the batch mode is the intended consumption pattern and the rate limit is intentionally scoped to one full retrieval per window.
3. **All records are bare strings (no per-record metadata).** Records have no ID, index field, or checksum. Positional ordering is the only addressing scheme for individual records.
4. **`cache-control: private, max-age=60` on an authenticated endpoint.** This is noteworthy because Phase 1 found NO `cache-control` on any response. The authenticated dataset response does have caching, but it is `private` (client-side only) and short-lived (60s).
5. **ETag on authenticated dataset.** A 64-char hex ETag (SHA-256 width) is present. This was not expected and may serve a dual purpose: standard HTTP caching and solver-facing integrity verification.
6. **`api_requests` counter in stats counts 1, not 2, after both the dataset call and the stats call.** Stats calls themselves are not counted — only dataset calls increment this counter. This is relevant for rate-limit tracking.
7. **Server clock precision.** `assessment_started_at` includes microseconds (`.027507`), confirming server-side high-precision timing. The 3-hour window is hard and server-enforced.

---

## Open Questions for Phase 3

1. **What is the exact input to the ETag hash?** Is it computed over the raw bytes of the 500 decoded records, the JSON-serialized `data` array, or something else? This determines whether the ETag can be used as the integrity proof for submission.
2. **What does `/api/v1/challenges` accept and return?** Phase 1 inferred POST-only. Does it return the decryption key? Does it define challenge-specific parameters (expected output format, hash algorithm, etc.)?
3. **What is the decryption algorithm?** All records are exactly 256 bytes — consistent with RSA-2048. But the key source is unknown. A symmetric cipher (e.g., AES-256-CBC with padding) can also produce 256-byte blocks.
4. **Does the batch range use inclusive or exclusive end?** `range=0-99` could mean indices 0–99 inclusive (100 items) or 0–98 (99 items). The naming convention strongly suggests inclusive, but needs verification.
5. **Is the `data` array ordering deterministic?** If re-fetching page 1 with `batch=true` returns the same records in the same order, position can be used as a reliable index. Non-deterministic ordering would complicate integrity proofs.
6. **What does `/api/v1/submit` accept as a payload?** The submission format (type, value, proof) was not exercised in Phase 1 or 2.
7. **Does `api_requests` count batch calls the same as paginated calls?** At rate limit 5 per window, batch strategy uses all 5 slots. Knowing the reset interval is critical.
8. **What is the rate-limit window duration?** `ratelimit-reset: 1` (second) was observed, but this may be the residual seconds until the CURRENT window resets, not the window size.

---

## Recommended First Action for Phase 3 Layer 1

Fetch the full dataset using the batch mode advertised in the `link` header: 5 sequential GET calls to `/api/v1/dataset?batch=true&range=0-99`, `100-199`, `200-299`, `300-399`, `400-499`. Confirm record count is 500, verify positional ordering is deterministic by checking overlap at range boundaries (e.g., last record of `0-99` matches first record when re-examined). Compute SHA-256 over the concatenated decoded 256-byte blobs and compare against the ETag value to determine if ETag is the integrity proof input. Then call `/api/v1/challenges` (likely POST) to obtain the decryption key and challenge parameters.
