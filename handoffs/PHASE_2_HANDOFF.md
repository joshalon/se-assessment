# Phase 2 Handoff — SE Assessment

> Synthesized: 2026-05-08 02:26 UTC (Fri May  8 02:26:02 UTC 2026)
> Phase: 2 (clock running)
> Authenticated requests made in Phase 2: **2 of 3** budget
> Audit verdict: **PASS** (10 / 10 gates)
> Commits made by working/audit agents: **0** (orchestrator commits at end of phase)

---

## Clock Status

| Item | Value |
|---|---|
| **T0 (clock started)** | `2026-05-08T02:16:44Z` |
| **Operational deadline (T0 + 2h50m)** | `2026-05-08T05:06:44Z` |
| **Server hard expiry (T0 + 3h)** | `2026-05-08T05:16:44Z` |
| Time consumed in Phase 2 | ~9m18s |
| Time remaining to operational deadline | ~2h40m41s |
| Safety margin (deadline → hard expiry) | 10 minutes |

The 10-minute buffer between operational deadline and the server's hard 3-hour cutoff is deliberate and should be preserved in Phase 3 planning.

---

## What Phase 2 Did

### Phase 2A — Pre-clock unauthenticated probes (5 paths, all 404)

`/api/v1/window`, `/api/v1/budget`, `/api/v1/quota`, `/api/v1/expires`, `/api/v1/deadline` — all 404 (not registered). No new real routes surfaced from speculation. These probes did not start the clock.

### Phase 2B — First authenticated call (CLOCK STARTED at T0)

`GET /api/v1/dataset` → 200, paginated JSON envelope (`data`, `has_more`, `page`, `page_size`, `total`). Page 1 of 20 returned 25 of 500 base64-encoded records, each decoding to exactly 256 bytes. The response carried a `link` header advertising:

- `</api/v1/dataset?batch=true&range=0-99>; rel="batch"` — a previously unknown batch fetch mode.
- `</api/v1/stats>; rel="related"` — a previously unknown companion endpoint.

It also carried an ETag (`W/"bf08cec00...585b47cf"`, 64 hex chars = SHA-256 width) and `ratelimit-limit: 5` / `ratelimit-remaining: 4` / `ratelimit-reset: 1`.

### Phase 2D — One justified follow-up call

`GET /api/v1/stats` (advertised by the `link: rel="related"` header) → 200. Returned `assessment_started_at`, `assessment_expires_at`, `elapsed_seconds`, `remaining_seconds`, `api_requests`, `dataset_records`. Confirmed the timer mechanism, the 3h hard expiry, and that the dataset has exactly 500 records. The `api_requests` counter increments only on `/dataset` calls, not on `/stats`.

Total authenticated calls: 2 of 3 allowed.

---

## Dataset Response — One-Paragraph Summary

The authenticated `GET /api/v1/dataset` returns a standard paginated JSON envelope (`data`, `has_more`, `page`, `page_size`, `total`) where `data` is an array of 25 bare base64 strings (no per-record IDs or wrappers). Each string decodes to exactly 256 bytes — consistent with RSA-2048 ciphertext. The total record count is 500, addressed positionally by index. The server advertises a batch fetch mode via a `link` header (`?batch=true&range=N-N+99`) that completes the full dataset in 5 calls — exactly matching `ratelimit-limit: 5`.

---

## Four Hypotheses (with confidence)

| # | Hypothesis | Confidence |
|---|---|---|
| H1 | The 64-hex-char ETag is the integrity-proof input — likely a SHA-256 over the dataset (input form TBD: raw bytes vs. JSON-serialized vs. concatenated decoded blocks). | medium |
| H2 | The decryption key is not in `/dataset` or `/stats`. Most likely returned by `POST /api/v1/challenges`. Records being uniformly 256 bytes suggests RSA-2048 ciphertext. | medium |
| H3 | Time-remaining is exposed only via `GET /api/v1/stats` body fields (`remaining_seconds`, `assessment_expires_at`). No per-response timing header observed. | high (empirically confirmed) |
| H4 | Batch mode (`?batch=true&range=N-N+99`) is the intended retrieval path — 5 calls = full dataset = exactly the rate-limit window. | high |

Full hypothesis evidence and alternatives are in `discovery/dataset-response-analysis.md` (191 lines, 12 sections, all gates verified).

---

## Recommended Phase 3 Layer 1 Approach

1. **Fetch dataset via batch mode.** 5 sequential GETs to `/api/v1/dataset?batch=true&range=0-99`, `100-199`, `200-299`, `300-399`, `400-499`. Verify positional ordering is deterministic by checking range-boundary records.
2. **Compute SHA-256 over candidate inputs.** Hash candidates: (a) concatenated decoded 256-byte blocks in positional order; (b) JSON-serialized `data` array as returned; (c) concatenated base64 strings. Compare against the ETag observed on the first batch response. Whichever matches is the integrity-proof input.
3. **Probe `/api/v1/challenges`** — Phase 1 inferred POST-only via the `allow: OPTIONS` anomaly. Likely returns the decryption key and challenge parameters; treat the call as scope-significant and design payload carefully.
4. **Submit Layer 1** — once the integrity proof is confirmed, submit via the existing CLI gate (`assessment.submit` requires an audit signoff under `audit/`).

`ratelimit-reset: 1` semantics are unresolved (residual seconds to current window reset vs. window duration); confirm during the first batch call. Stats calls do not count against `api_requests` but it is unknown whether they count against `ratelimit-limit` — assume they do until proven otherwise.

---

## Phase 2 Readiness Recommendation

**READY for Phase 3 Layer 1 scoping.**

Both audit gates were 10/10 PASS. Hypotheses are evidence-cited and confidence levels are calibrated (medium where uncertain, high only where empirically confirmed). All 4 hypotheses have actionable Phase 3 implications:

- H4 (high confidence): tells us the exact fetch sequence — 5 batch calls.
- H3 (high confidence): tells us how to read the clock — `/stats` body, not headers.
- H1 (medium): gives a falsifiable integrity-proof candidate (ETag = SHA-256 over dataset).
- H2 (medium): localises the next discovery target (`/challenges` POST).

The next prompt that Kael scopes for Phase 3 Layer 1 should specify: which ETag-input candidate to hash first, how to handle the rate-limit window between batch calls, and what payload shape to attempt for `/api/v1/challenges`.

---

## Non-Blocking Observations (from audit, for awareness)

1. **`endpoint-map.md` "Known Unknowns" section was updated, not appended.** The working agent replaced 5 Phase 1 bullets with Phase-2-resolved versions in the same section. No route probe data, inference text, or audit trail was modified. The section is explicitly labeled "post-clock discovery items" and is designed as a living summary. Classified non-blocking by audit.
2. **`ratelimit-reset: 1` semantics ambiguous** — could be residual seconds to current window reset, or window duration. Open question for Phase 3.
3. **`api_requests: 1` counter** counts dataset calls only, not stats calls. Track separately when planning rate-limit consumption.
4. **Operational deadline is 10 minutes inside server hard expiry** — preserve this safety margin in Phase 3.

---

## Artifact Inventory

```
discovery/dataset-response-analysis.md   (new, 191 lines)
discovery/audit-report-phase2.md         (new)
discovery/endpoint-map.md                (modified — Phase 2A probes + Phase 2B routes + updated Known Unknowns)
handoffs/PHASE_2_HANDOFF.md              (this file)
logs/20260508T021631Z-GET-api-v1-budget.json     (gitignored)
logs/20260508T021631Z-GET-api-v1-quota.json      (gitignored)
logs/20260508T021631Z-GET-api-v1-window.json     (gitignored)
logs/20260508T021632Z-GET-api-v1-expires.json    (gitignored)
logs/20260508T021634Z-GET-api-v1-deadline.json   (gitignored)
logs/20260508T021644Z-GET-api-v1-dataset.json    (gitignored — primary auth call)
logs/20260508T021837Z-GET-api-v1-stats.json      (gitignored — follow-up auth call)
```

No code changes. No `assessment/`, `tests/`, `pyproject.toml`, `.env`, `.gitignore`, or `README.md` modifications.

---

## Phase 2 Commits (orchestrator-executed at end of phase)

Two commits, mirroring the Phase 1 grouping pattern:

1. `docs: phase 2 dataset response analysis and audit report`
   — `discovery/dataset-response-analysis.md`, `discovery/audit-report-phase2.md`, `discovery/endpoint-map.md`
2. `docs: phase 2 handoff`
   — `handoffs/PHASE_2_HANDOFF.md`

Pushed to `origin/main` after both audit and synthesis are complete so the grader sees Phase 2 artifacts on the public repo.

End of Phase 2.
