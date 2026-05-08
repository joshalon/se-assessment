# Layer 1 Attempt 1 — Audit Report

> Audited: 2026-05-08T03:20:16Z
> Auditor: independent verification, read-only
> Working agent: Opus 4.7 high-effort (redo)
> Audit agent: Opus 4.7 high-effort

## 1. Dataset Fetch Verification

Inventory of `logs/*-GET-api-v1-dataset.json` (6 files):

| range   | log file                                                | status | len(data) | count |
|---------|---------------------------------------------------------|--------|-----------|-------|
| 0-99    | `20260508T025318_067695Z-GET-api-v1-dataset.json`       | 200    | 100       | 100   |
| 100-199 | `20260508T024003Z-GET-api-v1-dataset.json`              | 200    | 100       | 100   |
| 200-299 | `20260508T025319_841427Z-GET-api-v1-dataset.json`       | 200    | 100       | 100   |
| 300-399 | `20260508T024004Z-GET-api-v1-dataset.json`              | 200    | 100       | 100   |
| 400-499 | `20260508T024005Z-GET-api-v1-dataset.json`              | 200    | 100       | 100   |

The two `_<microseconds>Z` filenames are post-fix re-fetches (ranges 0-99 and 200-299); the three plain-second filenames survived the original collision.

Each batch log carries `request_params == {"batch": "true", "range": "N-M"}`, `response_status == 200`, and a `response_body` with `count == 100`, matching `range_start`, matching `range_end`, and `len(data) == 100`. `range=0-99` returned exactly 100 records — end bound inclusive, confirmed.

Phase 2 paginated probe present at `20260508T021644Z-GET-api-v1-dataset.json`: no params, `response_body.page == 1`, `page_size == 25`, `has_more == True`, `total == 500`, status 200.

Total batch records: 5 x 100 = 500 (verified by `len(records)` after assembly).

## 2. Independent Recomputation of C1-C5

Recomputed via standalone script (not committed). Inputs: 5 batch logs sorted by `range_start`, base64 strings concatenated in positional order.

| Candidate | Audit-computed                                                    | Report-stated                                                    | Result |
|-----------|-------------------------------------------------------------------|------------------------------------------------------------------|--------|
| C1        | `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37` | `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37` | MATCH  |
| C2        | `3d0f0e5fe6ae5684b52f62957b2715e6a6824757d8ebdad4b0b280c0510da478` | `3d0f0e5fe6ae5684b52f62957b2715e6a6824757d8ebdad4b0b280c0510da478` | MATCH  |
| C3        | `b67d4df9e37fb3e7f4af01c8fed29d03d1d0d89aa60f5a6134d42deef45ca8a4` | `b67d4df9e37fb3e7f4af01c8fed29d03d1d0d89aa60f5a6134d42deef45ca8a4` | MATCH  |
| C4        | `2623493785ad77341e6d6e1c00cdd82f5e2702a693a810268a0712114ed47b77` | `2623493785ad77341e6d6e1c00cdd82f5e2702a693a810268a0712114ed47b77` | MATCH  |
| C5        | `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf` | `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf` | MATCH  |

All 5/5 byte-exact matches.

## 3. Decoded Length and Dedupe Verification

- 500 base64 strings, every one validates and decodes to exactly 256 bytes (`set(map(len, decoded)) == {256}`).
- `len(set(records)) == 500` — zero duplicate base64 strings.
- Total decoded ciphertext: 128,000 bytes.

## 4. Primary Candidate Choice

Primary chosen: **C1** = `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37`. Consistent with the candidate set; not invented.

Rationale (in report): C1 hashes the raw decoded payloads in positional order, free of base64/JSON/envelope-shape choices. Cross-checked: this is a defensible canonical interpretation of "prove you reconstructed the dataset" given the 256-byte uniform record shape and the absence of a server-issued whole-dataset ETag.

Fallback ordering documented (C1 → C4 → C3 → C2 → C5) with the explicit caveat that the 8/8 budget allows only 1 attempt operationally.

Notes field present at lines 115-123 of the report. Length: ~520 chars. Names the algorithm (sha256), the input (concatenated raw decoded ciphertext, records 0..499 in batch order), the encoding (base64-decoded), the reconstruction method (5 authenticated batch fetches with explicit ranges), the byte counts (500 x 256 = 128,000), and the wrapper enforcement. Substantive — not boilerplate, not empty.

## 5. Layer 4 Observations Verification

`discovery/layer4-observations.md` exists and is substantive (99 lines, ~3.9 KB).

Independent recomputation:

- Shannon entropy over 128,000 bytes: **7.9985 bits/byte** (audit). Report: **7.9985**. Delta: 0.0000 — within tolerance.
- Byte-frequency: mean count 500.0 (matches), audit stdev 23.0624, report 23.0173 (delta 0.045, both close to theoretical 22.34 and consistent with uniform-random); min 441 at 0x7A and max 557 at 0x7B (both match).
- Per-record entropy at positions 0/124/249/374/499: audit 7.1545 / 7.1363 / 7.1146 / 7.1222 / 7.1832 — exact match.
- Distinct leading bytes: 193 (matches). Distinct trailing bytes: 218 (matches).
- Printable-ASCII run analysis present with explicit threshold (>=8), counts, samples, and an order-of-magnitude expectation calculation.
- Conclusion ties observations to a specific working hypothesis (RSA-2048 ciphertext) grounded in the 256-byte fixed record size.

This is analysis, not padding.

## 6. ETag Analysis Verification

The 5 batch ETag hashes (stripped of `W/"..."`):

- `c4810cc7fe6675612a8e148a2fe7bb21d85c04f0a700b2efdd8f73685cfedfec` (0-99)
- `42ad0a5e2a11b5b774bd77eb035f130d8faefe20fc21c0f20c327337751eb32e` (100-199)
- `3ce7ed990f739f30045482343480222c2c053e6cc2dca6054efcf218e84fcc10` (200-299)
- `ba577abcff3453e8d44715c466065c3cf058cf650b88a791c61c09503a550966` (300-399)
- `add573c0caf4f42d365d1a20333fd041d309715162534c763892046d729cb95b` (400-499)

`len(set(...)) == 5` — distinct. None equals the Phase 2 paginated ETag `bf08cec0...`. None equals C1, C2, C3, or C4.

## 7. Audit-Trail Gap and Recovery Section

Section "Audit-Trail Gap and Recovery" present at lines 125-144 of `discovery/layer-1-report.md`. Documents:

- Second-precision filename collision (the original `_fs_safe_timestamp`).
- Wrapper patch at commit `41a5bb2` introducing microsecond precision (`YYYYMMDDTHHMMSS_uuuuuuZ-...`).
- The 2 batch re-fetches (ranges 0-99 and 200-299) — confirmed on disk by the two `_<microseconds>Z` filenames.
- Recompute verification result (all C1-C5 match prior values bit-for-bit).
- Budget impact: 8 of 8 Layer 1 calls used (1 stats + 5 batches + 2 re-fetches), no retry buffer.
- Wrapper improvement carried forward.

Content correctness verified.

## 8. Code Scope Verification

- `git status` shows exactly the 4 expected untracked files: `assessment/layer1.py`, `tests/test_layer1.py`, `discovery/layer-1-report.md`, `discovery/layer4-observations.md`. No modified tracked files. No other untracked files.
- `git diff HEAD -- assessment/client.py assessment/submit.py` is empty — no modifications since `41a5bb2`.
- `git log --oneline | head -8` shows the wrapper-fix commit `41a5bb2` as HEAD, then Phase 2 commits `ca2bd3f` and `20335f4`, then the original Phase 1 commits (`1cc180a`, `dff36a6`, `ec2c01c`, `72908df`, `75d4efa`, ...). No commits authored by the working agent during this redo.

## 9. Wrapper-Only HTTP Enforcement

Grep of `assessment/layer1.py` and `tests/test_layer1.py` for `curl|wget|requests\.get|urllib|httpx\.get\(|httpx\.Client\(|requests\.post|httpx\.post`: zero matches.

Grep of `assessment/layer1.py` for `assessment.submit`, `/api/v1/challenges`, `POST`: zero matches.

Imports in `assessment/layer1.py`: `base64`, `hashlib`, `json`, `pathlib.Path`, typing. No HTTP libraries imported. `decode_records` uses `b64decode(s, validate=True)` with strict validation. The module is purely offline.

## 10. Test Verification

- `pytest tests/test_layer1.py -q` → **7 passed** in 0.10s.
- `pytest tests/test_client.py -q` → **15 passed** in 0.19s.

Both runs independent.

## 11. API Key Leak Scan

- `grep -rE "Bearer [^\*]"` across `assessment/layer1.py`, `tests/test_layer1.py`, the two discovery docs, and `logs/`: zero matches.
- All authenticated `logs/*.json` files have `request_headers.Authorization == "Bearer ***REDACTED***"` exactly. Verified by iterating all 13 logs; the 5 unauthenticated discovery logs (budget/quota/window/expires/deadline) carry no Authorization header. Eight logs carry the redacted Bearer.
- 60+ char alphanumeric hits in artifacts: only sha256 hex digests (64 chars) appearing in the candidate / ETag tables of `discovery/layer-1-report.md`. None resemble an API key (the real key is 67 chars per the brief; all matches here are 64-char hex consistent with sha256 outputs that the docs explicitly label as ETags or candidates).

No leaks.

## 12. Forbidden-Token Scan

Case-insensitive grep across the 4 Phase 3 Layer 1 artifacts for the five forbidden patterns specified in the audit instructions returned exactly 1 match:

- `discovery/layer-1-report.md:148` — the "Model-tier correction note" section names the lower-tier model identifier inline (a 16-char hyphenated token starting with `c-l-a-u-d-e`). Quoted text omitted from this audit doc to keep this file itself clean.

The remaining 3 artifacts (`assessment/layer1.py`, `tests/test_layer1.py`, `discovery/layer4-observations.md`) and all 13 log files have zero matches.

The audit instruction states "Zero matches required" — see Failures section below.

## 13. Authenticated Call Budget

Authenticated dataset+stats logs on disk:

- `20260508T021644Z-GET-api-v1-dataset.json` — Phase 2 paginated probe (1)
- `20260508T021837Z-GET-api-v1-stats.json` — Phase 2 stats (2)
- `20260508T024002Z-GET-api-v1-stats.json` — Phase 3 Task 1 stats (3)
- `20260508T024003Z-GET-api-v1-dataset.json` — batch 100-199 (4)
- `20260508T024004Z-GET-api-v1-dataset.json` — batch 300-399 (5)
- `20260508T024005Z-GET-api-v1-dataset.json` — batch 400-499 (6)
- `20260508T025318_067695Z-GET-api-v1-dataset.json` — batch 0-99 re-fetch (7)
- `20260508T025319_841427Z-GET-api-v1-dataset.json` — batch 200-299 re-fetch (8)

8 surviving authenticated logs. The 2 collision-lost original batch logs (ranges 0-99 and 200-299, original timestamps) do not exist on disk — this is the documented audit-trail gap closed by the re-fetches.

Wire-call counting per the orchestrator's framing:
- Phase 2 wire calls (authenticated): 1 paginated + 1 stats = 2
- Layer 1 wire calls (authenticated): 1 stats (T0+~23m) + 5 original batches (2 of which were lost to collision) + 2 re-fetches = 8
- Layer 1 budget exhausted: 8 of 8.
- Submission will be call #9 (Layer 1 attempt 1) — allowed per the orchestrator's framing.

## Submission Preparation Recap

From `discovery/layer-1-report.md` lines 85 and 115-123, the orchestrator should pass to `python -m assessment.submit`:

- `--type integrity_proof`
- `--value dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37`
- `--notes "Phase 3 Layer 1: integrity proof = sha256 of the concatenated raw decoded ciphertext for records 0..499 in batch order. Reconstructed offline from 5 authenticated batch fetches (ranges 0-99, 100-199, 200-299, 300-399, 400-499), 500 records x 256 bytes = 128,000 bytes. All HTTP through wrapper at assessment.client.make_request; per-call logs in logs/. Recomputed by Opus 4.7 high-effort redo to confirm the prior sonnet-tier values; all four computed candidates and the Phase 2 ETag matched on independent recompute."`

Note: the report does not specify the `--type` token explicitly; `integrity_proof` is the conventional value matching the candidate framing. Orchestrator should confirm against the submit CLI's accepted type values before invoking.

## Failures

1. Section 12: forbidden-token scan returned 1 match in `discovery/layer-1-report.md:148`. The audit checklist for this section states "Zero matches required" without exception; the literal forbidden substring appears as part of an inline model identifier in the "Model-tier correction note" section. The match is technical-context only (no co-authorship/attribution semantics), but the rule is literal.

   Remediation: working agent (or orchestrator with Shua's signoff) edits line 148 of `discovery/layer-1-report.md` to remove the model-name token (e.g., rephrase as "wrong model tier (lower tier)" or drop the parenthetical entirely). After remediation, re-grep the four artifacts plus this audit doc and re-run section 12. No code, log, or candidate-value changes are required; the submission preparation in this report (C1, notes string, budget) is otherwise correct.

## Overall Verdict: FAIL
