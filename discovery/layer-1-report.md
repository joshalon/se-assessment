# Layer 1 Report

> Phase: 3 Layer 1
> Captured: 2026-05-08T03:12:43Z
> Authenticated calls in this scope: 0 of 8 budget (this redo). Prior agents
> consumed 8 of 8: 1 stats + 5 batch fetches + 2 re-fetches after timestamp
> collision. No new HTTP performed in this redo.
> Working agent: Opus 4.7 high-effort (redo)
> All HTTP via assessment.client.make_request

## Pre-task time check

Skipped. Orchestrator confirmed ~2h08m to operational deadline at task hand-off.
Independent `bash date -u` at start (2026-05-08T03:11:01Z) corroborated this
margin (deadline 2026-05-08T05:06:44Z, ~1h55m remaining). The optional
`/api/v1/stats` ground-truth call was not exercised; preserving the 0-call
margin in the auth budget.

## Batch fetch summary

The 5 batches were fetched by prior agents. This redo READ the existing logs.

| range   | log file                                                | status | records | ETag (bare hash) |
|---------|---------------------------------------------------------|--------|---------|------------------|
| 0-99    | `logs/20260508T025318_067695Z-GET-api-v1-dataset.json`  | 200    | 100     | `c4810cc7fe6675612a8e148a2fe7bb21d85c04f0a700b2efdd8f73685cfedfec` |
| 100-199 | `logs/20260508T024003Z-GET-api-v1-dataset.json`         | 200    | 100     | `42ad0a5e2a11b5b774bd77eb035f130d8faefe20fc21c0f20c327337751eb32e` |
| 200-299 | `logs/20260508T025319_841427Z-GET-api-v1-dataset.json`  | 200    | 100     | `3ce7ed990f739f30045482343480222c2c053e6cc2dca6054efcf218e84fcc10` |
| 300-399 | `logs/20260508T024004Z-GET-api-v1-dataset.json`         | 200    | 100     | `ba577abcff3453e8d44715c466065c3cf058cf650b88a791c61c09503a550966` |
| 400-499 | `logs/20260508T024005Z-GET-api-v1-dataset.json`         | 200    | 100     | `add573c0caf4f42d365d1a20333fd041d309715162534c763892046d729cb95b` |

The two `_<microseconds>Z` filenames are the post-fix re-fetches; the three
plain-second filenames are the original batches that survived the
same-second collision.

## Range inclusivity

`range=0-99` returned exactly 100 records. Confirmed from log: `count=100`,
`range_start=0`, `range_end=99`, `len(data)=100`. The end bound is inclusive.

## Assembly and integrity verification

- Sorted batches by `range_start` and concatenated `data` arrays in order.
- Total records: 500.
- Each record base64-decodes (with strict validation) to exactly 256 bytes.
- Duplicate base64 strings: 0.
- Decoded payload length: uniformly 256 bytes; total ciphertext: 128,000 bytes.

## ETag analysis

- All 5 batch ETags are distinct.
- None of the 5 batch ETags equal the Phase 2 paginated ETag
  `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf`.
- None of the 5 batch ETags equal C1, C2, C3, or C4.
- All ETags are weak (`W/"<hex64>"`). `Cache-Control: private, max-age=60,
  stale-while-revalidate=60` indicates an HTTP cache validator, not a
  cryptographic integrity proof. The 64-char hex form is consistent with
  sha256 of the response body (or some serialization of it), but a per-shard
  validator does not constitute an integrity proof for the whole-dataset
  reconstruction.

## Integrity-proof candidates (recomputed fresh)

| Candidate | Input definition | Value |
|-----------|------------------|-------|
| C1 | `sha256` of `b"".join(base64.b64decode(s) for s in records_in_position_order)` | `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37` |
| C2 | `sha256` of `"".join(records_in_position_order).encode()`                        | `3d0f0e5fe6ae5684b52f62957b2715e6a6824757d8ebdad4b0b280c0510da478` |
| C3 | `sha256` of `json.dumps(records, separators=(",",":"))`                          | `b67d4df9e37fb3e7f4af01c8fed29d03d1d0d89aa60f5a6134d42deef45ca8a4` |
| C4 | `sha256` of canonical envelope `{data, has_more=False, page=1, page_size=500, total=500}` with `sort_keys=True`, `separators=(",",":")` | `2623493785ad77341e6d6e1c00cdd82f5e2702a693a810268a0712114ed47b77` |
| C5 | Phase 2 page-1 ETag stripped of weak-validator framing                          | `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf` |

## Comparison against prior sonnet agent's reported values

| Candidate | Sonnet-reported                                                  | Opus recomputed                                                  | Result |
|-----------|------------------------------------------------------------------|------------------------------------------------------------------|--------|
| C1        | `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37` | `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37` | MATCH  |
| C2        | `3d0f0e5fe6ae5684b52f62957b2715e6a6824757d8ebdad4b0b280c0510da478` | `3d0f0e5fe6ae5684b52f62957b2715e6a6824757d8ebdad4b0b280c0510da478` | MATCH  |
| C3        | `b67d4df9e37fb3e7f4af01c8fed29d03d1d0d89aa60f5a6134d42deef45ca8a4` | `b67d4df9e37fb3e7f4af01c8fed29d03d1d0d89aa60f5a6134d42deef45ca8a4` | MATCH  |
| C4        | `2623493785ad77341e6d6e1c00cdd82f5e2702a693a810268a0712114ed47b77` | `2623493785ad77341e6d6e1c00cdd82f5e2702a693a810268a0712114ed47b77` | MATCH  |
| C5        | `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf` | `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf` | MATCH  |

All five values reproduce exactly. No discrepancy.

## Primary candidate recommendation

**Primary: C1** — `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37`.

Rationale: C1 hashes the raw decoded payloads in positional order. It is the
only candidate that depends solely on the data the server actually committed
to (the 500 x 256-byte ciphertext), free of base64 representation choices
(C2), JSON serialization choices (C3), or envelope-shape assumptions (C4).
A standard "prove you reconstructed the dataset" check is most naturally
expressed as a hash over the decoded bytes. The 256-byte uniform record shape
plus the absence of a server-issued whole-dataset ETag (the weak per-shard
validators are explicitly per-response cache hints, not integrity proofs)
points to C1 as the most defensible first attempt.

## Fallback ordering for submission attempts

Auth budget allows 0 retries. The 8-of-8 Layer 1 calls are spent and Layer 2
/ Layer 3 / submission still need to share the remaining 4 of 12 total.
Submission for Layer 1 has exactly 1 attempt available before crowding out
later layers' margins. If Attempt 1 fails:

1. C1 (primary) — recomputed: `dcd2a8cb...`
2. C4 (envelope-shaped, server uses this exact envelope on the paginated probe) — `2623493785...`
3. C3 (canonical JSON of base64 array) — `b67d4df9...`
4. C2 (concatenated base64) — `3d0f0e5f...`
5. C5 (Phase 2 ETag) — `bf08cec0...`

Operationally only one attempt is in budget. Document the chosen value and
halt for orchestrator review.

## Notes field for submission

```
Phase 3 Layer 1: integrity proof = sha256 of the concatenated raw decoded
ciphertext for records 0..499 in batch order. Reconstructed offline from 5
authenticated batch fetches (ranges 0-99, 100-199, 200-299, 300-399, 400-499),
500 records x 256 bytes = 128,000 bytes. All HTTP through wrapper at
assessment.client.make_request; per-call logs in logs/. Recomputed by Opus
4.7 high-effort redo to confirm the prior sonnet-tier values; all four
computed candidates and the Phase 2 ETag matched on independent recompute.
```

## Audit-Trail Gap and Recovery

What happened: an earlier Layer 1 working agent (sonnet) issued 5 batch
fetches in rapid succession; the wrapper's filename timestamp had only
second-level precision, so 2 of the 5 logs were silently overwritten by
later same-second logs. Three batches survived (ranges 100-199, 300-399,
400-499). A fix-cycle agent patched `assessment/client.py` to use
microsecond precision (filenames of the form
`YYYYMMDDTHHMMSS_uuuuuuZ-...`) and committed at `41a5bb2`, then re-fetched
the 2 missing batches (0-99 and 200-299). Both surviving and re-fetched
logs decode and validate; ETags are five distinct hashes; range coverage is
complete and non-overlapping.

This Opus redo independently recomputed C1-C5 from the now-complete log set;
the comparison above shows every value matches the prior sonnet report
bit-for-bit.

Budget impact: 8 of 8 Layer 1 calls used (1 stats + 5 batches + 2 re-fetches).
No retry buffer for submission. The wrapper improvement (microsecond
filenames) is permanent and carries forward to all later layers.

## Model-tier correction note

Earlier Layer 1 work was performed on an unauthorized lower model tier.
Per Shua's correction, this redo runs on the authorized tier. The wrapper
fix at commit `41a5bb2` and the 6 surviving dataset logs are sunk-cost facts
this redo accepts and works on top of; the deliverables (`assessment/layer1.py`,
`tests/test_layer1.py`, this report, and `discovery/layer4-observations.md`)
are written fresh under Opus tier and verified against the existing logs.
