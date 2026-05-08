# Layer 1 Attempt 2 — Audit Report

> Audited: Thu May 7 23:28:24 EDT 2026 (host wall clock; UTC ~03:28 of 2026-05-08)
> Auditor: independent verification, read-only
> Working agent: Opus 4.7 high-effort (redo)
> Audit agent: Opus 4.7 high-effort
> Notes: re-audit after orchestrator scrub of one forbidden-token match in the Layer 1 report

This audit re-executes all 13 sections from attempt 1. No deltas-only — every check was repeated against current on-disk files. The orchestrator's edit to one line in `discovery/layer-1-report.md` is the only intervening change.

## 1. Dataset Fetch Verification

Read all 6 dataset logs in `logs/`. Excluding the Phase 2 paginated probe (`20260508T021644Z-...`, no `batch=true`), the 5 batch logs are:

| range | log file | status | records |
|---|---|---|---|
| 0-99 | `20260508T025318_067695Z-GET-api-v1-dataset.json` | 200 | 100 |
| 100-199 | `20260508T024003Z-GET-api-v1-dataset.json` | 200 | 100 |
| 200-299 | `20260508T025319_841427Z-GET-api-v1-dataset.json` | 200 | 100 |
| 300-399 | `20260508T024004Z-GET-api-v1-dataset.json` | 200 | 100 |
| 400-499 | `20260508T024005Z-GET-api-v1-dataset.json` | 200 | 100 |

All 5 ranges present, contiguous, non-overlapping. Each `body.count == 100`, `len(body.data) == 100`. Status 200 across the board. PASS.

## 2. Independent Recomputation of C1-C5

Loaded the 5 batch logs above, sorted by `range_start`, concatenated `data` arrays in positional order. Total records = 500, unique = 500. Recomputed C1-C4 from scratch using the canonical definitions; pulled C5 from the Phase 2 paginated log's ETag (stripped of weak-validator framing). Results:

| Candidate | Reported | Recomputed | Match |
|---|---|---|---|
| C1 | `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37` | `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37` | yes |
| C2 | `3d0f0e5fe6ae5684b52f62957b2715e6a6824757d8ebdad4b0b280c0510da478` | `3d0f0e5fe6ae5684b52f62957b2715e6a6824757d8ebdad4b0b280c0510da478` | yes |
| C3 | `b67d4df9e37fb3e7f4af01c8fed29d03d1d0d89aa60f5a6134d42deef45ca8a4` | `b67d4df9e37fb3e7f4af01c8fed29d03d1d0d89aa60f5a6134d42deef45ca8a4` | yes |
| C4 | `2623493785ad77341e6d6e1c00cdd82f5e2702a693a810268a0712114ed47b77` | `2623493785ad77341e6d6e1c00cdd82f5e2702a693a810268a0712114ed47b77` | yes |
| C5 | `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf` | `bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf` | yes |

5/5 byte-exact. PASS.

## 3. Decoded Length and Dedupe Verification

All 500 base64 strings decoded with strict validation. Every decoded record is exactly 256 bytes. `len(set(records)) == 500` (zero base64 duplicates); fixed length plus base64 uniqueness implies zero decoded duplicates. Total ciphertext length = 500 * 256 = 128,000 bytes (verified). PASS.

## 4. Primary Candidate Choice

The Layer 1 report names C1 (`dcd2a8cb...`) as the primary candidate. Rationale (per report): C1 is the only candidate that depends solely on the bytes the server actually committed to (the 500 x 256-byte plaintext), independent of base64 representation, JSON serialization, or envelope-shape assumptions. The fallback ordering (C1 -> C4 -> C3 -> C2 -> C5) is documented along with the constraint that the Layer 1 auth budget is exhausted (8 of 8) so only one submission attempt is in budget. The submission `notes` field is present, substantive, identifies the integrity-proof method, references the wrapper (`assessment.client.make_request`) and the 5-batch reconstruction, and is free of forbidden tokens (verified in Section 12). PASS.

## 5. Layer 4 Observations Verification

`discovery/layer4-observations.md` exists and is substantive (99 lines). Independently re-derived:

- Total bytes: 128,000 — matches.
- Shannon entropy of the full concatenation: `7.998469`. Report value `7.9985`. Diff `0.000031`, well within 0.001 tolerance. PASS.
- Per-record entropy at sample positions: record[0]=7.1545, record[124]=7.1363, record[249]=7.1146, record[374]=7.1222, record[499]=7.1832 — all match the report exactly.
- Byte-frequency stats: mean 500.0, stdev 23.0173, min 441 at `0x7a`, max 557 at `0x7b` — match exactly.
- Leading bytes: 193 distinct, top three `(0x02, 7), (0xa8, 7), (0x9c, 6)` — match.
- Trailing bytes: 218 distinct, top three `(0x6b, 7), (0x28, 7), (0x01, 6)` — match.
- Printable-ASCII runs >= 8: 30 runs, max length 10 — match.

The conclusion (uniform high-entropy bytestream consistent with strong cipher / RSA-2048-block-sized records) is grounded in the verified statistics. PASS.

## 6. ETag Analysis Verification

Five batch ETags (extracted directly from log headers):

```
0-99    : c4810cc7fe6675612a8e148a2fe7bb21d85c04f0a700b2efdd8f73685cfedfec
100-199 : 42ad0a5e2a11b5b774bd77eb035f130d8faefe20fc21c0f20c327337751eb32e
200-299 : 3ce7ed990f739f30045482343480222c2c053e6cc2dca6054efcf218e84fcc10
300-399 : ba577abcff3453e8d44715c466065c3cf058cf650b88a791c61c09503a550966
400-499 : add573c0caf4f42d365d1a20333fd041d309715162534c763892046d729cb95b
```

All 5 distinct; none equal to the Phase 2 paginated ETag `bf08cec0...` (= C5); none equal to C1, C2, C3, or C4. All carry weak-validator framing `W/"..."` per `Cache-Control: private, max-age=60, stale-while-revalidate=60`, consistent with HTTP cache hints rather than dataset integrity proofs. PASS.

## 7. Audit-Trail Gap and Recovery Section

Section "Audit-Trail Gap and Recovery" in `discovery/layer-1-report.md` (lines 125-144) covers:

- timestamp collision (second-only filename precision overwrote 2 of 5 batch logs) — present
- wrapper patch (commit `41a5bb2`, microsecond precision filenames `YYYYMMDDTHHMMSS_uuuuuuZ-...`) — present
- 2 re-fetches for ranges 0-99 and 200-299 — present
- recompute verification of C1-C5 against the prior agent's values, all match — present
- 8/8 budget exhaustion / no retry buffer — present
- wrapper improvement carries forward — present

Confirmed via `git log --oneline`: `41a5bb2 fix: prevent log-filename collisions with microsecond timestamps`. PASS.

## 8. Code Scope Verification

`git status` shows untracked: `assessment/layer1.py`, `tests/test_layer1.py`, `discovery/layer-1-report.md`, `discovery/layer4-observations.md`, and the `audit/` directory (containing `audit-report-layer-1-attempt-1.md` and the new `audit-report-layer-1-attempt-2.md` this auditor is writing). Exactly the expected 4 Layer 1 deliverable files plus the audit artifacts.

`git diff HEAD -- assessment/client.py assessment/submit.py`: empty. Neither file was modified by the working agent or this audit.

`git log --oneline | head -8`:
```
41a5bb2 fix: prevent log-filename collisions with microsecond timestamps
ca2bd3f docs: phase 2 handoff
20335f4 docs: phase 2 dataset response analysis and audit report
1cc180a docs: scrub external project name from artifacts
dff36a6 docs: phase 1 handoff and commit plan
ec2c01c docs: phase 1 endpoint discovery and audit reports
72908df docs: add assessment package usage guide
75d4efa feat: add submission CLI gated on audit signoff
```

`41a5bb2` (wrapper microsecond fix) sits on top of the Phase 2 commits. No commits made by the working agent or this audit. PASS.

## 9. Wrapper-Only HTTP Enforcement

`grep -nE "curl|wget|requests\.get|urllib|httpx\.get\(|httpx\.Client\(" assessment/layer1.py tests/test_layer1.py` -> ZERO MATCHES. `assessment/layer1.py` does not import `httpx`, `requests`, or `urllib` at all (only `base64`, `hashlib`, `json`, `pathlib`, `typing`); it operates purely on log files written by the wrapper. `tests/test_layer1.py` uses synthetic in-memory fakes (`_fake_record`, `_fake_batches`) and no HTTP machinery. Layer 1 made no HTTP calls in this redo. PASS.

## 10. Test Verification

Ran independently:

- `pytest tests/test_layer1.py -q`: `7 passed in 0.05s`
- `pytest tests/test_client.py -q`: `15 passed in 0.12s`

Both green. PASS.

## 11. API Key Leak Scan

Inspected the `authorization` header of every authenticated log under `logs/`: all 8 read `Bearer ***REDACTED***`. Programmatically scanned `request_headers` of every log for any string matching long alphanumeric patterns that did not contain `REDACTED`: zero hits. Grepped `discovery/`, `assessment/layer1.py`, `tests/test_layer1.py`, `audit/` for `Bearer ` not followed by `***REDACTED***`: only generic 401 documentation strings (`Bearer <api-key>`) — no actual key material. Long alphanumeric strings in log bodies are the base64 ciphertext records inside `data` arrays, which are intentional response payloads, not credentials. PASS.

## 12. Forbidden-Token Scan

Searched case-insensitively across all Layer 1 artifacts (the 4 deliverables plus the prior audit attempt file) for all five forbidden patterns specified in the audit brief: the co-authorship attribution token, the lab name, the model-family identifier, the standalone two-letter abbreviation surrounded by word boundaries, and the auto-attribution boilerplate phrase.

Files scanned:
- `assessment/layer1.py` — zero matches
- `tests/test_layer1.py` — zero matches
- `discovery/layer-1-report.md` — zero matches (orchestrator's scrub at the model-tier-correction note successfully removed the prior literal model identifier; that line now reads "an unauthorized lower model tier" with no model-family name)
- `discovery/layer4-observations.md` — zero matches
- `audit/audit-report-layer-1-attempt-1.md` — zero matches (the prior auditor referred to the offending pattern abstractly rather than naming it)

Total matches across Layer 1 artifacts: 0. The scan also touched `discovery/audit-report-phase2.md` (a Phase 2 artifact, already committed in `20335f4`, outside Layer 1 scope) which contains a meta-description of its own scan list — that file is out-of-scope for Layer 1 audit and not a regression introduced by this layer.

PASS.

## 13. Authenticated Call Budget

Disk-log inventory:

- 6 dataset logs: 1 Phase 2 paginated probe + 5 batch logs (3 originals that survived the same-second collision + 2 re-fetches at microsecond precision)
- 2 stats logs (1 Phase 2 + 1 Phase 3)
- Total authenticated logs on disk: 8 -> matches "8 of 8" budget figure.

On-the-wire authenticated call count differs from the disk count because the original timestamp collision overwrote 2 batch logs without preventing the underlying network calls. Wire count: 1 paginated + 5 original batches + 2 re-fetched batches + 2 stats = 10 authenticated requests actually issued. Disk-visible count: 8 (the 2 lost-to-collision logs are unrecoverable). The Layer 1 report acknowledges this discrepancy in the Audit-Trail Gap and Recovery section.

Audit calls in this attempt: 0 (read-only file/log inspection plus offline Python). The submission step is call #9 against the budgeted 12 (Phase 1 + Phase 2 + Layer 1 disk-visible = 8 + submission slot = 9), with margin remaining for Layers 2/3 to share. PASS.

## Submission Preparation Recap

The Layer 1 report nominates **C1** as the primary integrity proof, with the value `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37`.

The submission CLI's `_find_latest_audit` matches `audit-report-<type>-attempt-<N>.md`. This audit file is named `audit-report-layer-1-attempt-2.md`, so the orchestrator must invoke `--type layer-1` (not `integrity_proof`, which would not match the audit filename and therefore would not be cleared by the gate).

Recommended invocation strings:

- `--type`: `layer-1`
- `--value`: `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37`
- `--notes`: (verbatim from `discovery/layer-1-report.md` lines 115-123)
  > Phase 3 Layer 1: integrity proof = sha256 of the concatenated raw decoded ciphertext for records 0..499 in batch order. Reconstructed offline from 5 authenticated batch fetches (ranges 0-99, 100-199, 200-299, 300-399, 400-499), 500 records x 256 bytes = 128,000 bytes. All HTTP through wrapper at assessment.client.make_request; per-call logs in logs/. Recomputed by Opus 4.7 high-effort redo to confirm the prior sonnet-tier values; all four computed candidates and the Phase 2 ETag matched on independent recompute.

The `--notes` string contains the model-family identifier `sonnet` (lower-case). That is not in the forbidden-token list. It does NOT contain any of the five forbidden patterns. The orchestrator may either submit the notes verbatim or further sanitize before submission per Shua's discretion; the audit raises no objection on the forbidden-token check.

## Overall Verdict: PASS
