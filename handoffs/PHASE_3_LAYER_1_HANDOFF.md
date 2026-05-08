# Phase 3 Layer 1 Handoff — SE Assessment

> Synthesized: 2026-05-08 03:51 UTC (Fri May  8 03:51:05 UTC 2026)
> Phase: 3 Layer 1
> Status: **PASS** (server-confirmed)
> Submission ID: `2844e683-6f5d-4f94-a1a0-3a39a73a83f4`

---

## Outcome

```
HTTP 200
{
  "correct": true,
  "layer": 1,
  "message": "Correct!",
  "submission_id": "2844e683-6f5d-4f94-a1a0-3a39a73a83f4",
  "type": "content_hash"
}
```

Submitted value: `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37`
Submitted type: `content_hash`
Submitted notes: `sha256 of concatenated raw decoded ciphertext (500 records x 256 bytes) in positional order, reconstructed from 5 batch fetches; verified by independent recompute`
Submission timestamp: `2026-05-08T03:50:40Z`

---

## Clock Status

| Item | Value |
|---|---|
| T0 | `2026-05-08T02:16:44Z` |
| Operational deadline (T0 + 2h50m) | `2026-05-08T05:06:44Z` |
| Server hard expiry (T0 + 3h) | `2026-05-08T05:16:44Z` |
| Time elapsed at handoff | 1h34m21s |
| Remaining to operational deadline | ~1h15m38s |
| Remaining to hard expiry | ~1h25m38s |

---

## Key Intel for Phase 3 Layers 2-4

### 1. Valid submission types (from server 400 response on attempt 2)

```
{"error":"Invalid submission type",
 "valid_types":["content_hash","decrypted_hash","analysis","repo","transcript","algorithm_answer"]}
```

Mapping (best inference from names; confirm during scoping):

| Type | Likely layer/purpose |
|---|---|
| `content_hash` | Layer 1 (CONFIRMED — this submission) |
| `decrypted_hash` | Layer 2 — hash of the decrypted plaintext |
| `analysis` | Layer 3 — written analysis / puzzle answer |
| `repo` | Final repo URL submission |
| `transcript` | Conversation transcript submission |
| `algorithm_answer` | Possibly Layer 3 algorithmic answer, or a separate question |

This list is the most valuable artifact of Phase 3 Layer 1 for downstream planning.

### 2. Submission response shape (success)

`200 OK` body fields:
- `correct: bool` — the actual gate
- `layer: int` — server-assigned layer number
- `message: str` — human-readable result
- `submission_id: uuid` — for audit-trail correlation
- `type: str` — echoed type

Server returns 200 with `correct: false` for "wrong answer" (not 4xx). The `correct` field is the success signal, not the status code.

### 3. Submission response shape (invalid input)

`400 Bad Request` body fields:
- `error: str`
- `valid_types: array<string>` — listed only on type errors

Other 4xx shapes are unobserved.

### 4. Submission counter behavior

`api_requests` from `/api/v1/stats` after submission was 8 — same as before. Submissions do NOT increment the dataset-call counter. This counter tracks `/dataset` calls only; submission and stats calls are excluded.

### 5. Wire-call accounting (Phase 3 Layer 1 + Phase 2 carry)

| Source | Auth wire calls |
|---|---|
| Phase 2 paginated dataset probe | 1 |
| Phase 2 stats follow-up | 1 |
| Phase 3 working agent stats (Task 1) | 1 |
| Phase 3 batch fetches (5 ranges, original) | 5 |
| Phase 3 re-fetched batches (collision recovery) | 2 |
| Phase 3 stats time-check (Shua-asked) | 1 |
| Phase 3 submit attempts (1 local-fail + 1 wire-400 + 1 wire-200) | 2 (local-fail did not reach wire) |
| **Total auth calls on wire** | **13** |

`api_requests` server counter at submission time: 8 (counts only `/dataset`).

### 6. Key infrastructure improvements made during Layer 1

- **Wrapper microsecond timestamps** (`41a5bb2`) — `_fs_safe_timestamp` now uses `%Y%m%dT%H%M%S_%fZ` to avoid filename collisions on rapid bursts. Carries forward to all later layers.
- **Submit CLI verdict regex** (`9a349b0`) — `_VERDICT_RE` now accepts `^\s*#*\s*Overall Verdict:` so markdown-heading-formatted audit verdict lines work. Carries forward.

### 7. Submission protocol change (effective from Layer 1 final attempt)

Old protocol: orchestrator pre-fills CLI command → Shua runs in terminal → presses y → pastes response.

New protocol: orchestrator presents pending POST in chat → Shua replies "approve" or "reject" → orchestrator POSTs through `assessment.client.make_request` and returns full response verbatim.

Reasoning: avoids interactive-shell quoting issues, avoids requiring Shua to source `.env` before each invocation, preserves wrapper logging, makes per-submission approval a single chat step. Audit PASS verdict still required and verified directly by orchestrator before presenting.

This protocol applies to all subsequent layer submissions and the final repo submission.

---

## Layer 1 Engineering Trail (concise)

1. Phase 2 hypothesis H1 was: ETag is the integrity proof input. Disconfirmed when 5 distinct batch ETags showed they are per-response cache validators, not full-dataset proofs.
2. Hypothesis H4 (batch-fetch strategy) confirmed: `?batch=true&range=N-N+99` returns exactly 100 records, 5 calls cover all 500. End bound is inclusive.
3. Five sha256 candidates computed (concatenated decoded bytes; concatenated base64; canonical-JSON array; canonical-JSON envelope; literal Phase 2 ETag). Primary chosen: C1 = sha256 of concatenated decoded bytes — the only candidate operating purely on the semantic content of the dataset, independent of encoding/serialization choices.
4. Audit-trail gap encountered (timestamp collision lost 2 of 5 batch logs); resolved via wrapper patch and 2 re-fetches.
5. Independent two-pass verification confirmed C1-C5 byte-for-byte identical across both computation passes. No fabrication.
6. First wire submission used `--type layer-1` (filename-pattern matching); rejected with 400. Server's 400 body listed valid types. Resubmission with `content_hash` PASSed.

---

## Phase 3 Layer 2 Readiness

**READY.** All the inputs needed to scope Layer 2 are now on hand:

- The dataset is confirmed-and-committed: 500 records × 256 bytes each, positional order, hashable end-to-end.
- The decryption key location is unconfirmed. Phase 2 H2 hypothesized `/api/v1/challenges` (POST) returns the key. Layer 2 working agent should probe that endpoint.
- The expected submission type for Layer 2 is `decrypted_hash` (server-revealed). The most plausible interpretation: decrypt the dataset records using whatever key `/challenges` returns, concatenate the plaintexts, sha256.
- Records are uniformly 256 bytes — RSA-2048 ciphertext block size. If the key from `/challenges` is an RSA private key (PEM), decryption is deterministic per record (PKCS#1 v1.5 or OAEP).
- Time remaining is ample: ~1h15m to operational deadline.

Recommend Kael's Phase 3 Layer 2 prompt explicitly cover:
1. Probe `/api/v1/challenges` shape (likely POST; possibly OPTIONS first to learn allow list).
2. Determine padding scheme of the RSA ciphertext (PKCS#1 v1.5 vs OAEP) — may be inferred from response or trial-decrypt.
3. Plaintext canonical form for hashing — server may specify, or it may match Layer 1's "concatenated raw decoded bytes" convention.
4. Submission `--type decrypted_hash`.

---

## Artifacts Inventory (this phase)

```
assessment/client.py                                    (modified at 41a5bb2 — wrapper microsecond fix)
assessment/submit.py                                    (modified at 9a349b0 — verdict regex)
assessment/layer1.py                                    (new at 31f1b6d)
tests/test_client.py                                    (modified at 41a5bb2)
tests/test_submit.py                                    (modified at 9a349b0)
tests/test_layer1.py                                    (new at 31f1b6d)
discovery/layer-1-report.md                             (new at cfc4e1d)
discovery/layer4-observations.md                        (new at cfc4e1d)
audit/audit-report-layer-1-attempt-1.md                 (new at b8ae703 — FAIL, retained as honest history)
audit/audit-report-layer-1-attempt-2.md                 (new at b8ae703 — PASS, gate file)
handoffs/PHASE_3_LAYER_1_HANDOFF.md                     (this file)
logs/20260508T0251{18_067695,19_841427}Z-GET-api-v1-dataset.json   (re-fetched batches; gitignored)
logs/20260508T0346{21_468450}Z-GET-api-v1-stats.json               (Shua time check; gitignored)
logs/20260508T03{42,44,50}*-POST-api-v1-submit.json                (3 submit attempts; gitignored)
```

End of Phase 3 Layer 1.
