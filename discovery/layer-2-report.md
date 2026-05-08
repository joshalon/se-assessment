# Phase 3 Layer 2 - Working Report v2 (HALTED ON EXHAUSTIVE SWEEP MISS)

> Status: **HALTED for orchestrator decision**
> Captured: 2026-05-08T04:14Z (start) - 2026-05-08T04:30Z (halt)
> Wire calls used in this scope: **0** (offline experiment per Option A)
> v1 ledger: 1 wire call (POST /api/v1/challenges -> 405). Layer 2 wire budget: **7/8 remaining**.

---

## Recap of v1 halt

The v1 working scope attempted to source the decryption key by probing
`POST /api/v1/challenges` (the prior orchestrator hypothesis, H2). That endpoint
returned `405 Method Not Allowed` with `allow: OPTIONS`. OPTIONS earlier had
returned a markdown menu of three coding sub-challenges (`/design`, `/ui`,
`/algorithm`); none is a key-delivery channel. v1 halted there.

Logs of record:
- `logs/20260508T040407_036730Z-OPTIONS-api-v1-challenges.json` (OPTIONS catalog)
- `logs/20260508T040529_*-POST-api-v1-challenges.json` (405 confirmation)

The narrative breadcrumb that justified the v2 hypothesis: the `design`
sub-challenge brief explicitly cites "AES-GCM + HKDF for record encryption" as
the cryptography stack required for that service-design exercise. This is
incidental to that challenge's deliverable, but it doubles as a hint that the
500 dataset records are AES-GCM ciphertexts under an HKDF-derived key.

## v2 hypothesis

> The 500 ciphertexts are encrypted under an AES-GCM key derived from the
> `API_KEY` via HKDF-SHA256, with parameters drawn from a small enumerable
> matrix of (salt, info, length, record layout, nonce strategy, AAD).

This was tested **offline** with zero wire calls.

## Loader sanity (offline)

`assessment.layer2.load_ciphertexts_from_logs("logs")` reuses the Layer 1
patterns (batch detection, range coverage, base64 decode, fixed 256-byte
length). It also dedupes by newest filename when multiple logs cover the same
range. Re-derived `content_hash` after loading:

- Records loaded: 500 (5 batches: 0-99, 100-199, 200-299, 300-399, 400-499)
- Per-record decoded length: 256 bytes (verified for every record)
- sha256 of concatenated raw bytes:
  `dcd2a8cb8ed565ec0df4029ec82218d732cc1c988cf339151b646d7917f3ca37`
- Layer 1 server-confirmed value: same.
- **Match: yes.**

## Sweep matrix

### Search axes

| Axis | Cardinality | Values |
|---|---|---|
| IKM (input keying material) | 5 | `utf8`, `b64url_decoded`, `after_sa__utf8`, `after_sa__b64url`, `after_sa__hex` |
| Salt | 5 | `empty`, `se-assessment`, `se-assessment-api`, `host`, `dataset` |
| Info | 7 | `empty`, `dataset`, `records`, `record-encryption`, `se-assessment-records`, `aes-gcm`, `encryption-key` |
| HKDF output length | 2 | `32` (AES-256), `16` (AES-128) |
| Explicit-nonce layouts | 5 | `L1`, `L2`, `L3`, `L5`, `L6` |
| Implicit-nonce layout | 1 | `L4` |
| AAD | 3 | `none`, `idx2_be`, `idx4_be` |
| L4 nonce strategy | 4 | `be12`, `le12`, `be8_4`, `be4_8` |

Per-HKDF-key combos: `5 explicit layouts * 3 AAD + 4 nonce strategies * 3 AAD = 27`.
Total sweep: `5 IKM * 5 salt * 7 info * 2 length * 27 = 9450 attempts`.

### Layouts (256-byte record)

| Code | Layout |
|---|---|
| L1 | `nonce(12) || ct(228) || tag(16)` |
| L2 | `nonce(12) || tag(16) || ct(228)` |
| L3 | `tag(16) || nonce(12) || ct(228)` |
| L4 | `ct(240) || tag(16)`, with implicit nonce derived from record_index |
| L5 | `nonce(16) || ct(224) || tag(16)` |
| L6 | `u32_be(length) || nonce(12) || ct(L) || tag(16)` (variable length, padded) |

### IKM enumeration rationale

The `API_KEY` in env is 67 bytes long, characters drawn from base64url charset
plus a 2-character prefix terminated by `_`. We therefore enumerate:

- `utf8`: raw bytes of the API key.
- `b64url_decoded`: base64url-decode the entire key (auto-padded; yields 50 bytes).
- `after_sa__utf8`: drop the `sa_` prefix, take the 64-char tail as UTF-8 bytes.
- `after_sa__b64url`: the 64-char tail base64url-decoded (48 bytes).
- `after_sa__hex`: the 64-char tail hex-decoded (32 bytes - a strong AES-256 candidate).

Hex / base64 / b64url charset checks gate which decodings are attempted, so
this enumeration auto-adapts to other API key shapes too.

(No raw bytes of the API key are reproduced in this report; only sha256-prefix
fingerprints would be loggable, and we did not need to.)

### L6 length-prefix sanity

A separate offline check: if any record begins with a u32 length prefix in
plausible AES-GCM body range (4..230), L6 would have a nonzero hit. Across all
500 records, **0** had a plausible big-endian or little-endian length prefix
(values were uniformly distributed across the full u32 range, mean magnitude
~2^31). This is consistent with L6 being the wrong layout for this dataset,
but L6 was still swept anyway for completeness.

### L4 implicit-nonce check

A separate offline check: if record byte 0 were a record-index counter (LE),
record 0 would have `ct[0] == 0x00`, etc. Across all 500 records, only 2 had
`ct[0] == idx & 0xFF` (expected ~2 for uniform random). Consistent with L4
being unlikely under simple counter strategies, but all four strategies were
swept anyway.

## Result: exhaustive miss

**0 of 9,450 attempts produced a valid AES-GCM tag for record 0** (and
therefore for the gate set {0, 1, 100, 499}). The sweep ran in approximately
2 minutes wall-clock; per-attempt cost is dominated by HKDF derivation
(reused per-key for 27 layout/aad/nonce combos) and AES-GCM tag check on the
first record.

The v2 hypothesis is **disconfirmed in the form tested**.

## Anti-confirmation observations

A successful AES-GCM tag check is a 64-bit event (probability `2^-64` per
random key). With 9,450 trials and gate-of-1 (record 0 only), expected false
positives are `9450 * 2^-64 = ~5e-16`. The sweep is essentially noiseless: an
absence of hits is meaningful.

Combined with Layer 1's byte-distribution observations (overall entropy 7.9985
/ 8.0, no fixed prefix or suffix, all 500 records exactly 256 bytes), the
ciphertext is consistent with output from a strong AEAD or RSA-2048, but the
specific AES-GCM + HKDF configuration tested is ruled out for this matrix.

## Hypothesis space remaining

In rough rank order of likelihood given current evidence:

1. **Different KDF parameters not in the matrix.** Plausible additions:
   - salt = a specific dataset ETag (e.g. the `bf08...` paginated ETag, or one
     of the per-batch ETags), or the `request_id` from response headers.
   - info = a record-position-bound string (e.g. `f"record-{i}"`).
   - IKM = a concatenation like `API_KEY || ":" || dataset_etag`.
   The matrix as specified covers the brief's enumerated values; adding new
   labels is a deliberate, reportable extension and should be authorized by
   the orchestrator.

2. **Different AEAD or cipher.** Specifically:
   - **ChaCha20-Poly1305** with the same HKDF key derivation - tag is also
     16 bytes, nonce is 12 bytes, layout L1 still applies. This swap is one
     line in `try_decrypt_layout` and ~3000 attempts to re-test the matrix
     under it. Brief says: "do not pivot to a different family without
     orchestrator approval."
   - AES-OCB or AES-CCM (less likely, but worth ruling out).
   - AES-CTR with separate HMAC-SHA256 (the 16-byte `tag` slot would then be
     the HMAC tag; needs explicit verify-then-decrypt).

3. **RSA-2048 hybrid envelope.** Layer 4 originally suspected RSA-2048
   because the record length is exactly 256 bytes (= 2048 bits). A possible
   structure: each record is RSA-2048(OAEP)(session_key || message). To
   decrypt, we need the RSA private key - which would not derive from
   `API_KEY` and therefore could not be obtained offline. This hypothesis
   requires an RSA private key from somewhere on the wire.

4. **Key from a different source.** A non-`API_KEY` IKM, e.g.:
   - A response header on `/api/v1/dataset` not yet recognized as keying
     material (Layer 4 already enumerated headers; nothing obvious).
   - A `/key`, `/keys`, `/cipher`, `/secret` etc. endpoint (Phase 1 hit 404
     on the common names tried).
   - The candidate's submission `repo_url` registration response, or a
     side-channel field in the existing `/stats` body that was overlooked.

## Hash candidates

**N/A** - no plaintext computed. D1-D4 cannot be produced without successful
decryption.

## Notes draft (placeholder)

Not produced; awaiting plaintext.

Token-clean placeholder template (for whichever decryption path eventually
succeeds):

> sha256 of concatenated raw plaintext bytes (500 records, positional order)
> after decryption with key derived from `<key source>` via `<KDF spec>`;
> AEAD = `<scheme>`; record layout = `<layout>`; verified by independent
> recompute.

## Wire-call ledger (this scope)

| # | Method | Path | Status | Purpose |
|---|---|---|---|---|

**Total: 0 of 8.** No wire calls in v2.

## Deliverables status

| Deliverable | Status |
|---|---|
| `pyproject.toml` (cryptography>=42) | DONE - alphabetical, single line |
| `assessment/layer2.py` | DONE - loader, HKDF wrapper, layout decryptor, sweep, hash candidates, CLI |
| `tests/test_layer2.py` | DONE - 15 new tests, all pass; full suite 49 passed |
| `discovery/layer-2-report.md` | this file (replaces v1 halt report) |
| `discovery/layer4-observations.md` | updated (Layer 2 plaintext stub replaced with sweep-miss summary) |

## Recommended next move (for orchestrator)

Either:

A. **Extend the salt/info matrix** with concrete server-side keying values that
   were already on the wire - dataset ETag(s), `request_id` headers, the
   per-batch `etag` values - and re-sweep. ~0 additional wire calls.

B. **Authorize a ChaCha20-Poly1305 swap** (one-line code change, re-run the
   same 9,450-attempt matrix). ~5 minutes wall-clock, 0 wire calls.

C. **Authorize one wire call** to GET `/api/v1/challenges/design` - the
   markdown brief there may explicitly state how the assessment-side AES-GCM
   is keyed (it advertises "AES-GCM + HKDF" in the OPTIONS summary, but the
   full text may include parameters). ~1 of remaining 7 wire calls.

D. **Reconsider RSA-2048 hybrid** - this requires private-key delivery, which
   is the original Layer 2 puzzle, and we are back to Phase 2 H1.

Halting here per the brief's instruction: "do not pivot to a different family
without orchestrator approval."

---

## v3 extended sweep

> Captured: 2026-05-08T04:28Z - 2026-05-08T04:31Z
> Wire calls used in v3: **0**. Cumulative Layer 2 wire calls: 0/8.

The orchestrator authorized an extended matrix that adds ETag-derived material
(per-batch ETags + paginated dataset ETag), per-batch keying, per-record info
derivation, direct-key paths (no HKDF), and ChaCha20-Poly1305 as a swap-in
cipher.

### ETag -> batch range mapping (offline-derived)

Determined by reading each `logs/*-GET-api-v1-dataset.json` log's
`response_headers.etag` and pairing it with that log's `request_params.range`
(newest filename per range wins, mirroring the v2 dedup):

| Batch range | ETag (bare hex, 32 bytes / 64 hex chars) |
|---|---|
| 0-99    | `c4810cc7fe6675612a8e148a2fe7bb21d85c04f0a700b2efdd8f73685cfedfec` |
| 100-199 | `42ad0a5e2a11b5b774bd77eb035f130d8faefe20fc21c0f20c327337751eb32e` |
| 200-299 | `3ce7ed990f739f30045482343480222c2c053e6cc2dca6054efcf218e84fcc10` |
| 300-399 | `ba577abcff3453e8d44715c466065c3cf058cf650b88a791c61c09503a550966` |
| 400-499 | `add573c0caf4f42d365d1a20333fd041d309715162534c763892046d729cb95b` |

The 6th ETag (`bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf`)
comes from the Phase-2 paginated `/dataset` non-batch response and is treated
as a dataset-wide candidate (not tied to any single batch).

### Extended axes (deltas from v2)

| Axis | New values |
|---|---|
| Direct AES-256 keys (no HKDF) | 6 ETag-bytes (paginated + 5 per-batch), `API_KEY` truncated/padded to 32 bytes, `after_sa__hex` (32 bytes). 8 unique keys total. |
| HKDF IKM extensions | `etag_paginated_bytes`, `etag_paginated_hex_utf8`, per-batch `etag_*_bytes`, per-batch `etag_*_hex_utf8`, `api_key:etag`, `etag:api_key` |
| HKDF salt extensions | `etag_paginated_bytes`, `etag_paginated_hex_utf8`, per-batch `etag_*_bytes` and `_hex_utf8` (10 ETag-derived salts), `started_at_iso` (`2026-05-08T02:16:44.027507+00:00`), `base_url`, `dataset/v1` -- 15 total |
| HKDF info extensions | `record` literal, `v1` literal, `per_record_idx2_be` (`i.to_bytes(2,'big')`), `per_record_idx_string` (`f"record-{i}"`) |
| Per-batch keying | Records 0-99 use batch[0]'s ETag (as salt OR as IKM), records 100-199 use batch[1]'s, etc.; gated on indices `{0, 99, 100, 199, 200, 299, 300, 399, 400, 499}` |
| Cipher | `chacha20-poly1305` (alongside `aes-gcm`); fixed 32-byte key requirement skips length=16 combos |
| Layouts | Restricted to L1 + L4 (most plausible; L2/L3/L5/L6 already swept under v2) |

### Sub-search totals

Counted analytically by enumerating each generator and confirmed against the
runtime attempt counter:

| Sub-search | AES-GCM | ChaCha20 | Total |
|---|---|---|---|
| 1. Direct-key (no HKDF) | 120 | 120 | 240 |
| 2. ETag-as-salt with global HKDF keying | 9450 | 4725 | 14175 |
| 3. Per-batch keying with ETag-as-salt | 1260 | 630 | 1890 |
| 4. Per-batch keying with ETag-as-IKM | 1260 | 630 | 1890 |
| 5. Per-record info derivation | 180 | 90 | 270 |
| **Total v3-additional** | **12270** | **6195** | **18465** |
| **Aggregate v2+v3** | | | **27915** |

Wall-clock: ~0.3 seconds for the entire v3 sweep on this machine. Per-attempt
cost is dominated by HKDF derivation (mostly cached at the outer-loop level)
and a single AEAD tag-check at the gate index.

### v3 Result: extended sweep miss

**0 of 18,465 v3-additional attempts produced a valid AEAD tag for the gate
record set.** Combined with v2 this is **0 of 27,915** attempts. False-positive
floor under uniform random key with `2^-64` per tag is ~1.5e-15 -- the absence
of any hit is overwhelmingly meaningful.

The most-plausible v3 hypothesis -- per-batch ETag as the AEAD key directly,
or as the HKDF salt -- is **disconfirmed** in every layout/AAD/cipher form
tested.

### What v3 specifically rules out

For the 256-byte records under L1 (`nonce(12) || ct(228) || tag(16)`) or L4
(`ct(240) || tag(16)` with implicit record-index nonce), with AES-GCM or
ChaCha20-Poly1305:

1. The AEAD key is **not** any of the 6 ETags interpreted as raw 32-byte keys.
2. The AEAD key is **not** `API_KEY` truncated/padded to 32 bytes.
3. The AEAD key is **not** the 32-byte hex tail of `API_KEY` (after-`sa_`).
4. HKDF over `{utf8, after_sa__hex, b64url_decoded}` IKM, with any of the 15
   v3-extended salts (including all 6 ETags in both bytes and hex-string form,
   plus `started_at_iso` and `base_url`), any v2/v3 info, and length 32 or 16,
   does not produce a key that validates record 0 under either L1 or L4.
5. Per-batch keying via either salt or IKM, in both forms (bytes and
   hex-utf8), produces no validating key for the multi-batch gate set.
6. Per-record HKDF info derivation (`f"record-{i}"` or `i.to_bytes(2,'big')`)
   under any tested salt/length/cipher does not validate.
7. ChaCha20-Poly1305 swapped in for AES-GCM under all of the above also does
   not validate.

### Hash candidates

**N/A** -- no plaintext computed. D1-D4 cannot be produced without successful
decryption.

### Strongest remaining hypotheses (rank-ordered)

1. **The cipher is RSA-2048 (or an RSA-OAEP hybrid envelope)**, not an AEAD.
   The fixed 256-byte record length is exactly the RSA-2048 block size; AEAD
   ciphertexts of a fixed AAD-less plaintext would have variable length unless
   deliberately padded to 256 bytes, which is unusual for AEAD-on-record
   designs. RSA decryption requires a private key not derivable from
   `API_KEY` alone. **Next step: identify whether the wire side has a
   private-key delivery channel.**
2. **There is a key/parameter source we have not yet read.** Specifically:
   - The markdown body of `GET /api/v1/challenges/design` (or `/ui`,
     `/algorithm`) may name the exact KDF parameters used by the dataset
     encryption. The OPTIONS catalog hinted at "AES-GCM + HKDF" but full text
     was never fetched. **Cost: 1 wire call.**
   - The `/api/v1/challenges` family or a `/api/v1/key`/`/secret`/`/cipher`
     endpoint has not been enumerated. Phase 1 only tried a small set.
3. **The cipher uses authenticated AES-CTR + HMAC** (encrypt-then-MAC), not
   AES-GCM/ChaCha20-Poly1305. The 16-byte trailing block would be HMAC-SHA256
   truncated to 128 bits rather than a GCM tag. Layouts and KDFs would be
   identical, but the verify step uses `hmac.compare_digest(HMAC(k_mac, body),
   tail_16)` instead of an AEAD `decrypt`. **Not yet tested -- it is a
   different cryptographic family and was out-of-scope in v3.**

### Recommended next move (for orchestrator)

A. **Authorize 1 wire call**: `GET /api/v1/challenges/design` to read the full
   markdown brief. Even if the design challenge is unrelated to dataset
   decryption, the brief has been advertised as containing AES-GCM + HKDF
   text, which may explicitly state how the assessment-side records are
   keyed. Lowest-cost path to disambiguating between hypothesis 1 and 2.

B. **Authorize a non-AEAD swap to AES-CTR + HMAC-SHA256** (encrypt-then-MAC).
   The same 27,915-attempt matrix would apply with the verify step replaced.
   Fully offline, ~10 minutes wall-clock. Currently OUT under the v3 brief.

C. **Authorize an RSA-private-key search**. Look for a `/key`, `/secret`,
   `/private`, `/pem`, etc. endpoint. The brief explicitly rules out RSA
   hybrid as offline-tractable (would need a private key delivered over the
   wire), so this requires authorization for additional wire calls in
   service of the RSA hypothesis.

### Wire-call ledger (this scope)

| # | Method | Path | Status | Purpose |
|---|---|---|---|---|

**Total: 0 of 8.** No wire calls in v3.

### Deliverables status (v3)

| Deliverable | Status |
|---|---|
| `assessment/layer2.py` | EXTENDED -- v3 sweep, ETag collector, ChaCha20 helper, direct-key path |
| `tests/test_layer2.py` | EXTENDED -- 16 new v3 unit tests; full suite 65 passed |
| `discovery/layer-2-report.md` | this section appended |
| `discovery/layer4-observations.md` | extended rule-out section appended |
| `pyproject.toml` | unchanged (cryptography>=42 already present) |

---

## v4 AES-CTR + HMAC-SHA256 sweep

### Verdict: MISS

The encrypt-then-MAC variant `AES-CTR + HMAC-SHA256` was the remaining
offline-testable cipher family in scope after v2 + v3 closed AEAD without a
hit. The full sweep ran in **0.04 seconds** (3,488 attempts; budget cap
50,000) and returned no record-validating combination.

### Cipher model swept

For a 256-byte record under candidate `(enc_key, mac_key)` pair:

| Layout | iv_len | ct_len | mac_len | Notes |
|---|---|---|---|---|
| LE1 | 16 | 224 | 16 | 16-byte AES-CTR IV, HMAC-SHA256 truncated to 128 bits |
| LE2 | 16 | 208 | 32 | Full 32-byte HMAC tag |
| LE3 | 12 | 228 | 16 | 12-byte IV (zero-padded to 16-byte CTR block) |
| LE4 | 8 | 232 | 16 | 8-byte nonce + 8-byte counter style |

MAC scopes tried:

- `M1`: `HMAC(mac_key, iv || ct)`
- `M2`: `HMAC(mac_key, ct)`
- `M3`: `HMAC(mac_key, iv || ct || idx_4_be)` (positional binding)
- `M4`: `HMAC(mac_key, iv || ct || idx_2_be)`

Validation gate: HMAC compare via `hmac.compare_digest`. False-positive
probability for 4 records under a 128-bit truncated HMAC is on the order of
2^-512, so a hit would be unambiguous.

### Search matrix (all three passes ran)

**Pass 1 (split-derivation; HKDF 64 bytes -> first 32 = enc_key, last 32 =
mac_key):**
- IKMs: API_KEY utf-8, API_KEY tail-after-`sa_` hex-decoded (32 bytes if
  shape matches), each per-batch ETag bytes (5 ranges), paginated dataset
  ETag bytes
- Salts: empty, `se-assessment`, each per-batch ETag (bytes + hex-utf-8),
  paginated dataset ETag bytes
- Infos: empty, `dataset`, `records`, `record-encryption`
- Layouts: LE1, LE3
- MAC scopes: M1, M2
- Attempts: 1,664

**Pass 2 (per-batch keying):**
- Variant A: API_KEY-as-IKM, per-batch-ETag-as-salt (bytes and hex-utf-8),
  same INFO set, split-derivation, layouts LE1/LE3, scopes M1/M2.
  Per-batch gate at indices `{0, 99, 100, 199, 200, 499}`.
- Variant B: per-batch-ETag-as-IKM, salts `{empty, se-assessment, dataset}`,
  same INFO set, split-derivation.
- Attempts: 160

**Pass 3 (separate enc/mac derivations):**
- `enc_key = HKDF(IKM, salt, info+b"-enc", 32)`
- `mac_key = HKDF(IKM, salt, info+b"-mac", 32)`
- Same IKM/salt/info matrix as pass 1; layouts LE1/LE3; scopes M1/M2.
- Attempts: 1,664

**Total attempts: 3,488.** Wall-clock: 0.04s on M3. Result: zero records
MAC-validated under any (config, key_pair) combination tested.

### Interpretation

Combined with v2 (27,915 AEAD attempts) and v3 (extended AEAD with ETag
material + per-batch keying + per-record info derivation), v4 confirms that
**no symmetric-key construction reachable from API_KEY/ETag/dataset
literals via HKDF-SHA256 and the standard layout families validates the 500
records**. This rules out all symmetric-key constructions consistent with
the v2/v3/v4 search spaces.

The remaining offline-untested hypotheses are:

1. **Different KDF family** (PBKDF2, scrypt, Argon2id, BLAKE2 keyed). All
   would require a pepper/iteration-count pair we have no signal for. No
   cheap probe.
2. **Different cipher family** (XChaCha20+Poly1305 with 24-byte nonce,
   AES-GCM-SIV, AES-CCM). XChaCha was implicitly skipped because no layout
   in scope has a 24-byte nonce field. Worth one focused pass under a 16+8
   prefix layout.
3. **Asymmetric (RSA-OAEP/ECIES envelope)**. Requires a private-key fetch
   over the wire; ruled out as offline-tractable in v3.
4. **Server-side per-record key envelope** delivered in headers we have not
   collected (e.g., `x-record-key`, `x-iv`). Would require new wire calls
   to capture.

### Wire-call ledger (this scope)

| # | Method | Path | Status | Purpose |
|---|---|---|---|---|

**Total: 0 of 0.** v4 ran fully offline.

### Deliverables status (v4)

| Deliverable | Status |
|---|---|
| `assessment/layer2.py` | EXTENDED -- v4 sweep helpers, `search_ctr_hmac`, AES-CTR + HMAC primitives |
| `tests/test_layer2.py` | EXTENDED -- 9 new v4 unit tests (NIST AES-CTR vector, RFC 4231 HMAC vector, synthetic LE1+M1 round-trip, LE3+M3 positional binding, tamper rejection, sweep returns None on random input, sweep finds synthetic split64 dataset). Full suite 74 passed. |
| `discovery/layer-2-report.md` | this section appended |
| `discovery/layer4-observations.md` | v4 rule-out appended |

### Halt summary

```
v4 sweep: AES-CTR + HMAC-SHA256 (encrypt-then-MAC)
attempts: 3,488 (pass1=1,664, pass2=160, pass3=1,664)
wall-clock: 0.04s
result: MISS -- 0 records MAC-validated under any tested config
recommendation: pivot from symmetric-offline to wire-side discovery
```
