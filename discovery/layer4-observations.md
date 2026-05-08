# Layer 4 Observations

> Purpose: running log of data-property observations across Phase 3 layers.
> Started: Layer 1 (offline reconstruction).
> Captured: 2026-05-08T03:12:43Z
> Source: 500 records (positional order) reconstructed from 5 batch logs in `logs/`.

## Dataset shape

- Records: 500
- Per-record decoded length: 256 bytes (verified for every record)
- Total ciphertext: 500 x 256 = 128,000 bytes
- Duplicates among the 500 base64 strings: 0
- Duplicates among the 500 decoded payloads: 0 (implied by base64 uniqueness with fixed length)

## Byte-frequency distribution (over 128,000 bytes)

- Mean count per byte value: 500.0 (expected for uniform across 256 values)
- Standard deviation: 23.0173 (theoretical for uniform: ~22.34; observed is well within tolerance)
- Min count: 441 at byte value 0x7A (`z`)
- Max count: 557 at byte value 0x7B (`{`)
- Byte values outside +/-6 sigma of the mean: 0
  - Threshold: low=361.90, high=638.10. No byte value falls outside this band.

The distribution is consistent with a uniform random source over [0, 255].

## Shannon entropy

- Overall entropy: 7.9985 bits / byte (theoretical max: 8.0000)
- Per-record entropy (Shannon over the 256 bytes of the record):
  - record[0]:   7.1545
  - record[124]: 7.1363
  - record[249]: 7.1146
  - record[374]: 7.1222
  - record[499]: 7.1832

A single 256-byte sample cannot saturate 8.0 bits/byte even from a uniform source
because at most 256 distinct values can occur in 256 draws and most values appear
once or twice; ~7.1 bits/byte is the expected magnitude. No record looks anomalous.

## Leading-byte analysis

- Distinct leading bytes across 500 records: 193
- Most common leading bytes: 0x02 and 0xA8 (each 7 occurrences), 0x9C (6)
- No single fixed leading byte; no detectable fixed prefix
- Unique 1-byte prefixes: 193, 2-byte: 497, 3-byte: 500, 4-byte: 500
  - All 500 records become distinguishable by their first 3 bytes.

## Trailing-byte analysis

- Distinct trailing bytes across 500 records: 218
- Most common trailing bytes: 0x6B and 0x28 (each 7 occurrences), 0x01 (6)
- No fixed suffix marker.

The lack of a fixed prefix or suffix rules out unencrypted PEM / DER framing,
ASN.1 OIDs at fixed offsets, or PKCS#1 v1.5 / OAEP wrapper bytes that would
appear in plaintext-leaked positions.

## Printable-ASCII run analysis

Threshold: runs of length >= 8 of bytes in [0x20, 0x7E].

- Observed runs: 30 (max length: 10)
- Rough back-of-envelope expectation for uniform random: 128000 * (95/256)^8 ~= 46 runs
- Observed (30) is below the rough expectation; both are O(10), not O(1000), and
  none of the runs decode to recognizable ASCII text. Sample (first 10):
  - `KI:`QycP`
  - `qXy+IM\=`
  - `pgj1W;uA=`
  - `ZR9SZQ_t`
  - `-7hzj9)Z~`
  - `D398Oh.U:`
  - `NgF32zWL8`
  - `O?X_eK^=`
  - `\5d*txm_T`
  - `\@9<@~uM|`

These are random-looking byte sequences that happen to lie in the printable
range; no English words, no JSON / base64 structure embedded in the ciphertext.

## Conclusion

The 128,000-byte concatenation behaves like a uniform high-entropy bytestream:

- byte distribution within ~1 sigma of theoretical uniform, no outliers beyond 6 sigma
- overall entropy 7.9985 / 8.0
- no fixed prefix or suffix across records
- no embedded printable text or structural markers

This is consistent with output from a strong cipher (e.g. AES-CTR / AES-GCM) or
with raw RSA-2048 ciphertext (each record is exactly 256 bytes, matching the
RSA-2048 block size). The fixed 256-byte record size is a strong hint at
RSA-2048: AES modes typically produce variable-length output (or padded to 16-byte
multiples), whereas RSA-2048 ciphertext is exactly 256 bytes.

Working hypothesis for Layer 4: each record is a single RSA-2048 ciphertext
block, possibly OAEP-padded, encrypting a session key or a 256-byte plaintext.
This will be retested as more layers expose decryption material.

## Layer 2 plaintext observations

> Captured: 2026-05-08T04:30Z (post v2 sweep)
> Status: **STILL NO PLAINTEXT - v2 exhaustive sweep produced 0 hits across 9,450 attempts**

### Position-stratified ciphertext structure

Across the 500 ciphertexts, all four cut-points (first 4 / 8 / 12 / 16 bytes,
and last 4 / 8 / 12 / 16 bytes) yield 500 distinct values - i.e. byte-level
uniqueness is saturated within the leading 4 bytes and the trailing 4 bytes.
This is consistent with both:

- a fully encrypted 256-byte record (no fixed plaintext fields visible at the
  edges), and
- a layout in which the nonce - if any - is record-specific and uniformly
  random (rather than a counter or shared value).

### Negative results (rule-outs from v2 sweep)

L6 (`u32_be length || nonce || ct || tag || padding`) is **ruled out**: zero
of 500 records have a plausible u32 big-endian or little-endian length prefix
(any value in the AES-GCM body-length range 4..230). Length-prefix interpreted
values span the full u32 range with random magnitude.

L4 with simple counter strategies is **plausibility-low**: only 2 of 500
records have `ct[0] == record_index & 0xFF` (expected ~2 for uniform random),
i.e. no visible little-endian counter at offset 0. All four nonce strategies
were swept anyway.

### What v2 ruled out

Under the matrix `(IKM in {utf8, b64url_decoded, after-prefix utf8/b64url/hex})
* (salt in {empty, "se-assessment", "se-assessment-api", host, "dataset"})
* (info in {empty, "dataset", "records", "record-encryption",
"se-assessment-records", "aes-gcm", "encryption-key"}) * (length in {32, 16})
* (layout in {L1, L2, L3, L4 with 4 nonce strategies, L5, L6}) * (AAD in
{none, idx2_be, idx4_be})`, **no AES-GCM tag validated for record 0**.

This is meaningful: with 9,450 trials and per-trial false-positive probability
`2^-64`, the expected number of spurious hits is ~5e-16, so a clean miss is
statistically certain. Either the ciphertext is not AES-GCM at all, or the
HKDF parameters lie outside the matrix tested.

### Working hypothesis after v2

The fixed 256-byte length still matches RSA-2048 exactly. Without a delivered
RSA private key, RSA hybrid cannot be tested offline. The remaining
authorizable next steps (per the v2 report) are: extend HKDF salt/info to
include observed wire-side values (per-batch ETags, request_ids), swap AEAD
to ChaCha20-Poly1305, or read one of the markdown sub-challenge briefs to
check for an explicit parameter spec. None has been done yet - awaiting
orchestrator decision.

## Layer 2 plaintext observations -- v3 update

> Captured: 2026-05-08T04:31Z (post v3 extended sweep)
> Status: **STILL NO PLAINTEXT - v3 extended sweep produced 0 hits across an
> additional 18,465 attempts; aggregate v2+v3 = 0 of 27,915 attempts**

### What v3 added

- ETag-derived material: 6 ETags total (5 per-batch tied to ranges 0-99,
  100-199, 200-299, 300-399, 400-499, plus the dataset-wide paginated ETag
  `bf08...`), each tried as raw 32-byte keys, as HKDF salts, and as HKDF IKMs.
- Per-batch keying: records 0-99 keyed under batch[0]'s ETag, etc. Gated on
  `{0, 99, 100, 199, 200, 299, 300, 399, 400, 499}`.
- Per-record HKDF info: `record-{i}` and 2-byte big-endian record index.
- ChaCha20-Poly1305 cipher swap across the entire matrix (with key length
  fixed at 32 bytes).
- Direct-key paths (no HKDF): 8 candidate 32-byte keys, all tested under L1
  + L4 with both AEAD ciphers and 3 AAD options.

### Negative results from v3

The 256-byte ciphertext records are **not** decryptable under any of the
following, for layouts L1 (explicit 12-byte nonce prefix) or L4 (implicit
record-index-derived nonce):

1. AES-GCM keyed with any of the 6 ETag bytes directly.
2. AES-GCM keyed with `API_KEY` truncated/padded to 32 bytes.
3. AES-GCM keyed with the 32-byte hex tail of `API_KEY` after the `sa_` prefix.
4. AES-GCM keyed via `HKDF(API_KEY, salt=<any of 15 v3-extended salts>,
   info=<any of 7 v2 + 4 v3 info values>, length in {32,16})`.
5. AES-GCM under per-batch keying (ETag-as-salt or ETag-as-IKM, in both
   bytes and hex-utf8 forms).
6. AES-GCM under per-record HKDF info derivation (`record-{i}` or
   `i.to_bytes(2,'big')`).
7. All of (1)-(6) with ChaCha20-Poly1305 swapped in for AES-GCM.
8. All of (1)-(7) under each of `{none, idx2_be, idx4_be}` as AAD.

### Strengthened hypotheses

The fixed 256-byte record length is now a much louder signal that the cipher
is **RSA-2048**, not an AEAD with deliberately-padded fixed-length output.
The narrative breadcrumb in the OPTIONS catalog ("AES-GCM + HKDF") may refer
to a different sub-system (e.g. a transport-layer or audit-trail signing
path) and not to the dataset record encryption.

The remaining authorizable paths (in priority order):

1. Read the design-challenge markdown brief (1 wire call) to check for an
   explicit dataset-encryption parameter spec.
2. Test AES-CTR + HMAC-SHA256 (encrypt-then-MAC) as an alternative to AEAD;
   same matrix applies but verify step is HMAC-compare. ~10 minutes offline.
3. Search for an RSA private-key delivery endpoint (`/key`, `/secret`,
   `/private`, etc.); requires wire-call authorization.

---

## v4 update -- AES-CTR + HMAC-SHA256 ruled out

The encrypt-then-MAC alternative listed as path (2) above has now been
exercised offline. `assessment/layer2.py` `search_ctr_hmac(...)` ran 3,488
HKDF + AES-CTR + HMAC-SHA256 attempts across:

- 4 layouts (LE1/LE2/LE3/LE4 with iv-len in {16,12,8} and mac-len in {16,32})
- 4 MAC scopes (`iv||ct`, `ct`, with optional 4-byte or 2-byte BE positional
  binding)
- 2 derivation modes (HKDF length-64 split into enc||mac; or two separate
  HKDF derivations with `info+"-enc"` and `info+"-mac"`)
- IKM/salt/info combinations parallel to the v3 ETag-extended matrix
- Per-batch keying with ETag-as-salt and ETag-as-IKM variants

Result: zero records MAC-validated. Combined with v2 (27,915 AEAD attempts)
and v3 (extended AEAD), this closes the symmetric-key-from-API_KEY-or-ETag
hypothesis space tractable offline.

### Net narrowed hypothesis set

The dataset record encryption is **not** any of:

- AES-GCM keyed via HKDF over (API_KEY, ETag, paginated-ETag) with the
  v2/v3 salt/info matrix
- ChaCha20-Poly1305 under the same matrix
- Per-batch keying with batch ETag as salt or IKM
- Per-record `info` HKDF derivation
- AES-CTR + HMAC-SHA256 (encrypt-then-MAC) under the v4 matrix above,
  including split-derivation and separate-derivation modes

### Strengthened recommendation

Path (1) (read the design-challenge brief, 1 wire call) is now the cheapest
remaining lead. Path (3) (search for a key-delivery endpoint) is the
fallback if (1) yields no parameter spec. Continued offline cipher sweeping
is unlikely to be productive without new wire-side material.
