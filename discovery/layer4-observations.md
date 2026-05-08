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
