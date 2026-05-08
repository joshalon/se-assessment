"""Phase 3 Layer 2 - offline AES-GCM record decryption with HKDF-derived key.

Reads the 500 ciphertexts loaded by Layer 1 patterns, sweeps a fixed matrix of
HKDF (salt, info, length) parameters and AES-GCM record layouts to find a
configuration that tag-validates every record, then computes plaintext-hash
candidates D1-D4.

All functions are pure with respect to network: no HTTP, no live calls. The
only environment input is ``API_KEY`` (used as IKM for HKDF).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import hmac as _hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from assessment.layer1 import (
    EXPECTED_RANGES,
    EXPECTED_TOTAL,
    RECORD_DECODED_LEN,
    decode_records,
)

GCM_TAG_LEN = 16


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _parse_range(params: dict[str, Any] | None) -> tuple[int, int]:
    if not params or "range" not in params:
        raise ValueError(f"log missing batch range params: {params!r}")
    start_s, end_s = params["range"].split("-", 1)
    return int(start_s), int(end_s)


def load_ciphertexts_from_logs(logs_dir: str | Path = "logs") -> list[bytes]:
    """Return the 500 raw ciphertexts in positional order.

    If multiple batch logs cover the same range, keep only the newest by
    filename (filenames are sortable timestamps written by the wrapper).
    """
    logs_path = Path(logs_dir)
    by_range: dict[tuple[int, int], tuple[str, list[str]]] = {}
    for path in sorted(logs_path.glob("*-GET-api-v1-dataset.json")):
        with path.open() as fh:
            log = json.load(fh)
        params = log.get("request_params") or {}
        if params.get("batch") != "true" or "range" not in params:
            continue
        if log.get("response_status") != 200:
            raise ValueError(f"non-200 batch log: {path}")
        rng = _parse_range(params)
        body = log.get("response_body") or {}
        data = body.get("data")
        if not isinstance(data, list):
            raise ValueError(f"batch log {path} missing data array")
        prev = by_range.get(rng)
        if prev is None or path.name > prev[0]:
            by_range[rng] = (path.name, data)

    seen = sorted(by_range.keys())
    if seen != EXPECTED_RANGES:
        raise ValueError(f"batch ranges mismatch expected={EXPECTED_RANGES} got={seen}")

    records_b64: list[str] = []
    for rng in EXPECTED_RANGES:
        records_b64.extend(by_range[rng][1])

    if len(records_b64) != EXPECTED_TOTAL:
        raise ValueError(f"assembled {len(records_b64)} != {EXPECTED_TOTAL}")

    return decode_records(records_b64)


# ---------------------------------------------------------------------------
# HKDF + AES-GCM helpers
# ---------------------------------------------------------------------------


def derive_key_hkdf(
    ikm: bytes,
    *,
    salt: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """Thin wrapper around HKDF-SHA256."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def _split_layout(
    layout: str, ciphertext: bytes, record_index: int
) -> tuple[bytes, bytes] | None:
    """Return (nonce, ct_with_tag) for the named layout, or None if unsupported.

    AES-GCM in cryptography expects the 16-byte tag appended to the ciphertext
    body. We always return ``ct_with_tag = body || tag`` so the caller can pass
    it directly to ``AESGCM.decrypt``.
    """
    n = len(ciphertext)
    if layout == "L1":  # nonce(12) || ct(N) || tag(16)
        if n < 12 + GCM_TAG_LEN:
            return None
        nonce = ciphertext[:12]
        body = ciphertext[12:-GCM_TAG_LEN]
        tag = ciphertext[-GCM_TAG_LEN:]
        return nonce, body + tag
    if layout == "L2":  # nonce(12) || tag(16) || ct(N)
        if n < 12 + GCM_TAG_LEN:
            return None
        nonce = ciphertext[:12]
        tag = ciphertext[12 : 12 + GCM_TAG_LEN]
        body = ciphertext[12 + GCM_TAG_LEN :]
        return nonce, body + tag
    if layout == "L3":  # tag(16) || nonce(12) || ct(N)
        if n < 12 + GCM_TAG_LEN:
            return None
        tag = ciphertext[:GCM_TAG_LEN]
        nonce = ciphertext[GCM_TAG_LEN : GCM_TAG_LEN + 12]
        body = ciphertext[GCM_TAG_LEN + 12 :]
        return nonce, body + tag
    if layout == "L5":  # nonce(16) || ct(N) || tag(16)
        if n < 16 + GCM_TAG_LEN:
            return None
        nonce = ciphertext[:16]
        body = ciphertext[16:-GCM_TAG_LEN]
        tag = ciphertext[-GCM_TAG_LEN:]
        return nonce, body + tag
    if layout == "L6":  # u32_be length || nonce(12) || ct(L) || tag(16) || padding
        if n < 4 + 12 + GCM_TAG_LEN:
            return None
        length = int.from_bytes(ciphertext[:4], "big")
        if length > n - 4 - 12 - GCM_TAG_LEN:
            return None
        nonce = ciphertext[4 : 4 + 12]
        body = ciphertext[4 + 12 : 4 + 12 + length]
        tag = ciphertext[4 + 12 + length : 4 + 12 + length + GCM_TAG_LEN]
        return nonce, body + tag
    return None


def _derive_implicit_nonce(strategy: str, record_index: int) -> bytes | None:
    if strategy == "be12":
        return record_index.to_bytes(12, "big")
    if strategy == "le12":
        return record_index.to_bytes(12, "little")
    if strategy == "be8_4":
        return b"\x00" * 8 + record_index.to_bytes(4, "big")
    if strategy == "be4_8":
        return b"\x00" * 4 + record_index.to_bytes(8, "big")
    return None


def try_decrypt_layout(
    key: bytes,
    ciphertext: bytes,
    layout: str,
    record_index: int = 0,
    *,
    aad: bytes | None = None,
    nonce_strategy: str | None = None,
) -> bytes | None:
    """Attempt one AES-GCM decryption. Return plaintext, or None on InvalidTag.

    ``layout`` is one of L1, L2, L3, L4, L5, L6. For L4 the nonce is derived
    from ``record_index`` via ``nonce_strategy`` (be12/le12/be8_4/be4_8); the
    ciphertext is treated as ``body(N) || tag(16)``.
    """
    aesgcm = AESGCM(key)
    if layout == "L4":
        n = len(ciphertext)
        if n < GCM_TAG_LEN or nonce_strategy is None:
            return None
        nonce = _derive_implicit_nonce(nonce_strategy, record_index)
        if nonce is None:
            return None
        body_and_tag = ciphertext  # body || tag
        try:
            return aesgcm.decrypt(nonce, body_and_tag, aad)
        except InvalidTag:
            return None

    parts = _split_layout(layout, ciphertext, record_index)
    if parts is None:
        return None
    nonce, ct_with_tag = parts
    try:
        return aesgcm.decrypt(nonce, ct_with_tag, aad)
    except InvalidTag:
        return None
    except ValueError:
        # e.g. nonce length not in supported set for this backend
        return None


# ---------------------------------------------------------------------------
# Search matrix
# ---------------------------------------------------------------------------


def _ikm_candidates(api_key: bytes) -> list[tuple[str, bytes]]:
    """Enumerate IKM candidates derived from the raw API key bytes.

    Never logs the values. The label is what gets reported in artifacts.
    """
    cands: list[tuple[str, bytes]] = []
    cands.append(("utf8", api_key))

    s = api_key.decode("latin1")

    # If the API key looks like hex
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        cands.append(("hex_decoded", bytes.fromhex(s)))

    # base64 variants. Try with auto-padding so unpadded keys also decode.
    def _try_b64(label: str, raw: str, urlsafe: bool) -> None:
        for pad in range(4):
            candidate_str = raw + ("=" * pad)
            try:
                if urlsafe:
                    val = base64.urlsafe_b64decode(candidate_str)
                else:
                    val = base64.b64decode(candidate_str, validate=True)
            except Exception:
                continue
            cands.append((label, val))
            return

    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in s):
        _try_b64("b64_decoded", s, urlsafe=False)
    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for c in s):
        _try_b64("b64url_decoded", s, urlsafe=True)

    # Many service-account-style keys use a short prefix separated by `_` or `-`
    # (e.g. ``sa_<body>``, ``sk_<body>``). If a prefix is present, also try the
    # post-prefix body decoded in plausible ways. This is still keyed off the
    # API_KEY contents only - no other inputs.
    for sep in ("_", "-"):
        if sep in s:
            head, body = s.split(sep, 1)
            # Only consider short prefixes (typical: 2-6 chars).
            if 1 <= len(head) <= 6 and body:
                cands.append((f"after_{head}{sep}_utf8", body.encode("utf-8")))
                if all(
                    c
                    in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
                    for c in body
                ):
                    _try_b64(f"after_{head}{sep}_b64url", body, urlsafe=True)
                if all(
                    c
                    in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                    for c in body
                ):
                    _try_b64(f"after_{head}{sep}_b64", body, urlsafe=False)
                if all(c in "0123456789abcdefABCDEF" for c in body) and len(body) % 2 == 0:
                    cands.append((f"after_{head}{sep}_hex", bytes.fromhex(body)))
            break  # only first separator
    # Dedup by bytes value (label-stable: keep first occurrence)
    seen: dict[bytes, str] = {}
    out: list[tuple[str, bytes]] = []
    for label, val in cands:
        if val not in seen:
            seen[val] = label
            out.append((label, val))
    return out


SALT_CANDIDATES: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("se-assessment", b"se-assessment"),
    ("se-assessment-api", b"se-assessment-api"),
    ("host", b"ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"),
    ("dataset", b"dataset"),
]

INFO_CANDIDATES: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("dataset", b"dataset"),
    ("records", b"records"),
    ("record-encryption", b"record-encryption"),
    ("se-assessment-records", b"se-assessment-records"),
    ("aes-gcm", b"aes-gcm"),
    ("encryption-key", b"encryption-key"),
]

LENGTHS = [32, 16]
EXPLICIT_LAYOUTS = ["L1", "L2", "L3", "L5", "L6"]
IMPLICIT_LAYOUT = "L4"
NONCE_STRATEGIES = ["be12", "le12", "be8_4", "be4_8"]
AAD_CANDIDATES: list[tuple[str, Any]] = [
    ("none", None),
    ("idx2_be", "idx2_be"),
    ("idx4_be", "idx4_be"),
]


def _aad_for(label: str, record_index: int) -> bytes | None:
    if label == "none":
        return None
    if label == "idx2_be":
        return record_index.to_bytes(2, "big")
    if label == "idx4_be":
        return record_index.to_bytes(4, "big")
    raise ValueError(f"unknown aad label {label!r}")


def _gate_indices(total: int) -> list[int]:
    """Indices used for the quick gate (records 0, 1, 100, 499)."""
    return [i for i in (0, 1, 100, 499) if i < total]


def search_for_decryption(
    ciphertexts: list[bytes],
    api_key: bytes,
    *,
    progress: bool = False,
) -> tuple[dict, list[bytes]] | None:
    """Sweep the search matrix. On first hit, decrypt all 500 and return.

    Returns ``(config_dict, plaintexts)`` on success, or ``None`` on miss.
    """
    ikm_cands = _ikm_candidates(api_key)
    gate_idx = _gate_indices(len(ciphertexts))
    attempts = 0

    def _try_full_validate(
        key: bytes,
        layout: str,
        aad_label: str,
        nonce_strategy: str | None,
    ) -> list[bytes] | None:
        # Gate: indices 0, 1, 100, 499 must all decrypt.
        gate_pts: dict[int, bytes] = {}
        for idx in gate_idx:
            aad = _aad_for(aad_label, idx)
            pt = try_decrypt_layout(
                key,
                ciphertexts[idx],
                layout,
                record_index=idx,
                aad=aad,
                nonce_strategy=nonce_strategy,
            )
            if pt is None:
                return None
            gate_pts[idx] = pt
        # Full pass.
        plaintexts: list[bytes] = []
        for idx, ct in enumerate(ciphertexts):
            aad = _aad_for(aad_label, idx)
            pt = try_decrypt_layout(
                key,
                ct,
                layout,
                record_index=idx,
                aad=aad,
                nonce_strategy=nonce_strategy,
            )
            if pt is None:
                return None
            plaintexts.append(pt)
        return plaintexts

    for ikm_label, ikm in ikm_cands:
        for salt_label, salt in SALT_CANDIDATES:
            for info_label, info in INFO_CANDIDATES:
                for length in LENGTHS:
                    try:
                        key = derive_key_hkdf(ikm, salt=salt, info=info, length=length)
                    except Exception:
                        continue
                    # Explicit-nonce layouts
                    for layout in EXPLICIT_LAYOUTS:
                        for aad_label, _aad_marker in AAD_CANDIDATES:
                            attempts += 1
                            if progress and attempts % 100 == 0:
                                print(f"[sweep] attempt {attempts}", flush=True)
                            pts = _try_full_validate(key, layout, aad_label, None)
                            if pts is not None:
                                cfg = {
                                    "ikm_label": ikm_label,
                                    "salt_label": salt_label,
                                    "info_label": info_label,
                                    "length": length,
                                    "layout": layout,
                                    "nonce_strategy": None,
                                    "aad_label": aad_label,
                                    "attempts_until_hit": attempts,
                                }
                                return cfg, pts
                    # Implicit-nonce layout L4
                    for nonce_strategy in NONCE_STRATEGIES:
                        for aad_label, _aad_marker in AAD_CANDIDATES:
                            attempts += 1
                            if progress and attempts % 100 == 0:
                                print(f"[sweep] attempt {attempts}", flush=True)
                            pts = _try_full_validate(
                                key, IMPLICIT_LAYOUT, aad_label, nonce_strategy
                            )
                            if pts is not None:
                                cfg = {
                                    "ikm_label": ikm_label,
                                    "salt_label": salt_label,
                                    "info_label": info_label,
                                    "length": length,
                                    "layout": IMPLICIT_LAYOUT,
                                    "nonce_strategy": nonce_strategy,
                                    "aad_label": aad_label,
                                    "attempts_until_hit": attempts,
                                }
                                return cfg, pts
    if progress:
        print(f"[sweep] exhausted {attempts} attempts without a hit", flush=True)
    return None


def decrypt_records(ciphertexts: list[bytes], config: dict, key: bytes) -> list[bytes]:
    """Definitive decryption pass for ``config``. Raises if any record fails."""
    layout = config["layout"]
    nonce_strategy = config.get("nonce_strategy")
    aad_label = config["aad_label"]
    out: list[bytes] = []
    for idx, ct in enumerate(ciphertexts):
        aad = _aad_for(aad_label, idx)
        pt = try_decrypt_layout(
            key,
            ct,
            layout,
            record_index=idx,
            aad=aad,
            nonce_strategy=nonce_strategy,
        )
        if pt is None:
            raise ValueError(f"record {idx} failed under final config")
        out.append(pt)
    return out


# ---------------------------------------------------------------------------
# Hash candidates
# ---------------------------------------------------------------------------


def compute_hash_candidates(plaintexts: list[bytes]) -> dict[str, str]:
    """Compute D1-D4 lowercase hex sha256.

    - D1: sha256 of concatenated raw plaintext bytes (positional order).
    - D2: sha256 of concatenated UTF-8 strings (only if all decode as UTF-8).
    - D3: sha256 of canonical JSON array of UTF-8 strings (only if D2 valid).
    - D4: sha256 of plaintexts joined by 0x0a newlines.
    """
    out: dict[str, str] = {}

    h1 = hashlib.sha256()
    for p in plaintexts:
        h1.update(p)
    out["D1"] = h1.hexdigest()

    decoded_strings: list[str] | None
    try:
        decoded_strings = [p.decode("utf-8") for p in plaintexts]
    except UnicodeDecodeError:
        decoded_strings = None

    if decoded_strings is not None:
        out["D2"] = hashlib.sha256("".join(decoded_strings).encode("utf-8")).hexdigest()
        out["D3"] = hashlib.sha256(
            json.dumps(decoded_strings, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    else:
        out["D2"] = "N/A"
        out["D3"] = "N/A"

    out["D4"] = hashlib.sha256(b"\n".join(plaintexts)).hexdigest()
    return out


# ---------------------------------------------------------------------------
# v3 extended sweep: ETag-derived material, per-batch keying, ChaCha20
# ---------------------------------------------------------------------------


# Known constants for v3 sweep (offline-known from prior phase artifacts).
# These are values the server has already disclosed in headers/bodies; we are
# not introducing any new wire calls. They are kept here so the sweep is
# self-contained and deterministic.
PAGINATED_DATASET_ETAG_HEX: str = (
    "bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf"
)
ASSESSMENT_STARTED_AT_ISO: str = "2026-05-08T02:16:44.027507+00:00"


def _strip_etag(raw: str) -> str:
    """Strip the ``W/"..."`` weak-ETag wrapper, returning bare hex chars."""
    s = raw.strip()
    if s.startswith("W/"):
        s = s[2:]
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s


def _collect_etags_from_logs(
    logs_dir: str | Path = "logs",
) -> dict[str, str]:
    """Return mapping of batch range (e.g. ``"0-99"``) to bare-hex ETag string.

    Reads each ``*-GET-api-v1-dataset.json`` log and dedupes by newest filename
    per range. Skips logs that are not 200 OK or are not batch responses.
    """
    logs_path = Path(logs_dir)
    by_range: dict[str, tuple[str, str]] = {}
    for path in sorted(logs_path.glob("*-GET-api-v1-dataset.json")):
        with path.open() as fh:
            log = json.load(fh)
        params = log.get("request_params") or {}
        if params.get("batch") != "true" or "range" not in params:
            continue
        if log.get("response_status") != 200:
            continue
        rng = params["range"]
        raw_etag = (log.get("response_headers") or {}).get("etag")
        if not raw_etag:
            continue
        bare = _strip_etag(raw_etag)
        prev = by_range.get(rng)
        if prev is None or path.name > prev[0]:
            by_range[rng] = (path.name, bare)
    return {rng: etag for rng, (_, etag) in by_range.items()}


# ChaCha20-Poly1305 has 12-byte nonce + 16-byte tag, identical layouts to
# AES-GCM L1/L4. Provide a parallel layout splitter restricted to L1/L4 only
# (the cheap, primary cases per the v3 brief).


def try_decrypt_chacha20poly1305(
    key: bytes,
    ciphertext: bytes,
    layout: str,
    record_index: int = 0,
    *,
    aad: bytes | None = None,
    nonce_strategy: str | None = None,
) -> bytes | None:
    """ChaCha20-Poly1305 parallel of ``try_decrypt_layout``.

    Only L1 (nonce(12) || ct(N) || tag(16)) and L4 (ct || tag(16) with
    implicit record-index nonce) are supported. ChaCha20-Poly1305 keys are
    fixed 32 bytes - the caller must pass exactly 32-byte keys.
    """
    if len(key) != 32:
        return None
    cipher = ChaCha20Poly1305(key)
    n = len(ciphertext)
    if layout == "L1":
        if n < 12 + GCM_TAG_LEN:
            return None
        nonce = ciphertext[:12]
        body_and_tag = ciphertext[12:]
        try:
            return cipher.decrypt(nonce, body_and_tag, aad)
        except InvalidTag:
            return None
        except ValueError:
            return None
    if layout == "L4":
        if n < GCM_TAG_LEN or nonce_strategy is None:
            return None
        nonce = _derive_implicit_nonce(nonce_strategy, record_index)
        if nonce is None:
            return None
        try:
            return cipher.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            return None
        except ValueError:
            return None
    return None


def _try_decrypt_unified(
    cipher_name: str,
    key: bytes,
    ciphertext: bytes,
    layout: str,
    record_index: int,
    aad: bytes | None,
    nonce_strategy: str | None,
) -> bytes | None:
    """Dispatch to AES-GCM or ChaCha20-Poly1305 by ``cipher_name``."""
    if cipher_name == "aes-gcm":
        return try_decrypt_layout(
            key,
            ciphertext,
            layout,
            record_index=record_index,
            aad=aad,
            nonce_strategy=nonce_strategy,
        )
    if cipher_name == "chacha20-poly1305":
        return try_decrypt_chacha20poly1305(
            key,
            ciphertext,
            layout,
            record_index=record_index,
            aad=aad,
            nonce_strategy=nonce_strategy,
        )
    raise ValueError(f"unknown cipher {cipher_name!r}")


# v3 layouts: only L1 and L4 (most common; cheap to test). Per brief, L2/L3/
# L5/L6 already swept under v2 and are skipped here.
V3_EXPLICIT_LAYOUTS = ["L1"]
V3_IMPLICIT_LAYOUT = "L4"
V3_NONCE_STRATEGIES = ["be12", "le12", "be8_4", "be4_8"]
V3_AAD_CANDIDATES: list[tuple[str, Any]] = [
    ("none", None),
    ("idx2_be", "idx2_be"),
    ("idx4_be", "idx4_be"),
]
V3_CIPHERS = ["aes-gcm", "chacha20-poly1305"]


def _v3_etag_label(rng: str) -> str:
    """Stable label for an ETag tied to a batch range."""
    return f"etag_{rng.replace('-', '_')}"


def _v3_ikm_extensions(
    api_key: bytes,
    etags: dict[str, str],
) -> list[tuple[str, bytes]]:
    """v3 IKM extensions: ETag bytes, ETag hex strings, concatenations."""
    out: list[tuple[str, bytes]] = []
    # Paginated dataset ETag (canonical, dataset-wide).
    paginated_hex = PAGINATED_DATASET_ETAG_HEX
    out.append(("etag_paginated_bytes", bytes.fromhex(paginated_hex)))
    out.append(("etag_paginated_hex_utf8", paginated_hex.encode("utf-8")))
    # Per-batch ETags.
    for rng, etag_hex in sorted(etags.items()):
        if len(etag_hex) != 64 or any(
            c not in "0123456789abcdefABCDEF" for c in etag_hex
        ):
            continue
        label = _v3_etag_label(rng)
        out.append((f"{label}_bytes", bytes.fromhex(etag_hex)))
        out.append((f"{label}_hex_utf8", etag_hex.encode("utf-8")))
    # Concatenations using the paginated ETag (most likely dataset-wide salt).
    out.append(
        (
            "api_key_colon_etag_paginated",
            api_key + b":" + paginated_hex.encode("utf-8"),
        )
    )
    out.append(
        (
            "etag_paginated_colon_api_key",
            paginated_hex.encode("utf-8") + b":" + api_key,
        )
    )
    return out


def _v3_salt_extensions(
    etags: dict[str, str],
) -> list[tuple[str, bytes]]:
    """v3 salt extensions: ETag bytes, hex-string, started-at, BASE_URL."""
    out: list[tuple[str, bytes]] = []
    paginated_hex = PAGINATED_DATASET_ETAG_HEX
    out.append(("etag_paginated_bytes", bytes.fromhex(paginated_hex)))
    out.append(("etag_paginated_hex_utf8", paginated_hex.encode("utf-8")))
    for rng, etag_hex in sorted(etags.items()):
        if len(etag_hex) != 64:
            continue
        label = _v3_etag_label(rng)
        out.append((f"{label}_bytes", bytes.fromhex(etag_hex)))
        out.append((f"{label}_hex_utf8", etag_hex.encode("utf-8")))
    out.append(("started_at_iso", ASSESSMENT_STARTED_AT_ISO.encode("utf-8")))
    base_url = os.environ.get("BASE_URL", "").encode("utf-8")
    if base_url:
        out.append(("base_url", base_url))
    # Common literal candidates that pair well with ETag-as-IKM.
    out.append(("dataset_v1", b"dataset/v1"))
    return out


def _v3_info_extensions() -> list[tuple[str, Any]]:
    """v3 info extensions including per-record-info markers (lazy)."""
    out: list[tuple[str, Any]] = []
    # Static info candidates added in v3.
    out.append(("record_literal", b"record"))
    out.append(("v1_literal", b"v1"))
    # Per-record markers - resolved at gate time.
    out.append(("per_record_idx2_be", "per_record_idx2_be"))
    out.append(("per_record_idx_string", "per_record_idx_string"))
    return out


def _resolve_info_for_record(info_marker: Any, record_index: int) -> bytes:
    """Resolve a per-record info marker into the actual info bytes."""
    if isinstance(info_marker, bytes):
        return info_marker
    if info_marker == "per_record_idx2_be":
        return record_index.to_bytes(2, "big")
    if info_marker == "per_record_idx_string":
        return f"record-{record_index}".encode("utf-8")
    raise ValueError(f"unknown info marker {info_marker!r}")


def _is_per_record_info(info_marker: Any) -> bool:
    return isinstance(info_marker, str)


def _api_key_truncated_pad(api_key: bytes, length: int) -> bytes:
    """Truncate or zero-pad ``api_key`` to exactly ``length`` bytes."""
    if len(api_key) >= length:
        return api_key[:length]
    return api_key + b"\x00" * (length - len(api_key))


def _direct_key_candidates(
    api_key: bytes,
    etags: dict[str, str],
) -> list[tuple[str, bytes]]:
    """v3 direct-key candidates (no HKDF). All must be 32 bytes for AES-256.

    These are the cheapest to test - no derivation cost at all - so they go
    first.
    """
    out: list[tuple[str, bytes]] = []
    paginated_hex = PAGINATED_DATASET_ETAG_HEX
    out.append(("direct_etag_paginated_bytes", bytes.fromhex(paginated_hex)))
    for rng, etag_hex in sorted(etags.items()):
        if len(etag_hex) != 64:
            continue
        out.append(
            (f"direct_{_v3_etag_label(rng)}_bytes", bytes.fromhex(etag_hex))
        )
    # API_KEY truncated/padded to 32 bytes.
    out.append(
        ("direct_api_key_trunc_pad_32", _api_key_truncated_pad(api_key, 32))
    )
    # API_KEY tail-after-`sa_` hex-decoded if it fits the shape.
    s = api_key.decode("latin1")
    for sep in ("_", "-"):
        if sep in s:
            head, body = s.split(sep, 1)
            if (
                1 <= len(head) <= 6
                and len(body) == 64
                and all(c in "0123456789abcdefABCDEF" for c in body)
            ):
                out.append(
                    (
                        f"direct_after_{head}{sep}_hex_32",
                        bytes.fromhex(body),
                    )
                )
            break
    # Dedup
    seen: dict[bytes, str] = {}
    dedup: list[tuple[str, bytes]] = []
    for label, val in out:
        if len(val) != 32:
            continue
        if val not in seen:
            seen[val] = label
            dedup.append((label, val))
    return dedup


def _record_to_batch_range(record_index: int, ranges: list[str]) -> str | None:
    """Return the batch range string covering ``record_index``, or None."""
    for rng in ranges:
        s, e = rng.split("-", 1)
        if int(s) <= record_index <= int(e):
            return rng
    return None


def _per_batch_gate_indices(total: int) -> list[int]:
    """One index from each of the 5 batches plus boundary samples."""
    candidates = [0, 99, 100, 199, 200, 299, 300, 399, 400, 499]
    return [i for i in candidates if i < total]


def _per_record_gate_indices(total: int) -> list[int]:
    """Lighter gate for per-record-info sweeps (HKDF cost is per record)."""
    candidates = [0, 100, 250, 499]
    return [i for i in candidates if i < total]


def _validate_full(
    cipher_name: str,
    keys_by_index: dict[int, bytes] | bytes,
    ciphertexts: list[bytes],
    layout: str,
    aad_label: str,
    nonce_strategy: str | None,
    info_marker: Any | None = None,
    ikm_for_per_record: bytes | None = None,
    salt_for_per_record: bytes | None = None,
    length_for_per_record: int | None = None,
) -> list[bytes] | None:
    """Validate every record. ``keys_by_index`` is either a single key (bytes)
    used for all indices, or a dict mapping record_index->key (per-batch or
    per-record). For per-record-info mode, the key is derived inside this
    function from (ikm, salt, info-per-record, length).
    """
    plaintexts: list[bytes] = []
    for idx, ct in enumerate(ciphertexts):
        if info_marker is not None and _is_per_record_info(info_marker):
            assert ikm_for_per_record is not None
            assert salt_for_per_record is not None
            assert length_for_per_record is not None
            info = _resolve_info_for_record(info_marker, idx)
            try:
                key = derive_key_hkdf(
                    ikm_for_per_record,
                    salt=salt_for_per_record,
                    info=info,
                    length=length_for_per_record,
                )
            except Exception:
                return None
        elif isinstance(keys_by_index, dict):
            key = keys_by_index.get(idx)
            if key is None:
                return None
        else:
            key = keys_by_index
        aad = _aad_for(aad_label, idx)
        pt = _try_decrypt_unified(
            cipher_name, key, ct, layout, idx, aad, nonce_strategy
        )
        if pt is None:
            return None
        plaintexts.append(pt)
    return plaintexts


def _gate_then_full(
    cipher_name: str,
    key_or_dict: dict[int, bytes] | bytes,
    ciphertexts: list[bytes],
    layout: str,
    aad_label: str,
    nonce_strategy: str | None,
    gate_idx: list[int],
    *,
    info_marker: Any | None = None,
    ikm_for_per_record: bytes | None = None,
    salt_for_per_record: bytes | None = None,
    length_for_per_record: int | None = None,
) -> list[bytes] | None:
    """Run gate set first; return None if any gate record fails."""
    for idx in gate_idx:
        if info_marker is not None and _is_per_record_info(info_marker):
            assert ikm_for_per_record is not None
            assert salt_for_per_record is not None
            assert length_for_per_record is not None
            info = _resolve_info_for_record(info_marker, idx)
            try:
                key = derive_key_hkdf(
                    ikm_for_per_record,
                    salt=salt_for_per_record,
                    info=info,
                    length=length_for_per_record,
                )
            except Exception:
                return None
        elif isinstance(key_or_dict, dict):
            key = key_or_dict.get(idx)
            if key is None:
                return None
        else:
            key = key_or_dict
        aad = _aad_for(aad_label, idx)
        pt = _try_decrypt_unified(
            cipher_name,
            key,
            ciphertexts[idx],
            layout,
            idx,
            aad,
            nonce_strategy,
        )
        if pt is None:
            return None
    return _validate_full(
        cipher_name,
        key_or_dict,
        ciphertexts,
        layout,
        aad_label,
        nonce_strategy,
        info_marker=info_marker,
        ikm_for_per_record=ikm_for_per_record,
        salt_for_per_record=salt_for_per_record,
        length_for_per_record=length_for_per_record,
    )


def _layout_iter(cipher_name: str) -> list[tuple[str, str | None, str]]:
    """Yield (layout, nonce_strategy_or_None, aad_label) tuples for v3."""
    out: list[tuple[str, str | None, str]] = []
    for layout in V3_EXPLICIT_LAYOUTS:
        for aad_label, _m in V3_AAD_CANDIDATES:
            out.append((layout, None, aad_label))
    for ns in V3_NONCE_STRATEGIES:
        for aad_label, _m in V3_AAD_CANDIDATES:
            out.append((V3_IMPLICIT_LAYOUT, ns, aad_label))
    return out


def search_for_decryption_v3(
    ciphertexts: list[bytes],
    api_key: bytes,
    etags: dict[str, str],
    *,
    progress: bool = False,
    max_attempts: int = 200_000,
) -> tuple[dict, list[bytes]] | None:
    """v3 extended sweep. Returns ``(config_dict, plaintexts)`` on success.

    Order of sub-searches (cheapest/most-likely first):
      1. Direct-key paths (no HKDF)
      2. ETag-as-salt with global keying (per-batch ETags + paginated ETag)
      3. Per-batch keying (ETag-as-salt, HKDF over API_KEY)
      4. Per-batch keying (ETag-as-IKM)
      5. Per-record info derivation
      6. ChaCha20-Poly1305 swap of (1) + (2)
    """
    gate_idx = _gate_indices(len(ciphertexts))
    per_batch_gate = _per_batch_gate_indices(len(ciphertexts))
    per_record_gate = _per_record_gate_indices(len(ciphertexts))
    ranges = sorted(
        etags.keys(), key=lambda r: int(r.split("-")[0])
    )
    attempts = 0

    def _bump(label: str = "") -> None:
        nonlocal attempts
        attempts += 1
        if progress and attempts % 10_000 == 0:
            print(f"[v3-sweep] attempt {attempts} ({label})", flush=True)

    layout_combos_full = _layout_iter("aes-gcm")

    # --- 1. Direct-key paths (AES-GCM, then ChaCha20) ---
    direct = _direct_key_candidates(api_key, etags)
    for cipher_name in V3_CIPHERS:
        for key_label, key in direct:
            for layout, ns, aad_label in layout_combos_full:
                _bump(f"direct/{cipher_name}/{key_label}")
                if attempts > max_attempts:
                    if progress:
                        print(f"[v3-sweep] BUDGET EXCEEDED at {attempts}")
                    return None
                pts = _gate_then_full(
                    cipher_name,
                    key,
                    ciphertexts,
                    layout,
                    aad_label,
                    ns,
                    gate_idx,
                )
                if pts is not None:
                    return (
                        {
                            "mode": "direct_key",
                            "cipher": cipher_name,
                            "key_label": key_label,
                            "layout": layout,
                            "nonce_strategy": ns,
                            "aad_label": aad_label,
                            "attempts_until_hit": attempts,
                        },
                        pts,
                    )

    # --- 2. ETag-as-salt with global HKDF keying (HKDF over API_KEY IKM) ---
    salt_ext = _v3_salt_extensions(etags)
    base_ikm = _ikm_candidates(api_key)
    # Restrict global IKMs to most plausible 3 to keep costs in budget.
    global_ikm = [ikm for ikm in base_ikm if ikm[0] in {"utf8", "after_sa__hex", "b64url_decoded"}]

    for cipher_name in V3_CIPHERS:
        for ikm_label, ikm in global_ikm:
            for salt_label, salt in salt_ext:
                for info_label, info in INFO_CANDIDATES:
                    for length in LENGTHS:
                        try:
                            key = derive_key_hkdf(
                                ikm, salt=salt, info=info, length=length
                            )
                        except Exception:
                            continue
                        if cipher_name == "chacha20-poly1305" and length != 32:
                            continue
                        for layout, ns, aad_label in (
                            layout_combos_full
                            if cipher_name == "aes-gcm"
                            else _layout_iter("chacha20-poly1305")
                        ):
                            _bump(
                                f"global/{cipher_name}/{ikm_label}/{salt_label}"
                            )
                            if attempts > max_attempts:
                                return None
                            pts = _gate_then_full(
                                cipher_name,
                                key,
                                ciphertexts,
                                layout,
                                aad_label,
                                ns,
                                gate_idx,
                            )
                            if pts is not None:
                                return (
                                    {
                                        "mode": "global_etag_salt",
                                        "cipher": cipher_name,
                                        "ikm_label": ikm_label,
                                        "salt_label": salt_label,
                                        "info_label": info_label,
                                        "length": length,
                                        "layout": layout,
                                        "nonce_strategy": ns,
                                        "aad_label": aad_label,
                                        "attempts_until_hit": attempts,
                                    },
                                    pts,
                                )

    # --- 3. Per-batch keying with ETag-as-salt (HKDF over API_KEY IKM) ---
    # For each (ikm, info, length, layout, aad, cipher), build a per-record
    # key map where records in batch B use HKDF(ikm, salt=batch_etag_B,
    # info, length) and gate against per-batch sample indices.
    per_batch_etag_bytes: dict[str, bytes] = {
        rng: bytes.fromhex(etag_hex)
        for rng, etag_hex in etags.items()
        if len(etag_hex) == 64
    }
    per_batch_etag_hexbytes: dict[str, bytes] = {
        rng: etag_hex.encode("utf-8")
        for rng, etag_hex in etags.items()
        if len(etag_hex) == 64
    }

    def _build_per_batch_key_map(
        ikm: bytes,
        salt_per_batch: dict[str, bytes],
        info: bytes,
        length: int,
    ) -> dict[int, bytes] | None:
        if not all(rng in salt_per_batch for rng in ranges):
            return None
        try:
            key_per_batch = {
                rng: derive_key_hkdf(
                    ikm, salt=salt_per_batch[rng], info=info, length=length
                )
                for rng in ranges
            }
        except Exception:
            return None
        out: dict[int, bytes] = {}
        for rng in ranges:
            s, e = rng.split("-", 1)
            for i in range(int(s), int(e) + 1):
                if i < len(ciphertexts):
                    out[i] = key_per_batch[rng]
        return out

    for cipher_name in V3_CIPHERS:
        for ikm_label, ikm in global_ikm:
            for salt_form_label, salt_per_batch in [
                ("per_batch_etag_bytes", per_batch_etag_bytes),
                ("per_batch_etag_hex_utf8", per_batch_etag_hexbytes),
            ]:
                for info_label, info in INFO_CANDIDATES:
                    for length in LENGTHS:
                        if cipher_name == "chacha20-poly1305" and length != 32:
                            continue
                        key_map = _build_per_batch_key_map(
                            ikm, salt_per_batch, info, length
                        )
                        if key_map is None:
                            continue
                        for layout, ns, aad_label in (
                            layout_combos_full
                            if cipher_name == "aes-gcm"
                            else _layout_iter("chacha20-poly1305")
                        ):
                            _bump(
                                f"per_batch_salt/{cipher_name}/"
                                f"{ikm_label}/{salt_form_label}"
                            )
                            if attempts > max_attempts:
                                return None
                            pts = _gate_then_full(
                                cipher_name,
                                key_map,
                                ciphertexts,
                                layout,
                                aad_label,
                                ns,
                                per_batch_gate,
                            )
                            if pts is not None:
                                return (
                                    {
                                        "mode": "per_batch_etag_salt",
                                        "cipher": cipher_name,
                                        "ikm_label": ikm_label,
                                        "salt_form": salt_form_label,
                                        "info_label": info_label,
                                        "length": length,
                                        "layout": layout,
                                        "nonce_strategy": ns,
                                        "aad_label": aad_label,
                                        "attempts_until_hit": attempts,
                                    },
                                    pts,
                                )

    # --- 4. Per-batch keying with ETag-as-IKM ---
    # IKM = batch ETag (bytes or hex-utf8); salt = small set of literals;
    # info = INFO_CANDIDATES; length in LENGTHS.
    pb_salt_set: list[tuple[str, bytes]] = [
        ("empty", b""),
        ("dataset", b"dataset"),
        ("se-assessment", b"se-assessment"),
    ]

    for cipher_name in V3_CIPHERS:
        for ikm_form_label, ikm_per_batch in [
            ("per_batch_etag_bytes", per_batch_etag_bytes),
            ("per_batch_etag_hex_utf8", per_batch_etag_hexbytes),
        ]:
            for salt_label, salt in pb_salt_set:
                for info_label, info in INFO_CANDIDATES:
                    for length in LENGTHS:
                        if cipher_name == "chacha20-poly1305" and length != 32:
                            continue
                        # Build per-batch key map with ETag as IKM.
                        try:
                            key_per_batch = {
                                rng: derive_key_hkdf(
                                    ikm_per_batch[rng],
                                    salt=salt,
                                    info=info,
                                    length=length,
                                )
                                for rng in ranges
                            }
                        except Exception:
                            continue
                        key_map: dict[int, bytes] = {}
                        for rng in ranges:
                            s, e = rng.split("-", 1)
                            for i in range(int(s), int(e) + 1):
                                if i < len(ciphertexts):
                                    key_map[i] = key_per_batch[rng]
                        for layout, ns, aad_label in (
                            layout_combos_full
                            if cipher_name == "aes-gcm"
                            else _layout_iter("chacha20-poly1305")
                        ):
                            _bump(
                                f"per_batch_ikm/{cipher_name}/"
                                f"{ikm_form_label}/{salt_label}"
                            )
                            if attempts > max_attempts:
                                return None
                            pts = _gate_then_full(
                                cipher_name,
                                key_map,
                                ciphertexts,
                                layout,
                                aad_label,
                                ns,
                                per_batch_gate,
                            )
                            if pts is not None:
                                return (
                                    {
                                        "mode": "per_batch_etag_ikm",
                                        "cipher": cipher_name,
                                        "ikm_form": ikm_form_label,
                                        "salt_label": salt_label,
                                        "info_label": info_label,
                                        "length": length,
                                        "layout": layout,
                                        "nonce_strategy": ns,
                                        "aad_label": aad_label,
                                        "attempts_until_hit": attempts,
                                    },
                                    pts,
                                )

    # --- 5. Per-record-info derivation ---
    # Capped by per-record HKDF cost. Use only utf8 IKM and a small
    # salt/length subset to stay in budget.
    pr_ikm_label, pr_ikm = global_ikm[0]  # utf8 most likely
    pr_salt_set: list[tuple[str, bytes]] = [
        ("empty", b""),
        ("dataset", b"dataset"),
        ("etag_paginated_bytes", bytes.fromhex(PAGINATED_DATASET_ETAG_HEX)),
    ]
    for cipher_name in V3_CIPHERS:
        for info_label, info_marker in _v3_info_extensions():
            if not _is_per_record_info(info_marker):
                continue
            for salt_label, salt in pr_salt_set:
                for length in LENGTHS:
                    if cipher_name == "chacha20-poly1305" and length != 32:
                        continue
                    for layout, ns, aad_label in (
                        layout_combos_full
                        if cipher_name == "aes-gcm"
                        else _layout_iter("chacha20-poly1305")
                    ):
                        _bump(
                            f"per_record_info/{cipher_name}/"
                            f"{info_label}/{salt_label}"
                        )
                        if attempts > max_attempts:
                            return None
                        pts = _gate_then_full(
                            cipher_name,
                            b"",  # unused; per-record-info path derives keys
                            ciphertexts,
                            layout,
                            aad_label,
                            ns,
                            per_record_gate,
                            info_marker=info_marker,
                            ikm_for_per_record=pr_ikm,
                            salt_for_per_record=salt,
                            length_for_per_record=length,
                        )
                        if pts is not None:
                            return (
                                {
                                    "mode": "per_record_info",
                                    "cipher": cipher_name,
                                    "ikm_label": pr_ikm_label,
                                    "salt_label": salt_label,
                                    "info_label": info_label,
                                    "length": length,
                                    "layout": layout,
                                    "nonce_strategy": ns,
                                    "aad_label": aad_label,
                                    "attempts_until_hit": attempts,
                                },
                                pts,
                            )

    if progress:
        print(
            f"[v3-sweep] exhausted {attempts} attempts without a hit",
            flush=True,
        )
    return None


# ---------------------------------------------------------------------------
# v4 AES-CTR + HMAC-SHA256 (encrypt-then-MAC) sweep
# ---------------------------------------------------------------------------


# Each record is exactly RECORD_DECODED_LEN = 256 bytes. The layouts split
# that fixed length into iv || ct || mac.
CTR_HMAC_LAYOUTS: list[tuple[str, int, int, int]] = [
    # (label, iv_len, ct_len, mac_len)
    ("LE1", 16, 224, 16),
    ("LE2", 16, 208, 32),
    ("LE3", 12, 228, 16),
    ("LE4", 8, 232, 16),
]


def _ctr_iv_for_layout(iv_field: bytes, layout: str) -> bytes:
    """Pad the IV-field bytes from a layout to a 16-byte AES-CTR IV.

    AES-CTR requires a 16-byte initial counter block. For layouts whose
    IV field is shorter than 16 bytes, the standard convention is to
    right-pad with zero bytes so the trailing portion becomes the
    counter (incrementing per 16-byte block).
    """
    if len(iv_field) == 16:
        return iv_field
    if len(iv_field) in (8, 12):
        return iv_field + b"\x00" * (16 - len(iv_field))
    raise ValueError(f"unsupported iv length for layout {layout!r}")


def _aes_ctr_decrypt(enc_key: bytes, iv16: bytes, ct: bytes) -> bytes:
    """Decrypt ``ct`` with AES-CTR using a 16-byte IV/initial counter."""
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv16))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


def _hmac_sha256(mac_key: bytes, data: bytes, mac_len: int) -> bytes:
    """HMAC-SHA256, optionally truncated to ``mac_len`` bytes."""
    full = _hmac.new(mac_key, data, hashlib.sha256).digest()
    if mac_len == 32:
        return full
    if mac_len < 32:
        return full[:mac_len]
    raise ValueError(f"mac_len {mac_len} > sha256 size 32")


def _mac_scope(
    scope_label: str, iv: bytes, ct: bytes, record_index: int
) -> bytes | None:
    """Build the byte string the MAC is computed over for ``scope_label``."""
    if scope_label == "M1":
        return iv + ct
    if scope_label == "M2":
        return ct
    if scope_label == "M3":
        return iv + ct + record_index.to_bytes(4, "big")
    if scope_label == "M4":
        return iv + ct + record_index.to_bytes(2, "big")
    return None


CTR_HMAC_MAC_SCOPES = ["M1", "M2", "M3", "M4"]


def _aes_ctr_hmac_decrypt(
    enc_key: bytes,
    mac_key: bytes,
    record: bytes,
    layout: str,
    record_index: int,
    mac_scope_label: str,
) -> bytes | None:
    """Validate HMAC and decrypt one record. Returns plaintext or None."""
    spec = next((s for s in CTR_HMAC_LAYOUTS if s[0] == layout), None)
    if spec is None:
        return None
    _, iv_len, ct_len, mac_len = spec
    if len(record) != iv_len + ct_len + mac_len:
        return None
    iv_field = record[:iv_len]
    ct = record[iv_len : iv_len + ct_len]
    mac = record[iv_len + ct_len :]
    scope = _mac_scope(mac_scope_label, iv_field, ct, record_index)
    if scope is None:
        return None
    expected = _hmac_sha256(mac_key, scope, mac_len)
    if not _hmac.compare_digest(expected, mac):
        return None
    iv16 = _ctr_iv_for_layout(iv_field, layout)
    try:
        return _aes_ctr_decrypt(enc_key, iv16, ct)
    except Exception:
        return None


# v4 IKM/salt/info matrix (Pass 1 — narrow + most likely)
V4_PASS1_SALT_LABELS = {"empty", "se-assessment"}  # plus per-ETag, added below
V4_PASS1_INFO_CANDIDATES: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("dataset", b"dataset"),
    ("records", b"records"),
    ("record-encryption", b"record-encryption"),
]
V4_PASS1_LAYOUTS = ["LE1", "LE3"]
V4_PASS1_MAC_SCOPES = ["M1", "M2"]
V4_FULL_LAYOUTS = ["LE1", "LE2", "LE3", "LE4"]
V4_FULL_MAC_SCOPES = ["M1", "M2", "M3", "M4"]


def _v4_ikm_candidates_pass1(
    api_key: bytes,
    etags: dict[str, str],
) -> list[tuple[str, bytes]]:
    """Pass-1 IKM candidates for v4 sweep."""
    cands: list[tuple[str, bytes]] = []
    cands.append(("api_utf8", api_key))
    s = api_key.decode("latin1")
    for sep in ("_", "-"):
        if sep in s:
            head, body = s.split(sep, 1)
            if (
                1 <= len(head) <= 6
                and len(body) == 64
                and all(c in "0123456789abcdefABCDEF" for c in body)
            ):
                cands.append(
                    (f"after_{head}{sep}_hex", bytes.fromhex(body))
                )
            break
    # Per-batch ETag IKMs (hex-decoded bytes).
    for rng, etag_hex in sorted(etags.items()):
        if len(etag_hex) == 64 and all(
            c in "0123456789abcdefABCDEF" for c in etag_hex
        ):
            cands.append(
                (f"etag_{rng.replace('-', '_')}_bytes", bytes.fromhex(etag_hex))
            )
    cands.append(
        (
            "etag_paginated_bytes",
            bytes.fromhex(PAGINATED_DATASET_ETAG_HEX),
        )
    )
    seen: dict[bytes, str] = {}
    out: list[tuple[str, bytes]] = []
    for label, val in cands:
        if val and val not in seen:
            seen[val] = label
            out.append((label, val))
    return out


def _v4_salt_candidates_pass1(
    etags: dict[str, str],
) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = [
        ("empty", b""),
        ("se-assessment", b"se-assessment"),
    ]
    for rng, etag_hex in sorted(etags.items()):
        if len(etag_hex) == 64:
            label = _v3_etag_label(rng)
            out.append((f"{label}_bytes", bytes.fromhex(etag_hex)))
            out.append((f"{label}_hex_utf8", etag_hex.encode("utf-8")))
    out.append(
        ("etag_paginated_bytes", bytes.fromhex(PAGINATED_DATASET_ETAG_HEX))
    )
    return out


def _split_keypair(material: bytes) -> tuple[bytes, bytes]:
    """Split a 64-byte HKDF output into (enc_key=first32, mac_key=last32)."""
    if len(material) != 64:
        raise ValueError(f"split requires 64 bytes, got {len(material)}")
    return material[:32], material[32:]


def _ctr_hmac_gate_indices(total: int) -> list[int]:
    return [i for i in (0, 1, 100, 499) if i < total]


def _ctr_hmac_validate_full(
    enc_key: bytes,
    mac_key: bytes,
    ciphertexts: list[bytes],
    layout: str,
    mac_scope: str,
) -> list[bytes] | None:
    out: list[bytes] = []
    for idx, ct in enumerate(ciphertexts):
        pt = _aes_ctr_hmac_decrypt(
            enc_key, mac_key, ct, layout, idx, mac_scope
        )
        if pt is None:
            return None
        out.append(pt)
    return out


def _ctr_hmac_gate_then_full(
    enc_key: bytes,
    mac_key: bytes,
    ciphertexts: list[bytes],
    layout: str,
    mac_scope: str,
    gate_idx: list[int],
) -> list[bytes] | None:
    for idx in gate_idx:
        if (
            _aes_ctr_hmac_decrypt(
                enc_key, mac_key, ciphertexts[idx], layout, idx, mac_scope
            )
            is None
        ):
            return None
    return _ctr_hmac_validate_full(
        enc_key, mac_key, ciphertexts, layout, mac_scope
    )


def _iter_ctr_hmac_combos(
    api_key: bytes,
    etags: dict[str, str],
    *,
    pass_id: int,
):
    """Yield (label_dict, enc_key, mac_key, layout, mac_scope) tuples.

    pass_id == 1: narrow matrix, split-derivation (HKDF length=64).
    pass_id == 2: same matrix but per-batch keying applies (handled by caller
                  building per-record key maps).
    pass_id == 3: separate enc/mac derivations (info+"-enc", info+"-mac"),
                  HKDF length=32 each.
    """
    ikms = _v4_ikm_candidates_pass1(api_key, etags)
    salts = _v4_salt_candidates_pass1(etags)
    if pass_id == 1:
        layouts = V4_PASS1_LAYOUTS
        scopes = V4_PASS1_MAC_SCOPES
        infos = V4_PASS1_INFO_CANDIDATES
        for ikm_label, ikm in ikms:
            for salt_label, salt in salts:
                for info_label, info in infos:
                    try:
                        material = derive_key_hkdf(
                            ikm, salt=salt, info=info, length=64
                        )
                    except Exception:
                        continue
                    enc_key, mac_key = _split_keypair(material)
                    for layout in layouts:
                        for mac_scope in scopes:
                            yield (
                                {
                                    "mode": "split64",
                                    "ikm_label": ikm_label,
                                    "salt_label": salt_label,
                                    "info_label": info_label,
                                    "layout": layout,
                                    "mac_scope": mac_scope,
                                },
                                enc_key,
                                mac_key,
                                layout,
                                mac_scope,
                            )
    elif pass_id == 3:
        layouts = V4_PASS1_LAYOUTS
        scopes = V4_PASS1_MAC_SCOPES
        infos = V4_PASS1_INFO_CANDIDATES
        for ikm_label, ikm in ikms:
            for salt_label, salt in salts:
                for info_label, info in infos:
                    try:
                        enc_key = derive_key_hkdf(
                            ikm, salt=salt, info=info + b"-enc", length=32
                        )
                        mac_key = derive_key_hkdf(
                            ikm, salt=salt, info=info + b"-mac", length=32
                        )
                    except Exception:
                        continue
                    for layout in layouts:
                        for mac_scope in scopes:
                            yield (
                                {
                                    "mode": "separate_derivations",
                                    "ikm_label": ikm_label,
                                    "salt_label": salt_label,
                                    "info_label": info_label,
                                    "layout": layout,
                                    "mac_scope": mac_scope,
                                },
                                enc_key,
                                mac_key,
                                layout,
                                mac_scope,
                            )
    else:
        return


def search_ctr_hmac(
    ciphertexts: list[bytes],
    api_key: bytes,
    etags: dict[str, str],
    *,
    progress: bool = False,
    max_attempts: int = 50_000,
) -> tuple[dict, list[bytes]] | None:
    """v4 AES-CTR + HMAC-SHA256 sweep. Returns (config, plaintexts) on hit.

    Stops on first record that MAC-validates AND decrypts cleanly across all
    500 records. The MAC strength makes false positives effectively zero.
    """
    gate_idx = _ctr_hmac_gate_indices(len(ciphertexts))
    attempts = 0
    pass_counts = {1: 0, 2: 0, 3: 0}

    # --- Pass 1: split64 derivation, global keying ---
    for cfg, enc_key, mac_key, layout, mac_scope in _iter_ctr_hmac_combos(
        api_key, etags, pass_id=1
    ):
        attempts += 1
        pass_counts[1] += 1
        if attempts > max_attempts:
            if progress:
                print(f"[v4-sweep] BUDGET EXCEEDED at {attempts}")
            return None
        if progress and attempts % 2_000 == 0:
            print(f"[v4-sweep] pass1 attempt {attempts}", flush=True)
        pts = _ctr_hmac_gate_then_full(
            enc_key, mac_key, ciphertexts, layout, mac_scope, gate_idx
        )
        if pts is not None:
            cfg["pass"] = 1
            cfg["attempts_until_hit"] = attempts
            return cfg, pts

    # --- Pass 2: per-batch keying (batch ETag as salt OR IKM) ---
    # Build per-record key maps and gate on per-batch sample indices.
    ranges = sorted(etags.keys(), key=lambda r: int(r.split("-")[0]))
    per_batch_etag_bytes: dict[str, bytes] = {
        rng: bytes.fromhex(h) for rng, h in etags.items() if len(h) == 64
    }
    per_batch_etag_hex: dict[str, bytes] = {
        rng: h.encode("utf-8") for rng, h in etags.items() if len(h) == 64
    }
    per_batch_gate = [
        i for i in (0, 99, 100, 199, 200, 499) if i < len(ciphertexts)
    ]

    base_ikms = [("api_utf8", api_key)]
    s = api_key.decode("latin1")
    for sep in ("_", "-"):
        if sep in s:
            head, body = s.split(sep, 1)
            if (
                1 <= len(head) <= 6
                and len(body) == 64
                and all(c in "0123456789abcdefABCDEF" for c in body)
            ):
                base_ikms.append(
                    (f"after_{head}{sep}_hex", bytes.fromhex(body))
                )
            break

    pb_infos = V4_PASS1_INFO_CANDIDATES
    pb_layouts = V4_PASS1_LAYOUTS
    pb_scopes = V4_PASS1_MAC_SCOPES

    # Variant A: ETag-as-salt, API_KEY-as-IKM, split-derivation.
    for ikm_label, ikm in base_ikms:
        for salt_form_label, salt_per_batch in [
            ("per_batch_etag_bytes", per_batch_etag_bytes),
            ("per_batch_etag_hex_utf8", per_batch_etag_hex),
        ]:
            if not all(rng in salt_per_batch for rng in ranges):
                continue
            for info_label, info in pb_infos:
                try:
                    enc_per_batch: dict[str, bytes] = {}
                    mac_per_batch: dict[str, bytes] = {}
                    for rng in ranges:
                        material = derive_key_hkdf(
                            ikm,
                            salt=salt_per_batch[rng],
                            info=info,
                            length=64,
                        )
                        enc_per_batch[rng], mac_per_batch[rng] = _split_keypair(
                            material
                        )
                except Exception:
                    continue
                enc_map: dict[int, bytes] = {}
                mac_map: dict[int, bytes] = {}
                for rng in ranges:
                    s2, e2 = rng.split("-", 1)
                    for i in range(int(s2), int(e2) + 1):
                        if i < len(ciphertexts):
                            enc_map[i] = enc_per_batch[rng]
                            mac_map[i] = mac_per_batch[rng]
                for layout in pb_layouts:
                    for mac_scope in pb_scopes:
                        attempts += 1
                        pass_counts[2] += 1
                        if attempts > max_attempts:
                            return None
                        # Per-batch gate
                        ok = True
                        for idx in per_batch_gate:
                            if (
                                _aes_ctr_hmac_decrypt(
                                    enc_map[idx],
                                    mac_map[idx],
                                    ciphertexts[idx],
                                    layout,
                                    idx,
                                    mac_scope,
                                )
                                is None
                            ):
                                ok = False
                                break
                        if not ok:
                            continue
                        # Full pass.
                        plaintexts: list[bytes] = []
                        full_ok = True
                        for idx, ct in enumerate(ciphertexts):
                            pt = _aes_ctr_hmac_decrypt(
                                enc_map[idx],
                                mac_map[idx],
                                ct,
                                layout,
                                idx,
                                mac_scope,
                            )
                            if pt is None:
                                full_ok = False
                                break
                            plaintexts.append(pt)
                        if full_ok:
                            return (
                                {
                                    "mode": "per_batch_etag_salt_split64",
                                    "pass": 2,
                                    "ikm_label": ikm_label,
                                    "salt_form": salt_form_label,
                                    "info_label": info_label,
                                    "layout": layout,
                                    "mac_scope": mac_scope,
                                    "attempts_until_hit": attempts,
                                },
                                plaintexts,
                            )

    # Variant B: ETag-as-IKM, small salt set, split-derivation.
    pb_salts = [
        ("empty", b""),
        ("se-assessment", b"se-assessment"),
        ("dataset", b"dataset"),
    ]
    for ikm_form_label, ikm_per_batch in [
        ("per_batch_etag_bytes", per_batch_etag_bytes),
        ("per_batch_etag_hex_utf8", per_batch_etag_hex),
    ]:
        if not all(rng in ikm_per_batch for rng in ranges):
            continue
        for salt_label, salt in pb_salts:
            for info_label, info in pb_infos:
                try:
                    enc_per_batch = {}
                    mac_per_batch = {}
                    for rng in ranges:
                        material = derive_key_hkdf(
                            ikm_per_batch[rng],
                            salt=salt,
                            info=info,
                            length=64,
                        )
                        enc_per_batch[rng], mac_per_batch[rng] = _split_keypair(
                            material
                        )
                except Exception:
                    continue
                enc_map = {}
                mac_map = {}
                for rng in ranges:
                    s2, e2 = rng.split("-", 1)
                    for i in range(int(s2), int(e2) + 1):
                        if i < len(ciphertexts):
                            enc_map[i] = enc_per_batch[rng]
                            mac_map[i] = mac_per_batch[rng]
                for layout in pb_layouts:
                    for mac_scope in pb_scopes:
                        attempts += 1
                        pass_counts[2] += 1
                        if attempts > max_attempts:
                            return None
                        ok = True
                        for idx in per_batch_gate:
                            if (
                                _aes_ctr_hmac_decrypt(
                                    enc_map[idx],
                                    mac_map[idx],
                                    ciphertexts[idx],
                                    layout,
                                    idx,
                                    mac_scope,
                                )
                                is None
                            ):
                                ok = False
                                break
                        if not ok:
                            continue
                        plaintexts = []
                        full_ok = True
                        for idx, ct in enumerate(ciphertexts):
                            pt = _aes_ctr_hmac_decrypt(
                                enc_map[idx],
                                mac_map[idx],
                                ct,
                                layout,
                                idx,
                                mac_scope,
                            )
                            if pt is None:
                                full_ok = False
                                break
                            plaintexts.append(pt)
                        if full_ok:
                            return (
                                {
                                    "mode": "per_batch_etag_ikm_split64",
                                    "pass": 2,
                                    "ikm_form": ikm_form_label,
                                    "salt_label": salt_label,
                                    "info_label": info_label,
                                    "layout": layout,
                                    "mac_scope": mac_scope,
                                    "attempts_until_hit": attempts,
                                },
                                plaintexts,
                            )

    # --- Pass 3: separate enc/mac derivations ---
    for cfg, enc_key, mac_key, layout, mac_scope in _iter_ctr_hmac_combos(
        api_key, etags, pass_id=3
    ):
        attempts += 1
        pass_counts[3] += 1
        if attempts > max_attempts:
            if progress:
                print(f"[v4-sweep] BUDGET EXCEEDED at {attempts}")
            return None
        if progress and attempts % 2_000 == 0:
            print(f"[v4-sweep] pass3 attempt {attempts}", flush=True)
        pts = _ctr_hmac_gate_then_full(
            enc_key, mac_key, ciphertexts, layout, mac_scope, gate_idx
        )
        if pts is not None:
            cfg["pass"] = 3
            cfg["attempts_until_hit"] = attempts
            return cfg, pts

    if progress:
        print(
            f"[v4-sweep] exhausted {attempts} attempts ({pass_counts}) "
            "without a hit",
            flush=True,
        )
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _key_fingerprint(key: bytes) -> str:
    """Return sha256 hex of the derived key. Never returns the key itself."""
    return hashlib.sha256(key).hexdigest()


def main() -> None:
    api_key = os.environ.get("API_KEY")
    if not api_key:
        raise SystemExit("API_KEY not set")
    api_key_b = api_key.encode("utf-8")

    ciphertexts = load_ciphertexts_from_logs("logs")
    print(f"loaded {len(ciphertexts)} ciphertexts, {RECORD_DECODED_LEN} bytes each")

    result = search_for_decryption(ciphertexts, api_key_b, progress=True)
    if result is None:
        print("v2 sweep exhausted; falling back to v3 extended sweep")
        etags = _collect_etags_from_logs("logs")
        print(f"loaded {len(etags)} batch ETags for v3 sweep")
        result = search_for_decryption_v3(
            ciphertexts, api_key_b, etags, progress=True
        )
        if result is None:
            raise SystemExit("v3 sweep also exhausted with no decryption")
    config, plaintexts = result

    # Re-derive the key so we can fingerprint it (do not retain across calls).
    ikm_label = config["ikm_label"]
    ikm_map = dict(_ikm_candidates(api_key_b))
    ikm = ikm_map[ikm_label]
    salt = dict(SALT_CANDIDATES)[config["salt_label"]]
    info = dict(INFO_CANDIDATES)[config["info_label"]]
    key = derive_key_hkdf(ikm, salt=salt, info=info, length=config["length"])

    print(f"hit config: {config}")
    print(f"key fingerprint (sha256 of derived key): {_key_fingerprint(key)}")

    plaintexts2 = decrypt_records(ciphertexts, config, key)
    assert plaintexts == plaintexts2

    cands = compute_hash_candidates(plaintexts)
    for k in ("D1", "D2", "D3", "D4"):
        print(f"{k}: {cands[k]}")

    # Sample lengths and a probe of record content (in hex if not printable).
    lens = [len(p) for p in plaintexts]
    print(f"plaintext lengths: min={min(lens)} max={max(lens)} unique={len(set(lens))}")


if __name__ == "__main__":
    main()
