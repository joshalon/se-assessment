"""Offline tests for assessment.layer2. No HTTP, no live calls."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from assessment.layer2 import (
    _aes_ctr_decrypt,
    _aes_ctr_hmac_decrypt,
    _collect_etags_from_logs,
    _ctr_iv_for_layout,
    _direct_key_candidates,
    _hmac_sha256,
    _record_to_batch_range,
    _resolve_info_for_record,
    _split_keypair,
    _strip_etag,
    _v3_salt_extensions,
    compute_hash_candidates,
    decrypt_records,
    derive_key_hkdf,
    load_ciphertexts_from_logs,
    search_ctr_hmac,
    search_for_decryption,
    search_for_decryption_v3,
    try_decrypt_chacha20poly1305,
    try_decrypt_layout,
)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _fake_record_ct(i: int) -> str:
    raw = bytes((i + j) % 256 for j in range(256))
    return base64.b64encode(raw).decode()


def _write_batch_log(path: Path, start: int, end: int) -> None:
    body = {
        "data": [_fake_record_ct(i) for i in range(start, end + 1)],
        "count": end - start + 1,
    }
    log = {
        "method": "GET",
        "url": "https://example/api/v1/dataset",
        "request_headers": {},
        "request_body": None,
        "request_params": {"batch": "true", "range": f"{start}-{end}"},
        "response_status": 200,
        "response_headers": {},
        "response_body": body,
    }
    with path.open("w") as fh:
        json.dump(log, fh)


def test_load_ciphertexts_from_logs_assembles_500_records(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    for i, (s, e) in enumerate([(0, 99), (100, 199), (200, 299), (300, 399), (400, 499)]):
        _write_batch_log(
            logs_dir / f"2026{i:02d}-GET-api-v1-dataset.json", s, e
        )
    cts = load_ciphertexts_from_logs(logs_dir)
    assert len(cts) == 500
    assert all(len(c) == 256 for c in cts)
    # Positional ordering: record 0 starts with byte 0, record 250 starts with 250 mod 256.
    assert cts[0][0] == 0
    assert cts[250][0] == 250 % 256


def test_load_ciphertexts_dedups_by_newest_filename(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    # Older log for range 0-99 with records starting at seed=0.
    _write_batch_log(logs_dir / "20260101-GET-api-v1-dataset.json", 0, 99)
    # Newer log for the same range with records starting at seed=1000 - we
    # expect the newer one to win.
    newer = logs_dir / "20260201-GET-api-v1-dataset.json"
    body = {
        "data": [_fake_record_ct(1000 + i) for i in range(100)],
        "count": 100,
    }
    log = {
        "method": "GET",
        "url": "https://example/api/v1/dataset",
        "request_headers": {},
        "request_body": None,
        "request_params": {"batch": "true", "range": "0-99"},
        "response_status": 200,
        "response_headers": {},
        "response_body": body,
    }
    with newer.open("w") as fh:
        json.dump(log, fh)
    for s, e in [(100, 199), (200, 299), (300, 399), (400, 499)]:
        _write_batch_log(logs_dir / f"20260201-{s}-GET-api-v1-dataset.json", s, e)
    cts = load_ciphertexts_from_logs(logs_dir)
    # First record should reflect the newer (seed=1000) batch.
    assert cts[0][0] == 1000 % 256


# ---------------------------------------------------------------------------
# HKDF golden vector (RFC 5869 Test Case 1, SHA-256)
# ---------------------------------------------------------------------------


def test_derive_key_hkdf_matches_rfc5869_case1() -> None:
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    out = derive_key_hkdf(ikm, salt=salt, info=info, length=42)
    assert out == expected


# ---------------------------------------------------------------------------
# try_decrypt_layout against synthetic AES-GCM ciphertexts
# ---------------------------------------------------------------------------


def _make_record(layout: str, key: bytes, plaintext: bytes, idx: int) -> bytes:
    aesgcm = AESGCM(key)
    if layout == "L1":
        nonce = bytes(range(12))
        out = aesgcm.encrypt(nonce, plaintext, None)
        body, tag = out[:-16], out[-16:]
        return nonce + body + tag
    if layout == "L2":
        nonce = bytes(range(12))
        out = aesgcm.encrypt(nonce, plaintext, None)
        body, tag = out[:-16], out[-16:]
        return nonce + tag + body
    if layout == "L3":
        nonce = bytes(range(12))
        out = aesgcm.encrypt(nonce, plaintext, None)
        body, tag = out[:-16], out[-16:]
        return tag + nonce + body
    if layout == "L4":  # implicit nonce: be12 strategy
        nonce = idx.to_bytes(12, "big")
        out = aesgcm.encrypt(nonce, plaintext, None)
        return out  # body || tag
    if layout == "L5":
        nonce = bytes(range(16))
        out = aesgcm.encrypt(nonce, plaintext, None)
        body, tag = out[:-16], out[-16:]
        return nonce + body + tag
    if layout == "L6":
        nonce = bytes(range(12))
        out = aesgcm.encrypt(nonce, plaintext, None)
        body, tag = out[:-16], out[-16:]
        length_prefix = len(body).to_bytes(4, "big")
        # Pad to a fixed 256-byte record so the layout matches the assessment.
        rec = length_prefix + nonce + body + tag
        rec = rec + b"\x00" * (256 - len(rec))
        return rec
    raise ValueError(layout)


@pytest.mark.parametrize("layout", ["L1", "L2", "L3", "L5", "L6"])
def test_try_decrypt_layout_explicit_nonce(layout: str) -> None:
    key = b"k" * 32
    plaintext = b"hello world, this is a longer test plaintext for AES-GCM"
    rec = _make_record(layout, key, plaintext, 0)
    out = try_decrypt_layout(key, rec, layout, record_index=0)
    assert out == plaintext


def test_try_decrypt_layout_implicit_nonce_be12() -> None:
    key = b"k" * 32
    plaintext = b"record-bound payload"
    rec = _make_record("L4", key, plaintext, idx=42)
    out = try_decrypt_layout(
        key, rec, "L4", record_index=42, nonce_strategy="be12"
    )
    assert out == plaintext


def test_try_decrypt_layout_returns_none_on_invalid_tag() -> None:
    key = b"k" * 32
    plaintext = b"hello"
    rec = _make_record("L1", key, plaintext, 0)
    # Flip a byte in the body to break the tag.
    bad = bytearray(rec)
    bad[20] ^= 0xFF
    out = try_decrypt_layout(key, bytes(bad), "L1", record_index=0)
    assert out is None


def test_try_decrypt_layout_wrong_key_returns_none() -> None:
    key = b"k" * 32
    other = b"x" * 32
    rec = _make_record("L1", key, b"hello", 0)
    assert try_decrypt_layout(other, rec, "L1", record_index=0) is None


# ---------------------------------------------------------------------------
# search_for_decryption end-to-end against a synthetic dataset
# ---------------------------------------------------------------------------


def test_search_finds_synthetic_l1_dataset(monkeypatch: pytest.MonkeyPatch) -> None:
    # Build a dataset where every record encrypts under a key derived from
    # a small fake "API key" with HKDF over (utf8 IKM, empty salt, "dataset" info).
    api_key = b"test-api-key-do-not-use"
    key = derive_key_hkdf(api_key, salt=b"", info=b"dataset", length=32)
    # Pad to 256 bytes: nonce(12) + body(228) + tag(16) -> plaintext len 228.
    plaintexts_in = [bytes([i & 0xFF] * 228) for i in range(4)]
    cts = [_make_record("L1", key, p, i) for i, p in enumerate(plaintexts_in)]

    # Restrict the search to make the test fast and deterministic.
    from assessment import layer2

    monkeypatch.setattr(
        layer2, "_ikm_candidates", lambda ak: [("utf8", ak)]
    )
    monkeypatch.setattr(layer2, "SALT_CANDIDATES", [("empty", b"")])
    monkeypatch.setattr(layer2, "INFO_CANDIDATES", [("dataset", b"dataset")])
    monkeypatch.setattr(layer2, "LENGTHS", [32])
    monkeypatch.setattr(layer2, "EXPLICIT_LAYOUTS", ["L1"])
    monkeypatch.setattr(layer2, "NONCE_STRATEGIES", [])
    monkeypatch.setattr(layer2, "AAD_CANDIDATES", [("none", None)])

    result = search_for_decryption(cts, api_key)
    assert result is not None
    cfg, plaintexts_out = result
    assert cfg["layout"] == "L1"
    assert cfg["ikm_label"] == "utf8"
    assert plaintexts_out == plaintexts_in

    # decrypt_records should reproduce the same plaintexts under the cfg.
    pts2 = decrypt_records(cts, cfg, key)
    assert pts2 == plaintexts_in


def test_search_returns_none_on_miss(monkeypatch: pytest.MonkeyPatch) -> None:
    api_key = b"test-api-key"
    cts = [os.urandom(256) for _ in range(2)]

    from assessment import layer2

    monkeypatch.setattr(layer2, "_ikm_candidates", lambda ak: [("utf8", ak)])
    monkeypatch.setattr(layer2, "SALT_CANDIDATES", [("empty", b"")])
    monkeypatch.setattr(layer2, "INFO_CANDIDATES", [("dataset", b"dataset")])
    monkeypatch.setattr(layer2, "LENGTHS", [32])
    monkeypatch.setattr(layer2, "EXPLICIT_LAYOUTS", ["L1"])
    monkeypatch.setattr(layer2, "NONCE_STRATEGIES", [])
    monkeypatch.setattr(layer2, "AAD_CANDIDATES", [("none", None)])

    assert search_for_decryption(cts, api_key) is None


# ---------------------------------------------------------------------------
# Hash candidates
# ---------------------------------------------------------------------------


def test_compute_hash_candidates_known_vectors() -> None:
    plaintexts = [b"alpha", b"beta", b"gamma"]
    cands = compute_hash_candidates(plaintexts)

    expected_d1 = hashlib.sha256(b"alphabetagamma").hexdigest()
    expected_d2 = hashlib.sha256("alphabetagamma".encode("utf-8")).hexdigest()
    expected_d3 = hashlib.sha256(
        json.dumps(["alpha", "beta", "gamma"], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    expected_d4 = hashlib.sha256(b"alpha\nbeta\ngamma").hexdigest()

    assert cands["D1"] == expected_d1
    assert cands["D2"] == expected_d2
    assert cands["D3"] == expected_d3
    assert cands["D4"] == expected_d4


def test_compute_hash_candidates_non_utf8_marks_d2_d3_na() -> None:
    plaintexts = [b"\xff\xfe\xfd", b"valid"]
    cands = compute_hash_candidates(plaintexts)
    assert cands["D1"] == hashlib.sha256(b"\xff\xfe\xfdvalid").hexdigest()
    assert cands["D2"] == "N/A"
    assert cands["D3"] == "N/A"
    assert cands["D4"] == hashlib.sha256(b"\xff\xfe\xfd\nvalid").hexdigest()


# ---------------------------------------------------------------------------
# v3 extended-sweep helpers
# ---------------------------------------------------------------------------


def test_strip_etag_removes_weak_prefix_and_quotes() -> None:
    raw = 'W/"bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf"'
    out = _strip_etag(raw)
    assert out == "bf08cec00442d0e42e4dd6bca29e68649ec1d75f19c72bfeb64a73dc585b47cf"


def test_strip_etag_handles_bare_hex() -> None:
    raw = "abc123"
    assert _strip_etag(raw) == "abc123"


def _write_batch_log_with_etag(
    path: Path, start: int, end: int, etag_hex: str
) -> None:
    body = {
        "data": [_fake_record_ct(i) for i in range(start, end + 1)],
        "count": end - start + 1,
    }
    log = {
        "method": "GET",
        "url": "https://example/api/v1/dataset",
        "request_headers": {},
        "request_body": None,
        "request_params": {"batch": "true", "range": f"{start}-{end}"},
        "response_status": 200,
        "response_headers": {"etag": f'W/"{etag_hex}"'},
        "response_body": body,
    }
    with path.open("w") as fh:
        json.dump(log, fh)


def test_collect_etags_from_logs_maps_ranges_to_etags(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    cases = [
        ("0-99", "a" * 64),
        ("100-199", "b" * 64),
        ("200-299", "c" * 64),
    ]
    for i, (rng, etag_hex) in enumerate(cases):
        s, e = (int(p) for p in rng.split("-"))
        _write_batch_log_with_etag(
            logs_dir / f"2026{i:02d}-GET-api-v1-dataset.json",
            s,
            e,
            etag_hex,
        )
    out = _collect_etags_from_logs(logs_dir)
    assert out == {rng: etag_hex for rng, etag_hex in cases}


def test_collect_etags_dedups_by_newest_filename(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _write_batch_log_with_etag(
        logs_dir / "20260101-GET-api-v1-dataset.json",
        0,
        99,
        "a" * 64,
    )
    _write_batch_log_with_etag(
        logs_dir / "20260201-GET-api-v1-dataset.json",
        0,
        99,
        "b" * 64,
    )
    out = _collect_etags_from_logs(logs_dir)
    assert out == {"0-99": "b" * 64}


def test_record_to_batch_range_maps_correctly() -> None:
    ranges = ["0-99", "100-199", "200-299", "300-399", "400-499"]
    assert _record_to_batch_range(0, ranges) == "0-99"
    assert _record_to_batch_range(99, ranges) == "0-99"
    assert _record_to_batch_range(100, ranges) == "100-199"
    assert _record_to_batch_range(499, ranges) == "400-499"
    assert _record_to_batch_range(500, ranges) is None


def test_resolve_info_for_record_idx2_be() -> None:
    assert _resolve_info_for_record("per_record_idx2_be", 0) == b"\x00\x00"
    assert _resolve_info_for_record("per_record_idx2_be", 257) == b"\x01\x01"


def test_resolve_info_for_record_idx_string() -> None:
    assert _resolve_info_for_record("per_record_idx_string", 0) == b"record-0"
    assert _resolve_info_for_record("per_record_idx_string", 499) == b"record-499"


def test_resolve_info_for_record_passes_bytes_through() -> None:
    assert _resolve_info_for_record(b"raw-bytes", 7) == b"raw-bytes"


def test_direct_key_candidates_includes_etag_bytes_only_32_bytes() -> None:
    api_key = b"sa_" + ("a" * 64).encode()
    etags = {
        "0-99": "ab" * 32,  # 64 hex chars -> 32 bytes
        "100-199": "cd" * 32,
    }
    cands = _direct_key_candidates(api_key, etags)
    labels = {label for label, _ in cands}
    # Every key must be exactly 32 bytes
    assert all(len(val) == 32 for _, val in cands)
    # Etag-paginated and per-batch entries must be present
    assert "direct_etag_paginated_bytes" in labels
    assert "direct_etag_0_99_bytes" in labels
    assert "direct_etag_100_199_bytes" in labels
    # API key trunc-pad path
    assert "direct_api_key_trunc_pad_32" in labels
    # after_sa_ hex 32 path
    assert "direct_after_sa__hex_32" in labels


def test_v3_salt_extensions_includes_etag_and_started_at() -> None:
    etags = {"0-99": "a" * 64, "100-199": "b" * 64}
    out = _v3_salt_extensions(etags)
    labels = {label for label, _ in out}
    assert "etag_paginated_bytes" in labels
    assert "etag_paginated_hex_utf8" in labels
    assert "etag_0_99_bytes" in labels
    assert "etag_0_99_hex_utf8" in labels
    assert "started_at_iso" in labels


def test_chacha20_poly1305_l1_roundtrip() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    key = b"k" * 32
    nonce = bytes(range(12))
    plaintext = b"hello chacha world, AEAD payload"
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    rec = nonce + ct  # ChaCha20-Poly1305 emits body || tag, prepend nonce -> L1
    out = try_decrypt_chacha20poly1305(key, rec, "L1", record_index=0)
    assert out == plaintext


def test_chacha20_poly1305_l4_implicit_nonce_be12() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    key = b"k" * 32
    idx = 42
    nonce = idx.to_bytes(12, "big")
    plaintext = b"record-bound chacha payload"
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    out = try_decrypt_chacha20poly1305(
        key, ct, "L4", record_index=idx, nonce_strategy="be12"
    )
    assert out == plaintext


def test_chacha20_poly1305_returns_none_on_wrong_key_length() -> None:
    short = b"k" * 16
    rec = bytes(range(64))
    assert try_decrypt_chacha20poly1305(short, rec, "L1", record_index=0) is None


def test_chacha20_poly1305_returns_none_on_invalid_tag() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    key = b"k" * 32
    nonce = bytes(range(12))
    ct = ChaCha20Poly1305(key).encrypt(nonce, b"hello", None)
    rec = nonce + ct
    bad = bytearray(rec)
    bad[20] ^= 0xFF
    assert (
        try_decrypt_chacha20poly1305(key, bytes(bad), "L1", record_index=0)
        is None
    )


def test_search_for_decryption_v3_finds_direct_etag_key_synthetic() -> None:
    """Synthetic dataset where all records use a 32-byte ETag as the direct
    AES-GCM key. v3 direct-key sub-search must find it."""
    etag_hex = "ab" * 32  # 32 bytes
    key = bytes.fromhex(etag_hex)
    # 5 records under L1, AES-GCM, no AAD
    plaintexts = [bytes([i & 0xFF] * 228) for i in range(5)]
    cts = [_make_record("L1", key, p, i) for i, p in enumerate(plaintexts)]
    # Place the matching ETag at a per-batch range
    etags = {"0-99": etag_hex}
    api_key = b"unrelated-api-key-that-does-not-derive-the-real-key"
    result = search_for_decryption_v3(cts, api_key, etags, max_attempts=10_000)
    assert result is not None
    cfg, pts = result
    assert cfg["mode"] == "direct_key"
    assert cfg["cipher"] == "aes-gcm"
    assert cfg["layout"] == "L1"
    assert pts == plaintexts


def test_search_for_decryption_v3_returns_none_on_miss() -> None:
    """Random ciphertexts must not produce a v3 hit."""
    cts = [os.urandom(256) for _ in range(2)]
    api_key = b"some-api-key"
    etags = {"0-99": "a" * 64}
    # Cap attempts low to keep test fast; coverage of all sub-searches is in
    # search_for_decryption_v3_finds_direct_etag_key_synthetic.
    assert search_for_decryption_v3(cts, api_key, etags, max_attempts=200) is None


# ---------------------------------------------------------------------------
# v4 AES-CTR + HMAC-SHA256 sweep tests
# ---------------------------------------------------------------------------


def test_aes_ctr_roundtrip_golden_nist() -> None:
    """NIST SP 800-38A AES-128-CTR vector F.5.1 round-trip via _aes_ctr_decrypt."""
    # Key from test vector F.5.1 (AES-128 CTR).
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    # Initial counter block.
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    )
    expected_ct = bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
    )
    # Encrypt by feeding plaintext through CTR (CTR is symmetric).
    out = _aes_ctr_decrypt(key, iv, plaintext)
    assert out == expected_ct
    # Decrypt back.
    assert _aes_ctr_decrypt(key, iv, expected_ct) == plaintext


def test_hmac_sha256_truncation_golden() -> None:
    """RFC 4231 test case 1: HMAC-SHA256 with 20-byte key 0x0b*20 over 'Hi There'."""
    key = b"\x0b" * 20
    data = b"Hi There"
    full = bytes.fromhex(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    )
    assert _hmac_sha256(key, data, 32) == full
    assert _hmac_sha256(key, data, 16) == full[:16]
    assert _hmac_sha256(key, data, 8) == full[:8]


def test_split_keypair_basic() -> None:
    material = bytes(range(64))
    enc, mac = _split_keypair(material)
    assert enc == bytes(range(32))
    assert mac == bytes(range(32, 64))
    assert len(enc) == 32
    assert len(mac) == 32


def test_ctr_iv_for_layout_pads_short_iv() -> None:
    iv12 = b"\xaa" * 12
    iv8 = b"\xbb" * 8
    iv16 = b"\xcc" * 16
    assert _ctr_iv_for_layout(iv12, "LE3") == iv12 + b"\x00" * 4
    assert _ctr_iv_for_layout(iv8, "LE4") == iv8 + b"\x00" * 8
    assert _ctr_iv_for_layout(iv16, "LE1") == iv16


def test_aes_ctr_hmac_decrypt_synthetic_le1_m1_recovers_plaintext() -> None:
    """End-to-end synthetic record under LE1 + M1 must round-trip."""
    enc_key = bytes(range(32))
    mac_key = bytes(range(32, 64))
    iv = b"\x11" * 16
    plaintext = b"meridian-se-assessment-record-payload-" + b"\x00" * (
        224 - len("meridian-se-assessment-record-payload-")
    )
    assert len(plaintext) == 224
    # Encrypt with AES-CTR.
    ct = _aes_ctr_decrypt(enc_key, iv, plaintext)
    # MAC = HMAC(mac_key, iv || ct)[:16]
    mac = _hmac_sha256(mac_key, iv + ct, 16)
    record = iv + ct + mac
    assert len(record) == 256
    recovered = _aes_ctr_hmac_decrypt(
        enc_key, mac_key, record, "LE1", record_index=0, mac_scope_label="M1"
    )
    assert recovered == plaintext


def test_aes_ctr_hmac_decrypt_synthetic_le3_m3_with_index_binding() -> None:
    """LE3 layout (12-byte IV, 16-byte truncated MAC) with positional binding."""
    enc_key = bytes(range(32))
    mac_key = bytes(range(64, 96))
    iv12 = b"\x22" * 12
    iv16 = iv12 + b"\x00" * 4
    plaintext = b"X" * 228
    ct = _aes_ctr_decrypt(enc_key, iv16, plaintext)
    record_index = 7
    mac = _hmac_sha256(
        mac_key, iv12 + ct + record_index.to_bytes(4, "big"), 16
    )
    record = iv12 + ct + mac
    assert len(record) == 256
    recovered = _aes_ctr_hmac_decrypt(
        enc_key,
        mac_key,
        record,
        "LE3",
        record_index=record_index,
        mac_scope_label="M3",
    )
    assert recovered == plaintext
    # Wrong index must fail.
    assert (
        _aes_ctr_hmac_decrypt(
            enc_key, mac_key, record, "LE3", 8, "M3"
        )
        is None
    )


def test_aes_ctr_hmac_decrypt_rejects_tampered_mac() -> None:
    """A flipped MAC byte must cause rejection (None)."""
    enc_key = bytes(range(32))
    mac_key = bytes(range(32, 64))
    iv = b"\x33" * 16
    plaintext = b"\x01" * 224
    ct = _aes_ctr_decrypt(enc_key, iv, plaintext)
    mac = _hmac_sha256(mac_key, iv + ct, 16)
    bad_mac = bytes([mac[0] ^ 0xFF]) + mac[1:]
    record = iv + ct + bad_mac
    assert (
        _aes_ctr_hmac_decrypt(enc_key, mac_key, record, "LE1", 0, "M1")
        is None
    )


def test_search_ctr_hmac_returns_none_on_random_input() -> None:
    """Random ciphertexts must not produce a v4 hit (sanity)."""
    cts = [os.urandom(256) for _ in range(2)]
    api_key = b"some-api-key"
    etags = {"0-99": "a" * 64}
    assert (
        search_ctr_hmac(cts, api_key, etags, max_attempts=200) is None
    )


def test_search_ctr_hmac_finds_synthetic_split64_le1_m1() -> None:
    """Synthetic dataset under split64 derivation + LE1 + M1 must be found."""
    # Construct 4 records under a known config that the matrix WILL try.
    api_key = b"sa_" + b"0" * 64  # plausible shape
    salt = b""  # in the matrix
    info = b"dataset"  # in pass-1 INFO_CANDIDATES
    material = derive_key_hkdf(api_key, salt=salt, info=info, length=64)
    enc_key, mac_key = _split_keypair(material)

    plaintexts = []
    cts = []
    for i in range(4):
        iv = (i.to_bytes(2, "big") + b"\x00" * 14)
        pt = (b"row-%d-" % i).ljust(224, b".")
        ct_body = _aes_ctr_decrypt(enc_key, iv, pt)
        mac = _hmac_sha256(mac_key, iv + ct_body, 16)
        record = iv + ct_body + mac
        assert len(record) == 256
        plaintexts.append(pt)
        cts.append(record)

    # Pad ciphertexts list to length 500 with valid-LE1 records under same key
    # so the full-validation pass succeeds.
    for i in range(4, 500):
        iv = i.to_bytes(2, "big") + b"\x00" * 14
        pt = (b"row-%d-" % i).ljust(224, b".")
        ct_body = _aes_ctr_decrypt(enc_key, iv, pt)
        mac = _hmac_sha256(mac_key, iv + ct_body, 16)
        cts.append(iv + ct_body + mac)
        plaintexts.append(pt)

    result = search_ctr_hmac(cts, api_key, {}, max_attempts=50_000)
    assert result is not None, "synthetic v4 dataset must be discovered"
    cfg, pts = result
    assert cfg["mode"] == "split64"
    assert cfg["layout"] == "LE1"
    assert cfg["mac_scope"] == "M1"
    assert pts == plaintexts
