"""Offline tests for assessment.layer1. No HTTP, no real-log dependencies."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from assessment.layer1 import (
    assemble_dataset,
    compute_c1,
    compute_c3,
    compute_c4,
    decode_records,
)


def _fake_record(seed: int) -> str:
    """256 deterministic bytes derived from a single integer seed."""
    raw = bytes((seed + i) % 256 for i in range(256))
    return base64.b64encode(raw).decode()


def _fake_batches(records_per_batch: int = 100) -> list[dict]:
    batches = []
    counter = 0
    for start in (0, 100, 200, 300, 400):
        end = start + records_per_batch - 1
        data = [_fake_record(counter + i) for i in range(records_per_batch)]
        counter += records_per_batch
        batches.append(
            {
                "range_start": start,
                "range_end": end,
                "etag": f"W/\"fake-{start}\"",
                "data": data,
                "count": records_per_batch,
            }
        )
    return batches


def test_assemble_dataset_returns_500_in_order():
    batches = _fake_batches()
    records = assemble_dataset(batches)
    assert len(records) == 500
    assert records[0] == _fake_record(0)
    assert records[100] == _fake_record(100)
    assert records[499] == _fake_record(499)


def test_assemble_dataset_rejects_wrong_total():
    short = _fake_batches(records_per_batch=99)
    with pytest.raises(ValueError):
        assemble_dataset(short)


def test_decode_records_rejects_wrong_length():
    bad = base64.b64encode(b"\x00" * 128).decode()
    with pytest.raises(ValueError):
        decode_records([bad])


def test_decode_records_accepts_correct_length():
    good = _fake_record(0)
    decoded = decode_records([good])
    assert len(decoded) == 1
    assert len(decoded[0]) == 256


def test_compute_c1_deterministic():
    decoded = [bytes(256), bytes((1,) * 256)]
    assert compute_c1(decoded) == compute_c1(decoded)
    expected = hashlib.sha256(bytes(256) + bytes((1,) * 256)).hexdigest()
    assert compute_c1(decoded) == expected


def test_compute_c3_has_no_whitespace():
    records = [_fake_record(i) for i in range(3)]
    blob = json.dumps(records, separators=(",", ":"))
    assert " " not in blob
    assert "\n" not in blob
    assert compute_c3(records) == hashlib.sha256(blob.encode()).hexdigest()


def test_compute_c4_invariant_to_dict_construction_order():
    records = [_fake_record(i) for i in range(500)]
    expected_envelope = {
        "total": 500,
        "page_size": 500,
        "page": 1,
        "has_more": False,
        "data": records,
    }
    expected = hashlib.sha256(
        json.dumps(expected_envelope, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    assert compute_c4(records) == expected
