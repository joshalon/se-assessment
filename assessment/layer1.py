"""Phase 3 Layer 1 — offline dataset reconstruction and integrity-proof candidates.

Reads per-call JSON logs written by :mod:`assessment.client`, reconstructs the
500-record dataset from the 5 batch responses, and computes candidate
integrity proofs (C1-C4). C5 is the Phase 2 paginated ETag, surfaced as a
literal for completeness.

All functions are pure: no HTTP, no env, no globals.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

RECORD_DECODED_LEN = 256
EXPECTED_BATCH_SIZE = 100
EXPECTED_TOTAL = 500
EXPECTED_RANGES = [(0, 99), (100, 199), (200, 299), (300, 399), (400, 499)]


def _parse_range(params: dict[str, Any] | None) -> tuple[int, int]:
    if not params or "range" not in params:
        raise ValueError(f"log missing batch range params: {params!r}")
    start_s, end_s = params["range"].split("-", 1)
    return int(start_s), int(end_s)


def load_batches_from_logs(logs_dir: Path) -> list[dict[str, Any]]:
    """Read all batch dataset logs from ``logs_dir`` and return them sorted by range start.

    A batch log is a dataset call whose ``request_params`` contains ``batch=true``
    and a ``range=N-M`` value. The Phase 2 paginated probe (no params) is excluded.
    """
    batches: list[dict[str, Any]] = []
    for path in sorted(logs_dir.glob("*-GET-api-v1-dataset.json")):
        with path.open() as fh:
            log = json.load(fh)
        params = log.get("request_params") or {}
        if params.get("batch") != "true" or "range" not in params:
            continue
        if log.get("response_status") != 200:
            raise ValueError(f"non-200 batch log: {path} status={log.get('response_status')}")
        start, end = _parse_range(params)
        body = log.get("response_body") or {}
        data = body.get("data")
        if not isinstance(data, list):
            raise ValueError(f"batch log {path} missing data array")
        batches.append(
            {
                "path": str(path),
                "range_start": start,
                "range_end": end,
                "etag": log.get("response_headers", {}).get("etag"),
                "data": data,
                "count": body.get("count"),
            }
        )
    batches.sort(key=lambda b: b["range_start"])

    # Validate coverage: exactly the 5 expected ranges, no overlap, no gap, no dup.
    seen = [(b["range_start"], b["range_end"]) for b in batches]
    if seen != EXPECTED_RANGES:
        raise ValueError(f"batch ranges mismatch expected={EXPECTED_RANGES} got={seen}")
    return batches


def assemble_dataset(batches: list[dict[str, Any]]) -> list[str]:
    """Concatenate ``data`` arrays in positional order. Returns 500 base64 strings."""
    records: list[str] = []
    for b in batches:
        records.extend(b["data"])
    if len(records) != EXPECTED_TOTAL:
        raise ValueError(f"assembled length {len(records)} != {EXPECTED_TOTAL}")
    return records


def decode_records(records: list[str]) -> list[bytes]:
    """Base64-decode each record. Raises if any decoded length is not 256 bytes."""
    decoded: list[bytes] = []
    for i, s in enumerate(records):
        raw = base64.b64decode(s, validate=True)
        if len(raw) != RECORD_DECODED_LEN:
            raise ValueError(
                f"record {i} decoded length {len(raw)} != {RECORD_DECODED_LEN}"
            )
        decoded.append(raw)
    return decoded


def compute_c1(decoded: list[bytes]) -> str:
    """sha256 hex of concatenated raw decoded bytes (positional order)."""
    h = hashlib.sha256()
    for r in decoded:
        h.update(r)
    return h.hexdigest()


def compute_c2(records: list[str]) -> str:
    """sha256 hex of concatenated base64 strings (no separators)."""
    return hashlib.sha256("".join(records).encode()).hexdigest()


def compute_c3(records: list[str]) -> str:
    """sha256 hex of canonical (whitespace-free) JSON array of base64 strings."""
    return hashlib.sha256(
        json.dumps(records, separators=(",", ":")).encode()
    ).hexdigest()


def compute_c4(records: list[str]) -> str:
    """sha256 hex of canonical envelope: {data, has_more, page, page_size, total} sorted."""
    envelope = {
        "data": records,
        "has_more": False,
        "page": 1,
        "page_size": EXPECTED_TOTAL,
        "total": EXPECTED_TOTAL,
    }
    blob = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def main() -> None:
    logs_dir = Path("logs")
    batches = load_batches_from_logs(logs_dir)
    records = assemble_dataset(batches)
    decoded = decode_records(records)
    print(f"batches: {len(batches)}")
    print(f"records: {len(records)}")
    print(f"unique records: {len(set(records))}")
    print(f"C1: {compute_c1(decoded)}")
    print(f"C2: {compute_c2(records)}")
    print(f"C3: {compute_c3(records)}")
    print(f"C4: {compute_c4(records)}")


if __name__ == "__main__":
    main()
