"""HTTP client for the Meridian SE Assessment API.

Provides :func:`make_request`, a thin wrapper around ``httpx`` that:

- Reads ``BASE_URL`` and ``API_KEY`` from the environment at call time.
- Adds a redacted ``Authorization`` header when an API key is configured.
- Logs every request/response pair to stdout (human-readable) and to a
  per-call JSON file under ``logs/``.
- Returns the :class:`httpx.Response` regardless of status (callers decide
  how to handle non-2xx).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import httpx

_LOGGER = logging.getLogger(__name__)

_REDACTED = "Bearer ***REDACTED***"
_LOGS_DIR = "logs"
_BODY_TRUNC_CHARS = 500


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string with second precision."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fs_safe_timestamp() -> str:
    """Return a filesystem-safe UTC timestamp (e.g. ``20260508T004500Z``)."""
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slugify_path(path: str) -> str:
    """Turn an HTTP path into a filesystem-friendly slug.

    ``/api/v1/dataset/abc`` -> ``api-v1-dataset-abc``
    """
    cleaned = path.strip("/").replace("/", "-")
    safe = "".join(ch if (ch.isalnum() or ch in ("-", "_")) else "-" for ch in cleaned)
    return safe or "root"


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a shallow copy of ``headers`` with the auth value redacted."""
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() == "authorization":
            redacted[key] = _REDACTED
        else:
            redacted[key] = value
    return redacted


def _summarize_response_body(response: httpx.Response) -> Any:
    """Return a JSON-serializable summary of the response body.

    Returns parsed JSON when possible; otherwise returns text truncated to
    ``_BODY_TRUNC_CHARS`` (with a marker), or a binary size note when the
    payload is not decodable text.
    """
    content_type = response.headers.get("content-type", "")
    if "json" in content_type.lower():
        try:
            return response.json()
        except ValueError:
            pass
    try:
        text = response.text
    except UnicodeDecodeError:
        return f"<binary, {len(response.content)} bytes>"
    if not text:
        return ""
    if len(text) > _BODY_TRUNC_CHARS:
        return text[:_BODY_TRUNC_CHARS] + "...(truncated)"
    return text


def _emit_stdout(payload: str) -> None:
    """Write a structured log line to stdout."""
    sys.stdout.write(payload)
    if not payload.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def _format_request_block(
    timestamp: str,
    method: str,
    url: str,
    headers: dict[str, str],
    body: Any,
) -> str:
    """Format the outgoing-request stdout block."""
    return (
        f"[{timestamp}] -> {method} {url}\n"
        f"  headers: {json.dumps(headers)}\n"
        f"  body: {json.dumps(body)}"
    )


def _format_response_block(
    timestamp: str,
    status_code: int,
    elapsed_ms: int,
    headers: dict[str, str],
    body: Any,
) -> str:
    """Format the incoming-response stdout block."""
    return (
        f"[{timestamp}] <- {status_code} ({elapsed_ms} ms)\n"
        f"  headers: {json.dumps(headers)}\n"
        f"  body: {json.dumps(body, default=str)}"
    )


def _write_json_log(
    method: str,
    path: str,
    record: dict[str, Any],
) -> str:
    """Write the per-call JSON log file. Returns the file path written."""
    os.makedirs(_LOGS_DIR, exist_ok=True)
    filename = f"{_fs_safe_timestamp()}-{method}-{_slugify_path(path)}.json"
    file_path = os.path.join(_LOGS_DIR, filename)
    with open(file_path, "w", encoding="utf-8") as fp:
        json.dump(record, fp, indent=2, default=str)
    return file_path


def make_request(
    method: str,
    path: str,
    *,
    json: Any = None,
    params: dict[str, Any] | None = None,
) -> httpx.Response:
    """Send an HTTP request to the assessment API and log it.

    Reads ``BASE_URL`` and ``API_KEY`` from the environment. If ``API_KEY``
    is set and non-empty, an ``Authorization: Bearer <API_KEY>`` header is
    added; the key is never logged in plaintext.

    The function logs to stdout and writes a per-call JSON file under
    ``logs/``. Non-2xx responses are returned, not raised.

    Args:
        method: HTTP method (e.g. ``"GET"``, ``"POST"``).
        path: Path component to append to ``BASE_URL`` (e.g. ``/api/v1/foo``).
        json: Optional JSON-serializable request body.
        params: Optional query-string parameters.

    Returns:
        The :class:`httpx.Response` object.

    Raises:
        httpx.RequestError: For transport-level failures (DNS, timeout, etc).
    """
    base_url = os.environ.get("BASE_URL", "")
    api_key = os.environ.get("API_KEY", "")

    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    full_url = f"{base_url.rstrip('/')}{path}" if base_url else path

    request_record: dict[str, Any] = {
        "method": method,
        "url": full_url,
        "request_headers": _redact_headers(headers),
        "request_body": json,
        "request_params": params,
    }

    request_block = _format_request_block(
        timestamp=_now_iso(),
        method=method,
        url=full_url,
        headers=_redact_headers(headers),
        body=json,
    )
    _emit_stdout(request_block)

    started = time.monotonic()
    try:
        with httpx.Client() as client:
            response = client.request(
                method=method,
                url=full_url,
                headers=headers or None,
                json=json,
                params=params,
            )
    except httpx.RequestError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        _LOGGER.warning("httpx request error: %s", exc)
        error_record = {
            **request_record,
            "error": str(exc),
            "elapsed_ms": elapsed_ms,
        }
        _write_json_log(method, path, error_record)
        raise

    elapsed_ms = int((time.monotonic() - started) * 1000)
    response_headers = dict(response.headers)
    response_body = _summarize_response_body(response)

    response_block = _format_response_block(
        timestamp=_now_iso(),
        status_code=response.status_code,
        elapsed_ms=elapsed_ms,
        headers=response_headers,
        body=response_body,
    )
    _emit_stdout(response_block)

    full_record = {
        **request_record,
        "response_status": response.status_code,
        "response_headers": response_headers,
        "response_body": response_body,
        "elapsed_ms": elapsed_ms,
    }
    _write_json_log(method, path, full_record)

    return response
