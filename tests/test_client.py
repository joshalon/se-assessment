"""Unit tests for :mod:`assessment.client`.

All HTTP interactions are mocked via :class:`httpx.MockTransport`. No live
network requests are issued. Environment variables are manipulated through
``monkeypatch``; the working directory is redirected via ``monkeypatch.chdir``
to a ``tmp_path`` so the ``logs/`` directory is created in the test sandbox.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable

import httpx
import pytest

from assessment import client as client_mod

FIXTURES = Path(__file__).parent / "fixtures"


def _install_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> dict:
    """Patch ``httpx.Client`` so requests go through :class:`httpx.MockTransport`.

    Returns a ``dict`` whose ``"request"`` key gets populated with the captured
    :class:`httpx.Request` once the handler runs.
    """
    captured: dict = {}

    def _capturing_handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return handler(request)

    transport = httpx.MockTransport(_capturing_handler)
    real_client_cls = httpx.Client

    def _client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(client_mod.httpx, "Client", _client_factory)
    return captured


def _ok_handler(body: dict, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    """Return a handler that responds with ``body`` as JSON and ``status``."""

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=status,
            json=body,
            headers={"content-type": "application/json", "x-test": "yes"},
        )

    return _handler


@pytest.fixture(autouse=True)
def _chdir_tmp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect cwd to tmp_path so ``logs/`` is created there during tests."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_adds_auth_header_when_api_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """When ``API_KEY`` is set, the client must add a Bearer auth header."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.setenv("API_KEY", "fake_test_key_12345")

    captured = _install_mock_transport(monkeypatch, _ok_handler({"ok": True}))

    response = client_mod.make_request("GET", "/api/v1/health")

    assert response.status_code == 200
    request = captured["request"]
    assert request.headers.get("authorization") == "Bearer fake_test_key_12345"


def test_omits_auth_header_when_api_key_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """When ``API_KEY`` is unset, the request must not carry an auth header."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    captured = _install_mock_transport(monkeypatch, _ok_handler({"ok": True}))

    response = client_mod.make_request("GET", "/api/v1/health")

    assert response.status_code == 200
    request = captured["request"]
    assert "authorization" not in {k.lower() for k in request.headers.keys()}


def test_redacts_api_key_in_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The literal API key value must never appear in stdout."""
    canary = "redaction_canary_VALUE_xyz123"
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.setenv("API_KEY", canary)

    _install_mock_transport(monkeypatch, _ok_handler({"ok": True}))

    client_mod.make_request("GET", "/api/v1/health")

    out = capsys.readouterr().out
    assert canary not in out
    assert "***REDACTED***" in out


def test_redacts_api_key_in_log_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The literal API key value must never appear in any log file."""
    canary = "redaction_canary_VALUE_xyz123"
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.setenv("API_KEY", canary)

    _install_mock_transport(monkeypatch, _ok_handler({"ok": True}))

    client_mod.make_request("GET", "/api/v1/health")

    logs_dir = tmp_path / "logs"
    files = sorted(logs_dir.iterdir(), key=lambda p: p.stat().st_mtime)
    assert files, "expected at least one log file"
    content = files[-1].read_text(encoding="utf-8")
    assert canary not in content
    assert "***REDACTED***" in content


def test_logs_full_request_and_response_to_json_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The JSON log file must contain the full request and response record."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.setenv("API_KEY", "fake_test_key_12345")

    fixture_body = json.loads((FIXTURES / "response_200.json").read_text(encoding="utf-8"))
    _install_mock_transport(monkeypatch, _ok_handler(fixture_body))

    client_mod.make_request(
        "POST",
        "/api/v1/dataset/abc",
        json={"hello": "world"},
        params={"q": "1"},
    )

    logs_dir = tmp_path / "logs"
    files = sorted(logs_dir.iterdir(), key=lambda p: p.stat().st_mtime)
    assert files
    record = json.loads(files[-1].read_text(encoding="utf-8"))

    assert record["method"] == "POST"
    assert record["url"].endswith("/api/v1/dataset/abc")
    assert record["request_headers"]["Authorization"] == "Bearer ***REDACTED***"
    assert record["request_body"] == {"hello": "world"}
    assert record["response_status"] == 200
    assert "content-type" in {k.lower() for k in record["response_headers"].keys()}
    assert record["response_body"] == fixture_body

    # Filename slug for /api/v1/dataset/abc
    assert "api-v1-dataset-abc" in files[-1].name
    assert "POST" in files[-1].name


def test_handles_200_json_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 fixture response is returned and JSON-parsed correctly."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    fixture_body = json.loads((FIXTURES / "response_200.json").read_text(encoding="utf-8"))
    _install_mock_transport(monkeypatch, _ok_handler(fixture_body))

    response = client_mod.make_request("GET", "/api/v1/health")

    assert response.status_code == 200
    assert response.json() == fixture_body


def test_handles_401_json_error_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401 envelope is returned (not raised) and parses to the expected JSON."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    fixture_body = json.loads((FIXTURES / "response_401.json").read_text(encoding="utf-8"))
    _install_mock_transport(monkeypatch, _ok_handler(fixture_body, status=401))

    response = client_mod.make_request("GET", "/api/v1/submit")

    assert response.status_code == 401
    assert response.json() == fixture_body


def test_request_error_is_raised_and_logged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Transport-level errors propagate but still produce a JSON log file."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    def _raising(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated transport failure")

    _install_mock_transport(monkeypatch, _raising)

    with pytest.raises(httpx.RequestError):
        client_mod.make_request("GET", "/api/v1/health")

    logs_dir = tmp_path / "logs"
    files = list(logs_dir.iterdir())
    assert files, "expected an error log file"
    record = json.loads(files[-1].read_text(encoding="utf-8"))
    assert record["error"] == "simulated transport failure"


def test_non_json_response_is_truncated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Non-JSON response bodies above the truncation threshold get a marker."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    big_text = "x" * 600

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            text=big_text,
            headers={"content-type": "text/plain"},
        )

    _install_mock_transport(monkeypatch, _handler)

    client_mod.make_request("GET", "/api/v1/health")

    logs_dir = tmp_path / "logs"
    record = json.loads(sorted(logs_dir.iterdir())[-1].read_text(encoding="utf-8"))
    assert record["response_body"].endswith("...(truncated)")


def test_slugify_root_path() -> None:
    """The path slugifier returns ``root`` for the bare ``/`` path."""
    assert client_mod._slugify_path("/") == "root"


def test_summarize_invalid_json_falls_back_to_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When content-type claims JSON but body isn't, fall back to truncated text."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            text="not really json",
            headers={"content-type": "application/json"},
        )

    _install_mock_transport(monkeypatch, _handler)

    response = client_mod.make_request("GET", "/api/v1/health")
    assert response.status_code == 200

    logs_dir = tmp_path / "logs"
    record = json.loads(sorted(logs_dir.iterdir())[-1].read_text(encoding="utf-8"))
    assert record["response_body"] == "not really json"


def test_empty_body_logged_as_empty_string(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Empty-text non-JSON responses are logged as an empty string."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=204,
            text="",
            headers={"content-type": "text/plain"},
        )

    _install_mock_transport(monkeypatch, _handler)

    client_mod.make_request("DELETE", "/api/v1/thing")

    logs_dir = tmp_path / "logs"
    record = json.loads(sorted(logs_dir.iterdir())[-1].read_text(encoding="utf-8"))
    assert record["response_body"] == ""


def test_empty_api_key_omits_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty-string ``API_KEY`` is treated the same as unset (no auth header)."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.setenv("API_KEY", "")

    captured = _install_mock_transport(monkeypatch, _ok_handler({"ok": True}))

    client_mod.make_request("GET", "/api/v1/health")

    request = captured["request"]
    assert "authorization" not in {k.lower() for k in request.headers.keys()}


def test_logs_directory_is_created(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The ``logs/`` directory must be created on demand."""
    monkeypatch.setenv("BASE_URL", "https://example.invalid")
    monkeypatch.delenv("API_KEY", raising=False)

    assert not (tmp_path / "logs").exists()

    _install_mock_transport(monkeypatch, _ok_handler({"ok": True}))
    client_mod.make_request("GET", "/api/v1/health")

    assert (tmp_path / "logs").is_dir()
    assert os.listdir(tmp_path / "logs"), "expected a log file in logs/"
