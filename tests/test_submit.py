"""Unit tests for :mod:`assessment.submit`.

These tests import the CLI's ``main`` directly and call it with explicit
``argv`` lists. The HTTP layer (``assessment.client.make_request``) is
monkeypatched so no real network call is ever issued.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from assessment import submit as submit_mod


@pytest.fixture(autouse=True)
def _chdir_tmp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect cwd to ``tmp_path`` so ``audit/`` lookups happen there."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _write_audit(tmp_path: Path, layer_type: str, attempt: int, verdict: str) -> Path:
    """Create a fake audit-report file with the given verdict line."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(exist_ok=True)
    path = audit_dir / f"audit-report-{layer_type}-attempt-{attempt}.md"
    path.write_text(
        "# Audit\n\nSome text.\n\nOverall Verdict: " + verdict + "\n",
        encoding="utf-8",
    )
    return path


class _FakeResponse:
    """Minimal stand-in for :class:`httpx.Response`."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def _patch_http(monkeypatch: pytest.MonkeyPatch, status_code: int = 200) -> dict:
    """Patch ``client.make_request`` to record calls instead of making them."""
    calls: dict[str, Any] = {"count": 0, "last_args": None, "last_kwargs": None}

    def _fake(method: str, path: str, **kwargs: Any) -> _FakeResponse:
        calls["count"] += 1
        calls["last_args"] = (method, path)
        calls["last_kwargs"] = kwargs
        return _FakeResponse(status_code)

    monkeypatch.setattr(submit_mod.client, "make_request", _fake)
    return calls


def test_requires_type_and_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """Argparse must reject invocations missing ``--type`` or ``--value``."""
    calls = _patch_http(monkeypatch)

    with pytest.raises(SystemExit) as exc_no_type:
        submit_mod.main(["--value", "v"])
    assert exc_no_type.value.code == 2

    with pytest.raises(SystemExit) as exc_no_value:
        submit_mod.main(["--type", "layer-1"])
    assert exc_no_value.value.code == 2

    assert calls["count"] == 0


def test_dry_run_does_not_call_http(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--dry-run`` must skip both signoff gating and HTTP submission."""
    calls = _patch_http(monkeypatch)

    rc = submit_mod.main(["--type", "layer-1", "--value", "answer-value", "--dry-run"])

    assert rc == 0
    assert calls["count"] == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "Pending submission" in out


def test_refuses_when_signoff_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without an audit file the CLI must exit 2 and not call HTTP."""
    calls = _patch_http(monkeypatch)

    rc = submit_mod.main(["--type", "layer-1", "--value", "answer-value"])

    assert rc == 2
    assert calls["count"] == 0
    out = capsys.readouterr().out
    assert "MISSING" in out


def test_refuses_when_signoff_fail(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A FAIL verdict must yield exit 2 and no HTTP call."""
    _write_audit(tmp_path, "layer-1", 1, "FAIL")
    calls = _patch_http(monkeypatch)

    rc = submit_mod.main(["--type", "layer-1", "--value", "answer-value"])

    assert rc == 2
    assert calls["count"] == 0
    out = capsys.readouterr().out
    assert "FAIL" in out


def test_prompts_yn_when_signoff_pass_user_answers_no(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A PASS verdict prompts; answering ``n`` aborts cleanly without HTTP."""
    _write_audit(tmp_path, "layer-1", 1, "PASS")
    calls = _patch_http(monkeypatch)

    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))

    rc = submit_mod.main(["--type", "layer-1", "--value", "answer-value"])

    assert rc == 0
    assert calls["count"] == 0
    out = capsys.readouterr().out
    assert "Aborted" in out


def test_prompts_yn_when_signoff_pass_user_answers_yes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A PASS verdict + ``y`` triggers the HTTP submission and exits 0 on 200."""
    _write_audit(tmp_path, "layer-1", 1, "PASS")
    calls = _patch_http(monkeypatch, status_code=200)

    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))

    rc = submit_mod.main(["--type", "layer-1", "--value", "answer-value", "--notes", "hi"])

    assert rc == 0
    assert calls["count"] == 1
    method, path = calls["last_args"]
    assert method == "POST"
    assert path == "/api/v1/submit"
    assert calls["last_kwargs"]["json"] == {
        "type": "layer-1",
        "value": "answer-value",
        "notes": "hi",
    }


def test_non_2xx_response_yields_exit_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A 4xx/5xx response from the API must yield exit code 1."""
    _write_audit(tmp_path, "layer-1", 1, "PASS")
    _patch_http(monkeypatch, status_code=500)

    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))

    rc = submit_mod.main(["--type", "layer-1", "--value", "v"])

    assert rc == 1


def test_picks_highest_attempt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When multiple attempts exist, the highest-numbered one wins."""
    _write_audit(tmp_path, "layer-1", 1, "FAIL")
    _write_audit(tmp_path, "layer-1", 2, "PASS")
    _patch_http(monkeypatch)

    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))

    rc = submit_mod.main(["--type", "layer-1", "--value", "v"])

    assert rc == 0  # aborted, but we got past the gate (proving PASS was used)


def test_truncates_long_value_in_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Values longer than 80 chars get truncated with a ``...`` marker."""
    _patch_http(monkeypatch)
    long_value = "x" * 200

    rc = submit_mod.main(["--type", "layer-1", "--value", long_value, "--dry-run"])

    assert rc == 0
    out = capsys.readouterr().out
    # Truncated value: 80 x's + ...
    assert ("x" * 80) + "..." in out
    assert ("x" * 200) not in out


def test_audit_file_without_verdict_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An audit file with no ``Overall Verdict`` line is treated as MISSING."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit-report-layer-1-attempt-1.md").write_text(
        "# audit\nno verdict here\n", encoding="utf-8"
    )
    calls = _patch_http(monkeypatch)

    rc = submit_mod.main(["--type", "layer-1", "--value", "v"])

    assert rc == 2
    assert calls["count"] == 0


def test_main_entrypoint_dispatches() -> None:
    """The module-level ``main`` is callable and respects argv."""
    rc = submit_mod.main(["--type", "layer-1", "--value", "v", "--dry-run"])
    assert rc == 0
