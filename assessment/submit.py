"""Submission CLI for the Meridian SE Assessment.

Usage::

    python -m assessment.submit --type <layer-type> --value <value> \\
        [--notes "..."] [--dry-run]

The CLI looks up the highest-numbered audit report for the given
``--type`` under ``audit/`` and refuses to submit unless that report's
``Overall Verdict`` line is ``PASS``. Dry-run mode skips submission and
audit-gating entirely.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Optional

from assessment import client

AUDIT_DIR = "audit"
SIGNOFF_PASS = "PASS"
SIGNOFF_FAIL = "FAIL"
SIGNOFF_MISSING = "MISSING"

_VERDICT_RE = re.compile(r"^\s*Overall Verdict:\s*(PASS|FAIL)\s*$", re.MULTILINE)
_AUDIT_FILENAME_RE = re.compile(r"^audit-report-(?P<type>.+)-attempt-(?P<n>\d+)\.md$")


def _truncate_value(value: str, limit: int = 80) -> str:
    """Truncate ``value`` for display: full when short, ``...``-suffixed when long."""
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def _find_latest_audit(layer_type: str, audit_dir: str = AUDIT_DIR) -> Optional[str]:
    """Return the path to the highest-numbered audit file for ``layer_type``.

    Returns ``None`` if the directory is missing or no matching file exists.
    """
    if not os.path.isdir(audit_dir):
        return None
    best_n = -1
    best_path: Optional[str] = None
    for name in os.listdir(audit_dir):
        match = _AUDIT_FILENAME_RE.match(name)
        if not match:
            continue
        if match.group("type") != layer_type:
            continue
        try:
            n = int(match.group("n"))
        except ValueError:
            continue
        if n > best_n:
            best_n = n
            best_path = os.path.join(audit_dir, name)
    return best_path


def _read_signoff(path: Optional[str]) -> str:
    """Determine the signoff state for an audit file path.

    Returns one of ``SIGNOFF_PASS``, ``SIGNOFF_FAIL``, ``SIGNOFF_MISSING``.
    """
    if path is None or not os.path.isfile(path):
        return SIGNOFF_MISSING
    try:
        with open(path, encoding="utf-8") as fp:
            content = fp.read()
    except OSError:
        return SIGNOFF_MISSING
    match = _VERDICT_RE.search(content)
    if match is None:
        return SIGNOFF_MISSING
    verdict = match.group(1)
    if verdict == SIGNOFF_PASS:
        return SIGNOFF_PASS
    return SIGNOFF_FAIL


def _print_pending_block(
    layer_type: str,
    value: str,
    notes: Optional[str],
    signoff: str,
    signoff_path: Optional[str],
) -> None:
    """Print the pending-submission summary to stdout."""
    sys.stdout.write("Pending submission:\n")
    sys.stdout.write(f"  type: {layer_type}\n")
    sys.stdout.write(f"  value: {_truncate_value(value)}\n")
    sys.stdout.write(f"  notes: {notes if notes is not None else ''}\n")
    sys.stdout.write(f"  audit signoff: {signoff}\n")
    sys.stdout.write(f"  signoff file: {signoff_path if signoff_path else 'none'}\n")
    sys.stdout.flush()


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser for the submission CLI."""
    parser = argparse.ArgumentParser(
        prog="assessment.submit",
        description="Submit a value for the Meridian SE Assessment after audit signoff.",
    )
    parser.add_argument("--type", dest="layer_type", required=True, help="Layer/answer type.")
    parser.add_argument("--value", dest="value", required=True, help="Value to submit.")
    parser.add_argument("--notes", dest="notes", default=None, help="Optional notes.")
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Print pending block and exit without submitting.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Run the submission CLI. Returns the intended exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    signoff_path = _find_latest_audit(args.layer_type)
    signoff = _read_signoff(signoff_path)

    _print_pending_block(args.layer_type, args.value, args.notes, signoff, signoff_path)

    if args.dry_run:
        sys.stdout.write("DRY RUN - not submitting\n")
        sys.stdout.flush()
        return 0

    if signoff == SIGNOFF_MISSING:
        sys.stdout.write("Refusing to submit: no audit signoff file found for this type.\n")
        sys.stdout.flush()
        return 2

    if signoff == SIGNOFF_FAIL:
        sys.stdout.write("Refusing to submit: audit signoff is FAIL.\n")
        sys.stdout.flush()
        return 2

    sys.stdout.write("Confirm submit? [y/N]: ")
    sys.stdout.flush()
    answer = sys.stdin.readline().strip()
    if answer not in ("y", "Y"):
        sys.stdout.write("Aborted by user.\n")
        sys.stdout.flush()
        return 0

    response = client.make_request(
        "POST",
        "/api/v1/submit",
        json={"type": args.layer_type, "value": args.value, "notes": args.notes},
    )
    sys.stdout.write(f"Response status: {response.status_code}\n")
    sys.stdout.flush()
    if 200 <= response.status_code < 300:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
