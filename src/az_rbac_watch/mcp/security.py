"""Security foundation for CloudSight MCP server.

Every tool input passes through this module BEFORE any business logic.
Follows OWASP MCP Server Security Guide; addresses CVE-2025-53109/53110
(path traversal) and CVE-2025-68145 (path validation bypass).
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

_RE_SUBSCRIPTION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_RE_ACTION = re.compile(r"^[a-zA-Z]+(\.[a-zA-Z]+)+(\/[a-zA-Z*]+)*$")
_RE_SCOPE = re.compile(r"^\/[a-zA-Z0-9\-_\/\.]+$")

_CREDENTIAL_MARKERS = ("Bearer ", "SharedKey ", "sig=", "client_secret=")
_PATH_KEYS_TO_FILTER = {"policyPath", "outputPath", "snapshotPath"}

# ---------------------------------------------------------------------------
# Input validators
# ---------------------------------------------------------------------------


def validate_subscription_id(value: str) -> str:
    """Validate an Azure subscription ID (UUID format)."""
    if not _RE_SUBSCRIPTION_ID.match(value):
        msg = f"Invalid subscription_id: {value!r}"
        raise ValueError(msg)
    return value


def validate_action(value: str) -> str:
    """Validate an Azure action like ``Microsoft.Compute/virtualMachines/delete``."""
    if not _RE_ACTION.match(value):
        msg = f"Invalid action: {value!r}"
        raise ValueError(msg)
    return value


def validate_scope(value: str) -> str:
    """Validate an Azure scope like ``/subscriptions/{id}/resourceGroups/rg-prod``."""
    if not _RE_SCOPE.match(value):
        msg = f"Invalid scope: {value!r}"
        raise ValueError(msg)
    return value


def validate_principal(value: str) -> str:
    """Validate a principal name, email, or UUID."""
    if not value:
        msg = "Invalid principal: must not be empty"
        raise ValueError(msg)
    if len(value) > 256:
        msg = "Invalid principal: exceeds 256 characters"
        raise ValueError(msg)
    if any(ord(c) < 32 for c in value):
        msg = "Invalid principal: contains control characters"
        raise ValueError(msg)
    return value


# ---------------------------------------------------------------------------
# Path sanitization
# ---------------------------------------------------------------------------


def _allowed_dirs() -> list[Path]:
    """Return the list of directories a path is allowed to reside in."""
    return [
        Path.cwd().resolve(),
        Path.home().resolve() / ".config" / "cloudsight",
    ]


def validate_path(value: str, *, must_exist: bool = False) -> Path:
    """Resolve *value* to a canonical path and enforce security constraints.

    Blocks symlinks (CVE-2025-53109) and paths outside allowed directories.
    """
    p = Path(value).expanduser().resolve()

    # Check symlink BEFORE existence — use the original (non-resolved) path
    raw = Path(value).expanduser()
    if raw.is_symlink():
        msg = f"Path is a symlink (blocked): {value!r}"
        raise ValueError(msg)

    if must_exist and not p.exists():
        msg = f"Path does not exist: {value!r}"
        raise ValueError(msg)

    allowed = _allowed_dirs()
    if not any(p == d or d in p.parents for d in allowed):
        msg = f"Path outside allowed directories: {value!r}"
        raise ValueError(msg)

    return p


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


def audit_log(
    tool: str,
    args: dict[str, object],
    status: str,
    duration_ms: int,
    findings_count: int = 0,
) -> None:
    """Write a structured JSON audit record to *stderr*."""
    filtered_args = {k: v for k, v in args.items() if k not in _PATH_KEYS_TO_FILTER}
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": tool,
        "args": filtered_args,
        "status": status,
        "duration_ms": duration_ms,
        "findings": findings_count,
    }
    sys.stderr.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Safe error wrapping
# ---------------------------------------------------------------------------


def safe_error(error: Exception) -> str:
    """Return a sanitised error message, stripping any credential material."""
    msg = str(error)
    if any(marker in msg for marker in _CREDENTIAL_MARKERS):
        return "Azure authentication error. Run 'az login' and retry."
    return msg[:500]
