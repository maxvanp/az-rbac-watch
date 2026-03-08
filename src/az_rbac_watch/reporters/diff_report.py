"""Reporters for snapshot diff results — console (plain text) and JSON."""

from __future__ import annotations

import json

from az_rbac_watch.analyzers.diff import DiffResult

__all__ = ["format_diff_console", "format_diff_json"]


def format_diff_json(result: DiffResult) -> str:
    """Format diff result as JSON."""
    data = {
        "summary": {
            "added_count": result.added_count,
            "removed_count": result.removed_count,
            "modified_count": result.modified_count,
            "has_changes": result.has_changes,
        },
        "added": [a.model_dump(mode="json") for a in result.added],
        "removed": [a.model_dump(mode="json") for a in result.removed],
        "modified": [c.model_dump(mode="json") for c in result.modified],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_diff_console(result: DiffResult) -> str:
    """Format diff result as human-readable text."""
    if not result.has_changes:
        return "No changes detected between snapshots."

    lines: list[str] = []
    lines.append(
        f"Changes: +{result.added_count} added, "
        f"-{result.removed_count} removed, "
        f"~{result.modified_count} modified"
    )
    lines.append("")

    if result.added:
        lines.append("Added assignments:")
        for a in result.added:
            name = a.principal_display_name or a.principal_id
            lines.append(f"  + {name} — {a.role_name or '?'} at {a.scope}")
        lines.append("")

    if result.removed:
        lines.append("Removed assignments:")
        for a in result.removed:
            name = a.principal_display_name or a.principal_id
            lines.append(f"  - {name} — {a.role_name or '?'} at {a.scope}")
        lines.append("")

    if result.modified:
        lines.append("Modified assignments:")
        current_id = ""
        for c in result.modified:
            if c.assignment_id != current_id:
                current_id = c.assignment_id
                lines.append(f"  ~ {c.assignment_id}:")
            lines.append(f"      {c.field}: {c.old_value} → {c.new_value}")
        lines.append("")

    return "\n".join(lines)
