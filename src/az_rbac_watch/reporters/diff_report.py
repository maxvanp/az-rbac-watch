"""Reporters for snapshot diff results — console (plain text), JSON, and HTML."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from jinja2 import Environment

from az_rbac_watch.analyzers.diff import DiffResult
from az_rbac_watch.scanner.snapshot import Snapshot

__all__ = ["format_diff_console", "format_diff_html", "format_diff_json"]


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
        f"Changes: +{result.added_count} added, -{result.removed_count} removed, ~{result.modified_count} modified"
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


# ── HTML diff report ────────────────────────────────────────

_DIFF_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Azure Permissions Watch — Change Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0; padding: 0;
    background: #f5f6fa; color: #2d3436;
    line-height: 1.6;
  }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 1.6rem; margin: 0 0 8px; }
  .header {
    background: linear-gradient(135deg, #0078d4, #005a9e);
    color: #fff; padding: 32px 24px; border-radius: 8px; margin-bottom: 24px;
  }
  .header p { margin: 4px 0; opacity: 0.9; font-size: 0.95rem; }
  .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .card {
    flex: 1; min-width: 180px; background: #fff; border-radius: 8px;
    padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); text-align: center;
  }
  .card .value { font-size: 2rem; font-weight: 700; }
  .card .label { font-size: 0.85rem; color: #636e72; margin-top: 4px; }
  .section {
    background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
    padding: 24px; margin-bottom: 24px;
  }
  .section h2 { font-size: 1.2rem; margin: 0 0 16px; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; padding: 10px 12px; background: #f8f9fa;
    border-bottom: 2px solid #dee2e6; font-size: 0.85rem;
    text-transform: uppercase; color: #636e72;
  }
  td { padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 0.9rem; word-break: break-all; }
  tr:hover { background: #f8f9fa; }
  .badge {
    display: inline-block; padding: 3px 10px; border-radius: 4px;
    color: #fff; font-size: 0.8rem; font-weight: 600; text-transform: uppercase;
  }
  .badge-added { background: #27ae60; }
  .badge-removed { background: #e74c3c; }
  .badge-modified { background: #f39c12; }
  .verdict {
    text-align: center; padding: 20px; border-radius: 8px; font-size: 1.2rem; font-weight: 700;
  }
  .verdict-ok { background: #d4edda; color: #155724; }
  .verdict-ko { background: #f8d7da; color: #721c24; }
  .footer { text-align: center; font-size: 0.8rem; color: #b2bec3; padding: 16px 0; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Azure Permissions Watch — Change Report</h1>
    <p>Tenant : {{ tenant_id }}</p>
    <p>Old snapshot : {{ old_ts }}</p>
    <p>New snapshot : {{ new_ts }}</p>
  </div>

  <div class="cards">
    <div class="card">
      <div class="value" style="color: {{ '#27ae60' if added_count > 0 else '#636e72' }}">{{ added_count }}</div>
      <div class="label">Added</div>
    </div>
    <div class="card">
      <div class="value" style="color: {{ '#e74c3c' if removed_count > 0 else '#636e72' }}">{{ removed_count }}</div>
      <div class="label">Removed</div>
    </div>
    <div class="card">
      <div class="value" style="color: {{ '#f39c12' if modified_count > 0 else '#636e72' }}">{{ modified_count }}</div>
      <div class="label">Modified</div>
    </div>
  </div>

  {% if has_changes %}
  <div class="section">
    <h2>Changes</h2>
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Principal</th>
          <th>Role</th>
          <th>Scope</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {% for a in added %}
        <tr>
          <td><span class="badge badge-added">ADDED</span></td>
          <td>
            {%- if a.principal_display_name -%}
              {{ a.principal_display_name }}<br><small>{{ a.principal_id }}</small>
            {%- else -%}
              {{ a.principal_id }}
            {%- endif -%}
          </td>
          <td>{{ a.role_name or '?' }}</td>
          <td title="{{ a.scope }}">{{ truncate_scope(a.scope) }}</td>
          <td></td>
        </tr>
        {% endfor %}
        {% for a in removed %}
        <tr>
          <td><span class="badge badge-removed">REMOVED</span></td>
          <td>
            {%- if a.principal_display_name -%}
              {{ a.principal_display_name }}<br><small>{{ a.principal_id }}</small>
            {%- else -%}
              {{ a.principal_id }}
            {%- endif -%}
          </td>
          <td>{{ a.role_name or '?' }}</td>
          <td title="{{ a.scope }}">{{ truncate_scope(a.scope) }}</td>
          <td></td>
        </tr>
        {% endfor %}
        {% for aid, changes in modified_groups.items() %}
        <tr>
          <td><span class="badge badge-modified">MODIFIED</span></td>
          <td>{{ aid }}</td>
          <td></td>
          <td></td>
          <td>
            {%- for c in changes -%}
              {{ c.field }}: {{ c.old_value }} &rarr; {{ c.new_value }}
              {%- if not loop.last %}<br>{% endif -%}
            {%- endfor -%}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% set total = added_count + removed_count + modified_count %}
  <div class="verdict {{ 'verdict-ok' if not has_changes else 'verdict-ko' }}">
    {% if not has_changes %}
      No changes detected between snapshots.
    {% else %}
      {{ total }} change(s) detected
    {% endif %}
  </div>

  <div class="footer">Azure Permissions Watch — Change Report</div>
</div>
</body>
</html>
"""


def _truncate_scope(scope: str, max_segments: int = 2) -> str:
    """Truncate an ARM scope keeping the last N segments + ellipsis."""
    parts = scope.strip("/").split("/")
    if len(parts) <= max_segments * 2:
        return scope
    tail = "/".join(parts[-(max_segments * 2) :])
    return f".../{tail}"


def format_diff_html(
    result: DiffResult,
    old_snapshot: Snapshot,
    new_snapshot: Snapshot,
    output_path: Path,
) -> None:
    """Generate a standalone HTML change report from a diff result.

    Args:
        result: The diff result to render.
        old_snapshot: The older snapshot (for metadata).
        new_snapshot: The newer snapshot (for metadata).
        output_path: Path of the HTML file to create.
    """
    modified_groups: dict[str, list[object]] = defaultdict(list)
    for c in result.modified:
        modified_groups[c.assignment_id].append(c)

    env = Environment(autoescape=True)
    env.globals["truncate_scope"] = _truncate_scope
    template = env.from_string(_DIFF_HTML_TEMPLATE)

    html = template.render(
        tenant_id=old_snapshot.metadata.tenant_id,
        old_ts=old_snapshot.metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        new_ts=new_snapshot.metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        added=result.added,
        removed=result.removed,
        added_count=result.added_count,
        removed_count=result.removed_count,
        modified_count=result.modified_count,
        modified_groups=dict(modified_groups),
        has_changes=result.has_changes,
    )

    output_path.write_text(html, encoding="utf-8")
