"""HTML report generator — single-file, CSS inline.

Supports three modes:
- scan  (drift)     : title and vocabulary oriented "desired state / drift"
- audit (violations): title and vocabulary oriented "guardrails / violations"
- combined          : both (default, backward-compatible)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from jinja2 import Environment

from az_rbac_watch.analyzers.compliance import (
    DRIFT,
    SEVERITY_ORDER,
    ComplianceFinding,
    ComplianceReport,
    Severity,
)
from az_rbac_watch.utils.scope import scope_group_key

__all__ = ["ScopeGroup", "generate_html_report"]

ReportMode = Literal["scan", "audit", "combined"]


@dataclass(frozen=True)
class ScopeGroup:
    """A group of compliance findings for a single scope (subscription/MG)."""

    anchor: str
    label: str
    count: int
    drift: int
    violations: int
    findings: list[ComplianceFinding]

# ── Severity → CSS color mapping ────────────────────────────

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH: "#e74c3c",
    Severity.MEDIUM: "#f39c12",
    Severity.LOW: "#17a2b8",
    Severity.INFO: "#6c757d",
}

# ── Labels per mode ──────────────────────────────────────────

_MODE_LABELS: dict[ReportMode, dict[str, str]] = {
    "scan": {
        "title": "Azure Permissions Watch — Drift Report",
        "drift_label": "Undeclared (drift)",
        "violation_label": "",
        "ok": "No drift — actual state matches desired state",
        "ko_tpl": "{n} undeclared assignment(s)",
    },
    "audit": {
        "title": "Azure Permissions Watch — Audit Report",
        "drift_label": "",
        "violation_label": "Guardrail violations",
        "ok": "No violations — all guardrails passed",
        "ko_tpl": "{n} guardrail violation(s)",
    },
    "combined": {
        "title": "Azure Permissions Watch — Report",
        "drift_label": "Undeclared (drift)",
        "violation_label": "Guardrail violations",
        "ok": "Compliant — no findings",
        "ko_tpl": "{n} finding(s)",
    },
}

# ── Group findings by scope ─────────────────────────────────


def _group_findings_by_scope(
    findings: list[ComplianceFinding],
    scope_names: dict[str, str] | None = None,
) -> list[ScopeGroup]:
    """Group findings sorted by scope (subscription/MG).

    Returns:
        List of ScopeGroup ordered by scope type (MG, sub, other).
    """
    if not findings:
        return []

    scope_names = scope_names or {}

    groups: dict[tuple[int, str], list[ComplianceFinding]] = {}
    for f in findings:
        key = scope_group_key(f.scope)
        groups.setdefault(key, []).append(f)

    result: list[ScopeGroup] = []
    for key in sorted(groups):
        sort_order, group_id = key
        group_findings = groups[key]

        # Label
        name = scope_names.get(group_id, "")
        if sort_order == 0:
            label = f"Management Group : {name} ({group_id})" if name else f"Management Group : {group_id}"
        elif sort_order == 1:
            label = f"{name} ({group_id})" if name else group_id
        else:
            label = "Other scopes"

        # Anchor HTML-safe
        clean_id = re.sub(r"[^a-zA-Z0-9-]", "-", group_id) if group_id else "other"
        anchor = f"scope-{clean_id}"

        drift = sum(1 for f in group_findings if f.rule_id == DRIFT)
        violations = sum(1 for f in group_findings if f.rule_id != DRIFT)

        result.append(
            ScopeGroup(
                anchor=anchor,
                label=label,
                count=len(group_findings),
                drift=drift,
                violations=violations,
                findings=group_findings,
            )
        )

    return result


# ── Template HTML (Jinja2) ──────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ labels.title }}</title>
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
  .cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
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
  .section h2 { font-size: 1.2rem; margin: 0 0 16px; display: flex; align-items: center; gap: 10px; }
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
  .count-badge {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    background: #e0e0e0; font-size: 0.8rem; font-weight: 400; color: #2d3436;
  }
  .toc-link { text-decoration: none; color: #0078d4; }
  .toc-link:hover { text-decoration: underline; }
  .back-to-top { font-size: 0.85rem; color: #636e72; text-decoration: none; }
  .back-to-top:hover { text-decoration: underline; }
  .verdict {
    text-align: center; padding: 20px; border-radius: 8px; font-size: 1.2rem; font-weight: 700;
  }
  .verdict-ok { background: #d4edda; color: #155724; }
  .verdict-ko { background: #f8d7da; color: #721c24; }
  .warnings {
    background: #fff3cd; border-left: 4px solid #f39c12;
    padding: 16px; border-radius: 4px; margin-bottom: 24px;
  }
  .warnings h2 { color: #856404; margin: 0 0 8px; font-size: 1rem; }
  .warnings ul { margin: 0; padding-left: 20px; }
  .errors {
    background: #fff3cd; border-left: 4px solid #ffc107;
    padding: 16px; border-radius: 4px; margin-bottom: 24px;
  }
  .errors h2 { color: #856404; margin: 0 0 8px; }
  .errors ul { margin: 0; padding-left: 20px; }
  .remediation { font-size: 0.8rem; color: #636e72; font-style: italic; margin-top: 4px; }
  .filter-bar {
    display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px;
  }
  .filter-btn {
    padding: 4px 12px; border: 1px solid #dee2e6; border-radius: 4px;
    background: #fff; cursor: pointer; font-size: 0.8rem; font-weight: 600;
    text-transform: uppercase; transition: all 0.15s;
  }
  .filter-btn:hover { background: #f0f0f0; }
  .filter-btn.active { color: #fff; border-color: transparent; }
  .filter-btn.active[data-severity="critical"] { background: #dc3545; }
  .filter-btn.active[data-severity="high"] { background: #e74c3c; }
  .filter-btn.active[data-severity="medium"] { background: #f39c12; }
  .filter-btn.active[data-severity="low"] { background: #17a2b8; }
  .filter-btn.active[data-severity="info"] { background: #6c757d; }
  .filter-search {
    padding: 4px 10px; border: 1px solid #dee2e6; border-radius: 4px;
    font-size: 0.85rem; min-width: 200px;
  }
  .filter-count { font-size: 0.85rem; color: #636e72; margin-left: auto; }
  .scope-truncated { cursor: help; }
  .footer { text-align: center; font-size: 0.8rem; color: #b2bec3; padding: 16px 0; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>{{ labels.title }}</h1>
    <p>Tenant : {{ report.tenant_id }}</p>
    <p>Policy version : {{ report.policy_version }}</p>
    <p>Scan : {{ report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
  </div>

  {% if report.warnings %}
  <div class="warnings">
    <h2>Warnings</h2>
    <ul>
      {% for w in report.warnings %}
      <li>{{ w }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  <div class="cards">
    <div class="card">
      <div class="value">{{ report.summary.total_assignments_checked }}</div>
      <div class="label">Assignments scanned</div>
    </div>
    {% if labels.drift_label %}
    <div class="card">
      {% set dc = report.summary.drift_count %}
      <div class="value" style="color: {{ '#e74c3c' if dc else '#27ae60' }}">{{ dc }}</div>
      <div class="label">{{ labels.drift_label }}</div>
    </div>
    {% endif %}
    {% if labels.violation_label %}
    <div class="card">
      {% set vc = report.summary.violation_count %}
      <div class="value" style="color: {{ '#e74c3c' if vc else '#27ae60' }}">{{ vc }}</div>
      <div class="label">{{ labels.violation_label }}</div>
    </div>
    {% endif %}
    <div class="card">
      {% set tf = report.summary.total_findings %}
      <div class="value" style="color: {{ '#e74c3c' if tf else '#27ae60' }}">{{ tf }}</div>
      <div class="label">Total findings</div>
    </div>
  </div>

  {% if finding_groups|length > 1 %}
  <div class="section" id="toc">
    <h2>Findings by scope</h2>
    <table>
      <thead>
        <tr>
          <th>Scope</th>
          {% if labels.drift_label %}<th>Drift</th>{% endif %}
          {% if labels.violation_label %}<th>Violations</th>{% endif %}
          <th>Total</th>
        </tr>
      </thead>
      <tbody>
        {% for g in finding_groups %}
        <tr>
          <td><a class="toc-link" href="#{{ g.anchor }}">{{ g.label }}</a></td>
          {% if labels.drift_label %}<td>{{ g.drift }}</td>{% endif %}
          {% if labels.violation_label %}<td>{{ g.violations }}</td>{% endif %}
          <td><strong>{{ g.count }}</strong></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% for g in finding_groups %}
  <div class="section finding-section" id="{{ g.anchor }}">
    <h2>{{ g.label }} <span class="count-badge">{{ g.count }} finding(s)</span></h2>
    <div class="filter-bar">
      <button class="filter-btn active" data-severity="all" onclick="toggleFilter(this)">All</button>
      <button class="filter-btn active" data-severity="critical" onclick="toggleFilter(this)">Critical</button>
      <button class="filter-btn active" data-severity="high" onclick="toggleFilter(this)">High</button>
      <button class="filter-btn active" data-severity="medium" onclick="toggleFilter(this)">Medium</button>
      <button class="filter-btn active" data-severity="low" onclick="toggleFilter(this)">Low</button>
      <button class="filter-btn active" data-severity="info" onclick="toggleFilter(this)">Info</button>
      <input type="text" class="filter-search" placeholder="Search..." oninput="applyFilters(this)">
      <span class="filter-count"></span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Principal</th>
          <th>Role</th>
          <th>Scope</th>
        </tr>
      </thead>
      <tbody>
        {% for f in g.findings %}
        <tr data-severity="{{ f.severity.value }}">
          {% set sc = severity_color(f.severity) %}
          <td><span class="badge severity-{{ f.severity.value }}"
            style="background:{{ sc }}">{{ f.severity.value | upper }}</span></td>
          <td>{{ f.rule_id }}</td>
          <td>
            {%- if f.principal_display_name -%}
              {{ f.principal_display_name }}<br><small>{{ f.principal_id }}</small>
            {%- else -%}
              {{ f.principal_id }}
            {%- endif -%}
          </td>
          <td>{{ f.role_name }}</td>
          <td title="{{ f.scope }}">{{ truncate_scope(f.scope) }}
            {%- if f.details.get('remediation') %}
            <div class="remediation">{{ f.details['remediation'] }}</div>
            {%- endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% if finding_groups|length > 1 %}
    <p style="text-align:right; margin: 8px 0 0"><a class="back-to-top" href="#toc">&#8593; Summary</a></p>
    {% endif %}
  </div>
  {% endfor %}

  {% if report.scan_errors %}
  <div class="errors">
    <h2>Scan errors</h2>
    <ul>
      {% for err in report.scan_errors %}
      <li>{{ err }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  <div class="verdict {{ 'verdict-ok' if report.summary.total_findings == 0 else 'verdict-ko' }}">
    {% if report.summary.total_findings == 0 %}
      {{ labels.ok }}
    {% else %}
      {{ labels.ko_tpl.format(n=report.summary.total_findings) }}
    {% endif %}
  </div>

  {% set ts = report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') %}
  <div class="footer">Azure Permissions Watch v{{ report.policy_version }} — generated on {{ ts }}</div>
</div>
<script>
function toggleFilter(btn) {
  var section = btn.closest('.finding-section');
  var allBtn = section.querySelector('.filter-btn[data-severity="all"]');
  if (btn.dataset.severity === 'all') {
    var btns = section.querySelectorAll('.filter-btn');
    var activate = !btn.classList.contains('active');
    btns.forEach(function(b) { b.classList.toggle('active', activate); });
  } else {
    btn.classList.toggle('active');
    var severityBtns = section.querySelectorAll('.filter-btn:not([data-severity="all"])');
    var allActive = Array.from(severityBtns).every(function(b) { return b.classList.contains('active'); });
    allBtn.classList.toggle('active', allActive);
  }
  applyFilters(section.querySelector('.filter-search'));
}
function applyFilters(input) {
  var section = input.closest('.finding-section');
  var search = input.value.toLowerCase();
  var activeSeverities = new Set();
  section.querySelectorAll('.filter-btn.active:not([data-severity="all"])').forEach(function(b) {
    activeSeverities.add(b.dataset.severity);
  });
  var rows = section.querySelectorAll('tbody tr');
  var shown = 0, total = rows.length;
  rows.forEach(function(row) {
    var sev = row.dataset.severity;
    var text = row.textContent.toLowerCase();
    var visible = activeSeverities.has(sev) && (!search || text.indexOf(search) !== -1);
    row.style.display = visible ? '' : 'none';
    if (visible) shown++;
  });
  var counter = section.querySelector('.filter-count');
  if (counter) counter.textContent = shown + ' / ' + total + ' finding(s)';
}
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.filter-search').forEach(function(input) { applyFilters(input); });
});
</script>
</body>
</html>
"""


# ── Helpers ─────────────────────────────────────────────────


def _truncate_scope(scope: str, max_segments: int = 2) -> str:
    """Truncate an ARM scope keeping the last N segments + ellipsis.

    Ex: /subscriptions/xxx/resourceGroups/rg-infra/providers/... -> .../providers/...
    """
    parts = scope.strip("/").split("/")
    if len(parts) <= max_segments * 2:
        return scope
    tail = "/".join(parts[-(max_segments * 2):])
    return f".../{tail}"


# ── Public API ──────────────────────────────────────────────


def generate_html_report(
    report: ComplianceReport,
    output_path: Path,
    scope_names: dict[str, str] | None = None,
    mode: ReportMode = "combined",
) -> None:
    """Generate a standalone HTML report (single-file, CSS inline).

    Args:
        report: The compliance report to export.
        output_path: Path of the HTML file to create.
        scope_names: Mapping {scope_id_lower: display_name} for labels.
        mode: Report mode — "scan" (drift), "audit" (violations), or "combined".
    """
    sorted_findings = sorted(
        report.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )

    finding_groups = _group_findings_by_scope(sorted_findings, scope_names)
    labels = _MODE_LABELS[mode]

    env = Environment(autoescape=True)
    env.globals["severity_color"] = lambda s: _SEVERITY_COLOR.get(s, "#6c757d")
    env.globals["truncate_scope"] = _truncate_scope
    template = env.from_string(_HTML_TEMPLATE)

    html = template.render(
        report=report,
        finding_groups=finding_groups,
        labels=labels,
    )

    output_path.write_text(html, encoding="utf-8")
