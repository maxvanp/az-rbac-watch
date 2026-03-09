# v0.6.0 — Enhanced HTML Reports

## Goal

Improve the HTML report to provide at-a-glance compliance posture for non-technical stakeholders: compliance score, severity donut chart, executive summary, and improved stat cards.

## Decisions

- **SVG/CSS only** — no JS dependencies, no CDN, stays single-file and offline-compatible
- **Simple compliance score** — `(total_assignments - total_findings) / total_assignments × 100`, no severity weighting
- **All computation in Python** — arcs, score, summary text computed before Jinja2 rendering
- **No new models or files** — changes contained in `html_report.py` and its inline template

## Components

### 1. Compliance Score (Header)

Large SVG circular gauge in the report header, next to existing metadata (tenant, version, timestamp).

- **Formula:** `round((total - findings) / total * 100)` — 100% if 0 assignments
- **Color thresholds:** green ≥90%, yellow ≥70%, orange ≥50%, red <50%
- **SVG technique:** circle with `stroke-dasharray` to draw a partial arc

### 2. Executive Summary

2-3 auto-generated sentences below the score.

Example: *"128 assignments scanned across 3 scopes. 7 findings detected: 2 critical, 3 high, 2 medium."*

Generated in Python as a plain string, passed to the Jinja2 template.

### 3. Severity Donut Chart

SVG donut in the stats section (left side, stat cards on the right via flexbox).

- Proportional arcs per severity using `stroke-dasharray` + `stroke-dashoffset`
- Color mapping matches existing: CRITICAL=#dc3545, HIGH=#e74c3c, MEDIUM=#f39c12, LOW=#17a2b8, INFO=#6c757d
- Legend below with colored dots + counts
- Empty state: green circle with "No findings" text
- Arc data computed in Python: list of `{severity, count, percentage, offset}`

### 4. Improved Stat Cards

- Existing 4 cards remain (assignments scanned, drift, violations, total findings)
- Add 5th card: orphan count (already in `ComplianceSummary.orphan_count`)
- Conditional coloring: red if count > 0, neutral otherwise

## Testing

- Compliance score calculation: nominal, 0 findings, 0 assignments, all critical
- Executive summary formatting: various finding distributions
- SVG arc computation: proportions, single severity, all severities, empty
- HTML generation: verify new elements are present in output

## Out of Scope

- HTML report for diffs (v0.7.0)
- Azure Portal links in findings (future)
- Severity weighting in score
- JavaScript interactivity for new components
