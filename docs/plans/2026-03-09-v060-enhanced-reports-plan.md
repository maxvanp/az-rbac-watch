# v0.6.0 — Enhanced HTML Reports Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add compliance score gauge, severity donut chart, executive summary, and orphan card to the HTML report.

**Architecture:** All changes in `html_report.py` — new Python helper functions compute score, summary text, and SVG arc data, then pass them as template variables to the existing Jinja2 template. No new files, no new dependencies.

**Tech Stack:** Python, Jinja2, inline SVG/CSS

---

### Task 1: Compliance score computation

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py`
- Test: `tests/test_html_report.py`

**Step 1: Write the failing tests**

Add to `tests/test_html_report.py`:

```python
from az_rbac_watch.reporters.html_report import _compute_compliance_score


class TestComplianceScore:
    def test_no_assignments(self) -> None:
        assert _compute_compliance_score(0, 0) == 100

    def test_no_findings(self) -> None:
        assert _compute_compliance_score(50, 0) == 100

    def test_all_findings(self) -> None:
        assert _compute_compliance_score(10, 10) == 0

    def test_partial(self) -> None:
        assert _compute_compliance_score(100, 13) == 87

    def test_rounding(self) -> None:
        assert _compute_compliance_score(3, 1) == 67

    def test_more_findings_than_assignments(self) -> None:
        """Edge case: findings > assignments (duplicates). Clamp to 0."""
        assert _compute_compliance_score(5, 8) == 0
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestComplianceScore -v`
Expected: FAIL with `ImportError: cannot import name '_compute_compliance_score'`

**Step 3: Write implementation**

Add to `src/az_rbac_watch/reporters/html_report.py` after the `_truncate_scope` helper:

```python
def _compute_compliance_score(total_assignments: int, total_findings: int) -> int:
    """Compute compliance as a percentage: (total - findings) / total × 100.

    Returns 100 if no assignments. Clamps to 0 if findings > assignments.
    """
    if total_assignments == 0:
        return 100
    score = (total_assignments - total_findings) / total_assignments * 100
    return max(0, round(score))
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestComplianceScore -v`
Expected: 6 PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add compliance score computation"
```

---

### Task 2: Score color helper

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py`
- Test: `tests/test_html_report.py`

**Step 1: Write the failing tests**

```python
from az_rbac_watch.reporters.html_report import _score_color


class TestScoreColor:
    def test_green(self) -> None:
        assert _score_color(90) == "#27ae60"
        assert _score_color(100) == "#27ae60"

    def test_yellow(self) -> None:
        assert _score_color(70) == "#f39c12"
        assert _score_color(89) == "#f39c12"

    def test_orange(self) -> None:
        assert _score_color(50) == "#e67e22"
        assert _score_color(69) == "#e67e22"

    def test_red(self) -> None:
        assert _score_color(0) == "#e74c3c"
        assert _score_color(49) == "#e74c3c"
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestScoreColor -v`
Expected: FAIL with `ImportError`

**Step 3: Write implementation**

```python
def _score_color(score: int) -> str:
    """Return a CSS color for the compliance score."""
    if score >= 90:
        return "#27ae60"
    if score >= 70:
        return "#f39c12"
    if score >= 50:
        return "#e67e22"
    return "#e74c3c"
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestScoreColor -v`
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add score color helper"
```

---

### Task 3: Executive summary generator

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py`
- Test: `tests/test_html_report.py`

**Step 1: Write the failing tests**

```python
from az_rbac_watch.reporters.html_report import _build_executive_summary


class TestExecutiveSummary:
    def test_no_findings(self) -> None:
        summary = _build_executive_summary(
            total_assignments=50,
            scope_count=3,
            findings_by_severity={},
        )
        assert "50 assignments" in summary
        assert "3 scopes" in summary
        assert "No findings" in summary

    def test_with_findings(self) -> None:
        summary = _build_executive_summary(
            total_assignments=128,
            scope_count=3,
            findings_by_severity={"critical": 2, "high": 3, "medium": 2},
        )
        assert "128 assignments" in summary
        assert "7 findings" in summary
        assert "2 critical" in summary
        assert "3 high" in summary
        assert "2 medium" in summary

    def test_single_scope(self) -> None:
        summary = _build_executive_summary(
            total_assignments=10,
            scope_count=1,
            findings_by_severity={"low": 1},
        )
        assert "1 scope" in summary
        assert "1 finding" in summary  # singular

    def test_zero_assignments(self) -> None:
        summary = _build_executive_summary(
            total_assignments=0,
            scope_count=0,
            findings_by_severity={},
        )
        assert "0 assignments" in summary
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestExecutiveSummary -v`
Expected: FAIL

**Step 3: Write implementation**

```python
def _build_executive_summary(
    total_assignments: int,
    scope_count: int,
    findings_by_severity: dict[str, int],
) -> str:
    """Build a 1-2 sentence executive summary for the HTML report."""
    scope_word = "scope" if scope_count == 1 else "scopes"
    parts = [f"{total_assignments} assignments scanned across {scope_count} {scope_word}."]

    total_findings = sum(findings_by_severity.values())
    if total_findings == 0:
        parts.append("No findings detected.")
    else:
        finding_word = "finding" if total_findings == 1 else "findings"
        severity_order = ["critical", "high", "medium", "low", "info"]
        breakdown = [
            f"{count} {sev}"
            for sev in severity_order
            if (count := findings_by_severity.get(sev, 0)) > 0
        ]
        parts.append(f"{total_findings} {finding_word} detected: {', '.join(breakdown)}.")

    return " ".join(parts)
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestExecutiveSummary -v`
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add executive summary generator"
```

---

### Task 4: SVG donut arc computation

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py`
- Test: `tests/test_html_report.py`

**Step 1: Write the failing tests**

```python
from az_rbac_watch.reporters.html_report import DonutArc, _compute_donut_arcs


class TestDonutArcs:
    def test_empty_findings(self) -> None:
        arcs = _compute_donut_arcs({})
        assert arcs == []

    def test_single_severity(self) -> None:
        arcs = _compute_donut_arcs({"critical": 5})
        assert len(arcs) == 1
        assert arcs[0].severity == "critical"
        assert arcs[0].count == 5
        assert arcs[0].percentage == 100.0
        assert arcs[0].offset == 0.0

    def test_two_severities(self) -> None:
        arcs = _compute_donut_arcs({"critical": 1, "high": 3})
        assert len(arcs) == 2
        assert arcs[0].severity == "critical"
        assert arcs[0].percentage == 25.0
        assert arcs[0].offset == 0.0
        assert arcs[1].severity == "high"
        assert arcs[1].percentage == 75.0
        assert arcs[1].offset == 25.0

    def test_severity_order(self) -> None:
        """Arcs follow severity order: critical, high, medium, low, info."""
        arcs = _compute_donut_arcs({"low": 1, "critical": 1, "medium": 1})
        severities = [a.severity for a in arcs]
        assert severities == ["critical", "medium", "low"]

    def test_color_mapping(self) -> None:
        arcs = _compute_donut_arcs({"critical": 1})
        assert arcs[0].color == "#dc3545"
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestDonutArcs -v`
Expected: FAIL

**Step 3: Write implementation**

```python
from dataclasses import dataclass as _dataclass


@_dataclass(frozen=True)
class DonutArc:
    """One arc segment of the severity donut chart."""

    severity: str
    count: int
    percentage: float
    offset: float
    color: str


_SEVERITY_SORT = ["critical", "high", "medium", "low", "info"]


def _compute_donut_arcs(findings_by_severity: dict[str, int]) -> list[DonutArc]:
    """Compute SVG donut arc segments from severity counts."""
    total = sum(findings_by_severity.values())
    if total == 0:
        return []

    arcs: list[DonutArc] = []
    offset = 0.0
    for sev in _SEVERITY_SORT:
        count = findings_by_severity.get(sev, 0)
        if count == 0:
            continue
        pct = count / total * 100
        color = _SEVERITY_COLOR.get(Severity(sev), "#6c757d")
        arcs.append(DonutArc(severity=sev, count=count, percentage=pct, offset=offset, color=color))
        offset += pct

    return arcs
```

Note: `_dataclass` alias avoids conflict with existing `dataclass` import. Alternatively, just add `DonutArc` using the existing `dataclass` import — check which import form is already used in the file (`from dataclasses import dataclass` is already imported).

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestDonutArcs -v`
Expected: 5 PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add SVG donut arc computation"
```

---

### Task 5: Update HTML template — score gauge in header

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py` (template string + `generate_html_report` function)
- Test: `tests/test_html_report.py`

**Step 1: Write the failing tests**

```python
class TestHtmlComplianceScore:
    def test_score_displayed_in_empty_report(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "100%" in html
        assert "compliance-score" in html

    def test_score_displayed_with_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        # 20 assignments, 2 findings → 90%
        assert "90%" in html

    def test_score_gauge_svg(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "<svg" in html
        assert "stroke-dasharray" in html
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestHtmlComplianceScore -v`
Expected: FAIL (no "compliance-score" in HTML)

**Step 3: Update template and generate_html_report function**

**3a. Add CSS** inside the `<style>` block (after `.footer` rule):

```css
  .header-content { display: flex; align-items: center; gap: 32px; }
  .header-text { flex: 1; }
  .compliance-score { text-align: center; flex-shrink: 0; }
  .compliance-score .score-label { font-size: 0.85rem; opacity: 0.9; margin-top: 4px; }
  .executive-summary {
    background: rgba(255,255,255,0.1); border-radius: 6px;
    padding: 12px 16px; margin-top: 12px; font-size: 0.9rem; opacity: 0.95;
  }
```

**3b. Update header section** in the template. Replace the current header div:

```html
  <div class="header">
    <div class="header-content">
      <div class="header-text">
        <h1>{{ labels.title }}</h1>
        <p>Tenant : {{ report.tenant_id }}</p>
        <p>Policy version : {{ report.policy_version }}</p>
        <p>Scan : {{ report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
      </div>
      <div class="compliance-score">
        <svg width="100" height="100" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#ffffff33" stroke-width="8"/>
          <circle cx="50" cy="50" r="40" fill="none" stroke="{{ score_color }}" stroke-width="8"
            stroke-dasharray="{{ score * 2.51327 }} {{ 251.327 - score * 2.51327 }}"
            stroke-dashoffset="62.83" stroke-linecap="round" transform="rotate(-90 50 50)"/>
          <text x="50" y="50" text-anchor="middle" dominant-baseline="central"
            fill="#fff" font-size="22" font-weight="700">{{ score }}%</text>
        </svg>
        <div class="score-label">Compliance</div>
      </div>
    </div>
    {% if executive_summary %}
    <div class="executive-summary">{{ executive_summary }}</div>
    {% endif %}
  </div>
```

Note: `2.51327 = 2π × 40 / 100` (circumference per percentage point for radius 40).

**3c. Update `generate_html_report` function** to compute and pass new variables:

After `labels = _MODE_LABELS[mode]`, add:

```python
    score = _compute_compliance_score(
        report.summary.total_assignments_checked,
        report.summary.total_findings,
    )
    score_clr = _score_color(score)
    scope_count = len(finding_groups) if finding_groups else (1 if report.summary.total_assignments_checked > 0 else 0)
    exec_summary = _build_executive_summary(
        report.summary.total_assignments_checked,
        scope_count,
        report.summary.findings_by_severity,
    )
```

Update the `template.render()` call to include:

```python
    html = template.render(
        report=report,
        finding_groups=finding_groups,
        labels=labels,
        score=score,
        score_color=score_clr,
        executive_summary=exec_summary,
    )
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py -v`
Expected: ALL PASSED (new tests + existing tests still pass)

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add compliance score gauge and executive summary to HTML report"
```

---

### Task 6: Update HTML template — severity donut chart

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py` (template + render call)
- Test: `tests/test_html_report.py`

**Step 1: Write the failing tests**

```python
class TestHtmlDonutChart:
    def test_donut_present_with_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "donut" in html
        assert "stroke-dasharray" in html

    def test_no_donut_without_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "donut-chart" not in html

    def test_donut_legend(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "HIGH" in html or "high" in html.lower()
        assert "MEDIUM" in html or "medium" in html.lower()
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestHtmlDonutChart -v`
Expected: FAIL

**Step 3: Update template**

**3a. Add CSS:**

```css
  .stats-row { display: flex; gap: 24px; margin-bottom: 24px; align-items: flex-start; flex-wrap: wrap; }
  .donut-chart { flex-shrink: 0; text-align: center; }
  .donut-legend { display: flex; flex-wrap: wrap; gap: 8px 16px; margin-top: 8px; justify-content: center; }
  .donut-legend-item { display: flex; align-items: center; gap: 4px; font-size: 0.8rem; color: #636e72; }
  .donut-legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
  .cards { flex: 1; }
```

Note: `.cards` already exists — just add `flex: 1;` to the existing rule.

**3b. Wrap the existing `.cards` div** in a new `.stats-row` container and add the donut before it:

```html
  <div class="stats-row">
    {% if donut_arcs %}
    <div class="donut-chart">
      <svg width="140" height="140" viewBox="0 0 140 140">
        {% for arc in donut_arcs %}
        <circle cx="70" cy="70" r="50" fill="none" stroke="{{ arc.color }}" stroke-width="20"
          stroke-dasharray="{{ arc.percentage * 3.14159 }} {{ 314.159 - arc.percentage * 3.14159 }}"
          stroke-dashoffset="{{ -arc.offset * 3.14159 }}"
          transform="rotate(-90 70 70)"/>
        {% endfor %}
      </svg>
      <div class="donut-legend">
        {% for arc in donut_arcs %}
        <span class="donut-legend-item">
          <span class="donut-legend-dot" style="background:{{ arc.color }}"></span>
          {{ arc.count }} {{ arc.severity | upper }}
        </span>
        {% endfor %}
      </div>
    </div>
    {% endif %}

    <div class="cards">
      ... existing cards content ...
    </div>
  </div>
```

Note: `3.14159 = 2π × 50 / 100` (circumference per percentage point for radius 50).

**3c. Update `generate_html_report`** to compute and pass `donut_arcs`:

After the executive summary computation:

```python
    donut_arcs = _compute_donut_arcs(report.summary.findings_by_severity)
```

Add to `template.render()`:

```python
        donut_arcs=donut_arcs,
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py -v`
Expected: ALL PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add severity donut chart to HTML report"
```

---

### Task 7: Orphan count stat card

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py` (template only)
- Test: `tests/test_html_report.py`

**Step 1: Write the failing test**

```python
class TestHtmlOrphanCard:
    def test_orphan_card_shown(self, tmp_path: Path) -> None:
        report = _report_with_findings()
        report.summary.orphan_count = 3
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert "Orphaned" in html
        assert ">3<" in html  # value in card

    def test_no_orphan_card_when_zero(self, tmp_path: Path) -> None:
        report = _report_with_findings()
        report.summary.orphan_count = 0
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert "Orphaned" not in html
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestHtmlOrphanCard -v`
Expected: FAIL

**Step 3: Add orphan card to template**

After the "Total findings" card in the template, add:

```html
    {% if report.summary.orphan_count > 0 %}
    <div class="card">
      {% set oc = report.summary.orphan_count %}
      <div class="value" style="color: #e74c3c">{{ oc }}</div>
      <div class="label">Orphaned</div>
    </div>
    {% endif %}
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py -v`
Expected: ALL PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add orphan count card to HTML report"
```

---

### Task 8: Final verification

**Step 1: Run full test suite**

```bash
.venv/bin/python -m pytest --cov=az_rbac_watch --cov-fail-under=80 -v
```

Expected: ALL PASSED, coverage ≥80%

**Step 2: Run linters**

```bash
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src/ tests/
```

Expected: ALL PASS

**Step 3: Update `__all__` export**

If `DonutArc` should be public, add it to `__all__` in `html_report.py`. Otherwise keep it private (prefixed helpers stay private).

Check that `__all__` in `html_report.py` still matches the public API:

```python
__all__ = ["ScopeGroup", "generate_html_report"]
```

No change needed — all new functions are private (prefixed with `_`).

**Step 4: Verify existing tests still pass unchanged**

Run: `.venv/bin/python -m pytest tests/test_html_report.py -v`
Expected: ALL PASSED (old + new tests)
