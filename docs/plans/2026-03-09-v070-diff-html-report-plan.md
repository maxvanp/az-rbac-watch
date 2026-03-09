# v0.7.0 — Diff HTML Report Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an HTML report for the `diff` command, with stat cards, a changes table, and a verdict — same visual style as the compliance report.

**Architecture:** Add `format_diff_html` to the existing `diff_report.py`. The function takes a `DiffResult` and two `Snapshot` objects (for metadata) and writes a single-file HTML report. Update the `diff` CLI command to support HTML output.

**Tech Stack:** Python, Jinja2, inline SVG/CSS

---

### Task 1: Add `format_diff_html` function

**Files:**
- Modify: `src/az_rbac_watch/reporters/diff_report.py`
- Test: `tests/test_diff_report.py`

**Step 1: Write the failing tests**

Add to `tests/test_diff_report.py`:

```python
from datetime import UTC, datetime
from pathlib import Path

from az_rbac_watch.reporters.diff_report import format_diff_html
from az_rbac_watch.scanner.snapshot import Snapshot, SnapshotMetadata, SnapshotScope


def _make_snapshot(ts: datetime | None = None) -> Snapshot:
    return Snapshot(
        metadata=SnapshotMetadata(
            timestamp=ts or datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC),
            tenant_id="aaaa-bbbb-cccc",
            tool_version="0.7.0",
        ),
        scopes=SnapshotScope(),
    )


class TestDiffHtmlReport:
    def test_generates_valid_html(self, tmp_path: Path) -> None:
        out = tmp_path / "diff.html"
        format_diff_html(DiffResult(), _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert html.startswith("<!DOCTYPE html>")

    def test_no_changes_verdict(self, tmp_path: Path) -> None:
        out = tmp_path / "diff.html"
        format_diff_html(DiffResult(), _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "No changes" in html
        assert "verdict-ok" in html

    def test_changes_verdict(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "1 change(s)" in html
        assert "verdict-ko" in html

    def test_stat_cards(self, tmp_path: Path) -> None:
        result = DiffResult(
            added=[_make_sa(id="a-1")],
            removed=[_make_sa(id="a-2", principal_id="p-2")],
        )
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "Added" in html
        assert "Removed" in html
        assert "Modified" in html

    def test_added_badge(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "ADDED" in html
        assert "Reader" in html
        assert "Alice" in html

    def test_removed_badge(self, tmp_path: Path) -> None:
        result = DiffResult(removed=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "REMOVED" in html

    def test_modified_details(self, tmp_path: Path) -> None:
        result = DiffResult(
            modified=[DiffChange(assignment_id="a-1", field="role_name", old_value="Reader", new_value="Contributor")]
        )
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "MODIFIED" in html
        assert "Reader" in html
        assert "Contributor" in html

    def test_header_timestamps(self, tmp_path: Path) -> None:
        old_snap = _make_snapshot(datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC))
        new_snap = _make_snapshot(datetime(2026, 3, 8, 10, 0, 0, tzinfo=UTC))
        out = tmp_path / "diff.html"
        format_diff_html(DiffResult(), old_snap, new_snap, out)
        html = out.read_text(encoding="utf-8")
        assert "2026-03-01" in html
        assert "2026-03-08" in html

    def test_xss_escaped(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa(principal_display_name='<script>alert("x")</script>')])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_diff_report.py::TestDiffHtmlReport -v`
Expected: FAIL with `ImportError: cannot import name 'format_diff_html'`

**Step 3: Write implementation**

Add to `src/az_rbac_watch/reporters/diff_report.py`:

```python
from pathlib import Path

from jinja2 import Environment

from az_rbac_watch.scanner.snapshot import Snapshot, SnapshotAssignment

# Update __all__
__all__ = ["format_diff_console", "format_diff_html", "format_diff_json"]


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
  .cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .card {
    flex: 1; min-width: 150px; background: #fff; border-radius: 8px;
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
    <p>Old snapshot : {{ old_timestamp }}</p>
    <p>New snapshot : {{ new_timestamp }}</p>
  </div>

  <div class="cards">
    <div class="card">
      <div class="value" style="color: {{ '#27ae60' if added_count > 0 else '#636e72' }}">+{{ added_count }}</div>
      <div class="label">Added</div>
    </div>
    <div class="card">
      <div class="value" style="color: {{ '#e74c3c' if removed_count > 0 else '#636e72' }}">-{{ removed_count }}</div>
      <div class="label">Removed</div>
    </div>
    <div class="card">
      <div class="value" style="color: {{ '#f39c12' if modified_count > 0 else '#636e72' }}">~{{ modified_count }}</div>
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
          <td>{% if a.principal_display_name %}{{ a.principal_display_name }}<br><small>{{ a.principal_id }}</small>{% else %}{{ a.principal_id }}{% endif %}</td>
          <td>{{ a.role_name or '—' }}</td>
          <td title="{{ a.scope }}">{{ truncate_scope(a.scope) }}</td>
          <td></td>
        </tr>
        {% endfor %}
        {% for a in removed %}
        <tr>
          <td><span class="badge badge-removed">REMOVED</span></td>
          <td>{% if a.principal_display_name %}{{ a.principal_display_name }}<br><small>{{ a.principal_id }}</small>{% else %}{{ a.principal_id }}{% endif %}</td>
          <td>{{ a.role_name or '—' }}</td>
          <td title="{{ a.scope }}">{{ truncate_scope(a.scope) }}</td>
          <td></td>
        </tr>
        {% endfor %}
        {% for change in modified_groups %}
        <tr>
          <td><span class="badge badge-modified">MODIFIED</span></td>
          <td><small>{{ change.assignment_id }}</small></td>
          <td></td>
          <td></td>
          <td>{% for c in change.changes %}{{ c.field }}: {{ c.old_value }} → {{ c.new_value }}{% if not loop.last %}<br>{% endif %}{% endfor %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% set total_changes = added_count + removed_count + modified_count %}
  <div class="verdict {{ 'verdict-ok' if total_changes == 0 else 'verdict-ko' }}">
    {% if total_changes == 0 %}
      No changes detected between snapshots
    {% else %}
      {{ total_changes }} change(s) detected
    {% endif %}
  </div>

  <div class="footer">Azure Permissions Watch — generated from snapshots comparison</div>
</div>
</body>
</html>
"""


def _truncate_scope(scope: str, max_segments: int = 2) -> str:
    """Truncate an ARM scope keeping the last N segments + ellipsis."""
    parts = scope.strip("/").split("/")
    if len(parts) <= max_segments * 2:
        return scope
    tail = "/".join(parts[-(max_segments * 2):])
    return f".../{tail}"


def format_diff_html(
    result: DiffResult,
    old_snapshot: Snapshot,
    new_snapshot: Snapshot,
    output_path: Path,
) -> None:
    """Generate a standalone HTML report for a snapshot diff."""
    # Group modified changes by assignment_id for display
    from dataclasses import dataclass, field as dc_field

    @dataclass
    class ModifiedGroup:
        assignment_id: str
        changes: list[DiffChange] = dc_field(default_factory=list)

    groups: dict[str, ModifiedGroup] = {}
    for c in result.modified:
        if c.assignment_id not in groups:
            groups[c.assignment_id] = ModifiedGroup(assignment_id=c.assignment_id)
        groups[c.assignment_id].changes.append(c)

    env = Environment(autoescape=True)
    env.globals["truncate_scope"] = _truncate_scope
    template = env.from_string(_DIFF_HTML_TEMPLATE)

    html = template.render(
        tenant_id=old_snapshot.metadata.tenant_id,
        old_timestamp=old_snapshot.metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        new_timestamp=new_snapshot.metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        added=result.added,
        removed=result.removed,
        modified_groups=list(groups.values()),
        added_count=result.added_count,
        removed_count=result.removed_count,
        modified_count=result.modified_count,
        has_changes=result.has_changes,
    )

    output_path.write_text(html, encoding="utf-8")
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_diff_report.py -v`
Expected: ALL PASSED

**Step 5: Run linters**

Run: `.venv/bin/python -m ruff check src/az_rbac_watch/reporters/diff_report.py && .venv/bin/python -m mypy src/az_rbac_watch/reporters/diff_report.py`
Expected: PASS

**Step 6: Commit**

```bash
git add src/az_rbac_watch/reporters/diff_report.py tests/test_diff_report.py
git commit -m "feat: add HTML report for snapshot diffs"
```

---

### Task 2: Wire HTML output in CLI diff command

**Files:**
- Modify: `src/az_rbac_watch/cli.py:985-1033`
- Test: `tests/test_cli.py`

**Step 1: Write the failing test**

Add to `tests/test_cli.py` (find the existing diff CLI tests and add alongside):

```python
def test_diff_html_output(tmp_path, old_snapshot_path, new_snapshot_path):
    """diff --output report.html produces an HTML file."""
    out = tmp_path / "diff.html"
    result = runner.invoke(app, [
        "diff", str(old_snapshot_path), str(new_snapshot_path),
        "--output", str(out),
    ])
    assert out.exists()
    html = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "Change Report" in html
```

Note: check how existing diff CLI tests set up snapshot fixtures (`old_snapshot_path`, `new_snapshot_path`). If they don't exist, create them using the existing `_make_sa` pattern and `save_snapshot`.

**Step 2: Update CLI**

In `src/az_rbac_watch/cli.py`, modify the `diff_snapshots` function:

1. Accept `html` as a format — update the validation:

```python
    if fmt not in ("console", "json", "html"):
        console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console', 'json', or 'html'.")
        raise typer.Exit(code=2)
```

2. Auto-detect HTML from output path extension when format is not explicitly set. After loading snapshots and computing diff:

```python
    # Auto-detect HTML from output extension
    effective_fmt = fmt
    if output is not None and fmt == "console" and output.suffix.lower() == ".html":
        effective_fmt = "html"

    if effective_fmt == "html":
        if output is None:
            console.print("[bold red]Error[/bold red]: HTML format requires --output.")
            raise typer.Exit(code=2)
        from az_rbac_watch.reporters.diff_report import format_diff_html
        format_diff_html(result, old, new, output)
        console.print(f"Diff report written to: [bold]{output}[/bold]")
    elif effective_fmt == "json":
        text = format_diff_json(result)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            console.print(f"Diff report written to: [bold]{output}[/bold]")
        else:
            print(text)  # noqa: T201
    else:
        text = format_diff_console(result)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            console.print(f"Diff report written to: [bold]{output}[/bold]")
        else:
            print(text)  # noqa: T201

    raise typer.Exit(code=1 if result.has_changes else 0)
```

3. Update the help string for `--format`:

```python
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json, html."),
    ] = "console",
```

**Step 3: Run tests**

Run: `.venv/bin/python -m pytest tests/test_cli.py -v -k diff`
Expected: PASS

**Step 4: Run full test suite**

Run: `.venv/bin/python -m pytest --cov=az_rbac_watch --cov-fail-under=80`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/az_rbac_watch/cli.py tests/test_cli.py
git commit -m "feat: wire HTML output for diff command"
```

---

### Task 3: Update GitHub Action and README

**Files:**
- Modify: `action.yml`
- Modify: `README.md`

**Step 1: Update action.yml format input description**

In `action.yml`, update the format input description:

```yaml
  format:
    description: "Output format: console, json, or html (diff only)"
```

**Step 2: Update README diff command table**

In the `### az-rbac-watch diff` section, update the format option:

```markdown
| `-f, --format FORMAT` | `console` (default), `json`, or `html` |
```

Add a note: "HTML format is auto-detected when `--output` ends with `.html`."

**Step 3: Update the GitHub Actions "Available modes" table**

No change needed — diff mode was already listed.

**Step 4: Commit**

```bash
git add action.yml README.md
git commit -m "docs: update format options for diff HTML support"
```

---

### Task 4: Final verification

**Step 1: Run full test suite with coverage**

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
