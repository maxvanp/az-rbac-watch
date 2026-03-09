# v0.8.0 — Azure Portal Links Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add clickable Azure Portal links for scopes and principals in all report formats (HTML, console, JSON).

**Architecture:** New `utils/portal_links.py` module with two pure URL-builder functions. Each reporter is updated to call these functions and render links in its own format (HTML `<a>`, Rich `[link=]`, JSON fields). No model changes — URLs are computed at render time.

**Tech Stack:** Python, regex for ARM scope parsing, Rich link markup, Jinja2 template updates

---

### Task 1: Portal link builders

**Files:**
- Create: `src/az_rbac_watch/utils/portal_links.py`
- Create: `tests/test_portal_links.py`

**Step 1: Write the failing tests**

Create `tests/test_portal_links.py`:

```python
"""Tests for Azure Portal URL builders."""

from __future__ import annotations

from az_rbac_watch.utils.portal_links import build_principal_url, build_scope_url


class TestBuildScopeUrl:
    def test_subscription(self) -> None:
        url = build_scope_url("/subscriptions/sub-123", "tenant-abc")
        assert url == "https://portal.azure.com/#@tenant-abc/resource/subscriptions/sub-123/overview"

    def test_resource_group(self) -> None:
        url = build_scope_url(
            "/subscriptions/sub-123/resourceGroups/rg-infra",
            "tenant-abc",
        )
        assert url == (
            "https://portal.azure.com/#@tenant-abc/resource"
            "/subscriptions/sub-123/resourceGroups/rg-infra/overview"
        )

    def test_management_group(self) -> None:
        url = build_scope_url(
            "/providers/Microsoft.Management/managementGroups/mg-prod",
            "tenant-abc",
        )
        assert url == (
            "https://portal.azure.com/#view/Microsoft_Azure_ManagementGroups"
            "/ManagmentGroupDrilldownMenuBlade/~/overview"
            "/tenantId/tenant-abc/mgId/mg-prod"
        )

    def test_deep_resource_scope(self) -> None:
        """Deep ARM paths (below RG) still get a link to the full resource."""
        url = build_scope_url(
            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
            "tenant-abc",
        )
        assert url is not None
        assert "sub-1" in url

    def test_unknown_scope(self) -> None:
        url = build_scope_url("/something/weird", "tenant-abc")
        assert url is None

    def test_empty_scope(self) -> None:
        url = build_scope_url("", "tenant-abc")
        assert url is None

    def test_case_insensitive(self) -> None:
        url = build_scope_url("/Subscriptions/SUB-123", "tenant-abc")
        assert url is not None
        assert "SUB-123" in url


class TestBuildPrincipalUrl:
    def test_normal_id(self) -> None:
        url = build_principal_url("aaaa-bbbb-cccc")
        assert url == (
            "https://portal.azure.com/#view/Microsoft_AAD_IAM"
            "/ManagedAppMenuBlade/~/Overview/objectId/aaaa-bbbb-cccc"
        )

    def test_empty_id(self) -> None:
        url = build_principal_url("")
        assert url is None

    def test_none_like(self) -> None:
        url = build_principal_url("")
        assert url is None
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_portal_links.py -v`
Expected: FAIL with `ModuleNotFoundError`

**Step 3: Write implementation**

Create `src/az_rbac_watch/utils/portal_links.py`:

```python
"""Azure Portal URL builders for scopes and principals."""

from __future__ import annotations

import re

__all__ = ["build_principal_url", "build_scope_url"]

_PORTAL = "https://portal.azure.com"

_SUB_RE = re.compile(r"^/subscriptions/([^/]+)(/.*)?$", re.IGNORECASE)
_MG_RE = re.compile(
    r"^/providers/Microsoft\.Management/managementGroups/([^/]+)$",
    re.IGNORECASE,
)


def build_scope_url(scope: str, tenant_id: str) -> str | None:
    """Build an Azure Portal URL for an ARM scope.

    Supports subscriptions, resource groups, deep resource paths,
    and management groups. Returns None for unrecognized formats.
    """
    if not scope:
        return None

    mg = _MG_RE.match(scope)
    if mg:
        mg_id = mg.group(1)
        return (
            f"{_PORTAL}/#view/Microsoft_Azure_ManagementGroups"
            f"/ManagmentGroupDrilldownMenuBlade/~/overview"
            f"/tenantId/{tenant_id}/mgId/{mg_id}"
        )

    sub = _SUB_RE.match(scope)
    if sub:
        # Link to the full scope path (subscription, RG, or deeper resource)
        clean = scope.rstrip("/")
        return f"{_PORTAL}/#@{tenant_id}/resource{clean}/overview"

    return None


def build_principal_url(principal_id: str) -> str | None:
    """Build an Azure Portal URL for an Entra ID principal.

    Returns None if principal_id is empty.
    """
    if not principal_id:
        return None
    return (
        f"{_PORTAL}/#view/Microsoft_AAD_IAM"
        f"/ManagedAppMenuBlade/~/Overview/objectId/{principal_id}"
    )
```

**Step 4: Update `__all__` in `src/az_rbac_watch/utils/__init__.py`** if needed (check the file).

**Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_portal_links.py -v`
Expected: ALL PASSED

**Step 6: Run linters**

Run: `.venv/bin/python -m ruff check src/az_rbac_watch/utils/portal_links.py tests/test_portal_links.py && .venv/bin/python -m mypy src/az_rbac_watch/utils/portal_links.py`
Expected: PASS

**Step 7: Commit**

```bash
git add src/az_rbac_watch/utils/portal_links.py tests/test_portal_links.py
git commit -m "feat: add Azure Portal URL builders"
```

---

### Task 2: HTML compliance report — portal links

**Files:**
- Modify: `src/az_rbac_watch/reporters/html_report.py`
- Test: `tests/test_html_report.py`

**Step 1: Write the failing tests**

Add to `tests/test_html_report.py`:

```python
class TestHtmlPortalLinks:
    def test_scope_link_present(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "portal.azure.com" in html
        assert 'target="_blank"' in html

    def test_principal_link_present(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "ManagedAppMenuBlade" in html
        assert "user-1111" in html
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_html_report.py::TestHtmlPortalLinks -v`
Expected: FAIL

**Step 3: Update html_report.py**

3a. Add import:
```python
from az_rbac_watch.utils.portal_links import build_principal_url, build_scope_url
```

3b. In `generate_html_report`, register the URL builders as Jinja2 globals (after existing globals):
```python
    env.globals["build_scope_url"] = lambda s: build_scope_url(s, report.tenant_id)
    env.globals["build_principal_url"] = build_principal_url
```

3c. In the template, update the scope cell (inside the findings table `{% for f in g.findings %}` loop):
```html
          <td title="{{ f.scope }}">
            {%- set scope_url = build_scope_url(f.scope) -%}
            {%- if scope_url -%}
              <a href="{{ scope_url }}" target="_blank" style="color:#0078d4;text-decoration:none">{{ truncate_scope(f.scope) }}</a>
            {%- else -%}
              {{ truncate_scope(f.scope) }}
            {%- endif -%}
            {%- if f.details.get('remediation') %}
            <div class="remediation">{{ f.details['remediation'] }}</div>
            {%- endif %}
          </td>
```

3d. Update the principal cell:
```html
          <td>
            {%- set principal_url = build_principal_url(f.principal_id) -%}
            {%- if f.principal_display_name -%}
              {%- if principal_url -%}
                <a href="{{ principal_url }}" target="_blank" style="color:#0078d4;text-decoration:none">{{ f.principal_display_name }}</a><br><small>{{ f.principal_id }}</small>
              {%- else -%}
                {{ f.principal_display_name }}<br><small>{{ f.principal_id }}</small>
              {%- endif -%}
            {%- else -%}
              {%- if principal_url -%}
                <a href="{{ principal_url }}" target="_blank" style="color:#0078d4;text-decoration:none">{{ f.principal_id }}</a>
              {%- else -%}
                {{ f.principal_id }}
              {%- endif -%}
            {%- endif -%}
          </td>
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_html_report.py -v`
Expected: ALL PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/html_report.py tests/test_html_report.py
git commit -m "feat: add portal links to HTML compliance report"
```

---

### Task 3: HTML diff report — portal links

**Files:**
- Modify: `src/az_rbac_watch/reporters/diff_report.py`
- Test: `tests/test_diff_report.py`

**Step 1: Write the failing tests**

Add to `tests/test_diff_report.py`:

```python
class TestDiffHtmlPortalLinks:
    def test_scope_link_in_added(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "portal.azure.com" in html
        assert 'target="_blank"' in html

    def test_principal_link_in_added(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "ManagedAppMenuBlade" in html
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_diff_report.py::TestDiffHtmlPortalLinks -v`
Expected: FAIL

**Step 3: Update diff_report.py**

3a. Add import:
```python
from az_rbac_watch.utils.portal_links import build_principal_url, build_scope_url
```

3b. In `format_diff_html`, register globals:
```python
    env.globals["build_scope_url"] = lambda s: build_scope_url(s, old_snapshot.metadata.tenant_id)
    env.globals["build_principal_url"] = build_principal_url
```

3c. Update the added/removed scope cell in `_DIFF_HTML_TEMPLATE`:
```html
          <td title="{{ a.scope }}">
            {%- set scope_url = build_scope_url(a.scope) -%}
            {%- if scope_url -%}
              <a href="{{ scope_url }}" target="_blank" style="color:#0078d4;text-decoration:none">{{ truncate_scope(a.scope) }}</a>
            {%- else -%}
              {{ truncate_scope(a.scope) }}
            {%- endif -%}
          </td>
```

3d. Update the added/removed principal cell:
```html
          <td>
            {%- set principal_url = build_principal_url(a.principal_id) -%}
            {%- if a.principal_display_name -%}
              {%- if principal_url -%}
                <a href="{{ principal_url }}" target="_blank" style="color:#0078d4;text-decoration:none">{{ a.principal_display_name }}</a><br><small>{{ a.principal_id }}</small>
              {%- else -%}
                {{ a.principal_display_name }}<br><small>{{ a.principal_id }}</small>
              {%- endif -%}
            {%- else -%}
              {%- if principal_url -%}
                <a href="{{ principal_url }}" target="_blank" style="color:#0078d4;text-decoration:none">{{ a.principal_id }}</a>
              {%- else -%}
                {{ a.principal_id }}
              {%- endif -%}
            {%- endif -%}
          </td>
```

**Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_diff_report.py -v`
Expected: ALL PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/diff_report.py tests/test_diff_report.py
git commit -m "feat: add portal links to HTML diff report"
```

---

### Task 4: Console report — Rich portal links

**Files:**
- Modify: `src/az_rbac_watch/reporters/console_report.py`
- Test: `tests/test_console_report.py`

**Step 1: Write the failing tests**

Check existing tests first. Add to `tests/test_console_report.py`:

```python
class TestConsolePortalLinks:
    def test_scope_link_in_output(self) -> None:
        """Rich link markup appears for scope."""
        report = _make_report_with_findings()
        console = Console(file=StringIO())
        print_drift_report(report, console=console)
        output = console.file.getvalue()
        assert "portal.azure.com" in output

    def test_principal_link_in_output(self) -> None:
        """Rich link markup appears for principal."""
        report = _make_report_with_findings()
        console = Console(file=StringIO())
        print_drift_report(report, console=console)
        output = console.file.getvalue()
        assert "ManagedAppMenuBlade" in output or "portal.azure.com" in output
```

Note: Check how existing console tests create reports and import helpers. Adapt accordingly.

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_console_report.py::TestConsolePortalLinks -v`
Expected: FAIL

**Step 3: Update console_report.py**

3a. Add import:
```python
from az_rbac_watch.utils.portal_links import build_principal_url, build_scope_url
```

3b. In `_print_report`, update the scope cell construction (around line 105):
```python
            scope_url = build_scope_url(f.scope, report.tenant_id)
            if scope_url:
                scope_cell = f"[link={scope_url}]{f.scope}[/link]"
            else:
                scope_cell = f.scope
            if remediation:
                scope_cell = f"{scope_cell}\n[dim]Remediation : {remediation}[/dim]"
```

3c. Update the principal cell construction (around line 101):
```python
            principal_url = build_principal_url(f.principal_id)
            if f.principal_display_name:
                if principal_url:
                    principal_cell = f"[link={principal_url}]{f.principal_display_name}[/link]\n({f.principal_id})"
                else:
                    principal_cell = f"{f.principal_display_name}\n({f.principal_id})"
            else:
                if principal_url:
                    principal_cell = f"[link={principal_url}]{f.principal_id}[/link]"
                else:
                    principal_cell = f.principal_id
```

**Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_console_report.py -v`
Expected: ALL PASSED

**Step 5: Commit**

```bash
git add src/az_rbac_watch/reporters/console_report.py tests/test_console_report.py
git commit -m "feat: add portal links to console report"
```

---

### Task 5: JSON report — portal URL fields

**Files:**
- Modify: `src/az_rbac_watch/reporters/json_report.py`
- Test: `tests/test_html_report.py` or create `tests/test_json_report.py`

**Step 1: Write the failing tests**

Check if `tests/test_json_report.py` exists. If not, add tests where appropriate.

```python
import json

from az_rbac_watch.reporters.json_report import generate_json_report


class TestJsonPortalLinks:
    def test_scope_url_in_findings(self) -> None:
        report = _report_with_findings()  # reuse or create fixture
        output = generate_json_report(report)
        data = json.loads(output)
        finding = data["findings"][0]
        assert "scope_url" in finding
        assert "portal.azure.com" in finding["scope_url"]

    def test_principal_url_in_findings(self) -> None:
        report = _report_with_findings()
        output = generate_json_report(report)
        data = json.loads(output)
        finding = data["findings"][0]
        assert "principal_url" in finding
        assert "ManagedAppMenuBlade" in finding["principal_url"]
```

**Step 2: Update json_report.py**

The current implementation uses `report.model_dump(mode="json")` which serializes the Pydantic model directly. We need to post-process the findings to add URL fields:

```python
from az_rbac_watch.utils.portal_links import build_principal_url, build_scope_url


def generate_json_report(report: ComplianceReport) -> str:
    """Serialize a ComplianceReport to a JSON string."""
    data = report.model_dump(mode="json")
    tenant_id = report.tenant_id
    for finding in data.get("findings", []):
        finding["scope_url"] = build_scope_url(finding.get("scope", ""), tenant_id)
        finding["principal_url"] = build_principal_url(finding.get("principal_id", ""))
    return json.dumps(data, indent=2, ensure_ascii=False)
```

**Step 3: Run tests**

Run: `.venv/bin/python -m pytest tests/ -v -k json`
Expected: PASS

**Step 4: Commit**

```bash
git add src/az_rbac_watch/reporters/json_report.py tests/test_json_report.py
git commit -m "feat: add portal URLs to JSON report"
```

---

### Task 6: Final verification

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
