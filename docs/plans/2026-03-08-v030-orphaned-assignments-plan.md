# v0.3.0 Orphaned Assignment Detection — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect RBAC assignments whose principal has been deleted from Entra ID and report them as `ORPHANED_ASSIGNMENT` findings (severity HIGH), both in normal scans and via a standalone `--orphans-only` mode.

**Architecture:** Orphan detection happens in the compliance engine (`compliance.py`) by checking if an assignment has an empty/unknown principal type. A new `_check_orphans()` function produces findings that are merged into existing reports. The CLI gets a `--orphans-only` flag on `scan` that skips policy loading and only reports orphans.

**Tech Stack:** Python 3.12, Pydantic v2, Typer, pytest, ruff, mypy.

---

## Task 1: Add `ORPHANED_ASSIGNMENT` constant and `_check_orphans()` to compliance engine

**Files:**
- Modify: `src/az_rbac_watch/analyzers/compliance.py`
- Test: `tests/test_compliance.py`

**Step 1: Write the failing tests**

Add to `tests/test_compliance.py`:

```python
from az_rbac_watch.analyzers.compliance import (
    ORPHANED_ASSIGNMENT,
    _check_orphans,
)

# ── TestOrphanDetection ──────────────────────────────────────


class TestOrphanDetection:
    """Tests for orphaned assignment detection."""

    def test_orphaned_assignment_constant(self):
        assert ORPHANED_ASSIGNMENT == "ORPHANED_ASSIGNMENT"

    def test_empty_principal_type_is_orphan(self):
        """An assignment with principal_type UNKNOWN is orphaned."""
        a = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Reader",
            principal_display_name=None,
        )
        findings = _check_orphans([a])
        assert len(findings) == 1
        assert findings[0].rule_id == ORPHANED_ASSIGNMENT
        assert findings[0].severity == Severity.HIGH

    def test_normal_assignment_not_orphan(self):
        """An assignment with a valid principal_type is NOT orphaned."""
        a = make_assignment(
            principal_type=PrincipalType.USER,
            role_name="Reader",
            principal_display_name="Alice",
        )
        findings = _check_orphans([a])
        assert len(findings) == 0

    def test_orphan_with_no_role_name_still_detected(self):
        """Orphans with role_name=None should still be detected."""
        a = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name=None,
        )
        findings = _check_orphans([a])
        assert len(findings) == 1

    def test_orphan_finding_contains_principal_id(self):
        """The finding should contain the principal_id (only remaining identifier)."""
        a = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Contributor",
            principal_id="dead-beef-dead-beef",
        )
        findings = _check_orphans([a])
        assert findings[0].principal_id == "dead-beef-dead-beef"
        assert findings[0].role_name == "Contributor"

    def test_multiple_orphans(self):
        """Multiple orphaned assignments produce multiple findings."""
        a1 = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Reader",
            assignment_id="orphan-1",
        )
        a2 = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Contributor",
            assignment_id="orphan-2",
        )
        normal = make_assignment(
            principal_type=PrincipalType.USER,
            role_name="Reader",
            assignment_id="normal-1",
        )
        findings = _check_orphans([a1, a2, normal])
        assert len(findings) == 2

    def test_orphan_remediation_hint(self):
        """Orphan findings should include a remediation hint."""
        a = make_assignment(principal_type=PrincipalType.UNKNOWN, role_name="Reader")
        findings = _check_orphans([a])
        assert "remediation" in findings[0].details
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_compliance.py::TestOrphanDetection -v
```

Expected: FAIL — `ORPHANED_ASSIGNMENT` and `_check_orphans` not importable.

**Step 3: Implement `_check_orphans()` in compliance.py**

Add to `src/az_rbac_watch/analyzers/compliance.py`:

1. Add constant after the existing `GOVERNANCE_VIOLATION` line (~line 45):
```python
ORPHANED_ASSIGNMENT = "ORPHANED_ASSIGNMENT"
```

2. Add to `__all__`:
```python
"ORPHANED_ASSIGNMENT",
"_check_orphans",
```

3. Add the `_check_orphans` function (after `_check_drift`, ~line 272):

```python
def _check_orphans(
    assignments: list[ScannedRoleAssignment],
) -> list[ComplianceFinding]:
    """Detect orphaned assignments — principal deleted from Entra ID.

    An assignment is orphaned when its principal_type is UNKNOWN,
    meaning the principal no longer exists in the directory.
    """
    findings: list[ComplianceFinding] = []
    for a in assignments:
        if a.principal_type != PrincipalType.UNKNOWN:
            continue
        role_display = a.role_name or "(unknown role)"
        findings.append(
            ComplianceFinding(
                rule_id=ORPHANED_ASSIGNMENT,
                severity=Severity.HIGH,
                message=(
                    f"Orphaned assignment: principal {a.principal_id} "
                    f"no longer exists in Entra ID — "
                    f"role {role_display} at {a.scope}"
                ),
                assignment_id=a.id,
                scope=a.scope,
                principal_id=a.principal_id,
                principal_display_name="",
                principal_type=str(a.principal_type),
                role_name=a.role_name or "",
                details={
                    "remediation": "Remove this role assignment — the principal no longer exists",
                },
            )
        )
    return findings
```

4. Add import of `PrincipalType` at top of file:
```python
from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    ScannedRoleAssignment,
)
```

**Step 4:** Run tests to verify they pass:

```bash
.venv/bin/python -m pytest tests/test_compliance.py::TestOrphanDetection -v
```

Expected: all 7 pass.

**Step 5:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/analyzers/ tests/test_compliance.py && .venv/bin/mypy src/az_rbac_watch/analyzers/ tests/test_compliance.py
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/analyzers/compliance.py tests/test_compliance.py
git commit -m "feat: add orphaned assignment detection to compliance engine"
```

---

## Task 2: Integrate orphan detection into `check_drift`, `check_violations`, and `check_compliance`

**Files:**
- Modify: `src/az_rbac_watch/analyzers/compliance.py`
- Test: `tests/test_compliance.py`

**Step 1: Write the failing tests**

Add to `tests/test_compliance.py`:

```python
from az_rbac_watch.analyzers.compliance import (
    ORPHANED_ASSIGNMENT,
    check_compliance,
    check_drift,
    check_violations,
)


class TestOrphanIntegration:
    """Orphan detection is included in all check_* entry points."""

    def test_check_drift_includes_orphans(self):
        """check_drift should also report orphaned assignments."""
        orphan = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Reader",
            assignment_id="orphan-1",
        )
        normal = make_assignment(
            principal_type=PrincipalType.USER,
            role_name="Reader",
            assignment_id="normal-1",
            principal_id=VALID_PRINCIPAL_USER,
        )
        policy = make_policy(rules=[{
            "name": "allow-reader",
            "type": "baseline",
            "match": {"principal_id": VALID_PRINCIPAL_USER, "role": "Reader"},
        }])
        scan_result = make_scan_result(assignments=[orphan, normal])
        report = check_drift(policy, scan_result)
        orphan_findings = [f for f in report.findings if f.rule_id == ORPHANED_ASSIGNMENT]
        assert len(orphan_findings) == 1

    def test_check_violations_includes_orphans(self):
        """check_violations should also report orphaned assignments."""
        orphan = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Owner",
            assignment_id="orphan-1",
        )
        policy = make_policy(rules=[{
            "name": "no-owner",
            "type": "governance",
            "severity": "critical",
            "match": {"role": "Owner"},
        }])
        scan_result = make_scan_result(assignments=[orphan])
        report = check_violations(policy, scan_result)
        orphan_findings = [f for f in report.findings if f.rule_id == ORPHANED_ASSIGNMENT]
        assert len(orphan_findings) == 1

    def test_check_compliance_includes_orphans(self):
        """check_compliance should include orphans alongside drift and violations."""
        orphan = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Contributor",
            assignment_id="orphan-1",
        )
        policy = make_policy(rules=[
            {"name": "baseline", "type": "baseline", "match": {"role": "Reader"}},
            {"name": "no-owner", "type": "governance", "severity": "high", "match": {"role": "Owner"}},
        ])
        scan_result = make_scan_result(assignments=[orphan])
        report = check_compliance(policy, scan_result)
        orphan_findings = [f for f in report.findings if f.rule_id == ORPHANED_ASSIGNMENT]
        assert len(orphan_findings) == 1

    def test_summary_counts_orphans(self):
        """Orphan findings should be counted in summary.total_findings."""
        orphan = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Reader",
        )
        policy = make_policy()
        scan_result = make_scan_result(assignments=[orphan])
        report = check_drift(policy, scan_result)
        assert report.summary.total_findings >= 1
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_compliance.py::TestOrphanIntegration -v
```

Expected: FAIL — orphans not yet included in check_drift/check_violations.

**Step 3: Modify the three entry points**

In `src/az_rbac_watch/analyzers/compliance.py`:

1. In `check_drift()` (~line 307), add orphan detection after drift findings:
```python
def check_drift(
    policy: PolicyModel,
    scan_result: RbacScanResult,
) -> ComplianceReport:
    assignments = scan_result.all_assignments
    baseline_rules = [r for r in policy.rules if r.type == "baseline"]
    findings = _check_drift(baseline_rules, assignments)
    findings.extend(_check_orphans(assignments))
    return _build_report(policy, scan_result, findings)
```

2. In `check_violations()` (~line 322), add orphan detection:
```python
def check_violations(
    policy: PolicyModel,
    scan_result: RbacScanResult,
) -> ComplianceReport:
    assignments = scan_result.all_assignments
    governance_rules = [r for r in policy.rules if r.type == "governance"]
    findings = _check_governance_rules(governance_rules, assignments)
    findings.extend(_check_orphans(assignments))
    return _build_report(policy, scan_result, findings)
```

3. In `check_compliance()` (~line 337), add orphan detection:
```python
def check_compliance(
    policy: PolicyModel,
    scan_result: RbacScanResult,
) -> ComplianceReport:
    assignments = scan_result.all_assignments
    governance_rules = [r for r in policy.rules if r.type == "governance"]
    baseline_rules = [r for r in policy.rules if r.type == "baseline"]
    findings: list[ComplianceFinding] = []
    findings.extend(_check_governance_rules(governance_rules, assignments))
    findings.extend(_check_drift(baseline_rules, assignments))
    findings.extend(_check_orphans(assignments))
    return _build_report(policy, scan_result, findings)
```

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_compliance.py -v
```

Expected: all pass (existing + new).

**Step 5:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/analyzers/ tests/test_compliance.py && .venv/bin/mypy src/az_rbac_watch/analyzers/ tests/test_compliance.py
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/analyzers/compliance.py tests/test_compliance.py
git commit -m "feat: integrate orphan detection into check_drift, check_violations, check_compliance"
```

---

## Task 3: Add `--orphans-only` flag to the `scan` CLI command

**Files:**
- Modify: `src/az_rbac_watch/cli.py`
- Test: `tests/test_cli.py`

**Step 1: Write the failing tests**

Add to `tests/test_cli.py`. First, check the existing test pattern:

The CLI tests use `typer.testing.CliRunner`. Add these tests:

```python
from az_rbac_watch.analyzers.compliance import ORPHANED_ASSIGNMENT


class TestOrphansOnlyFlag:
    """Tests for the --orphans-only flag on the scan command."""

    def test_orphans_only_requires_tenant_id(self, runner):
        """--orphans-only without --tenant-id should error."""
        result = runner.invoke(app, ["scan", "--orphans-only"])
        assert result.exit_code == 2
        assert "tenant" in result.output.lower() or "tenant" in (result.stderr or "").lower()

    def test_orphans_only_incompatible_with_policy(self, runner, tmp_path):
        """--orphans-only and --policy are mutually exclusive."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            'version: "2.0"\ntenant_id: "11111111-1111-1111-1111-111111111111"\n'
        )
        result = runner.invoke(app, ["scan", "--orphans-only", "-p", str(policy_file)])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.check_credentials", return_value=True)
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.resolve_display_names")
    def test_orphans_only_with_auto_discovery(
        self, mock_resolve, mock_scan, mock_list_subs, mock_creds, runner
    ):
        """--orphans-only with -t auto-discovers subscriptions and reports orphans."""
        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Test-Sub", VALID_TENANT_ID),
        ]
        orphan_assignment = ScannedRoleAssignment(
            id="orphan-1",
            scope=f"/subscriptions/{VALID_SUB_ID}",
            role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/fake",
            principal_id="dead-beef",
            principal_type=PrincipalType.UNKNOWN,
            role_name="Reader",
            role_type=RoleType.BUILT_IN,
        )
        scan_result = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Test-Sub",
                    assignments=[orphan_assignment],
                )
            ]
        )
        mock_scan.return_value = scan_result
        mock_resolve.return_value = scan_result

        result = runner.invoke(app, [
            "scan", "--orphans-only",
            "-t", VALID_TENANT_ID,
            "--format", "json",
        ])
        assert result.exit_code == 1  # findings detected
        assert "ORPHANED_ASSIGNMENT" in result.output
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_cli.py::TestOrphansOnlyFlag -v
```

Expected: FAIL — `--orphans-only` flag doesn't exist yet.

**Step 3: Add `--orphans-only` flag to scan command**

In `src/az_rbac_watch/cli.py`:

1. Add the `--orphans-only` parameter to the `scan` function (~line 449):

```python
    orphans_only: Annotated[
        bool,
        typer.Option("--orphans-only", help="Scan for orphaned assignments only (no policy file needed)."),
    ] = False,
```

2. Add validation after `_setup_logging(verbose)` (~line 501):

```python
    # --orphans-only validations
    if orphans_only and policy is not None:
        console.print(
            "[bold red]Error[/bold red]: --orphans-only and --policy are mutually exclusive."
        )
        raise typer.Exit(code=2)

    if orphans_only and not tenant_id:
        console.print(
            "[bold red]Error[/bold red]: --orphans-only requires --tenant-id / -t."
        )
        raise typer.Exit(code=2)
```

3. Add orphans-only scan logic before the normal scan flow (after the validations above):

```python
    if orphans_only:
        if not dry_run:
            _check_credentials_or_exit()

        # Build ad-hoc model for orphan scanning
        model = _build_model_from_args(tenant_id, subscription, management_group)
        model = _resolve_and_filter_model(model, exclude_subscription, exclude_management_group)
        _validate_scopes_or_exit(model)

        if dry_run:
            _print_dry_run_plan(model)
            raise typer.Exit(code=0)

        scan_result = _run_scan(model, fmt=fmt)
        scan_result = _resolve_names(scan_result, fmt=fmt)

        # Only check for orphans — no drift, no governance
        from az_rbac_watch.analyzers.compliance import _check_orphans, _build_report

        orphan_findings = _check_orphans(scan_result.all_assignments)
        report = _build_report(model, scan_result, orphan_findings)

        _output_report(
            report,
            fmt=fmt,
            output=output,
            model=model,
            console_printer=print_drift_report,
            html_mode="scan",
        )

        if fmt == "console":
            code = _exit_code(report)
            if code == 1:
                n = report.summary.total_findings
                console.print(f"\n[dim]{n} orphaned assignment(s) found. Remove them with:\n  az role assignment delete --ids <assignment-id>[/dim]")
            elif code == 0:
                console.print("\n[dim]No orphaned assignments found.[/dim]")

        raise typer.Exit(code=_exit_code(report))
```

4. Move the `_check_credentials_or_exit()` call for the normal flow to after the orphans-only block (since orphans-only handles it internally):

The existing `_check_credentials_or_exit()` call at line 515 needs to stay where it is for the normal flow. The orphans-only block returns early via `raise typer.Exit`, so the normal flow code after it remains unchanged.

5. Add `_build_report` and `_check_orphans` to the imports from compliance (or use lazy import as shown above).

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_cli.py::TestOrphansOnlyFlag -v
```

Expected: all pass.

**Step 5:** Run full test suite:

```bash
.venv/bin/python -m pytest -q
```

Expected: all pass (401+ tests).

**Step 6:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/cli.py tests/test_cli.py && .venv/bin/mypy src/az_rbac_watch/cli.py tests/test_cli.py
```

**Step 7:** Commit:

```bash
git add src/az_rbac_watch/cli.py tests/test_cli.py
git commit -m "feat: add --orphans-only flag to scan command"
```

---

## Task 4: Update `__all__` exports and add `ComplianceSummary.orphan_count`

**Files:**
- Modify: `src/az_rbac_watch/analyzers/compliance.py`
- Test: `tests/test_compliance.py`

**Step 1: Write the failing test**

```python
class TestOrphanSummaryCount:
    def test_summary_has_orphan_count(self):
        """ComplianceSummary should have an orphan_count field."""
        orphan = make_assignment(
            principal_type=PrincipalType.UNKNOWN,
            role_name="Reader",
        )
        policy = make_policy()
        scan_result = make_scan_result(assignments=[orphan])
        report = check_drift(policy, scan_result)
        assert report.summary.orphan_count == 1

    def test_summary_orphan_count_zero(self):
        """orphan_count should be 0 when no orphans."""
        normal = make_assignment(
            principal_type=PrincipalType.USER,
            role_name="Reader",
        )
        policy = make_policy(rules=[{
            "name": "allow-reader",
            "type": "baseline",
            "match": {"principal_id": VALID_PRINCIPAL_USER, "role": "Reader"},
        }])
        scan_result = make_scan_result(assignments=[normal])
        report = check_drift(policy, scan_result)
        assert report.summary.orphan_count == 0
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_compliance.py::TestOrphanSummaryCount -v
```

**Step 3: Add `orphan_count` to `ComplianceSummary`**

In `src/az_rbac_watch/analyzers/compliance.py`:

1. Add field to `ComplianceSummary` (~line 83):
```python
class ComplianceSummary(BaseModel):
    total_assignments_checked: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    drift_count: int = 0
    violation_count: int = 0
    orphan_count: int = 0
```

2. Update `_build_report()` to compute `orphan_count` (~line 275):
```python
def _build_report(
    policy: PolicyModel,
    scan_result: RbacScanResult,
    findings: list[ComplianceFinding],
) -> ComplianceReport:
    drift_count = sum(1 for f in findings if f.rule_id == DRIFT)
    orphan_count = sum(1 for f in findings if f.rule_id == ORPHANED_ASSIGNMENT)
    violation_count = sum(1 for f in findings if f.rule_id not in (DRIFT, ORPHANED_ASSIGNMENT))

    severity_counts = Counter(f.severity for f in findings)
    summary = ComplianceSummary(
        total_assignments_checked=len(scan_result.all_assignments),
        total_findings=len(findings),
        findings_by_severity={str(k): v for k, v in severity_counts.items()},
        drift_count=drift_count,
        violation_count=violation_count,
        orphan_count=orphan_count,
    )
    ...
```

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_compliance.py -v
```

**Step 5:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/analyzers/ && .venv/bin/mypy src/az_rbac_watch/analyzers/
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/analyzers/compliance.py tests/test_compliance.py
git commit -m "feat: add orphan_count to ComplianceSummary"
```

---

## Task 5: Final verification and full test suite

**Step 1:** Run all validations:

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check . && .venv/bin/mypy src/ tests/
```

Expected: all pass.

**Step 2:** Verify no French:

```bash
grep -rn '[àâéèêëîïôùûüç]' src/ tests/ --include='*.py'
```

Expected: no output.

**Step 3:** Quick smoke test — verify the new constant is accessible:

```bash
.venv/bin/python -c "from az_rbac_watch.analyzers.compliance import ORPHANED_ASSIGNMENT; print(ORPHANED_ASSIGNMENT)"
```

Expected: `ORPHANED_ASSIGNMENT`

**Step 4:** Verify `--orphans-only` flag appears in help:

```bash
.venv/bin/az-rbac-watch scan --help | grep orphans
```

Expected: `--orphans-only` shown in help output.

---

## Execution order summary

| Task | Component | Depends on |
|------|-----------|------------|
| 1 | `_check_orphans()` + constant | — |
| 2 | Integration into `check_*` entry points | 1 |
| 3 | `--orphans-only` CLI flag | 1, 2 |
| 4 | `orphan_count` in summary | 1, 2 |
| 5 | Final verification | 1-4 |

Tasks are sequential (each builds on the previous).
