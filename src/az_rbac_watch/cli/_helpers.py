"""CLI entry point for Azure Permissions Watch.

Commands:
- scan     : detect RBAC drift against the desired state (baseline rules)
- audit    : check governance guardrails (governance rules)
- discover : generate a draft policy model from the actual Azure state
- validate : validate a policy model YAML file (offline)
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal  # noqa: F401
from uuid import UUID

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn

from az_rbac_watch.analyzers.compliance import (
    ComplianceReport,
    check_drift,
    check_violations,
)
from az_rbac_watch.auth.azure_clients import (
    check_credentials,
    list_accessible_management_groups,
    list_accessible_subscriptions,
)
from az_rbac_watch.config.policy_model import (
    ManagementGroup,
    PolicyModel,
    Subscription,
    filter_scopes,
    load_policy_model,
    resolve_scopes,
    save_policy_model,
)
from az_rbac_watch.config.settings import Settings, load_settings
from az_rbac_watch.reporters.console_report import (
    print_audit_report,
    print_discover_summary,
    print_drift_report,
)
from az_rbac_watch.reporters.html_report import generate_framework_html_report, generate_html_report
from az_rbac_watch.reporters.json_report import generate_json_report
from az_rbac_watch.scanner.discovery import discover_policy
from az_rbac_watch.scanner.rbac_scanner import RbacScanResult, resolve_display_names, scan_rbac

__all__ = [
    # Re-exported for command modules
    "ComplianceReport",
    "Literal",
    "ManagementGroup",
    "PolicyModel",
    "RbacScanResult",
    "Settings",
    "Subscription",
    "check_credentials",
    "check_drift",
    "check_violations",
    "discover_policy",
    "filter_scopes",
    "generate_framework_html_report",
    "generate_html_report",
    "generate_json_report",
    "list_accessible_management_groups",
    "list_accessible_subscriptions",
    "load_policy_model",
    "load_settings",
    "print_audit_report",
    "print_discover_summary",
    "print_drift_report",
    "resolve_display_names",
    "resolve_scopes",
    "save_policy_model",
    "scan_rbac",
    "traceback",
]

# Noisy third-party loggers — kept at WARNING even with --verbose
_NOISY_LOGGERS = (
    "azure.identity",
    "azure.core",
    "msal",
    "urllib3",
    "httpcore",
    "httpx",
)

logger = logging.getLogger(__name__)

_debug_mode = False
_quiet_mode = False
_no_color_mode = False
_settings = Settings()


def _debug_callback(value: bool) -> None:
    """Enable debug mode (full traceback on error)."""
    global _debug_mode
    _debug_mode = value


console = Console(stderr=True)


def _load_policy_or_exit(policy_path: Path) -> PolicyModel:
    """Load and validate a policy model, or exit with an error message."""
    try:
        return load_policy_model(policy_path)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error[/bold red]: {e}")
        raise typer.Exit(code=2) from None
    except ValueError as e:
        console.print(f"[bold red]Validation error[/bold red]: {e}")
        raise typer.Exit(code=2) from None


def _validate_scopes_or_exit(model: PolicyModel) -> None:
    """Check that there are scopes to scan, or exit cleanly."""
    if not model.subscriptions and not model.management_groups:
        console.print("[yellow]No subscriptions or management groups in the policy model.[/yellow]")
        raise typer.Exit(code=0)


def _setup_logging(verbose: bool) -> None:
    """Configure logging — verbose enables DEBUG for az_rbac_watch, WARNING for third-party SDKs."""
    if not verbose:
        return
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def _check_credentials_or_exit() -> None:
    """Check Azure credentials before API calls."""
    if not check_credentials():
        console.print(
            "[bold red]Error[/bold red]: no Azure credentials found.\n\n"
            "Quick fix:\n"
            "  az login\n\n"
            "Then retry:\n"
            "  az-rbac-watch"
        )
        raise typer.Exit(code=2)


def _resolve_and_filter_model(
    model: PolicyModel,
    exclude_subscription: list[str] | None,
    exclude_management_group: list[str] | None,
) -> PolicyModel:
    """Resolve scopes if needed and apply CLI exclusions."""
    if model.scope == "all":
        console.print("[dim]Auto-discovering accessible scopes (scope: all)...[/dim]")
        model = resolve_scopes(model)

    if exclude_subscription or exclude_management_group:
        model = filter_scopes(model, exclude_subscription, exclude_management_group)

    return model


def _run_scan(
    model: PolicyModel,
    *,
    fmt: str,
) -> RbacScanResult:
    """Execute the RBAC scan with progress bar (console) or silently (json)."""
    if fmt == "json":
        return scan_rbac(model)

    total_scopes = len(model.subscriptions) + len(model.management_groups)
    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scan RBAC", total=total_scopes)

        def _on_progress(scope_type: str, scope_name: str) -> None:
            progress.update(task, description=f"Scanning {scope_type}: {scope_name}")
            progress.advance(task)

        return scan_rbac(model, progress_callback=_on_progress)


def _print_dry_run_plan(model: PolicyModel) -> None:
    """Print the dry-run plan: scopes and rules without calling Azure."""
    n_subs = len(model.subscriptions)
    n_mgs = len(model.management_groups)
    n_baseline = sum(1 for r in model.rules if r.type == "baseline")
    n_governance = sum(1 for r in model.rules if r.type == "governance")

    output_console = Console(no_color=_no_color_mode)
    output_console.print()
    output_console.print(
        f"[bold cyan]Dry run[/bold cyan] — would scan {n_subs} subscription(s), {n_mgs} management group(s)"
    )
    for sub in model.subscriptions:
        label = sub.name or str(sub.id)
        output_console.print(f"  subscription: {label} ({sub.id})")
    for mg in model.management_groups:
        label = mg.name or mg.id
        output_console.print(f"  management group: {label} ({mg.id})")
    output_console.print(f"  {n_baseline} baseline rule(s), {n_governance} governance rule(s)")
    output_console.print()


def _resolve_names(scan_result: RbacScanResult, *, fmt: str) -> RbacScanResult:
    """Resolve display names via Graph API."""
    try:
        if fmt != "json":
            with console.status("Resolving names via Graph API..."):
                return resolve_display_names(scan_result)
        else:
            return resolve_display_names(scan_result)
    except Exception as e:
        logger.warning("Name resolution failed: %s", e)
        return scan_result


def _output_report(
    report: ComplianceReport,
    *,
    fmt: str,
    output: Path | None,
    model: PolicyModel,
    console_printer: Callable[..., None],
    html_mode: Literal["scan", "audit", "combined"],
) -> None:
    """Output report in the requested format."""
    if fmt == "json":
        json_str = generate_json_report(report)
        if output is not None:
            output.write_text(json_str, encoding="utf-8")
            console.print(f"JSON report generated: [bold]{output}[/bold]")
        else:
            print(json_str)  # noqa: T201 — raw stdout, no Rich formatting
    else:
        output_console = Console(no_color=_no_color_mode)
        console_printer(report, console=output_console)

        if output is not None:
            scope_names: dict[str, str] = {str(s.id).lower(): s.name for s in model.subscriptions if s.name}
            scope_names.update({m.id.lower(): m.name for m in model.management_groups if m.name})
            generate_html_report(report, output, scope_names=scope_names, mode=html_mode)
            console.print(f"HTML report generated: [bold]{output}[/bold]")


def _exit_code(report: ComplianceReport) -> int:
    """Determine exit code from report."""
    if report.scan_errors and report.summary.total_findings == 0:
        return 2
    if report.summary.total_findings > 0:
        return 1
    return 0


def _detect_policy_file() -> Path | None:
    """Search for a policy file in the current directory.

    Priority order: policy.yaml, .az-rbac-watch.yaml, az-rbac-watch.yaml.
    """
    candidates = ("policy.yaml", ".az-rbac-watch.yaml", "az-rbac-watch.yaml")
    cwd = Path.cwd()
    for name in candidates:
        candidate = cwd / name
        if candidate.is_file():
            return candidate
    return None


def _load_or_build_model(
    *,
    policy: Path | None,
    subscription: list[str] | None,
    management_group: list[str] | None,
    tenant_id: str | None = None,
    inject_default_governance: bool = False,
) -> PolicyModel:
    """Load a policy model from a file or build an ad-hoc model.

    - If --policy is provided, load the YAML file.
    - If no --policy and no -s/-m, auto-detect a policy file in cwd.
    - Otherwise, build a model from -s/-m/--tenant-id (or auto-discovery).
    - inject_default_governance=True injects default rules (for ad-hoc audit).
    """
    if policy is not None:
        if subscription or management_group:
            console.print(
                "[bold red]Error[/bold red]: --policy and --subscription/--management-group are mutually exclusive."
            )
            raise typer.Exit(code=2)
        return _load_policy_or_exit(policy)

    # Auto-detect a policy file in the current directory
    if not subscription and not management_group:
        detected = _detect_policy_file()
        if detected is not None:
            console.print(f"[dim]Using policy file: ./{detected.name}[/dim]")
            return _load_policy_or_exit(detected)

    # Ad-hoc mode
    model = _build_model_from_args(tenant_id, subscription, management_group)

    if inject_default_governance and not any(r.type == "governance" for r in model.rules):
        from az_rbac_watch.config.default_rules import DEFAULT_GOVERNANCE_RULES

        model = model.model_copy(update={"rules": list(model.rules) + list(DEFAULT_GOVERNANCE_RULES)})
        n = len(DEFAULT_GOVERNANCE_RULES)
        console.print(f"[bold yellow]Ad-hoc mode: {n} default governance rule(s) loaded.[/bold yellow]")

    return model


def _inject_framework_rules(model: PolicyModel, framework_name: str | None) -> PolicyModel:
    """Inject governance rules from a framework's YAML into the policy model.

    Only adds rules whose names are not already present in the model.
    """
    if framework_name is None:
        return model

    # Load the raw YAML to get governance_rules section
    from pathlib import Path as _Path

    import yaml as _yaml

    builtin_map = {"CIS": "cis_azure_1_4_0.yaml"}
    upper = framework_name.upper()
    if upper in builtin_map:
        yaml_path = _Path(__file__).parent.parent / "frameworks" / builtin_map[upper]
    else:
        yaml_path = _Path(framework_name)

    if not yaml_path.exists():
        return model

    raw = yaml_path.read_text(encoding="utf-8")
    data = _yaml.safe_load(raw)
    gov_rules_data = data.get("governance_rules", [])
    if not gov_rules_data:
        return model

    from az_rbac_watch.config.policy_model import Rule

    existing_names = {r.name for r in model.rules}
    new_rules = []
    for rd in gov_rules_data:
        if rd.get("name") not in existing_names:
            new_rules.append(Rule.model_validate(rd))

    if new_rules:
        console.print(f"[dim]Injected {len(new_rules)} framework governance rule(s).[/dim]")
        return model.model_copy(update={"rules": list(model.rules) + new_rules})

    return model


def _build_model_from_args(
    tenant_id: str | None,
    subscription_ids: list[str] | None,
    management_group_ids: list[str] | None,
) -> PolicyModel:
    """Build a PolicyModel from CLI arguments or via auto-discovery."""
    if subscription_ids or management_group_ids:
        subs: list[Subscription] = []
        if subscription_ids:
            accessible = list_accessible_subscriptions()
            name_map = {sid: name for sid, name, _ in accessible}
            subs = [Subscription(id=UUID(sid), name=name_map.get(sid, "")) for sid in subscription_ids]

        mgs: list[ManagementGroup] = []
        if management_group_ids:
            accessible_mgs = list_accessible_management_groups()
            mg_name_map = {mgid: name for mgid, name in accessible_mgs}
            mgs = [ManagementGroup(id=mgid, name=mg_name_map.get(mgid, "")) for mgid in management_group_ids]

        resolved_tenant_id = tenant_id
        if not resolved_tenant_id:
            accessible = list_accessible_subscriptions()
            for _, _, tid in accessible:
                if tid:
                    resolved_tenant_id = tid
                    break
        if not resolved_tenant_id:
            console.print(
                "Error: could not determine tenant ID. Try:\n"
                "  1. az login\n"
                "  2. az account show --query tenantId\n"
                "  3. Pass --tenant-id explicitly"
            )
            raise typer.Exit(code=2)

    else:
        console.print("[dim]Auto-discovering accessible scopes...[/dim]")
        accessible_subs = list_accessible_subscriptions()
        accessible_mgs = list_accessible_management_groups()

        subs = [Subscription(id=UUID(sid), name=name) for sid, name, _ in accessible_subs]
        mgs = [ManagementGroup(id=mgid, name=name) for mgid, name in accessible_mgs]

        resolved_tenant_id = tenant_id
        if not resolved_tenant_id:
            for _, _, tid in accessible_subs:
                if tid:
                    resolved_tenant_id = tid
                    break
        if not resolved_tenant_id:
            console.print(
                "Error: could not determine tenant ID. Try:\n"
                "  1. az login\n"
                "  2. az account show --query tenantId\n"
                "  3. Pass --tenant-id explicitly"
            )
            raise typer.Exit(code=2)

        if not subs and not mgs:
            console.print(
                "Error: no accessible subscriptions found. Check:\n"
                "  1. Run: az login\n"
                "  2. Verify: az account list\n"
                "  3. Ensure your identity has Reader role on at least one subscription"
            )
            raise typer.Exit(code=2)

        console.print(f"[dim]Found {len(subs)} subscription(s) and {len(mgs)} management group(s).[/dim]")

    return PolicyModel(
        version="2.0",
        tenant_id=UUID(resolved_tenant_id),
        subscriptions=subs,
        management_groups=mgs,
    )
