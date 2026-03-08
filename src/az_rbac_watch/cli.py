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
from typing import Annotated, Literal
from uuid import UUID

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn

__all__ = ["app"]

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
from az_rbac_watch.reporters.html_report import generate_html_report
from az_rbac_watch.reporters.json_report import generate_json_report
from az_rbac_watch.scanner.discovery import discover_policy
from az_rbac_watch.scanner.rbac_scanner import RbacScanResult, resolve_display_names, scan_rbac

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


app = typer.Typer(
    name="az-rbac-watch",
    invoke_without_command=True,
    epilog="Quick start: az-rbac-watch (scans all accessible subscriptions with default rules)",
)

console = Console(stderr=True)


@app.callback()
def main(
    ctx: typer.Context,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress all output except findings and exit code."),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output."),
    ] = False,
) -> None:
    """Azure RBAC as Code — drift detection and guardrails."""
    import os

    global console, _quiet_mode, _no_color_mode, _settings

    # Charger les paramètres (fichier + env vars) et les utiliser comme fallback
    _settings = load_settings()

    _quiet_mode = quiet or _settings.quiet
    _no_color_mode = no_color or _settings.no_color or os.environ.get("NO_COLOR", "") != ""
    if _quiet_mode:
        console = Console(stderr=True, quiet=True)
    elif _no_color_mode:
        console = Console(stderr=True, no_color=True)

    # Zéro-args → lancer audit par défaut
    if ctx.invoked_subcommand is None:
        ctx.invoke(audit)


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
    """Vérifie les credentials Azure avant les appels API."""
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
    """Affiche le plan de dry-run : scopes et règles sans appeler Azure."""
    n_subs = len(model.subscriptions)
    n_mgs = len(model.management_groups)
    n_baseline = sum(1 for r in model.rules if r.type == "baseline")
    n_governance = sum(1 for r in model.rules if r.type == "governance")

    output_console = Console(no_color=_no_color_mode)
    output_console.print()
    output_console.print(
        f"[bold cyan]Dry run[/bold cyan] — would scan {n_subs} subscription(s), "
        f"{n_mgs} management group(s)"
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
    """Cherche un fichier de politique dans le répertoire courant.

    Ordre de priorité : policy.yaml, .az-rbac-watch.yaml, az-rbac-watch.yaml.
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
                "[bold red]Error[/bold red]: --policy and --subscription/--management-group "
                "are mutually exclusive."
            )
            raise typer.Exit(code=2)
        return _load_policy_or_exit(policy)

    # Auto-détection d'un fichier de politique dans le répertoire courant
    if not subscription and not management_group:
        detected = _detect_policy_file()
        if detected is not None:
            console.print(f"[dim]Using policy file: ./{detected.name}[/dim]")
            return _load_policy_or_exit(detected)

    # Mode ad-hoc
    model = _build_model_from_args(tenant_id, subscription, management_group)

    if inject_default_governance and not any(r.type == "governance" for r in model.rules):
        from az_rbac_watch.config.default_rules import DEFAULT_GOVERNANCE_RULES

        model = model.model_copy(update={"rules": list(model.rules) + list(DEFAULT_GOVERNANCE_RULES)})
        n = len(DEFAULT_GOVERNANCE_RULES)
        console.print(f"[bold yellow]Ad-hoc mode: {n} default governance rule(s) loaded.[/bold yellow]")

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


# ── validate command ──────────────────────────────────────────


@app.command()
def validate(
    policy: Annotated[
        Path,
        typer.Option("--policy", "-p", help="Path to policy model YAML file."),
    ],
) -> None:
    """Validate a policy model YAML file (offline, no Azure credentials needed)."""
    model = _load_policy_or_exit(policy)

    n_subs = len(model.subscriptions)
    n_mgs = len(model.management_groups)
    n_rules = len(model.rules)
    n_baseline = sum(1 for r in model.rules if r.type == "baseline")
    n_governance = sum(1 for r in model.rules if r.type == "governance")

    output_console = Console(no_color=_no_color_mode)
    output_console.print()
    output_console.print(
        f"[bold green]Policy model valid[/bold green] — version {model.version}\n"
        f"  Scope                : {model.scope}\n"
        f"  Subscriptions        : {n_subs}\n"
        f"  Management groups    : {n_mgs}\n"
        f"  Rules                : {n_rules} ({n_baseline} baseline, {n_governance} governance)"
    )
    if model.exclude_subscriptions:
        output_console.print(f"  Exclude subscriptions: {len(model.exclude_subscriptions)}")
    if model.exclude_management_groups:
        output_console.print(f"  Exclude MGs          : {len(model.exclude_management_groups)}")
    output_console.print()
    raise typer.Exit(code=0)


# ── scan command (drift detection) ────────────────────────────


@app.command()
def scan(
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to policy model YAML file."),
    ] = None,
    subscription: Annotated[
        list[str] | None,
        typer.Option("--subscription", "-s", help="Subscription ID to scan (repeatable, ad-hoc mode)."),
    ] = None,
    management_group: Annotated[
        list[str] | None,
        typer.Option("--management-group", "-m", help="Management group ID to scan (repeatable, ad-hoc mode)."),
    ] = None,
    tenant_id: Annotated[
        str | None,
        typer.Option("--tenant-id", "-t", help="Tenant ID (auto-detected if omitted)."),
    ] = None,
    exclude_subscription: Annotated[
        list[str] | None,
        typer.Option("--exclude-subscription", help="Subscription ID to exclude (repeatable)."),
    ] = None,
    exclude_management_group: Annotated[
        list[str] | None,
        typer.Option("--exclude-management-group", help="Management group ID to exclude (repeatable)."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json."),
    ] = "console",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose logging."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show scan plan without making API calls."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Show full traceback on error."),
    ] = False,
) -> None:
    """Detect RBAC drift — compare actual state to desired state (baseline rules).

    Classic mode: --policy <file.yaml>
    Ad-hoc mode:  --subscription <id> (no policy, every assignment = drift)
    """
    _debug_callback(debug)
    _setup_logging(verbose)

    # Appliquer les valeurs par défaut depuis la configuration
    if policy is None and _settings.policy is not None:
        policy = Path(_settings.policy)
    if fmt == "console" and _settings.format != "console":
        fmt = _settings.format

    if fmt not in ("console", "json"):
        console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console' or 'json'.")
        raise typer.Exit(code=2)

    if not dry_run:
        _check_credentials_or_exit()

    model = _load_or_build_model(
        policy=policy,
        subscription=subscription,
        management_group=management_group,
        tenant_id=tenant_id,
    )
    model = _resolve_and_filter_model(model, exclude_subscription, exclude_management_group)
    _validate_scopes_or_exit(model)

    if dry_run:
        _print_dry_run_plan(model)
        raise typer.Exit(code=0)

    # Check baseline rules exist — warn user in ad-hoc mode
    n_baseline = sum(1 for r in model.rules if r.type == "baseline")
    if n_baseline == 0 and policy is not None:
        console.print(
            "No baseline rules in policy model. To create a baseline:\n"
            "  az-rbac-watch discover -o policy.yaml"
        )
        raise typer.Exit(code=0)
    if n_baseline == 0 and policy is None:
        console.print(
            "[bold yellow]Ad-hoc mode: no baseline rules"
            " — every assignment will be reported as drift.[/bold yellow]"
        )
        # Inject a dummy baseline that matches nothing → all assignments become drift
        from az_rbac_watch.config.policy_model import Rule, RuleMatch

        _sentinel = Rule(
            name="_adhoc-empty-baseline",
            type="baseline",
            match=RuleMatch(principal_id="00000000-0000-0000-0000-000000000000"),
        )
        model = model.model_copy(update={"rules": [*list(model.rules), _sentinel]})

    # Scanner RBAC
    try:
        scan_result = _run_scan(model, fmt=fmt)
    except Exception as e:
        logger.debug("Traceback scan", exc_info=True)
        console.print(f"[bold red]Scan error[/bold red]: {e}")
        if _debug_mode:
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            console.print("[dim]Rerun with --debug for full traceback.[/dim]")
        raise typer.Exit(code=2) from None

    scan_result = _resolve_names(scan_result, fmt=fmt)

    # Drift detection
    report = check_drift(model, scan_result)

    _output_report(
        report,
        fmt=fmt,
        output=output,
        model=model,
        console_printer=print_drift_report,
        html_mode="scan",
    )

    # Next steps footer (console uniquement)
    if fmt == "console":
        code = _exit_code(report)
        if code == 1:
            console.print("\n[dim]Next steps:\n  Review findings and update policy.yaml[/dim]")
        elif code == 0:
            console.print(
                "\n[dim]All clear! Integrate in CI:\n"
                "  az-rbac-watch scan -p policy.yaml --format json[/dim]"
            )

    raise typer.Exit(code=_exit_code(report))


# ── audit command (guardrails) ────────────────────────────────


@app.command()
def audit(
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to policy model YAML file."),
    ] = None,
    subscription: Annotated[
        list[str] | None,
        typer.Option("--subscription", "-s", help="Subscription ID to scan (repeatable, ad-hoc mode)."),
    ] = None,
    management_group: Annotated[
        list[str] | None,
        typer.Option("--management-group", "-m", help="Management group ID to scan (repeatable, ad-hoc mode)."),
    ] = None,
    tenant_id: Annotated[
        str | None,
        typer.Option("--tenant-id", "-t", help="Tenant ID (auto-detected if omitted)."),
    ] = None,
    exclude_subscription: Annotated[
        list[str] | None,
        typer.Option("--exclude-subscription", help="Subscription ID to exclude (repeatable)."),
    ] = None,
    exclude_management_group: Annotated[
        list[str] | None,
        typer.Option("--exclude-management-group", help="Management group ID to exclude (repeatable)."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json."),
    ] = "console",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose logging."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show scan plan without making API calls."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Show full traceback on error."),
    ] = False,
) -> None:
    """Audit guardrails — check governance rules (forbidden patterns).

    Classic mode: --policy <file.yaml>
    Ad-hoc mode:  --subscription <id> (uses default rules)
    """
    _debug_callback(debug)
    _setup_logging(verbose)

    # Appliquer les valeurs par défaut depuis la configuration
    if policy is None and _settings.policy is not None:
        policy = Path(_settings.policy)
    if fmt == "console" and _settings.format != "console":
        fmt = _settings.format

    if fmt not in ("console", "json"):
        console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console' or 'json'.")
        raise typer.Exit(code=2)

    if not dry_run:
        _check_credentials_or_exit()

    model = _load_or_build_model(
        policy=policy,
        subscription=subscription,
        management_group=management_group,
        tenant_id=tenant_id,
        inject_default_governance=True,
    )
    model = _resolve_and_filter_model(model, exclude_subscription, exclude_management_group)
    _validate_scopes_or_exit(model)

    if dry_run:
        _print_dry_run_plan(model)
        raise typer.Exit(code=0)

    # Check governance rules exist
    n_governance = sum(1 for r in model.rules if r.type == "governance")
    if n_governance == 0:
        console.print("[yellow]No governance rules in policy model — nothing to audit.[/yellow]")
        raise typer.Exit(code=0)

    # Scanner RBAC
    try:
        scan_result = _run_scan(model, fmt=fmt)
    except Exception as e:
        logger.debug("Traceback scan", exc_info=True)
        console.print(f"[bold red]Scan error[/bold red]: {e}")
        if _debug_mode:
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            console.print("[dim]Rerun with --debug for full traceback.[/dim]")
        raise typer.Exit(code=2) from None

    scan_result = _resolve_names(scan_result, fmt=fmt)

    # Audit violations
    report = check_violations(model, scan_result)

    _output_report(
        report,
        fmt=fmt,
        output=output,
        model=model,
        console_printer=print_audit_report,
        html_mode="audit",
    )

    # Next steps footer (console uniquement)
    if fmt == "console" and policy is None:
        console.print(
            "\n[dim]Next steps:\n"
            "  az-rbac-watch discover -o policy.yaml  # capture current state\n"
            "  az-rbac-watch scan -p policy.yaml       # detect drift[/dim]"
        )

    raise typer.Exit(code=_exit_code(report))


# ── discover command ──────────────────────────────────────────


@app.command()
def discover(
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Policy YAML file (optional)."),
    ] = None,
    tenant_id: Annotated[
        str | None,
        typer.Option("--tenant-id", "-t", help="Tenant ID (auto-detected if omitted)."),
    ] = None,
    subscription: Annotated[
        list[str] | None,
        typer.Option("--subscription", "-s", help="Subscription ID (repeatable)."),
    ] = None,
    management_group: Annotated[
        list[str] | None,
        typer.Option("--management-group", "-m", help="Management group ID (repeatable)."),
    ] = None,
    exclude_subscription: Annotated[
        list[str] | None,
        typer.Option("--exclude-subscription", help="Subscription ID to exclude (repeatable)."),
    ] = None,
    exclude_management_group: Annotated[
        list[str] | None,
        typer.Option("--exclude-management-group", help="Management group ID to exclude (repeatable)."),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output YAML file path."),
    ] = Path("discovered_policy.yaml"),
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose logging."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show scan plan without making API calls."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Show full traceback on error."),
    ] = False,
) -> None:
    """Discover existing RBAC assignments and generate a draft policy model."""
    _debug_callback(debug)
    _setup_logging(verbose)

    if not dry_run:
        _check_credentials_or_exit()

    # 1. Build the PolicyModel
    if policy is not None:
        model = _load_policy_or_exit(policy)
        if model.scope == "all":
            console.print("[dim]Auto-discovering accessible scopes (scope: all)...[/dim]")
            model = resolve_scopes(model)
    else:
        model = _build_model_from_args(tenant_id, subscription, management_group)

    # 2. Apply exclusions
    if exclude_subscription or exclude_management_group:
        model = filter_scopes(model, exclude_subscription, exclude_management_group)

    _validate_scopes_or_exit(model)

    if dry_run:
        _print_dry_run_plan(model)
        raise typer.Exit(code=0)

    # 3. Scan RBAC
    total_scopes = len(model.subscriptions) + len(model.management_groups)
    try:
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

            scan_result = scan_rbac(model, progress_callback=_on_progress)
    except Exception as e:
        logger.debug("Traceback scan", exc_info=True)
        console.print(f"[bold red]Scan error[/bold red]: {e}")
        if _debug_mode:
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            console.print("[dim]Rerun with --debug for full traceback.[/dim]")
        raise typer.Exit(code=2) from None

    # 4. Discovery
    with console.status("Resolving names via Graph API..."):
        discovered = discover_policy(
            scan_result,
            tenant_id=str(model.tenant_id),
            subscriptions=model.subscriptions,
            management_groups=model.management_groups,
        )

    # 5. Save
    save_policy_model(discovered, output)

    # 6. Summary
    output_console = Console(no_color=_no_color_mode)
    print_discover_summary(discovered, output, console=output_console)
