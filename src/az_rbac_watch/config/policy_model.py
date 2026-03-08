"""Parse and validate YAML policy model.

The policy model describes compliance rules for an Azure tenant:
subscriptions, management groups, and baseline/governance rules.
"""

from __future__ import annotations

import logging
import warnings
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import yaml
from pydantic import BaseModel, field_validator, model_validator

from az_rbac_watch.utils.scope import scope_group_key

__all__ = [
    "SUPPORTED_VERSIONS",
    "VALID_RULE_TYPES",
    "VALID_SCOPE_MODES",
    "VALID_SEVERITIES",
    "ManagementGroup",
    "PolicyModel",
    "Rule",
    "RuleMatch",
    "Subscription",
    "filter_scopes",
    "load_policy_model",
    "resolve_scopes",
    "save_policy_model",
]

logger = logging.getLogger(__name__)

SUPPORTED_VERSIONS = {"2.0"}

VALID_RULE_TYPES = {"baseline", "governance"}

VALID_SCOPE_MODES = {"all", "explicit"}


class Subscription(BaseModel):
    id: UUID
    name: str = ""


class ManagementGroup(BaseModel):
    id: str
    name: str = ""

    @field_validator("id")
    @classmethod
    def id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Management group ID must not be empty")
        return v


VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class RuleMatch(BaseModel):
    """Declarative match conditions for a compliance rule. All conditions are AND-combined."""

    scope: str | None = None
    scope_prefix: str | None = None
    role: str | None = None
    role_in: list[str] | None = None
    role_not_in: list[str] | None = None
    role_type: str | None = None
    principal_type: str | None = None
    principal_type_in: list[str] | None = None
    principal_id: str | None = None
    principal_name_prefix: str | None = None
    principal_name_not_prefix: str | None = None
    principal_name_contains: str | None = None
    principal_name_not_contains: str | None = None

    @model_validator(mode="after")
    def _warn_contradictory_operators(self) -> RuleMatch:
        """Emit a warning if match operators are contradictory."""
        messages: list[str] = []

        # role ∈ role_not_in
        if self.role is not None and self.role_not_in is not None:
            not_in_lower = {v.lower() for v in self.role_not_in}
            if self.role.lower() in not_in_lower:
                messages.append(f"role='{self.role}' is also in role_not_in")

        # role_in ∩ role_not_in
        if self.role_in is not None and self.role_not_in is not None:
            in_lower = {v.lower() for v in self.role_in}
            not_in_lower = {v.lower() for v in self.role_not_in}
            overlap = in_lower & not_in_lower
            if overlap:
                messages.append(f"role_in and role_not_in overlap on {overlap}")

        # principal_name_prefix == principal_name_not_prefix
        if (
            self.principal_name_prefix is not None
            and self.principal_name_not_prefix is not None
            and self.principal_name_prefix.lower() == self.principal_name_not_prefix.lower()
        ):
            messages.append(
                f"principal_name_prefix and principal_name_not_prefix are both '{self.principal_name_prefix}'"
            )

        # principal_name_contains == principal_name_not_contains
        if (
            self.principal_name_contains is not None
            and self.principal_name_not_contains is not None
            and self.principal_name_contains.lower() == self.principal_name_not_contains.lower()
        ):
            messages.append(
                f"principal_name_contains and principal_name_not_contains are both '{self.principal_name_contains}'"
            )

        for msg in messages:
            warnings.warn(f"contradictory match operators: {msg}", UserWarning, stacklevel=2)

        return self


class Rule(BaseModel):
    """A declarative compliance rule with composable match conditions."""

    name: str
    type: str = "governance"
    description: str = ""
    severity: str = "high"
    match: RuleMatch = RuleMatch()
    remediation: str | None = None

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Rule name must not be empty")
        return v

    @field_validator("type")
    @classmethod
    def type_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule type: '{v}'. Valid values: {VALID_RULE_TYPES}")
        return v

    @field_validator("severity")
    @classmethod
    def severity_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: '{v}'. Valid values: {VALID_SEVERITIES}")
        return v


class PolicyModel(BaseModel):
    version: str
    tenant_id: UUID
    scope: str = "explicit"
    subscriptions: list[Subscription] = []
    management_groups: list[ManagementGroup] = []
    exclude_subscriptions: list[str] = []
    exclude_management_groups: list[str] = []
    rules: list[Rule] = []

    @field_validator("version")
    @classmethod
    def version_supported(cls, v: str) -> str:
        if v not in SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported version: '{v}'. Supported versions: {SUPPORTED_VERSIONS}")
        return v

    @field_validator("scope")
    @classmethod
    def scope_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in VALID_SCOPE_MODES:
            raise ValueError(f"Invalid scope mode: '{v}'. Valid values: {VALID_SCOPE_MODES}")
        return v


def filter_scopes(
    model: PolicyModel,
    exclude_subscriptions: list[str] | None = None,
    exclude_management_groups: list[str] | None = None,
) -> PolicyModel:
    """Return a copy of PolicyModel without excluded scopes.

    Filter subscriptions, management groups AND rules targeting these scopes.
    Case-insensitive comparison on IDs.
    """
    if not exclude_subscriptions and not exclude_management_groups:
        return model.model_copy()

    excluded_sub_ids = {s.lower() for s in (exclude_subscriptions or [])}
    excluded_mg_ids = {m.lower() for m in (exclude_management_groups or [])}

    new_subs = [s for s in model.subscriptions if str(s.id).lower() not in excluded_sub_ids]
    new_mgs = [m for m in model.management_groups if m.id.lower() not in excluded_mg_ids]

    def _is_excluded(scope: str) -> bool:
        sort_order, group_id = scope_group_key(scope)
        if sort_order == 0 and group_id in excluded_mg_ids:
            return True
        return sort_order == 1 and group_id in excluded_sub_ids

    def _rule_is_excluded(rule: Rule) -> bool:
        """A rule is excluded if its scope or scope_prefix targets an excluded scope."""
        return any(scope_val and _is_excluded(scope_val) for scope_val in (rule.match.scope, rule.match.scope_prefix))

    new_rules = [r for r in model.rules if not _rule_is_excluded(r)]

    return model.model_copy(
        update={
            "subscriptions": new_subs,
            "management_groups": new_mgs,
            "rules": new_rules,
        }
    )


def resolve_scopes(
    model: PolicyModel,
    list_subs_fn: Callable[[], list[tuple[str, str, str]]] | None = None,
    list_mgs_fn: Callable[[], list[tuple[str, str]]] | None = None,
) -> PolicyModel:
    """Resolve scopes according to policy model mode.

    If scope=explicit → return the model unchanged.
    If scope=all → auto-discover accessible scopes, then apply
    exclusions defined in YAML (exclude_subscriptions / exclude_management_groups).

    Args:
        model: The PolicyModel to resolve.
        list_subs_fn: Callable returning list[tuple[str, str, str]] (sub_id, name, tenant_id).
                      Default: list_accessible_subscriptions.
        list_mgs_fn: Callable returning list[tuple[str, str]] (mg_id, name).
                     Default: list_accessible_management_groups.

    Returns:
        A PolicyModel with resolved scopes (scope reset to "explicit").
    """
    if model.scope == "explicit":
        return model

    # Lazy imports to avoid circular dependency and keep Azure SDK optional for tests
    from az_rbac_watch.auth.azure_clients import (
        list_accessible_management_groups,
        list_accessible_subscriptions,
    )

    _list_subs = list_subs_fn or list_accessible_subscriptions
    _list_mgs = list_mgs_fn or list_accessible_management_groups

    accessible_subs = _list_subs()
    accessible_mgs = _list_mgs()

    subs = [Subscription(id=UUID(sid), name=name) for sid, name, _ in accessible_subs]
    mgs = [ManagementGroup(id=mgid, name=name) for mgid, name in accessible_mgs]

    resolved = model.model_copy(
        update={
            "scope": "explicit",
            "subscriptions": subs,
            "management_groups": mgs,
        }
    )

    # Apply YAML-level exclusions
    if model.exclude_subscriptions or model.exclude_management_groups:
        resolved = filter_scopes(
            resolved,
            exclude_subscriptions=model.exclude_subscriptions,
            exclude_management_groups=model.exclude_management_groups,
        )

    return resolved.model_copy(
        update={
            "exclude_subscriptions": [],
            "exclude_management_groups": [],
        }
    )


def load_policy_model(path: str | Path) -> PolicyModel:
    """Load and validate a policy model from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy model file not found: {path}")

    raw = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ValueError(f"YAML parsing error: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("YAML file must contain a mapping at the root")

    logger.info("Loading policy model from %s", path)
    return PolicyModel.model_validate(data)


# ── Helpers for YAML serialization ────────────────────


def _serialize_header(policy: PolicyModel) -> str:
    """Serialize policy model header (version, tenant, scopes) to YAML."""
    header: dict[str, object] = {
        "version": policy.version,
        "tenant_id": str(policy.tenant_id),
    }
    if policy.scope != "explicit":
        header["scope"] = policy.scope
    if policy.subscriptions:
        header["subscriptions"] = [{"id": str(s.id), "name": s.name} for s in policy.subscriptions]
    if policy.management_groups:
        header["management_groups"] = [{"id": m.id, "name": m.name} for m in policy.management_groups]
    if policy.exclude_subscriptions:
        header["exclude_subscriptions"] = policy.exclude_subscriptions
    if policy.exclude_management_groups:
        header["exclude_management_groups"] = policy.exclude_management_groups
    result: str = yaml.dump(header, default_flow_style=False, allow_unicode=True, sort_keys=False)
    return result.rstrip()


def save_policy_model(policy: PolicyModel, path: str | Path) -> None:
    """Serialize a PolicyModel to YAML file, rules grouped by type (baseline then governance)."""
    path = Path(path)
    parts: list[str] = [_serialize_header(policy)]

    if not policy.rules:
        parts.append("rules: []")
    else:
        baseline_rules = [r for r in policy.rules if r.type == "baseline"]
        governance_rules = [r for r in policy.rules if r.type == "governance"]

        parts.append(f"\n# {'─' * 50}")
        parts.append(
            f"# {len(policy.rules)} rule(s) — {len(baseline_rules)} baseline, {len(governance_rules)} governance"
        )
        parts.append(f"# {'─' * 50}")
        parts.append("rules:")

        if baseline_rules:
            parts.append("\n  # ── Baseline rules ───────────────────────────────────")
            for r in baseline_rules:
                parts.append(_serialize_rule(r))

        if governance_rules:
            parts.append("\n  # ── Governance rules ─────────────────────────────────")
            for r in governance_rules:
                parts.append(_serialize_rule(r))

    parts.append("")
    path.write_text("\n".join(parts), encoding="utf-8")


def _serialize_rule(rule: Rule) -> str:
    """Serialize a Rule to indented YAML fragment (list item)."""
    data = rule.model_dump(exclude_defaults=True)
    # Always include type for clarity
    data["type"] = rule.type
    yaml_str = yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False).rstrip()
    yaml_lines = yaml_str.split("\n")
    lines = [f"  - {yaml_lines[0]}"]
    for yl in yaml_lines[1:]:
        lines.append(f"    {yl}")
    return "\n".join(lines)
