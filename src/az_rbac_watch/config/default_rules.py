"""Default governance rules for ad-hoc mode.

These rules are used when `audit` is run without a policy file (ad-hoc mode).
They cover the most common Azure RBAC best practices.
"""

from __future__ import annotations

from az_rbac_watch.config.policy_model import Rule, RuleMatch

DEFAULT_GOVERNANCE_RULES: list[Rule] = [
    Rule(
        name="no-owner-at-subscription",
        type="governance",
        description="Owner role is forbidden at subscription scope",
        severity="critical",
        remediation="Remove the Owner assignment or reduce scope to a resource group",
        match=RuleMatch(
            scope_prefix="/subscriptions/",
            role="Owner",
        ),
    ),
    Rule(
        name="no-direct-users",
        type="governance",
        description="Users must be assigned through groups",
        severity="high",
        remediation="Add the user to an Entra group and assign the role to the group",
        match=RuleMatch(
            principal_type="User",
        ),
    ),
    Rule(
        name="no-custom-roles",
        type="governance",
        description="Custom roles are discouraged — prefer built-in roles",
        severity="medium",
        remediation="Replace the custom role with a built-in role",
        match=RuleMatch(
            role_type="CustomRole",
        ),
    ),
]
