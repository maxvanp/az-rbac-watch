"""Unit tests for policy model parsing and validation."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from pydantic import ValidationError

from az_rbac_watch.config.policy_model import (
    ManagementGroup,
    PolicyModel,
    Rule,
    RuleMatch,
    Subscription,
    filter_scopes,
    load_policy_model,
    resolve_scopes,
    save_policy_model,
)

VALID_TENANT_ID = "11111111-1111-1111-1111-111111111111"
VALID_SUB_ID = "22222222-2222-2222-2222-222222222222"


def _minimal_policy(**overrides: object) -> dict:
    """Return a minimal valid dict for constructing a PolicyModel."""
    base: dict = {
        "version": "2.0",
        "tenant_id": VALID_TENANT_ID,
    }
    base.update(overrides)
    return base


# ── Subscription ──────────────────────────────────────────────


class TestSubscription:
    def test_valid(self):
        sub = Subscription(id=VALID_SUB_ID, name="Production")
        assert str(sub.id) == VALID_SUB_ID
        assert sub.name == "Production"

    def test_name_defaults_empty(self):
        sub = Subscription(id=VALID_SUB_ID)
        assert sub.name == ""

    def test_invalid_uuid(self):
        with pytest.raises(ValidationError, match="uuid"):
            Subscription(id="not-a-uuid", name="Bad")


# ── ManagementGroup ──────────────────────────────────────────


class TestManagementGroup:
    def test_valid(self):
        mg = ManagementGroup(id="mg-prod", name="Production")
        assert mg.id == "mg-prod"
        assert mg.name == "Production"

    def test_name_defaults_empty(self):
        mg = ManagementGroup(id="mg-prod")
        assert mg.name == ""

    def test_empty_id_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            ManagementGroup(id="   ")

    def test_string_id_accepted(self):
        """MG IDs are not UUIDs — they are arbitrary strings."""
        mg = ManagementGroup(id="my-custom-mg-id-123")
        assert mg.id == "my-custom-mg-id-123"


# ── PolicyModel ──────────────────────────────────────────────


class TestPolicyModel:
    def test_minimal_valid(self):
        model = PolicyModel(**_minimal_policy())
        assert str(model.tenant_id) == VALID_TENANT_ID
        assert model.version == "2.0"
        assert model.rules == []
        assert model.management_groups == []

    def test_full_valid(self):
        model = PolicyModel(
            **_minimal_policy(
                subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
                management_groups=[{"id": "mg-prod", "name": "Production"}],
                rules=[
                    {"name": "test-rule", "type": "governance", "match": {"role": "Owner"}},
                ],
            )
        )
        assert len(model.subscriptions) == 1
        assert len(model.management_groups) == 1
        assert len(model.rules) == 1

    def test_unsupported_version_rejected(self):
        with pytest.raises(ValidationError, match="Unsupported version"):
            PolicyModel(**_minimal_policy(version="99.0"))

    def test_version_1_0_rejected(self):
        """v1.0 is no longer supported."""
        with pytest.raises(ValidationError, match="Unsupported version"):
            PolicyModel(**_minimal_policy(version="1.0"))

    def test_invalid_tenant_id_rejected(self):
        with pytest.raises(ValidationError, match="uuid"):
            PolicyModel(**_minimal_policy(tenant_id="bad-tenant"))

    def test_with_management_groups(self):
        model = PolicyModel(
            **_minimal_policy(
                management_groups=[
                    {"id": "mg-prod", "name": "Production"},
                    {"id": "mg-dev"},
                ],
            )
        )
        assert len(model.management_groups) == 2
        assert model.management_groups[0].id == "mg-prod"
        assert model.management_groups[0].name == "Production"
        assert model.management_groups[1].name == ""

    def test_scope_defaults_explicit(self):
        model = PolicyModel(**_minimal_policy())
        assert model.scope == "explicit"

    def test_scope_all_accepted(self):
        model = PolicyModel(**_minimal_policy(scope="all"))
        assert model.scope == "all"

    def test_scope_explicit_accepted(self):
        model = PolicyModel(**_minimal_policy(scope="explicit"))
        assert model.scope == "explicit"

    def test_scope_invalid_rejected(self):
        with pytest.raises(ValidationError, match="Invalid scope mode"):
            PolicyModel(**_minimal_policy(scope="partial"))

    def test_scope_normalized_lowercase(self):
        model = PolicyModel(**_minimal_policy(scope="ALL"))
        assert model.scope == "all"

    def test_exclude_subscriptions_parsed(self):
        model = PolicyModel(**_minimal_policy(exclude_subscriptions=["sub-1", "sub-2"]))
        assert model.exclude_subscriptions == ["sub-1", "sub-2"]

    def test_exclude_management_groups_parsed(self):
        model = PolicyModel(**_minimal_policy(exclude_management_groups=["mg-sandbox"]))
        assert model.exclude_management_groups == ["mg-sandbox"]

    def test_exclude_defaults_empty(self):
        model = PolicyModel(**_minimal_policy())
        assert model.exclude_subscriptions == []
        assert model.exclude_management_groups == []


# ── RuleMatch ──────────────────────────────────────────────────


class TestRuleMatch:
    def test_all_defaults_none(self):
        m = RuleMatch()
        assert m.scope is None
        assert m.scope_prefix is None
        assert m.role is None
        assert m.role_in is None
        assert m.role_not_in is None
        assert m.role_type is None
        assert m.principal_type is None
        assert m.principal_type_in is None
        assert m.principal_id is None
        assert m.principal_name_prefix is None
        assert m.principal_name_not_prefix is None
        assert m.principal_name_contains is None
        assert m.principal_name_not_contains is None

    def test_all_operators(self):
        m = RuleMatch(
            scope="/subscriptions/xxx",
            scope_prefix="/subscriptions/",
            role="Owner",
            role_in=["Owner", "Contributor"],
            role_not_in=["Reader"],
            role_type="CustomRole",
            principal_type="User",
            principal_type_in=["User", "ServicePrincipal"],
            principal_id="aaa-bbb",
            principal_name_prefix="GRP-PERM-",
            principal_name_not_prefix="GRP-TEMP-",
            principal_name_contains="INFRA",
            principal_name_not_contains="TEMP",
        )
        assert m.scope == "/subscriptions/xxx"
        assert m.scope_prefix == "/subscriptions/"
        assert m.role == "Owner"
        assert m.role_in == ["Owner", "Contributor"]
        assert m.role_not_in == ["Reader"]
        assert m.role_type == "CustomRole"
        assert m.principal_type == "User"
        assert m.principal_type_in == ["User", "ServicePrincipal"]
        assert m.principal_id == "aaa-bbb"
        assert m.principal_name_prefix == "GRP-PERM-"
        assert m.principal_name_not_prefix == "GRP-TEMP-"
        assert m.principal_name_contains == "INFRA"
        assert m.principal_name_not_contains == "TEMP"


# ── RuleMatch contradictory operators ─────────────────────────


class TestRuleMatchContradictions:
    def test_conflicting_role_and_role_not_in(self) -> None:
        """role='Owner' + role_not_in=['Owner'] should warn."""
        with pytest.warns(UserWarning, match="contradictory"):
            RuleMatch(role="Owner", role_not_in=["Owner"])

    def test_conflicting_role_in_and_role_not_in(self) -> None:
        """role_in=['Owner'] + role_not_in=['Owner'] should warn."""
        with pytest.warns(UserWarning, match="contradictory"):
            RuleMatch(role_in=["Owner"], role_not_in=["Owner"])

    def test_conflicting_principal_name_prefix(self) -> None:
        """principal_name_prefix + principal_name_not_prefix same value should warn."""
        with pytest.warns(UserWarning, match="contradictory"):
            RuleMatch(principal_name_prefix="AZ_", principal_name_not_prefix="AZ_")

    def test_conflicting_principal_name_contains(self) -> None:
        """principal_name_contains + principal_name_not_contains same value should warn."""
        with pytest.warns(UserWarning, match="contradictory"):
            RuleMatch(principal_name_contains="admin", principal_name_not_contains="admin")

    def test_case_insensitive_role_contradiction(self) -> None:
        """Contradiction detection should be case-insensitive."""
        with pytest.warns(UserWarning, match="contradictory"):
            RuleMatch(role="owner", role_not_in=["OWNER"])

    def test_no_warning_on_non_contradictory(self) -> None:
        """Non-contradictory combinations should not emit warnings."""
        import warnings as _warnings

        with _warnings.catch_warnings():
            _warnings.simplefilter("error")
            RuleMatch(role="Owner", role_not_in=["Reader"])
            RuleMatch(role_in=["Owner"], role_not_in=["Reader"])
            RuleMatch(principal_name_prefix="AZ_", principal_name_not_prefix="GRP_")
            RuleMatch(principal_name_contains="admin", principal_name_not_contains="guest")
            RuleMatch()


# ── Rule ──────────────────────────────────────────────────────


class TestRule:
    def test_valid_minimal(self):
        rule = Rule(name="my-rule")
        assert rule.name == "my-rule"
        assert rule.type == "governance"
        assert rule.description == ""
        assert rule.severity == "high"
        assert rule.match == RuleMatch()

    def test_full(self):
        rule = Rule(
            name="no-owner",
            type="governance",
            description="No Owner allowed",
            severity="critical",
            match=RuleMatch(role="Owner"),
        )
        assert rule.name == "no-owner"
        assert rule.type == "governance"
        assert rule.severity == "critical"
        assert rule.match.role == "Owner"

    def test_baseline_type(self):
        rule = Rule(name="allow-reader", type="baseline")
        assert rule.type == "baseline"

    def test_invalid_type_rejected(self):
        with pytest.raises(ValidationError, match="Invalid rule type"):
            Rule(name="test", type="block")

    def test_type_normalized_lowercase(self):
        rule = Rule(name="test", type="BASELINE")
        assert rule.type == "baseline"

    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            Rule(name="   ")

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError, match="Invalid severity"):
            Rule(name="test", severity="urgent")

    def test_severity_normalized_lowercase(self):
        rule = Rule(name="test", severity="HIGH")
        assert rule.severity == "high"

    def test_all_valid_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            rule = Rule(name="test", severity=sev)
            assert rule.severity == sev


class TestPolicyModelRules:
    def test_default_empty(self):
        model = PolicyModel(**_minimal_policy())
        assert model.rules == []

    def test_retrocompat_no_rules(self):
        """YAML without rules still parses fine."""
        model = PolicyModel(
            **_minimal_policy(
                subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
            )
        )
        assert model.rules == []

    def test_with_rules(self):
        model = PolicyModel(
            **_minimal_policy(
                rules=[
                    {"name": "no-owner", "type": "governance", "severity": "critical", "match": {"role": "Owner"}},
                    {"name": "allow-reader", "type": "baseline", "match": {"role": "Reader"}},
                ],
            )
        )
        assert len(model.rules) == 2
        assert model.rules[0].name == "no-owner"
        assert model.rules[0].type == "governance"
        assert model.rules[0].severity == "critical"
        assert model.rules[0].match.role == "Owner"
        assert model.rules[1].type == "baseline"
        assert model.rules[1].severity == "high"  # default

    def test_rules_roundtrip_yaml(self, tmp_path: Path):
        """Rules survive YAML save/load roundtrip."""
        model = PolicyModel(
            **_minimal_policy(
                subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
                rules=[
                    {
                        "name": "no-owner-prod",
                        "type": "governance",
                        "description": "No Owner on prod",
                        "severity": "critical",
                        "match": {"scope_prefix": f"/subscriptions/{VALID_SUB_ID}", "role": "Owner"},
                    },
                    {
                        "name": "allow-infra",
                        "type": "baseline",
                        "match": {"principal_id": "aaa-bbb", "role": "Contributor"},
                    },
                ],
            )
        )
        out = tmp_path / "policy.yaml"
        save_policy_model(model, out)
        loaded = load_policy_model(out)
        assert len(loaded.rules) == 2
        governance_rules = [r for r in loaded.rules if r.type == "governance"]
        baseline_rules = [r for r in loaded.rules if r.type == "baseline"]
        assert len(governance_rules) == 1
        assert len(baseline_rules) == 1
        assert governance_rules[0].name == "no-owner-prod"
        assert governance_rules[0].severity == "critical"
        assert governance_rules[0].match.role == "Owner"
        assert baseline_rules[0].name == "allow-infra"
        assert baseline_rules[0].match.principal_id == "aaa-bbb"

    def test_name_operators_roundtrip_yaml(self, tmp_path: Path):
        """Name-based operators survive YAML save/load roundtrip."""
        model = PolicyModel(
            **_minimal_policy(
                subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
                rules=[
                    {
                        "name": "only-perm-groups",
                        "type": "governance",
                        "description": "Only GRP-PERM-* groups can have roles",
                        "severity": "high",
                        "match": {
                            "principal_type": "Group",
                            "principal_name_not_prefix": "GRP-PERM-",
                        },
                    },
                    {
                        "name": "no-temp-groups",
                        "type": "governance",
                        "severity": "medium",
                        "match": {
                            "principal_type": "Group",
                            "principal_name_contains": "TEMP",
                        },
                    },
                ],
            )
        )
        out = tmp_path / "policy.yaml"
        save_policy_model(model, out)
        loaded = load_policy_model(out)
        assert len(loaded.rules) == 2
        assert loaded.rules[0].match.principal_name_not_prefix == "GRP-PERM-"
        assert loaded.rules[0].match.principal_type == "Group"
        assert loaded.rules[1].match.principal_name_contains == "TEMP"


# ── save_policy_model ───────────────────────────────────────


class TestSavePolicyModel:
    def test_roundtrip(self, tmp_path: Path):
        original = PolicyModel(
            **_minimal_policy(
                subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
                rules=[
                    {
                        "name": "allow-reader",
                        "type": "baseline",
                        "match": {"principal_id": "aaa", "role": "Reader", "scope": "/subscriptions/xxx"},
                    },
                ],
            )
        )
        out = tmp_path / "policy.yaml"
        save_policy_model(original, out)
        loaded = load_policy_model(out)
        assert str(loaded.tenant_id) == VALID_TENANT_ID
        assert len(loaded.rules) == 1
        assert loaded.rules[0].type == "baseline"
        assert loaded.rules[0].match.principal_id == "aaa"

    def test_uuid_serialized_as_string(self, tmp_path: Path):
        policy = PolicyModel(
            **_minimal_policy(
                subscriptions=[{"id": VALID_SUB_ID, "name": "Test"}],
            )
        )
        out = tmp_path / "policy.yaml"
        save_policy_model(policy, out)
        raw = out.read_text(encoding="utf-8")
        # UUID should be a string, not a Python UUID object
        assert VALID_TENANT_ID in raw
        assert VALID_SUB_ID in raw
        assert "UUID" not in raw

    def test_empty_rules(self, tmp_path: Path):
        policy = PolicyModel(**_minimal_policy())
        out = tmp_path / "policy.yaml"
        save_policy_model(policy, out)
        loaded = load_policy_model(out)
        assert loaded.rules == []

    def test_baseline_governance_grouping(self, tmp_path: Path):
        """Le YAML contient des commentaires de regroupement baseline/governance."""
        policy = PolicyModel(
            **_minimal_policy(
                rules=[
                    {"name": "allow-1", "type": "baseline", "match": {"role": "Reader"}},
                    {"name": "deny-1", "type": "governance", "match": {"role": "Owner"}},
                    {"name": "allow-2", "type": "baseline", "match": {"role": "Contributor"}},
                ],
            )
        )
        out = tmp_path / "policy.yaml"
        save_policy_model(policy, out)
        raw = out.read_text(encoding="utf-8")

        # Check comments present
        assert "Baseline rules" in raw
        assert "Governance rules" in raw
        # Baseline before governance
        baseline_pos = raw.index("Baseline rules")
        governance_pos = raw.index("Governance rules")
        assert baseline_pos < governance_pos
        # Still loadable
        loaded = load_policy_model(out)
        assert len(loaded.rules) == 3


# ── load_policy_model (YAML) ────────────────────────────────


class TestLoadPolicyModel:
    def test_load_valid_yaml(self, tmp_path: Path):
        yaml_content = dedent(f"""\
            version: "2.0"
            tenant_id: "{VALID_TENANT_ID}"
            subscriptions:
              - id: "{VALID_SUB_ID}"
                name: "Prod"
            rules:
              - name: no-owner
                type: governance
                match:
                  role: Owner
        """)
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml_content, encoding="utf-8")

        model = load_policy_model(policy_file)
        assert str(model.tenant_id) == VALID_TENANT_ID
        assert len(model.subscriptions) == 1
        assert len(model.rules) == 1

    def test_load_file_not_found(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_policy_model("/nonexistent/path/policy.yaml")

    def test_load_invalid_yaml_syntax(self, tmp_path: Path):
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("  :\n- [invalid yaml{{{", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML"):
            load_policy_model(bad_yaml)

    def test_load_yaml_not_a_mapping(self, tmp_path: Path):
        list_yaml = tmp_path / "list.yaml"
        list_yaml.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="mapping"):
            load_policy_model(list_yaml)

    def test_load_yaml_missing_required_fields(self, tmp_path: Path):
        incomplete = tmp_path / "incomplete.yaml"
        incomplete.write_text('version: "2.0"\n', encoding="utf-8")
        with pytest.raises(ValidationError, match="tenant_id"):
            load_policy_model(incomplete)

    def test_load_example_policy_model(self):
        """Verify that the example file in examples/ is valid."""
        example = Path(__file__).resolve().parent.parent / "examples" / "policy_model.yaml"
        if not example.exists():
            pytest.skip("examples/policy_model.yaml not found")
        model = load_policy_model(example)
        assert model.version == "2.0"


# ── filter_scopes ─────────────────────────────────────────────


VALID_SUB_ID_2 = "33333333-3333-3333-3333-333333333333"


class TestFilterScopes:
    def _make_model(self) -> PolicyModel:
        return PolicyModel(
            **_minimal_policy(
                subscriptions=[
                    {"id": VALID_SUB_ID, "name": "Sub-A"},
                    {"id": VALID_SUB_ID_2, "name": "Sub-B"},
                ],
                management_groups=[
                    {"id": "mg-prod", "name": "Production"},
                    {"id": "mg-dev", "name": "Development"},
                ],
                rules=[
                    {
                        "name": "allow-sub-a",
                        "type": "baseline",
                        "match": {"scope": f"/subscriptions/{VALID_SUB_ID}", "role": "Reader"},
                    },
                    {
                        "name": "allow-sub-b",
                        "type": "baseline",
                        "match": {"scope_prefix": f"/subscriptions/{VALID_SUB_ID_2}"},
                    },
                    {
                        "name": "deny-mg-prod",
                        "type": "governance",
                        "match": {"scope": "/providers/Microsoft.Management/managementGroups/mg-prod"},
                    },
                    {
                        "name": "deny-mg-dev",
                        "type": "governance",
                        "match": {"scope": "/providers/Microsoft.Management/managementGroups/mg-dev"},
                    },
                    {
                        "name": "global-deny",
                        "type": "governance",
                        "match": {"role": "Owner"},
                    },
                ],
            )
        )

    def test_exclude_subscription(self):
        model = self._make_model()
        filtered = filter_scopes(model, exclude_subscriptions=[VALID_SUB_ID])

        assert len(filtered.subscriptions) == 1
        assert str(filtered.subscriptions[0].id) == VALID_SUB_ID_2
        assert len(filtered.management_groups) == 2
        # The rule targeting Sub-A is excluded, but global deny and sub-b rules remain
        rule_names = {r.name for r in filtered.rules}
        assert "allow-sub-a" not in rule_names
        assert "allow-sub-b" in rule_names
        assert "global-deny" in rule_names

    def test_exclude_management_group(self):
        model = self._make_model()
        filtered = filter_scopes(model, exclude_management_groups=["mg-prod"])

        assert len(filtered.management_groups) == 1
        assert filtered.management_groups[0].id == "mg-dev"
        assert len(filtered.subscriptions) == 2
        rule_names = {r.name for r in filtered.rules}
        assert "deny-mg-prod" not in rule_names
        assert "deny-mg-dev" in rule_names

    def test_exclude_both(self):
        model = self._make_model()
        filtered = filter_scopes(
            model,
            exclude_subscriptions=[VALID_SUB_ID],
            exclude_management_groups=["mg-dev"],
        )

        assert len(filtered.subscriptions) == 1
        assert len(filtered.management_groups) == 1
        rule_names = {r.name for r in filtered.rules}
        assert "allow-sub-a" not in rule_names
        assert "deny-mg-dev" not in rule_names
        assert "global-deny" in rule_names

    def test_case_insensitive(self):
        model = self._make_model()
        filtered = filter_scopes(
            model,
            exclude_subscriptions=[VALID_SUB_ID.upper()],
            exclude_management_groups=["MG-PROD"],
        )

        assert len(filtered.subscriptions) == 1
        assert len(filtered.management_groups) == 1

    def test_no_exclusions_returns_copy(self):
        model = self._make_model()
        filtered = filter_scopes(model)

        assert filtered is not model
        assert len(filtered.subscriptions) == len(model.subscriptions)
        assert len(filtered.management_groups) == len(model.management_groups)
        assert len(filtered.rules) == len(model.rules)

    def test_empty_exclusion_lists_returns_copy(self):
        model = self._make_model()
        filtered = filter_scopes(model, exclude_subscriptions=[], exclude_management_groups=[])

        assert filtered is not model
        assert len(filtered.rules) == len(model.rules)


# ── resolve_scopes ─────────────────────────────────────────────


class TestResolveScopes:
    def test_explicit_returns_unchanged(self):
        """scope=explicit → model returned as-is."""
        model = PolicyModel(
            **_minimal_policy(
                subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
            )
        )
        result = resolve_scopes(model)
        assert str(result.subscriptions[0].id) == VALID_SUB_ID
        assert result.scope == "explicit"

    def test_all_discovers_scopes(self):
        """scope=all → auto-discovery injects the scopes."""
        model = PolicyModel(**_minimal_policy(scope="all"))

        def mock_subs():
            return [(VALID_SUB_ID, "Prod", VALID_TENANT_ID), (VALID_SUB_ID_2, "Dev", VALID_TENANT_ID)]

        def mock_mgs():
            return [("mg-prod", "Production")]

        result = resolve_scopes(model, list_subs_fn=mock_subs, list_mgs_fn=mock_mgs)

        assert result.scope == "explicit"
        assert len(result.subscriptions) == 2
        assert str(result.subscriptions[0].id) == VALID_SUB_ID
        assert result.subscriptions[0].name == "Prod"
        assert len(result.management_groups) == 1
        assert result.management_groups[0].id == "mg-prod"

    def test_all_with_exclusions(self):
        """scope=all + exclude_subscriptions → filtered."""
        model = PolicyModel(
            **_minimal_policy(
                scope="all",
                exclude_subscriptions=[VALID_SUB_ID_2],
            )
        )

        def mock_subs():
            return [(VALID_SUB_ID, "Prod", VALID_TENANT_ID), (VALID_SUB_ID_2, "Dev", VALID_TENANT_ID)]

        def mock_mgs():
            return [("mg-prod", "Production"), ("mg-sandbox", "Sandbox")]

        result = resolve_scopes(model, list_subs_fn=mock_subs, list_mgs_fn=mock_mgs)

        assert len(result.subscriptions) == 1
        assert str(result.subscriptions[0].id) == VALID_SUB_ID
        assert len(result.management_groups) == 2
        assert result.exclude_subscriptions == []
        assert result.exclude_management_groups == []

    def test_all_with_mg_exclusions(self):
        """scope=all + exclude_management_groups → filtered."""
        model = PolicyModel(
            **_minimal_policy(
                scope="all",
                exclude_management_groups=["mg-sandbox"],
            )
        )

        def mock_subs():
            return [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]

        def mock_mgs():
            return [("mg-prod", "Production"), ("mg-sandbox", "Sandbox")]

        result = resolve_scopes(model, list_subs_fn=mock_subs, list_mgs_fn=mock_mgs)

        assert len(result.management_groups) == 1
        assert result.management_groups[0].id == "mg-prod"

    def test_all_no_exclusions(self):
        """scope=all without exclusions → all discovered scopes kept."""
        model = PolicyModel(**_minimal_policy(scope="all"))

        def mock_subs():
            return [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]

        def mock_mgs():
            return []

        result = resolve_scopes(model, list_subs_fn=mock_subs, list_mgs_fn=mock_mgs)

        assert len(result.subscriptions) == 1
        assert len(result.management_groups) == 0
        assert result.scope == "explicit"


# ── TestRuleRemediation ─────────────────────────────────────


class TestRuleRemediation:
    """Tests for the optional remediation field on Rule."""

    def test_remediation_default_none(self) -> None:
        from az_rbac_watch.config.policy_model import Rule

        rule = Rule(name="test", type="governance")
        assert rule.remediation is None

    def test_remediation_set(self) -> None:
        from az_rbac_watch.config.policy_model import Rule

        rule = Rule(name="test", type="governance", remediation="Fix it")
        assert rule.remediation == "Fix it"

    def test_remediation_in_yaml_roundtrip(self, tmp_path: Path) -> None:
        from az_rbac_watch.config.policy_model import load_policy_model

        data = {
            "version": "2.0",
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "subscriptions": [{"id": "22222222-2222-2222-2222-222222222222", "name": "Sub"}],
            "rules": [
                {
                    "name": "no-owners",
                    "type": "governance",
                    "remediation": "Remove Owner role",
                    "match": {"role": "Owner"},
                }
            ],
        }
        p = tmp_path / "policy.yaml"
        import yaml

        p.write_text(yaml.dump(data), encoding="utf-8")
        model = load_policy_model(p)
        assert model.rules[0].remediation == "Remove Owner role"
