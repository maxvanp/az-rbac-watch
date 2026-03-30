"""Tests for MCP security module — input validation, path sanitization, audit logging."""

from __future__ import annotations

import json

import pytest

from az_rbac_watch.mcp.security import (
    audit_log,
    safe_error,
    validate_action,
    validate_path,
    validate_principal,
    validate_scope,
    validate_subscription_id,
)


class TestSubscriptionIdValidation:
    def test_valid_uuid(self):
        result = validate_subscription_id("12345678-1234-1234-1234-123456789abc")
        assert result == "12345678-1234-1234-1234-123456789abc"

    def test_valid_uuid_uppercase(self):
        result = validate_subscription_id("12345678-1234-1234-1234-123456789ABC")
        assert result == "12345678-1234-1234-1234-123456789ABC"

    def test_rejects_non_uuid(self):
        with pytest.raises(ValueError, match="subscription_id"):
            validate_subscription_id("not-a-uuid")

    def test_rejects_shell_injection(self):
        with pytest.raises(ValueError, match="subscription_id"):
            validate_subscription_id("$(whoami)")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="subscription_id"):
            validate_subscription_id("")


class TestActionValidation:
    def test_valid_action(self):
        result = validate_action("Microsoft.Compute/virtualMachines/delete")
        assert result == "Microsoft.Compute/virtualMachines/delete"

    def test_valid_wildcard(self):
        result = validate_action("Microsoft.Compute/*")
        assert result == "Microsoft.Compute/*"

    def test_rejects_shell_chars(self):
        with pytest.raises(ValueError, match="action"):
            validate_action("Microsoft.Compute;rm -rf /")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="action"):
            validate_action("")

    def test_rejects_single_segment(self):
        with pytest.raises(ValueError, match="action"):
            validate_action("Microsoft")


class TestScopeValidation:
    def test_valid_scope(self):
        result = validate_scope("/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/rg-prod")
        assert result == "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/rg-prod"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="scope"):
            validate_scope("")

    def test_rejects_invalid_chars(self):
        with pytest.raises(ValueError, match="scope"):
            validate_scope("/subscriptions/$(whoami)")

    def test_rejects_no_leading_slash(self):
        with pytest.raises(ValueError, match="scope"):
            validate_scope("subscriptions/foo")


class TestPrincipalValidation:
    def test_valid_name(self):
        result = validate_principal("John Doe")
        assert result == "John Doe"

    def test_valid_email(self):
        result = validate_principal("john@example.com")
        assert result == "john@example.com"

    def test_valid_uuid(self):
        result = validate_principal("12345678-1234-1234-1234-123456789abc")
        assert result == "12345678-1234-1234-1234-123456789abc"

    def test_rejects_control_chars(self):
        with pytest.raises(ValueError, match="principal"):
            validate_principal("user\x00name")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError, match="principal"):
            validate_principal("a" * 257)

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="principal"):
            validate_principal("")


class TestPathValidation:
    def test_valid_path_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        test_file = tmp_path / "test.yaml"
        test_file.write_text("hello")
        result = validate_path(str(test_file))
        assert result == test_file.resolve()

    def test_rejects_traversal(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="outside allowed"):
            validate_path("../../etc/passwd")

    def test_rejects_etc_passwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="outside allowed"):
            validate_path("/etc/passwd")

    def test_rejects_must_exist_nonexistent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="does not exist"):
            validate_path(str(tmp_path / "nonexistent.yaml"), must_exist=True)

    def test_rejects_symlink(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        target = tmp_path / "real.yaml"
        target.write_text("hello")
        link = tmp_path / "link.yaml"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="symlink"):
            validate_path(str(link))


class TestSafeError:
    def test_strips_bearer_token(self):
        err = Exception("Failed with Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")
        result = safe_error(err)
        assert result == "Azure authentication error. Run 'az login' and retry."

    def test_strips_shared_key(self):
        err = Exception("Auth failed: SharedKey abc123")
        result = safe_error(err)
        assert result == "Azure authentication error. Run 'az login' and retry."

    def test_strips_sig(self):
        err = Exception("URL contains sig=abc123def456")
        result = safe_error(err)
        assert result == "Azure authentication error. Run 'az login' and retry."

    def test_strips_client_secret(self):
        err = Exception("Credential with client_secret=supersecret")
        result = safe_error(err)
        assert result == "Azure authentication error. Run 'az login' and retry."

    def test_truncates_long_errors(self):
        err = Exception("x" * 600)
        result = safe_error(err)
        assert len(result) <= 500

    def test_passes_normal_errors(self):
        err = Exception("Something went wrong")
        result = safe_error(err)
        assert result == "Something went wrong"


class TestAuditLog:
    def test_writes_json_to_stderr(self, capsys):
        audit_log(
            tool="rbac_scan", args={"scope": "/subscriptions/abc"}, status="success", duration_ms=42, findings_count=3
        )
        captured = capsys.readouterr()
        data = json.loads(captured.err)
        assert data["tool"] == "rbac_scan"
        assert data["status"] == "success"
        assert data["duration_ms"] == 42
        assert data["findings"] == 3

    def test_excludes_paths_from_logged_args(self, capsys):
        audit_log(
            tool="rbac_scan",
            args={
                "scope": "/sub/abc",
                "policyPath": "/home/user/policy.yaml",
                "outputPath": "/tmp/out.json",
                "snapshotPath": "/tmp/snap.json",
            },
            status="success",
            duration_ms=10,
        )
        captured = capsys.readouterr()
        data = json.loads(captured.err)
        assert "policyPath" not in data["args"]
        assert "outputPath" not in data["args"]
        assert "snapshotPath" not in data["args"]
        assert data["args"]["scope"] == "/sub/abc"
