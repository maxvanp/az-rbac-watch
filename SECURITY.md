# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in az-rbac-watch, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/maxvanp/az-rbac-watch/security/advisories/new).

## Scope

az-rbac-watch is a read-only scanning tool — it never modifies Azure RBAC assignments. Security concerns typically involve:

- Credentials leaking through logs or reports
- Policy model parsing vulnerabilities
- Dependency vulnerabilities

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |
