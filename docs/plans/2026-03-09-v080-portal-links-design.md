# v0.8.0 — Azure Portal Links

## Goal

Add clickable Azure Portal links for scopes and principals in all report formats (HTML, console, JSON).

## Decisions

- **Scope + principal links** — no IAM blade links (fragile URLs)
- **All formats** — HTML `<a>` tags, Rich OSC 8 links in console, URL fields in JSON
- **Both reports** — compliance HTML and diff HTML
- **New utility module** — `utils/portal_links.py` with pure functions

## URL Patterns

### Scope

- Subscription: `https://portal.azure.com/#@{tenant_id}/resource/subscriptions/{sub_id}/overview`
- Resource group: `https://portal.azure.com/#@{tenant_id}/resource/subscriptions/{sub_id}/resourceGroups/{rg_name}/overview`
- Management group: `https://portal.azure.com/#view/Microsoft_Azure_ManagementGroups/ManagmentGroupDrilldownMenuBlade/~/overview/tenantId/{tenant_id}/mgId/{mg_id}`

### Principal

- Generic (works for users, groups, SPs): `https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{principal_id}`

## Components

### `src/az_rbac_watch/utils/portal_links.py`

Two pure functions:
- `build_scope_url(scope: str, tenant_id: str) -> str | None` — parse ARM scope, return portal URL or None
- `build_principal_url(principal_id: str) -> str | None` — return Entra ID URL or None if empty

### Reporter Changes

- **HTML compliance** (`html_report.py`): scope and principal columns become `<a href target="_blank">` links
- **HTML diff** (`diff_report.py`): same treatment
- **Console** (`console_report.py`): Rich `[link=url]text[/link]` markup
- **JSON** (`json_report.py`): add `scope_url` and `principal_url` fields per finding

### Tenant ID Access

- Compliance reports: `ComplianceReport.tenant_id` (already available)
- Diff reports: `Snapshot.metadata.tenant_id` (already available)

## Testing

- Unit tests for `build_scope_url`: subscription, resource group, management group, unknown format
- Unit tests for `build_principal_url`: valid ID, empty string
- HTML integration: verify `<a href=` present in output
- Console integration: verify Rich link markup
- JSON integration: verify `scope_url` and `principal_url` fields

## Out of Scope

- IAM blade deep links
- Custom role definition links
- Assignment-level links (no stable URL pattern)
