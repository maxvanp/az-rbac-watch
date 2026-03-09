# v0.7.0 — HTML Report for Diffs

## Goal

Add an HTML report output for the `diff` command, matching the visual style of the compliance HTML report.

## Decisions

- **Same visual style** as compliance report — gradient header, stat cards, single table, verdict
- **Single table** with all changes (added, removed, modified) using colored badges
- **No donut/score** — not relevant for diffs
- **Single-file HTML** with inline CSS, same approach as compliance report
- **HTML output** triggered by `--output path.html` or explicit `--format html` (to be determined in CLI integration)

## Components

### Header

Gradient blue, title "Azure Permissions Watch — Change Report". Metadata: old snapshot timestamp, new snapshot timestamp.

### Stat Cards

3 cards: Added (green if >0), Removed (red if >0), Modified (yellow if >0).

### Changes Table

| Column | Description |
|--------|-------------|
| Type | Badge: green `ADDED`, red `REMOVED`, yellow `MODIFIED` |
| Principal | Display name + ID |
| Role | Role name |
| Scope | ARM scope (truncated) |
| Details | For modified: `field: old → new` |

### Verdict

Green "No changes detected" or red "X change(s) detected".

## Files

- Modify: `src/az_rbac_watch/reporters/diff_report.py` — add `format_diff_html`
- Modify: `src/az_rbac_watch/cli.py` — wire HTML output for diff command
- Test: `tests/test_diff_report.py` — HTML generation tests

## Out of Scope

- Donut chart or compliance score
- Grouping by scope or type (single flat table)
- Filtering/search JS (keep it simple for v1)
