# SENTINEL V2 Repository Audit

## Scope and baseline

This audit reflects the current working tree, which already contains uncommitted V2/V2.1 development changes. It does not replace or reset them. No application, test, configuration, or database files were modified during this audit.

The last complete verified suite run recorded for this code state was Python 3.11.9, **75 passed, 0 failed, 0 skipped**, 54.24 seconds, exit code 0. A new rerun during this audit returned incomplete progress output without a final summary; it is not counted as a new completed run.

## Architecture

- Flask serves one Jinja page and JSON routes from `app.py`.
- `analyzer.py` validates/parses CSV files and normalizes event dictionaries.
- `windows_collector.py` reads selected local Security events through a fixed PowerShell `Get-WinEvent` script.
- `detector.py` applies rule-based authentication heuristics.
- `database.py` owns SQLite schema setup and persistence.
- `templates/index.html`, `static/script.js`, and `static/style.css` form a server-rendered, plain-JavaScript frontend; Chart.js and fonts are loaded from CDNs.
- No frontend framework, package manifest, service/repository abstraction, or migration framework is present.

## Routes and workflows

`/` renders the dashboard; `/health` is a basic health response. JSON APIs provide filtered alerts and dashboard aggregates, Windows event querying and collection, CSV upload, status/note updates, and synthetic simulation control. Sidebar navigation is hash-based across Overview, Alerts, Threats, Intel, and Reports. Intel and Reports are explicit empty states.

## Data flow

CSV and Windows adapters normalize inputs. Demo, CSV, Windows, and simulation events enter `security_events` for dashboard aggregates. Windows records are additionally stored in `windows_events`. Detection runs on newly inserted/imported batches or a simulation tick and writes alert rows. Alerts, status history, and notes are distinct from source events; V2 does not persist alert-to-event evidence links or investigation cases.

## Security and operations

Positive controls include parameterized SQL values, SQLite foreign-key enforcement on connections, bounded CSV request/row sizes, input validation, JSON object/type validation, mocked Windows permission handling, and safe DOM construction using `textContent`. Windows PowerShell arguments are a fixed script with validated numeric limits.

The application is local-only and lacks authentication, authorization, analyst identity, and CSRF protection. `app.run(debug=True)` is development-only. Configuration and SQLite path are mostly hard-coded. There is no centralized production logging/error policy, rate limiting, retention worker, or migration version table. Windows integration tests are mocked; real Security-log access was not validated on a controlled Windows host.

## External dependencies

`requirements.txt` pins Flask 3.0.3 and pandas 2.2.3. Pandas is not used by the inspected application modules. Pytest is a development/test dependency but is installed separately per README. Chart.js and Google Fonts are runtime CDN dependencies. PowerShell is provided by Windows; no Python Windows Event Log package is used.

## Main risks

1. No identity/authorization boundary for any dashboard or mutation endpoint.
2. Event identity and deduplication are not observation-preserving: generic event uniqueness is an exact-field uniqueness constraint; there is no durable import/observation ledger.
3. Windows events have a separate projection/table with no canonical-event FK.
4. Detection only sees each newly processed batch/tick, limiting cross-batch correlation.
5. No evidence links or immutable rule-version foreign keys exist for alerts.
6. SQLite startup/schema evolution is inline and only explicitly initialized in direct `python app.py` startup.
7. Concurrency, retention, archive, and production backup/restore have not been qualified.
8. Threat intelligence, full investigations, and report generation are not implemented.

See `SENTINEL_V2_DATABASE_AUDIT.md`, `SENTINEL_V3_IMPLEMENTATION_GAPS.md`, and `SENTINEL_V3_CHANGE_PLAN.md` for detailed follow-up.