# SENTINEL_V2_REPOSITORY_AUDIT.md

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

---

# SENTINEL_V2_FILE_MAP.md

# SENTINEL V2 File Map

| Path | Responsibility | Current status / dependency |
|---|---|---|
| `app.py` | Flask app, routes, input validation, ingestion orchestration, metrics, simulation, detection calls | Imports analyzer, database, detector, Windows collector; direct route-to-database coupling |
| `database.py` | SQLite schema, seed alerts, alert lifecycle, event persistence, metric queries | Single persistence module; inline CREATE/ALTER schema management |
| `analyzer.py` | CSV file/stream parsing, semantic validation, common event normalization | Used for sample CSV initialization and CSV import route |
| `windows_collector.py` | Windows capability check, PowerShell query, Windows event normalization | Called by Windows collect API; subprocess only on supported collection request |
| `detector.py` | Authentication pattern detection and alert construction | Called by CSV, Windows, and synthetic ingestion flows |
| `templates/index.html` | Single server-rendered dashboard, nav views, forms and tables | Uses Flask/Jinja and IDs/classes consumed by script.js |
| `static/script.js` | Navigation, charts, alert table, filters, CSV upload, Windows collection polling, live simulation | Plain DOM APIs and fetch; Chart.js global from CDN |
| `static/style.css` | Dashboard layout, navigation, panels, tables and responsive styles | Applied to Jinja template; no CSS build process |
| `sample_logs.csv` | Fictional demo authentication records | Loaded into demo event store on dashboard initialization |
| `requirements.txt` | Runtime package pins | Flask and pandas; pandas appears unused in application code |
| `.gitignore` | Python caches and local DB files for a standalone repository | Does not untrack already-tracked database files in a parent Git repository |
| `conftest.py` | Autouse test fixture using temporary SQLite database and resetting Flask config | Isolates tests from default development DB |
| `test_alert_filters.py` | Alert filter, status/note, simulation and detector regression tests | Uses Flask test client and fixture database |
| `test_api_validation.py` | JSON shape, content type, field allowlist, type/range validation | Uses Flask test client |
| `test_csv_import.py` | CSV semantic validation, limits, upload, deduplication | Exercises parser and multipart route |
| `test_dashboard_metrics.py` | Empty/large aggregates and dashboard metrics API | Includes 10,000-event aggregate case |
| `test_database_reliability.py` | FK enforcement, alert deduplication, iterator handling | SQLite persistence tests |
| `test_frontend_security.py` | Malicious payload pass-through and guard against HTML-parsing sinks | Static source assertion plus API test; browser XSS probe was separately verified |
| `test_navigation.py` | Nav links map to views and Overview is initial active link | HTML structure contract; browser back/forward tested separately |
| `test_windows_collector.py` | Mocked PowerShell result parsing, permission/Linus behavior, filters and record dedup | Does not exercise actual local Security log |
| `security_dashboard.db` | Local SQLite development data | Present/tracked in workspace; treat as user data and do not reset during planning |

## Directory outline

```text
sentinel-dashboard/
  app.py
  analyzer.py
  database.py
  detector.py
  windows_collector.py
  requirements.txt
  README.md
  sample_logs.csv
  security_dashboard.db
  conftest.py
  test_*.py
  templates/index.html
  static/script.js
  static/style.css
```

The listed files describe the inspected working tree. This audit did not add or remove any application files.

---

# SENTINEL_V2_DATABASE_AUDIT.md

# SENTINEL V2 Database Audit

## Scope

Inventory is based on `database.py` schema creation and migration logic, not a fresh inspection/mutation of the live database. No migrations or database writes were performed for this report.

## Tables and relationships

| Table | Columns / role | Relationships and constraints |
|---|---|---|
| `alerts` | Timestamp, source IP/host, event type, severity, reason, status, created/updated, rule ID, first/last-seen, occurrence count | Integer PK. No FK to source event, detection rule/version, investigation, or actor. Active detection upsert is rule/IP/host/status/time-window logic in application code, not a uniqueness constraint. |
| `alert_notes` | Note text, creation time | FK `alert_id -> alerts.id`; FK enforcement enabled by `get_connection()`. No actor FK. |
| `alert_status_history` | Previous/new status, change time | FK `alert_id -> alerts.id`; no actor FK. |
| `analysis_history` | Analysis time, total event count, alert count, status | No relationships; currently unused by visible API/UI. |
| `windows_events` | Record ID, event ID, timestamp, username/computer, IP, logon type, description, severity, type/status, import time | Unique `(computer_name, event_record_id)`. No FK to general event, batch, source registry, alert, or evidence. |
| `security_events` | Timestamp, IP, event type, username, status, host, source | Unique `(source, timestamp, source_ip, event_type, username, status, host)`; indexed on timestamp and source IP. No source FK, stable event ID, batch FK, raw payload reference, or observation ledger. |

The connection factory sets `PRAGMA foreign_keys = ON`. The context manager handles commit/rollback but does not explicitly close connections. The development schema is created via `CREATE TABLE IF NOT EXISTS` and conditional `ALTER TABLE` statements; no schema version or migration history is recorded. Initial seed alerts are inserted when the alert table is empty.

## Existing event and alert records

- **Events:** `security_events` is the aggregate source for total/success/failure counts and trends. Windows-specific records also exist in `windows_events`.
- **Alerts:** `alerts` is the finding/workflow row. Detection evidence is not stored as a relationship.
- **Incidents/investigations:** no separate table exists. Current investigation workflow is alert status, note, and status history.
- **Imports:** there is no import-batch/import-receipt table. CSV request metadata, file digest, row ordinal, rejected row records, and import-operation identity are not durable.
- **Observations:** there is no immutable per-input-row observation table. Generic exact-field uniqueness and Windows record uniqueness can prevent duplicate rows but do not preserve each observation or provenance.

## Integrity, deduplication and migration concerns

1. V2 Windows and generic event tables duplicate overlapping event data without FK linkage or a documented reconciliation key.
2. Generic event deduplication treats equality of source/timestamp/IP/type/user/status/host as identity. Two legitimately identical rows can collapse; repeated observations are not retained.
3. Windows record identity is scoped only by computer name and record ID, not channel/log generation; reset/reuse collisions need handling.
4. Alert upsert uses a 15-minute window based on `created_at`; repeat updates set `last_seen_at`, but matching is not extended by that timestamp.
5. Legacy alerts have no immutable detection-rule version/evidence linkage.
6. `analysis_history` is dormant and should not be confused with durable ingestion-batch history.
7. Migration logic has no version table, explicit migration transaction log, backup verification, or rollback/replay process.

## Proposed V3 direction (design only)

Retain the V2 tables during additive migration. Add source registry, durable batches, per-row observations, conflict records, canonical-event identity metadata, evidence links, versioned rules, investigations, analyst activity, IOC/feed provenance, and optional report snapshots only after policy approval. Never backfill unknown legacy evidence/rule versions by inference. Keep SQLite behind a repository contract. See the change plan; no schema has been changed.

---

# SENTINEL_V3_IMPLEMENTATION_GAPS.md

# SENTINEL V3 Implementation Gaps

This document distinguishes current V2 behavior from proposed V3 work. Proposed capabilities are not present merely because they appear in planning material.

## Implemented V2 capabilities

- Local Flask/Jinja dashboard and JSON APIs.
- Alert filtering, status changes, notes and status history.
- CSV upload with 2 MiB request bound, 10,000-row cap, semantic validation, and exact normalized-row deduplication by source.
- Mock-tested Windows Security collection using fixed PowerShell `Get-WinEvent` query for IDs 4624, 4625, 4634, 4648, and 4672; manual/polling frontend controls.
- Synthetic activity simulation.
- SQLite event metrics, alert severity distribution, and seven UTC-day trend.
- Hash navigation across Overview, Alerts, Threats, Intel, Reports. Intel/Reports are empty states, not functional subsystems.
- JSON API shape validation, SQLite FK enforcement, safe DOM construction for API-backed content.

## Gaps against V3 direction

### Identity, events and ingestion

- No authenticated source registry, source configuration versions, durable import operation keys, content-digest records, or parent/child batches.
- No per-row immutable observation ledger, quarantine/reprocessing workflow, or identity-conflict record.
- Generic and Windows events are represented in separate tables; no reliable cross-table canonical relationship.
- Generic dedupe is exact-field based and can collapse indistinguishable legitimate observations; there is no stable ID/fingerprint confidence model.
- No structured network telemetry adapters or schema versioning.
- External API adapters, checkpoints, feed retries and source health are not present.

### Detection, alerts and investigations

- Rules are Python functions, not persisted immutable/versioned rule definitions.
- Findings are evaluated per newly imported batch/tick; there is no persisted correlation window/query spanning batches.
- No alert-to-source-event evidence links or reproducibility record.
- Alert workflow has status/notes/history, but no incident/investigation entity, assignment, actor attribution, case grouping, or authorization.
- No D-06 timestamp precision metadata, source timezone policy registry, or clock uncertainty model. V2 normalized timestamps do not preserve full original timestamp interpretation metadata.

### Threat intelligence and reports

- Intel view is a placeholder. No manual IOC registry, feed sync, provenance, confidence/reliability, expiry/revocation history, match records, licensing controls or provider integrations.
- Reports view is a placeholder. No report definitions, snapshots, exports, calculation-versioning or report retention.

### Security and operations

- Local-only application has no login, RBAC, CSRF protection, analyst audit principal or rate limiting. Debug server must not be used for shared deployment.
- SQLite initialization is coupled to direct script startup, not a production application factory/migration runner.
- No logging/metrics/health detail for source ingestion, no durable queue, retry scheduler, retention/archival, backup verification, or recovery replay.
- SQLite single-writer behavior has not been benchmarked under the approved workload; no actual Windows collector validation on a controlled Windows host is established.
- `pandas` is declared but appears unused. Chart.js and fonts are CDN dependencies.

## Dependencies and implementation order

1. Owner approvals for D-06 and remaining identity/privacy/retention/source/actor/performance policies.
2. Migration runner, backup, repository contract, and V2 compatibility adapter.
3. Source registry, batch receipts, observations, idempotency, and conflicts.
4. Canonical event identity, timestamp interpretation and adapters.
5. Versioned detection rules and exact evidence.
6. Auth/RBAC and append-only analyst audit before multi-user workflow.
7. Investigations, IOC/feed lifecycle, network telemetry, reports and retention.
8. Controlled Windows integration, load/concurrency, migration/rollback and security acceptance.

Do not begin persistent V3 ingestion or migration until the blocking policies and tests are approved.

---

# SENTINEL_V3_CHANGE_PLAN.md

# SENTINEL V3 Change Plan

**Status: planning only.** This plan does not authorize implementation, migration, or cutover. It is scoped to the current V2 working tree and preserves all existing workflows until V3 acceptance.

## Working-tree preservation

The audit found pre-existing uncommitted changes across V2 source, tests, README and SQLite data. They are outside the scope of these reports and must not be reset or overwritten. Audit outputs are additive Markdown documents only.

## Proposed stages and file impact

| Stage | Existing files likely to modify | New files/components likely needed | Acceptance gates |
|---|---|---|---|
| 0. Owner decisions | None until approval | ADR/decision records, policy docs | D-01â€“D-16 owner decisions; D-06 timestamp decisions included |
| 1. Foundation | `app.py`, `database.py`, `requirements.txt` only if approved dependency/config changes | App factory/config, repository interfaces, migration runner, logging/error config | Startup, health, repository contract, V2 regression tests |
| 2. Identity/time/event persistence | `analyzer.py`, `windows_collector.py`, `database.py`, `app.py` | Source adapters, source registry, batches, observations, conflicts, event identity policy | D-01/02/03/04/05/06 tests; retries, conflicts, UTC policy |
| 3. Detection/evidence | `detector.py`, `database.py`, `app.py` | Rule registry/version repository, detection service/evidence tables | Deterministic replay, rule version immutability, exact evidence |
| 4. Authentication/RBAC/audit | `app.py`, `templates/index.html`, `static/script.js`, `static/style.css`, `database.py` | Auth/session, user/role, CSRF and audit services | Access matrix, CSRF, session, actor attribution, audit immutability |
| 5. Investigations | Existing alert templates/API only with compatibility; `database.py`, `app.py`, JS/CSS | Investigation service, alert join and activity UI | Group/unlink without alert mutation; concurrent ownership/audit |
| 6. Threat intelligence | `app.py`, templates, JS/CSS, database only behind services | Feed adapters, IOC repository, provenance/history/match services | Feed idempotency, conflict, expiry/revoke, licensing review |
| 7. Network telemetry | Ingestion contracts/adapters, event queries, UI if approved | Versioned flow/DNS/IDS adapters | Representative-data schema, privacy, throughput, no loss |
| 8. Reporting | Report route/UI only after scope approved | Report service, immutable snapshots, artifact storage adapter | Reproducible snapshots, authorization, integrity/retention |
| 9. Retention and cutover | Migration/config/deployment files only after approval | Archive/retention worker, backup/replay tooling | Backup restore, parity, load, rollback and post-cutover replay |

Actual file names and boundaries should be decided after implementation approval and an updated inspection; this plan is not a request to create all listed components at once.

## Existing functionality to preserve

- `/`, `/health`, alert/dashboard APIs, status/note workflows, Windows collection APIs, CSV import, and synthetic simulation unless an approved compatibility plan replaces them.
- Current Jinja dashboard and hash navigation.
- SQLite V2 data, alert IDs, notes, status history, and Windows records.
- Existing CSV schema and validated import behavior.
- Existing detection output and dashboard metrics until acceptance tests prove a replacement is equivalent or intentionally changed.

## Proposed database additions

Additive schema only: schema version/migration log; `data_sources`; `ingest_batches` and child batches; immutable `event_observations`; identity conflicts; canonical event identity/provenance fields; Windows extension/compatibility mapping; immutable detection rule versions; detection evidence; investigations and alert links; analysts and append-only activity; threat-intelligence feeds, indicators, observations, history and matches; optional report snapshots; archive/retention metadata. Exact columns, constraints, transaction boundaries and indexes remain subject to approved decisions.

## Migration and rollback risks

- V2 lacks import observations, so old deduped rows cannot be reconstructed.
- V2 alerts lack source-event evidence and immutable rule versions; those fields must stay explicitly unknown for legacy rows.
- `windows_events` and `security_events` overlap but cannot always be safely reconciled; uncertain rows must remain distinct and create conflicts.
- Baseline seed/demo rows and existing local user data must be distinguished without deleting them.
- SQLite has one writer; large migrations and ingestion can contend.
- Restoring a pre-cutover backup alone loses acknowledged post-cutover writes; freeze writes or use a durable replay journal.
- Do not use destructive renames/drops until V3 acceptance, independent backup restore, parity verification, and explicit owner authorization.

## Required validation

- Preserve baseline counts for alerts, notes, status history, security events and Windows events; reconcile metrics and UTC date ranges.
- `PRAGMA integrity_check` exactly `ok`, zero rows from `PRAGMA foreign_key_check`, and executable orphan/evidence/source/conflict/rule-version verification queries.
- Idempotency, ambiguity, conflict, transaction rollback, restart recovery, evidence immutability, and V2 migration fixtures.
- Authentication/RBAC/CSRF/XSS/SQLi/secret-redaction tests before shared-user deployment.
- Controlled Windows event-log test, representative network/feed datasets, concurrent ingest/read load, backup restore, archive restore and rollback/replay rehearsal.
- Full suite with explicit final summary and process exit code 0; no success claim from partial terminal output.

No code, tests, configuration or database changes are part of this plan.

---

