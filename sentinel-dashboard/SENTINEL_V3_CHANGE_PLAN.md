# SENTINEL V3 Change Plan

**Status: planning only.** This plan does not authorize implementation, migration, or cutover. It is scoped to the current V2 working tree and preserves all existing workflows until V3 acceptance.

## Working-tree preservation

The audit found pre-existing uncommitted changes across V2 source, tests, README and SQLite data. They are outside the scope of these reports and must not be reset or overwritten. Audit outputs are additive Markdown documents only.

## Proposed stages and file impact

| Stage | Existing files likely to modify | New files/components likely needed | Acceptance gates |
|---|---|---|---|
| 0. Owner decisions | None until approval | ADR/decision records, policy docs | D-01–D-16 owner decisions; D-06 timestamp decisions included |
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