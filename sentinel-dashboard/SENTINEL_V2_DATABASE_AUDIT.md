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