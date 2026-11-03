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