# SENTINEL_V3_DECISION_REGISTER.md

## Owner-Confirmed Architectural Foundations (O-01 through O-05)

These five decisions form the immutable foundation for all V3 work. Four are fully owner-confirmed; one contains a confirmed fact with a pending sub-choice that cascades to technical decisions but does not block Phase 1A start.

| ID | Decision | Summary | Status |
|----|---|---|---|
| **O-01** | **Deployment Target: Local** | Sentinel is a **local application** deployed on premises. The local deployment fact is confirmed. **The access model remains pending** and cascades to TD-10, TD-11, and all authentication-dependent decisions, but the confirmed local deployment fact does not block Phase 1A start. Phase 1A proceeds on the confirmed local fact, with the access model determined later. | LOCAL_CONFIRMED / ACCESS_PENDING |
| **O-02** | **Data Sources** | Four event ingestion paths: Windows events, CSV imports, network telemetry, and external APIs. V3 must support all four without preference. **Simulation is an internal test/demo path, not one of the four owner-confirmed sources.** | CONFIRMED |
| **O-03** | **Threat Intelligence Model** | Hybrid model: manual IOC registry plus framework for automated feed providers. Does not mandate automated feed integration in Phase 1, but the architectural contract must accommodate it. Manual and automated feeds are separate implementation stages. | CONFIRMED |
| **O-04** | **Backend Framework** | Confirms Flask remains the web framework. No migration to other frameworks in V3 Phase 1. Existing route patterns, Jinja templates, and WSGI configuration must be preserved. | CONFIRMED |
| **O-05** | **Database Engine** | Confirms SQLite remains the persistence engine. No migration to PostgreSQL, MySQL, or production-grade RDBMS in Phase 1. File-based database, development workflow compatibility, and zero-dependency deployment are preserved. | CONFIRMED |

---
## Technical Decisions (TD-01 through TD-16)

Each decision includes: Title, Rationale, Options, Recommendation, Advantages/Disadvantages, Dependencies, Status, Owner approval requirement.
# SENTINEL_V3_DECISION_REGISTER.md

## Owner-Confirmed Architectural Foundations (O-01 through O-05)

These five decisions form the immutable foundation for all V3 work. Four are fully owner-confirmed; one contains a confirmed fact with a pending sub-choice that cascades to technical decisions but does not block Phase 1A start.

| ID | Decision | Summary | Status |
|----|---|---|---|
| **O-01** | **Deployment Target: Local** | Sentinel is a **local application** deployed on premises. The local deployment fact is confirmed. **The access model remains pending** and cascades to TD-10, TD-11, and all authentication-dependent decisions, but the confirmed local deployment fact does not block Phase 1A start. Phase 1A proceeds on the confirmed local fact, with the access model determined later. | LOCAL_CONFIRMED / ACCESS_PENDING |
| **O-02** | **Data Sources** | Four event ingestion paths: Windows events, CSV imports, network telemetry, and external APIs. V3 must support all four without preference. **Simulation is an internal test/demo path, not one of the four owner-confirmed sources.** | CONFIRMED |
| **O-03** | **Threat Intelligence Model** | Hybrid model: manual IOC registry plus framework for automated feed providers. Does not mandate automated feed integration in Phase 1, but the architectural contract must accommodate it. Manual and automated feeds are separate implementation stages. | CONFIRMED |
| **O-04** | **Backend Framework** | Confirms Flask remains the web framework. No migration to other frameworks in V3 Phase 1. Existing route patterns, Jinja templates, and WSGI configuration must be preserved. | CONFIRMED |
| **O-05** | **Database Engine** | Confirms SQLite remains the persistence engine. No migration to PostgreSQL, MySQL, or production-grade RDBMS in Phase 1. File-based database, development workflow compatibility, and zero-dependency deployment are preserved. | CONFIRMED |

---
### TD-04: Schema Version and Migration Log

| Field | Content |
|---|---|
| **Title** | Schema Version and Migration Log |
| **Rationale** | V2 database audit identifies: "Migration logic has no version table, explicit migration transaction log, backup verification, or rollback/replay process." V3 change plan Stage 1 foundation requires: "App factory/config, repository interfaces, migration runner, logging/error config." |
| **Options** | A. Add `schema_migrations` table: `version VARCHAR NOT NULL`, `migrated_at TEXT NOT NULL`, `batch_id TEXT`, `up_applied TEXT`, `down_applied TEXT`. Initialize with existing V2 schema version ("v2.0"). Full migration runner capability.<br>B. Add minimal version table: `version VARCHAR NOT NULL PRIMARY KEY`, `migrated_at TEXT NOT NULL` only. No rollback columns.<br>C. Defer; keep V2 inline schema creation and document that migrations are out of V3 scope. |
| **Recommendation** | A – Full `schema_migrations` table as specified in V3 change plan Stage 1. Enables future schema evolution with rollback, backup verification, and replay journal patterns. Initialize with "v2.0" to mark existing V2 schema state. Low risk: table added via `CREATE TABLE IF NOT EXISTS`; no V2 data alteration. |
| **Advantages** | Enables future schema evolution with rollback. Supports backup verification and replay journal patterns. Aligns with V3 change plan Stage 1 foundation. Low risk: `CREATE TABLE IF NOT EXISTS`; no V2 data alteration. |
| **Disadvantages** | Adds table; must validate `PRAGMA integrity_check` and `PRAGMA foreign_key_check` after addition. Does not automatically migrate existing V2 data; requires seed/backfill script for existing installations. |
| **Dependencies** | TD-01 (batches – migration log can reference batch IDs for partial rollforward). TD-05 (detection rule_version – recorded in migration log). TD-05 owner approval for column addition. |
| **Status** | PROPOSED – Awaiting owner input on whether to include migration runner in Phase 1 or defer to Phase 2. |
| **Owner approval required** | YES – must validate that adding `schema_migrations` table does not break `init_db()` startup behavior or V2 seed alert insertion logic. Must pass `integrity_check` and `foreign_key_check` after addition. **This approval is required as a Phase 1A gate prerequisite.** The implementation work itself occurs within Phase 1A after approval. |
### TD-03: Immutable Observation Ledger (Conditional on TD-01)

| Field | Content |
|---|---|
| **Title** | Immutable Observation Ledger |
| **Rationale** | V3 implementation gaps document explicitly lists: "No per-row immutable observation ledger, quarantine/reprocessing workflow, or identity-conflict record." V2 database audit: "there is no import-batch/import-receipt table. CSV request metadata, file digest, row ordinal, rejected row records, and import-operation identity are not durable." TD-01 and TD-03 must be coherent: observations depend on batch IDs from TD-01. |
| **Options** | A. Add `event_observations` table (id PK, batch_id FK, event_fingerprint, source_file, row_ordinal, normalization_status, rejection_reason, original_timestamp_iso, retained_original_timestamp BOOLEAN). Each row records: fingerprint, source CSV/file, import batch ID, original row ordinal, normalization status, rejection reason (if any), and **preserves original timestamp with timezone**. Append-only, insert-never-update. Linked to TD-01 batches. If batch ID is NULL (pre-TD-01 data), original timestamp and fingerprint still retained. **Never truncate to minute granularity.**<br>B. Add per-row observation capability but allow updates/deletes via application logic (not append-only).<br>C. Defer; keep V2 behavior and document that observation ledger is out of scope for V3 Phase 1. |
| **Recommendation** | A – Add `event_observations` table as append-only, linked to TD-01 batches. **Critical coherence**: If TD-01 is not implemented, TD-03 reverts to DEFERRED status, because observations depend on batch IDs. If TD-01 IS implemented, TD-03 is PROPOSED. Original timestamps are preserved with timezone; `retained_original_timestamp` BOOLEAN flag indicates whether the row stores the original ISO timestamp or a normalized version. Never truncate to minute granularity. Coherent with TD-01 and TD-02: fingerprint is auxiliary, original timestamp is canonical identity. |
| **Advantages** | Full provenance for every imported row. Enables quarantine/reprocessing workflow. Supports conflict resolution and re-import idempotency. Compliant with V3 change plan Stage 2. Preserves original timestamp precision and timezone. Coherent with TD-01 batch infrastructure and TD-02 fingerprint model. |
| **Disadvantages** | Adds table and foreign keys; must validate with integrity checks. Requires application code to write observations on every import path (confirmed Windows, CSV, network telemetry, external APIs). Blocked until TD-01 is implemented. |
| **Dependencies** | TD-01 (source registry/batches – observations linked to batch ID). If TD-01 not implemented, TD-03 is DEFERRED. TD-04 (schema version/migration log – records ledger creation). **Confirmed ingestion paths** must be updated to write observations. |
| **Status** | PROPOSED (CONDITIONAL) – Deferred until TD-01 (batch receipts) is implemented. If TD-01 remains PROPOSED, TD-03 is also DEFERRED. Owner must decide Phase 1 vs Phase 2 scope. Ensures TD-01 and TD-03 do not contradict each other. **TD-03 is conditional on TD-01.** It does not block Phase 1A start if TD-01 is implemented first. Implementation is a task within Phase 1A if the owner chooses, but Phase 1A can start without it. |
| **Owner approval required** | YES – decision on Phase 1 vs Phase 2 scope. If Phase 1, must validate that confirmed ingestion paths can be updated without V2 regressions. Must pass `integrity_check` and `foreign_key_check` after additions. **This decision is conditional on TD-01.** It does not block Phase 1A start if TD-01 is implemented first. |
### TD-02: Event Identity and Fingerprint Confidence Model

| Field | Content |
|---|---|
| **Title** | Event Identity and Fingerprint Confidence Model |
| **Rationale** | V2 database audit notes generic event deduplication treats equality of source/timestamp/IP/type/user/status/host as identity, which can collapse two legitimately identical rows. V3 implementation gaps document: "No per-row immutable observation ledger, quarantine/reprocessing workflow, or identity-conflict record." No stable ID/fingerprint confidence model exists. |
| **Options** | A. Store a computed fingerprint (SHA-256 of canonical fields: normalized_source_ip, event_type, **original_timestamp_iso**, username, host) with confidence scoring, but do **not** enforce uniqueness. Original timestamps preserved intact with timezone information. Fingerprint is an auxiliary identity signal with a confidence level, **not** definitive proof that two observations are identical. Two events with identical fingerprints may be legitimate distinct observations; two events with different fingerprints may share meaningful identity fields.<br>B. Enforce unique constraint on fingerprint column and collapse duplicates at ingest time.<br>C. Skip fingerprinting; rely on application-level dedup only (current V2 behavior). |
| **Recommendation** | A – Store fingerprint with confidence scoring, do not enforce uniqueness. Preserves V2 ability to have multiple legitimate identical rows while making duplicates visible. Fingerprint is supplementary; canonical identity relies on original exact fields, not the hash. **Never silently discard potentially distinct observations.** Never truncate timestamps to minute granularity as a universal identity rule. |
| **Advantages** | Makes duplicate detection visible without losing legitimate observations. Enables conflict records (TD-04) and quarantine workflows. Low implementation risk; no constraint violations on existing data. Respects timestamp precision and timezone. |
| **Disadvantages** | Does not prevent duplicate rows at the DB level. Requires application code to compute and store fingerprints. Confidence threshold requires owner definition. Never conflates fingerprint with definitive identity. |
| **Dependencies** | TD-01 (source registry/batches – fingerprint stored at batch level). TD-04 (schema version log – records fingerprint generation). |
| **Status** | PROPOSED – Awaiting owner input on confidence score threshold and whether fingerprints should be exposed via API. |
| **Owner approval required** | NO – computed column, no constraint change. Can be implemented in application code (`analyzer.py` or `database.py`) with a migration that adds the column via `ALTER TABLE`. Owner sign-off needed only for API exposure policy and confidence threshold. **This decision is optional for Phase 1A.** It does not block Phase 1A start. Implementation is an task within Phase 1A if the owner chooses, but Phase 1A can start without it. |
| **Title** | Source Registry and Durable Ingestion Batches |
| **Rationale** | V2 repository audit identified overlapping event data in `security_events` and `windows_events` tables without FK linkage or reconciliation key. No import-batch/receipt table exists. CSV request metadata, file digest, row ordinal, and import-operation identity are not durable. V3 requires source tracking and batch-level dedup as a coherent foundation for all subsequent decisions. |
| **Options** | A. Add `data_sources` table (source_type, source_name, file_hash, config_path) + `ingest_batches` table (batch_id PK, source_type FK, source_ref, file_hash, imported_at, status, event_count). Link child batch records for multi-file imports. Record batch-level metadata enabling dedup and re-import idempotency.<br>B. Add only `ingest_batches` table with batch_id, source_type, imported_at; track source via `source_type` column on each event row.<br>C. Keep V2 schema unchanged; document manual reconciliation procedures. |
| **Recommendation** | A – Additive: `data_sources` and `ingest_batches` (with child batches). Retain existing V2 tables during migration. This is the foundation for TD-02 (fingerprints), TD-03 (observations), and TD-06 (source attribution). Batch ID propagates to all downstream tables. |
| **Advantages** | Preserves all V2 data. Enables batch-level dedup and idempotent re-imports. Provides source attribution without requiring actor FK on every row. Lower migration risk than full schema overhaul. Serves as foundation for observations and attribution. |
| **Disadvantages** | Adds table(s); must validate with `PRAGMA integrity_check` and `PRAGMA foreign_key_check` after additions. Does not add canonical-event identity/fingerprint confidence model (addressed in TD-02). Still no immutable observation ledger for per-row provenance (addressed in TD-03). |
| **Dependencies** | TD-02 (event fingerprint – stored at batch level). TD-03 (observations – linked to batch ID). TD-06 (source attribution – includes batch ID). **Confirmed ingestion paths** (Windows, CSV, network telemetry, external APIs) must write batch metadata. |
| **Status** | PROPOSED – Awaiting owner input on whether additive tables require explicit approval or can be implemented via `ALTER TABLE` in a development branch. |
| **Owner approval required** | YES – table additions must not break V2 `init_db()` startup or seed logic. Must validate with `PRAGMA integrity_check` and `PRAGMA foreign_key_check` after additions. **This approval is required as a Phase 1A gate prerequisite.** The implementation work itself occurs within Phase 1A after approval. Distinguishing: the approval enables the implementation work; it is not the implementation itself. |
## Technical Decisions (TD-01 through TD-16)

Each decision includes: Title, Rationale, Options, Recommendation, Advantages/Disadvantages, Dependencies, Status, Owner approval requirement.