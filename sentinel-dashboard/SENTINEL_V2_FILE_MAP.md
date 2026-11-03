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