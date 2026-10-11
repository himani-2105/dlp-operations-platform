# DLP Operations Platform (v2.1) — Data Loss Prevention Detection & Incident Response Lab
Flask + SQLite + vanilla JS. Detects Aadhaar (Verhoeff), payment cards (Luhn), PAN, Indian phone numbers and emails, then manages the full incident lifecycle with configurable policies, RBAC, an audit trail, a leakage simulator, reports and an OWASP assessment tracker. Checksum/format validity reduces false positives; it does **not** prove an identity is real or a card is active.

## Architecture
`db.py` schema + non-destructive migrations (schema v3) · `dlp_engine.py` policy-driven detection + synthetic scenarios · `app.py` REST API (auth, CSRF, RBAC, audit, cases, analytics, policies, simulator, reports, findings, users) · `static/` single-page UI; each page has its own security-themed 3D scene (padlock, vault, radar network, policy shield, firewall tunnel). v1 code backup: `backup_v1/`.

## Features
- **Cases:** INC/CASE IDs, 5 statuses, assignment, priority, notes, root cause, impact, remediation, resolution/closure, full status history, false-positive reasons + reopen.
- **Analytics (from DB):** status/severity/category, daily + monthly trends, top policies, FP rate, MTTR, repeated violations, top sources, date + category filters; scan runs counted separately; live active-incident badge.
- **Closure rules:** Resolve requires saved root-cause analysis, remediation taken and a resolution summary; False Positive and Reopen require a reason (5+ characters). The history and audit entry always record a non-empty reason. Reports and exports show each incident's saved root cause, business impact, remediation and resolution, or an explicit "Not recorded" — never generic policy text.
- **Policies:** enable/disable, severity, response (alert/escalate/quarantine-simulation), threshold, allowlist (exact or `re:`).
- **Simulator:** 6 synthetic scenarios over email, file upload, shared document, app log and USB copy; records user, channel, categories, policy, severity and response. Quarantine is simulated only.
- **Reports:** daily, monthly, policy-violation, remediation/closure and per-incident reports; on-screen, print / save-as-PDF via the browser, CSV download; masked values only.
- **Assessment tracker:** manual OWASP Top 10 findings with risk, rationale, mitigation, owner, due date, status, retest outcome and evidence references (not a scanner).
- **Security:** hashed passwords, 5-failure lockout, CSRF tokens, secure cookies, 3 roles, append-only audit trail (no sensitive values), upload validation, CSV formula-injection guard, security headers.

## Limitations
No built-in PDF library (use the browser's Save as PDF); SQLite single-node; no email/SSO; the simulator never touches real mail, files or devices; screenshots not included.

## Windows setup
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    python manage.py migrate
    python app.py
Open http://127.0.0.1:8000. On a first *development* run, temporary credentials for `admin`, `analyst` and `auditor` are printed once and **must be changed at first sign-in** (the app forces it). Production never prints passwords. Forgot one: `python manage.py reset-password admin`. Production-style: `waitress-serve --listen=127.0.0.1:8000 wsgi:app` (Linux: `gunicorn wsgi:app`); set `DLP_HTTPS=1` behind HTTPS.

## Migration
Starting the app (or `python manage.py migrate`) upgrades an existing v1/v2 `dlp.db` in place after copying it to `dlp.db.bak-<timestamp>`. No incidents are dropped.

## Demo workflow
Login as analyst → Simulator → run "Email: refund with card + Aadhaar" → Incidents → open one, assign, add root cause, resolve → Policies (admin): disable Email policy, re-run → Reports → Daily / Closure → Audit Trail (admin/auditor).

## Tests
    python -m unittest -v
    python verify_dlp.py

## Deployment & security checklist
| Item | How it is handled | Check |
|---|---|---|
| Change initial credentials | Initial and admin-reset passwords are temporary: the backend blocks every API call until the user sets a new one (Change password button also available). Production creates only `admin`, from the secret env var `DLP_INITIAL_ADMIN_PASSWORD`. Remove that variable after first start. | `test_new_and_reset_accounts_must_change_password` |
| Roles enforced on the backend | Every `/api` route has a server-side role check; CSRF is required on all state changes. A matrix test fails if any route is missing or mis-permissioned. | `TestHardening.test_every_api_route_enforces_roles_on_the_backend` |
| No passwords / unmasked values in logs | Only masked values are stored; audit never records passwords or text typed into a failed-login username box; request logs drop query strings; search runs in the browser; first-run printing is development-only. | `test_failed_login_never_logs_what_was_typed`, `test_request_log_query_strings_are_redacted` |
| Secrets out of Git | `.gitignore` excludes `.env*` (except `.env.example`), `*.db`, `*.db-*`, `*.secret`, `*.bak*`, `backups/`. Verify: `git check-ignore -v .env dlp.db dlp.db.secret` | |
| Production DB path | With `DLP_ENV=production` the app refuses to start unless the database is `/var/data/dlp.db` on a writable mounted disk (`render.yaml` / `Dockerfile` set this). The secret key file is stored beside it. | `test_production_database_path_and_secrets_policy` |
| Backups | `python manage.py backup` makes a consistent SQLite backup, verifies `PRAGMA integrity_check`, keeps the newest 14 (`BACKUP_KEEP`, `BACKUP_DIR`). A `.bak` copy is also made automatically before any schema upgrade. Schedule it (Render cron / Task Scheduler) and copy backups off the server. | `test_backup_is_consistent_and_rotates` |

Restore: stop the app, copy a backup over `dlp.db`, start the app. Back up `dlp.db.secret` too (or set `SECRET_KEY`), otherwise sessions and repeated-violation matching reset.
