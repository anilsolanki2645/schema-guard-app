# 🛡️ Schema Guard

**Continuous Database Schema Gatekeeper & Data Contract Compliance Platform**

Schema Guard protects production data warehouses, analytics databases, and microservices from silent, breaking schema mutations. Enforce strict, cryptographically-locked data contracts between upstream databases and downstream pipelines (dbt, Apache Airflow, Kafka, Tableau, Looker) before unauthorized DDL changes break production at 3 AM.

---

## ⚡ Key Capabilities

| Feature | Description |
| :--- | :--- |
| **🔐 Cryptographic Data Contracts** | YAML-based schema contracts sealed with SHA-256 integrity signatures. Tamper-proof, version-controlled. |
| **🛡️ CI/CD Compliance Gates** | Block breaking PRs via GitHub Actions, GitLab CI, or Apache Airflow operators using secure `sg_live_...` API tokens. |
| **🔍 Multi-Database Extractors** | Fast metadata introspection across PostgreSQL, MySQL, Snowflake, BigQuery, SQL Server, Oracle, Databricks, and SQLite. |
| **⏱️ Automated Drift Audits** | Background cron checking with instant alerts via Slack, Microsoft Teams, PagerDuty, WhatsApp, Email, or custom webhooks. |
| **🧪 DDL Simulation Sandbox** | Simulate proposed `ALTER TABLE` statements to calculate blast radius before modifying production. |
| **📦 dbt & Airflow Integrations** | Export contracts as dbt `schema.yml` and download ready-to-run Airflow operators. |
| **💎 Stripe Billing & Subscriptions** | Tiered plans (Developer Free → Team Pro → Enterprise) with Checkout, Customer Portal & webhook lifecycle. |
| **⚡ 1-Click OAuth Sign-In** | Frictionless developer authentication via GitHub and Google OAuth 2.0. |
| **🔒 Enterprise Security** | AES-256 Fernet encryption for all database credentials, SSRF-protected webhook dispatchers, HSTS, CSP headers. |
| **📜 Legal & Compliance** | Terms of Service and GDPR/CCPA Privacy Policy. Zero customer row data ingestion — schema metadata only. |

---

## 🚀 Quick Start (Local Development)

### 1. Clone & Configure Environment
```bash
git clone https://github.com/anilsolanki2645/schema-guard-app.git
cd schema-guard-app
cp .env.example .env
# Edit .env with your database, email, and Stripe credentials
```

### 2. Create Virtual Environment & Install Dependencies
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Run Database Migrations
```bash
python manage.py migrate
```

### 4. Start the Development Server
```bash
# Using Django runserver (development)
python manage.py runserver

# Using Waitress (production-grade, Windows-compatible)
waitress-serve --listen=0.0.0.0:8000 --threads=4 wsgi:application
```

Open **http://127.0.0.1:8000** in your browser.

---

## 🌐 Live Demo

> **Hosted on Render:** [https://schema-guard-app.onrender.com](https://schema-guard-app.onrender.com)

| Page | URL |
| :--- | :--- |
| Landing / Login | `/` |
| Pipelines Dashboard | `/dashboard` |
| YAML Contract Builder | `/builder` |
| Connection Profiles | `/connections` |
| DDL Simulation Sandbox | `/sandbox` |
| Pricing & Plans | `/pricing` |
| Developer Documentation | `/docs` |
| Terms of Service | `/terms` |
| Privacy Policy | `/privacy` |
| Health Check API | `/api/health` |

---

## 🏗️ Architecture Overview

```
Developer Pull Request / DDL ALTER
           │
           ▼
[CI/CD Gate: POST /api/pipelines/<id>/validate-gate]
           │
           ├─► (1) Verify API Token & Plan Quota
           ├─► (2) Verify SHA-256 Contract Lock Signature
           ├─► (3) Extract Live DB Schema (Postgres/MySQL/Snowflake...)
           ├─► (4) Run Strict Type Compatibility Engine
           │
      ┌────┴────┐
      ▼         ▼
 [PASSED]   [VIOLATION]
 HTTP 200   HTTP 409 Conflict
 ✓ Merge    ✗ PR Blocked + Multi-Channel Alerts
```

---

## 🔧 Configuration (.env Variables)

```env
# Django Core
SECRET_KEY=your-secret-key
DEBUG=false
ALLOWED_HOSTS=.onrender.com,localhost

# Database (choose one)
DB_CONNECTION_STRING=postgresql://user:pass@host:5432/db?sslmode=require
# OR individual Neon variables:
# PGHOST, PGDATABASE, PGUSER, PGPASSWORD, PGSSLMODE

# Admin seed account (first run only)
ADMIN_EMAIL=admin@your-domain.com
ADMIN_PASSWORD=change-this-strong-password

# Email Alerting (SMTP)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=your@gmail.com

# Stripe Billing
STRIPE_PUBLIC_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRO_PRICE_ID=price_...
STRIPE_ENTERPRISE_PRICE_ID=price_...

# OAuth (optional)
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

---

## 🤖 GitHub Actions CI/CD Gate

Add this workflow to your repository to block breaking schema migrations before merge:

```yaml
# .github/workflows/schema-guard.yml
name: Schema Guard Contract Validation

on:
  pull_request:
    branches: [main, staging]
    paths:
      - '**/*.sql'
      - '**/migrations/**'

jobs:
  schema-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate Schema Contract
        run: |
          curl --fail -s -X POST \
            https://schema-guard-app.onrender.com/api/pipelines/${{ secrets.PIPELINE_ID }}/validate-gate \
            -H "Authorization: Bearer ${{ secrets.SCHEMA_GUARD_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{"commit_sha": "${{ github.sha }}", "branch": "${{ github.head_ref }}"}'
```

---

## 🧪 Running Tests

```bash
# Full test suite (89 tests)
python manage.py test core

# Individual test modules
python manage.py test core.tests
python manage.py test core.tests_billing_oauth
python manage.py test core.tests_security_launch
```

**Test coverage includes:**
- Multi-database schema extraction & contract locking
- CI/CD gate validation API (token auth, quota enforcement, violation detection)
- SSRF defense on outbound webhook dispatchers
- AES-256 credential encryption & decryption cycles
- Stripe billing webhooks (mocked)
- OAuth login flows (GitHub & Google)
- Terms, Privacy, Docs, and Badge API endpoint rendering
- Audit log CSV export

---

## 🚢 Deployment (Render.com)

This repository includes `render.yaml` for one-click deployment.

### Manual Setup Steps:
1. Fork or push this repo to your GitHub account.
2. Go to [render.com](https://render.com) → **New Blueprint** → Select this repo.
3. Render will auto-provision a **PostgreSQL database** and a **web service**.
4. Set the following **secret** environment variables in the Render dashboard:
   - `EMAIL_USER`, `EMAIL_PASSWORD`, `EMAIL_FROM`
   - `STRIPE_PUBLIC_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
   - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
   - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
5. After first deploy, the `build.sh` script automatically runs `migrate` and `collectstatic`.

---

## 📊 Live GitHub Status Badge

Embed a live pipeline health badge in any repository README:

```markdown
[![Schema Guard](https://schema-guard-app.onrender.com/api/pipelines/YOUR_PIPELINE_ID/badge)](https://schema-guard-app.onrender.com)
```

Renders:
- 🟢 **passing** — Schema contract is clean, no drift detected.
- 🟡 **drifted** — Schema mutation detected, review required.
- 🔴 **failed** — Extractor connection failed or gate timeout.

---

## 🔒 Security & Compliance

- **Zero Customer Row Data:** Schema Guard reads only database metadata (`information_schema.columns`, `SHOW COLUMNS`). Customer payload rows never leave your network.
- **AES-256 Fernet Encryption:** All connection strings are encrypted at rest before writing to the database.
- **SSRF Protection:** Outbound webhook dispatcher rejects requests targeting private IPs, cloud metadata endpoints, or loopback addresses.
- **Signed Cookie Sessions:** Browser sessions are cryptographically signed server-side — no plaintext session tokens stored in the database.
- **HSTS + Security Headers:** Strict-Transport-Security, X-Frame-Options: DENY, Referrer-Policy, and Content-Type-Nosniff enforced in production.

---

## 📄 License

MIT License. Copyright © 2026 Schema Guard Inc.
