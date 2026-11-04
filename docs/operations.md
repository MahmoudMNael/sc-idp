# Operations Runbook

---

## 1. Environment Configuration

Copy `.env.example` to `.env` and configure every required parameter. The `.env.example` file contains variable names without defaults.

### Required Production Secrets

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | Postgres connection string (e.g., `postgresql://user:pass@localhost:5432/idp`). Rewritten to `postgresql+psycopg://` automatically. |
| `IDP_ISSUER` | Publicly accessible origin of the IdP (e.g. `https://auth.example.com`, no trailing slash). Must match browser navigation origin. |
| `SECRET_KEY` | High-entropy key used for cookie signing, CSRF tokens, and temporary state tickets (`itsdangerous`). |
| `TOKEN_HASH_PEPPER` | HMAC-SHA256 secret key used for indexing auth codes, refresh tokens, session cookies, client secrets, and OTPs. |
| `KEY_ENCRYPTION_KEY` | Master encryption key used to derive Fernet symmetric keys (HKDF) for encrypting RSA private JWKs and TOTP secrets at rest. |
| `IDP_ADMIN_API_KEY` | Bearer token for accessing headless `/admin/*` REST endpoints. If omitted, admin REST routes return HTTP 503. |

### Operational Defaults & Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `COOKIE_SECURE` | `true` | Enforces `Secure` flag on cookies. Set to `false` only during local HTTP development. |
| `COOKIE_SAMESITE` | `lax` | Cookie SameSite policy (`lax` is required for top-level OAuth redirects). |
| `COOKIE_NAME` | `idp_session` | Name of the browser session cookie. |
| `AUTH_CODE_TTL` | `60` | Authorization code validity window in seconds. |
| `IDP_ACCESS_TTL` | `900` | Access token and ID token lifetime (15 minutes). |
| `IDP_REFRESH_TTL` | `2592000` | Sliding window for IdP refresh tokens (30 days). |
| `IDP_REFRESH_ABSOLUTE_TTL` | `7776000` | Hard cap on total refresh family lifetime (90 days). |
| `SESSION_IDLE_TTL` | `43200` | Browser session idle expiration (12 hours). |
| `SESSION_ABSOLUTE_TTL` | `604800` | Browser session absolute expiration (7 days). |
| `KEY_CACHE_SECONDS` | `30` | In-memory cache TTL for public JWKS and active signing keys. |
| `KEY_RETIRE_SECONDS` | `3600` | Overlap duration retiring RSA keys remain in JWKS after rotation. |
| `OTP_TTL` | `600` | Expiration window for 6-digit email OTPs (10 minutes). |
| `OTP_MAX_ATTEMPTS` | `5` | Maximum failed OTP attempts before lockout. |
| `COMPANY_DOMAIN` | `shortcircuitcompany.com` | Email domain eligible for automatic internal role assignment. |
| `COMPANY_ROLE` | `sc_member` | Role automatically granted to verified company domain accounts. |
| `MAIL_BACKEND` | `console` | `console` (prints to stdout) or `smtp`. |
| `SMTP_HOST` / `SMTP_PORT` | `""` / `587` | SMTP server connection settings. |
| `SMTP_USER` / `SMTP_PASSWORD` | `""` / `""` | SMTP authentication credentials. |
| `SMTP_FROM` | `""` | Sender email address for OTP messages. |

---

## 2. Service Management

### Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Applying Database Migrations
Alembic manages all schema alterations. The server lifespan ensures active signing keys exist, but does not execute `create_all`:
```bash
alembic upgrade head
```

To rollback:
```bash
alembic downgrade -1
```

### Starting the Server
```bash
uvicorn src.main:app --host 127.0.0.1 --port 8000 --workers 4
```

---

## 3. Cryptographic Key Rotation

RSA-2048 signing keys should be rotated periodically or following suspected key leakage:

```bash
curl -X POST https://auth.example.com/admin/keys/rotate \
  -H "Authorization: Bearer $IDP_ADMIN_API_KEY"
```

### Rotation Behavior
1. A new RSA key pair is generated, encrypted, and set to `status="active"`.
2. The previous active key transitions to `status="retiring"` with `retire_after = now() + KEY_RETIRE_SECONDS`.
3. `/.well-known/jwks.json` serves both the new active key and retiring keys, allowing existing relying parties with in-flight JWTs to continue verification without outage.

---

## 4. Health Checks & Audit Trail

### Liveness Endpoint
```http
GET /healthz
```
Executes `SELECT 1` on the primary Postgres database and returns `{"ok": true}`.

### Audit Events
Audit records are persisted to `audit_events`. Events include:
`register`, `login_success`, `login_failure`, `email_verified`, `password_reset_requested`, `password_reset`, `token_code`, `token_refresh`, `refresh_reuse`, `code_replay`, `mfa_setup`, `mfa_enable`, `mfa_disable`, `logout`, `admin_create_client`, `admin_rotate_client_secret`, `admin_toggle_client_status`, `admin_rotate_keys`, `admin_create_role`, `admin_assign_role`, `admin_unassign_role`.

Audit detail JSON objects never contain passwords, peppers, OTPs, or private keys.

---

## 5. Verification Suite

Run the full end-to-end integration test suite against a dedicated test database:

```bash
.venv/bin/python3 tests/test_flow.py
```

*Note: The test suite resets and recreates database tables. Never run tests against production databases.*
