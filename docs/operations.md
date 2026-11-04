# Operations

## Environment

Copy `.env.example` to `.env` and fill every variable. The example file contains **names only**. This process will not write `.env` for you.

Secrets (must be set, no useful defaults):

| Name | Purpose |
| --- | --- |
| `DATABASE_URL` | Postgres URL. `postgresql://` is rewritten to `postgresql+psycopg://`. |
| `IDP_ISSUER` | Public issuer, no trailing slash, e.g. the origin browsers use. |
| `SECRET_KEY` | Cookie / CSRF / `next` signatures (`itsdangerous`). |
| `TOKEN_HASH_PEPPER` | HMAC key for codes, refresh, sessions, client secrets, recovery codes. |
| `KEY_ENCRYPTION_KEY` | Encrypts signing-key private JWKs and TOTP secrets. |
| `IDP_ADMIN_API_KEY` | Bearer token for `/admin/*`. Leave empty to disable admin (503). |

Optional with code defaults: cookie flags, every TTL, Argon2 costs, lockout, rate limits, mail. Demo product vars (`PRODUCT_A_*`, `PRODUCT_B_*`) are required only if you run the demo apps; when set, the IdP upserts those clients on boot.

TTL defaults: auth code 60s; IdP access/ID 900s; IdP refresh 30d sliding / 90d absolute; session 12h idle / 7d absolute; key cache 30s; key retire 3600s.

`COOKIE_SECURE` must be true behind HTTPS. `COOKIE_SAMESITE` is `lax`.

Mail: `MAIL_BACKEND=console` prints links to stdout. `smtp` uses stdlib `smtplib` (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`). Verification and reset links are `{MAIL_BASE_URL or IDP_ISSUER}/verify-email?token=` and `/reset-password?token=`.

## Run

See the README. Install with `pip install -e .`, fill `.env`, `alembic upgrade head`, then `uvicorn src.main:app`. Demos: `PRODUCT_NAME=a` / `b` with `uvicorn demo.product:app`.

## Migrations

Alembic only. No `create_all` in production. The IdP lifespan generates an RSA key if `signing_keys` has no `active` row; it does not create tables.

```bash
alembic upgrade head
alembic downgrade -1
```

## Key rotation

```http
POST /admin/keys/rotate
Authorization: Bearer <IDP_ADMIN_API_KEY>
```

Current `active` becomes `retiring` until now + `KEY_RETIRE_SECONDS` (keep this ≥ access-token TTL). A new `active` key signs. JWKS serves both until retire. In-process caches refresh within `KEY_CACHE_SECONDS`; bounce processes if you need faster.

Rotate by generating a new key, never by deleting the old one first.

## Health

`GET /healthz` — `SELECT 1`.

## Audit

Rows in `audit_events`: `register`, `login_success`, `login_failure`, `email_verified`, `password_reset_requested`, `password_reset`, `token_code`, `token_refresh`, `refresh_reuse`, `code_replay`, `mfa_*`, `logout`, `admin_create_client`, `admin_rotate_keys`. No secrets in `detail`.

## Tests

Needs a reachable Postgres and the same secrets as runtime (`DATABASE_URL` at minimum; others are generated for the process if missing). Forces `IDP_ISSUER=http://testserver` and `COOKIE_SECURE=false`.

```bash
python tests/test_flow.py
```

Drops and recreates tables in that database. Do not point it at production.

## Admin

v1 is a static API key. Treat `/admin` as an internal network concern until staff auth exists. Client secrets are shown once at creation; lost secret ⇒ register a new client.
