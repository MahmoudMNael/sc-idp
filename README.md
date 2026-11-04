# sc-idp

Central OpenID Connect provider: **who the user is**. Products decide **what they can do**.

## Documentation

- **Product Integration**: [docs/integrating-a-product.md](docs/integrating-a-product.md) — OIDC wire protocol, tokens, scopes, claims, and redirect contracts.
- **IdP Technical Reference**: [docs/idp-reference.md](docs/idp-reference.md) — Subsystem architecture, schema, tokens, and theory.
- **Authentication & User Flows**: [docs/flows.md](docs/flows.md) — 6-digit OTP verification, password reset, MFA step-up, cancellation, and silent SSO.
- **Admin Guide & Dashboard**: [docs/admin-guide.md](docs/admin-guide.md) — Web Admin Dashboard (`/admin/dashboard`), REST admin API, client secrets, and role assignments.
- **Core Architecture & Operations**:
  - [Architecture](docs/architecture.md)
  - [Security](docs/security.md)
  - [Operations](docs/operations.md)

---

## Install

Python 3.12+ and a running Postgres 14+ (the app does not start a database).

```bash
cd sc-idp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Installs this package and every pinned dependency from `pyproject.toml` (FastAPI, uvicorn, SQLAlchemy, psycopg, Alembic, and cryptography dependencies).

Copy `.env.example` to `.env` and fill the variables:

```bash
cp .env.example .env
```

`DATABASE_URL` must point at your Postgres. `IDP_ISSUER` is the origin the browser uses to reach this IdP (scheme + host + port, no trailing slash). For local HTTP development set `COOKIE_SECURE=false`.

Apply database migrations:

```bash
alembic upgrade head
```

---

## Run the IdP

From the repo root, with the venv active:

```bash
uvicorn src.main:app --reload --host 127.0.0.1 --port 8000
```

- **UI**: `{IDP_ISSUER}/`
- **Admin Dashboard**: `{IDP_ISSUER}/admin/dashboard`
- **OIDC Discovery**: `GET {IDP_ISSUER}/.well-known/openid-configuration`
- **OAuth Server Metadata**: `GET {IDP_ISSUER}/.well-known/oauth-authorization-server`
- **JWKS**: `GET {IDP_ISSUER}/.well-known/jwks.json`
- **Health check**: `GET {IDP_ISSUER}/healthz`

---

## Tests

Postgres must be up and `DATABASE_URL` set (from `.env` or the environment):

```bash
source .venv/bin/activate
python tests/test_flow.py
```

This end-to-end integration suite drops and recreates tables in that database. **Do not point it at production.**
