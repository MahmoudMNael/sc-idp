# sc-idp

Central OpenID Connect provider: **who the user is**. Products decide **what they can do**.

---

## Documentation

| Document | Purpose |
| --- | --- |
| [Product Integration](docs/integrating-a-product.md) | OIDC wire protocol, tokens, scopes, claims, and redirect contracts |
| [IdP Technical Reference](docs/idp-reference.md) | Subsystem architecture, database schema, tokens, and theory |
| [Authentication & User Flows](docs/flows.md) | 6-digit OTP verification, password reset, account confirmation & switching, MFA step-up, cancellation, and silent SSO |
| [Admin Guide & Dashboard](docs/admin-guide.md) | Web Admin Dashboard (`/admin/dashboard`), REST admin API, client secrets, and role assignments |
| [Architecture](docs/architecture.md) | Token layer split, two-tier role architecture, and silent SSO mechanics |
| [Security](docs/security.md) | Threat model, non-negotiables, token hashing, and rate limiting |
| [Operations](docs/operations.md) | Environment configuration, migrations, key rotation, and runbooks |

---

## Run with Docker (Recommended)

Start the app and MySQL with Docker Compose Watch:

```bash
docker compose up --watch
# or in background:
# docker compose up -d && docker compose watch
```

- Automatic migrations run on startup once MySQL is healthy.
- Docker watch syncs code edits in `./src`, `./assets`, and `./migrations` instantly into the container with hot reloading.
- MySQL 8.4 is available on port `3306`.

---

## Local Development (Without Docker)

Python 3.12+ and a running MySQL 8+ instance:

```bash
cd sc-idp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Copy `.env.example` to `.env` and fill the variables:

```bash
cp .env.example .env
```

`DATABASE_URL` must point at your MySQL instance (`mysql+asyncmy://...`). `IDP_ISSUER` is the origin the browser uses to reach this IdP (scheme + host + port, no trailing slash). For local HTTP development set `COOKIE_SECURE=false`.

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

MySQL must be up and `DATABASE_URL` set (from `.env` or the environment):

```bash
docker compose exec web python tests/test_flow.py
# or locally:
# python tests/test_flow.py
```

This end-to-end integration suite drops and recreates tables in that database. **Do not point it at production.**
