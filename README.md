# sc-idp

Central OpenID Connect provider: **who the user is**. Products decide **what they can do**.

- Implementation spec: [plan.md](plan.md)
- Product teams: [docs/integrating-a-product.md](docs/integrating-a-product.md)
- [Architecture](docs/architecture.md) · [Security](docs/security.md) · [Operations](docs/operations.md)

## Install

Python 3.12+ and a running Postgres 14+ (the app does not start a database).

```bash
cd sc-idp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

That installs this package and every pinned dependency from `pyproject.toml` (FastAPI, uvicorn, SQLAlchemy, psycopg, Alembic, and the rest). Re-run `pip install -e .` after pulling changes that touch that file.

Copy `.env.example` to `.env` and fill **every** variable yourself. The example file has names only.

`DATABASE_URL` must point at your Postgres. `IDP_ISSUER` is the origin the browser uses to reach this IdP (scheme + host + port, no trailing slash). For local HTTP set `COOKIE_SECURE` so cookies work without TLS.

Apply schema:

```bash
alembic upgrade head
```

## Run the IdP

From the repo root, with the venv active:

```bash
uvicorn idp.main:app --reload --host 127.0.0.1 --port 8000
```

- UI: the origin you set as `IDP_ISSUER`
- Discovery: `GET {IDP_ISSUER}/.well-known/openid-configuration`
- Health: `GET {IDP_ISSUER}/healthz`

## Run the demos

Two first-party products share `demo/product.py`. They read `PRODUCT_A_*` / `PRODUCT_B_*` from `.env`. Set those plus matching `PRODUCT_*_URL` origins, and keep the IdP process running.

Terminal 2 — product A:

```bash
source .venv/bin/activate
PRODUCT_NAME=a uvicorn demo.product:app --reload --host 127.0.0.1 --port 8001
```

Terminal 3 — product B:

```bash
source .venv/bin/activate
PRODUCT_NAME=b uvicorn demo.product:app --reload --host 127.0.0.1 --port 8002
```

If `PRODUCT_A_CLIENT_ID` / secret / URL (and the B equivalents) are set, the IdP upserts those clients on boot. Open A, create an account, sign in. Open B. You should not see a second login prompt. Each product mints its own JWT pair.

## Tests

Postgres must be up and `DATABASE_URL` set (from your `.env` or the environment):

```bash
source .venv/bin/activate
python tests/test_flow.py
```

This drops and recreates tables in that database. Do not point it at production.
