# IdP technical reference

Every piece of **this** identity provider: what it is, how this repo uses it, and why it exists in real systems. Demo products are out of scope; they are relying parties. Product-facing integration is [integrating-a-product.md](integrating-a-product.md). Threat bullets: [security.md](security.md). Env and runbooks: [operations.md](operations.md).

This process is a **B2C OpenID Connect authorization server**. It answers **who the human is**. It does not answer what they can do in a product, whether they pay, or which tenant they belong to.

---

## Authentication vs authorization

In production identity, **authentication (AuthN)** is proving an identity. **Authorization (AuthZ)** is deciding whether that identity may do a thing. Google, Microsoft, Auth0, and Keycloak all split these in practice: a central login, then each app (or a policy engine next to the app) decides permissions.

This IdP is AuthN only. `sub` (the user UUID) is the join key. Roles, permissions, entitlements, and billing stay in each product. Putting them on IdP tokens looks convenient and then every product deploy, every permission change, and every confused cache becomes an IdP change. Google’s ID tokens are identity claims; Gmail does not ask `accounts.google.com` “may they delete this thread?”

Open Policy Agent, if a product needs it, lives **in that product**.

---

## OAuth 2.0 and OpenID Connect

**OAuth 2.0** is a delegation protocol: a **client** (an application) obtains an **access token** to call an API, after a **resource owner** (the user) authenticates at an **authorization server**. It does not define a standard “who is this person?” token.

**OpenID Connect (OIDC)** layers identity on OAuth. The same code flow returns an **ID token** (a JWT that asserts `sub`, issuer, audience) plus an access token. **Discovery** (`/.well-known/openid-configuration`) and **JWKS** (`/.well-known/jwks.json`) let a library find endpoints and verify signatures without a vendor SDK.

This IdP implements a **confidential** authorization-code client only:

- `response_type=code` — no implicit (`token`, `id_token` in the URL). Implicit leaked tokens to browser history and logs; it is obsolete.
- PKCE `S256` on every code — originally for public mobile clients; current practice is to require it for confidential clients too (stolen codes + leaked logs).
- Grants: `authorization_code`, `refresh_token`. No client-credentials, device, password, or hybrid.

The **authorization code** is a one-time ticket the browser can carry. The **tokens** are fetched by the product **backend** with `client_secret`, so the browser never sees IdP tokens. That is the same pattern Slack, Atlassian, and Google use for first-party web apps: the app’s server is the OAuth client.

---

## HTTP surface

| Method | Path | Job |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | OIDC discovery. Advertises only what we actually support. |
| GET | `/.well-known/jwks.json` | Public RSA keys, including retiring keys during overlap. |
| GET | `/authorize` | Start (or silently continue) login; issue a code. |
| POST | `/token` | Exchange code or rotate IdP refresh. Client authenticated. |
| GET | `/userinfo` | Identity claims for a valid IdP **access** token. |
| GET | `/logout` | End the IdP **browser session**. RP-initiated logout. |
| GET/POST | `/register` `/login` `/forgot-password` `/reset-password` | Account. HTML + CSRF. |
| GET | `/verify-email` | Consume a mailed one-time token. |
| GET/POST | `/login/mfa` `/account/mfa*` | TOTP setup/enable/disable and step-up. |
| POST | `/consent` | Third-party (non-first-party) allow/deny. |
| POST | `/admin/clients` | Register a confidential client; secret shown once. |
| POST | `/admin/keys/rotate` | Signing-key rotation with JWKS overlap. |
| GET | `/healthz` | `SELECT 1`. |
| GET | `/` | Human landing page. |

Account HTML is the IdP’s UI. Products do not reimplement it.

---

## Users and passwords

Table `users`: UUID `id` (this is OIDC `sub`), unique lowercased email, Argon2id `password_hash`, `email_verified`, TOTP fields, `failed_login_count`, `locked_until`, `is_active`.

**Theory.** Passwords are low entropy. Slow, salted, memory-hard hashes (Argon2id, bcrypt, scrypt) make offline guessing expensive after a DB leak. Fast hashes (SHA-256 of the password) do not.

**Here.** `argon2-cffi` with configurable time/memory/parallelism. On success, `check_needs_rehash` upgrades the stored hash if costs changed. Unknown emails still run a **dummy Argon2 verify** so response time does not leak whether the account exists. The error text is always `Invalid email or password`, including for locked accounts.

Lockout: after `LOGIN_MAX_FAILURES` wrong passwords, `locked_until` is set. That slows online guessing against a known inbox. It is not a substitute for rate limits (which are per IP). Combined, they are what banks and Google do: throttle the network path, then lock the account.

Email is normalized to lowercase. No `citext`; the unique index is on the stored value.

---

## Browser session (silent SSO)

Table `auth_sessions`. Cookie name default `idp_session`: HttpOnly, `SameSite=Lax`, `Secure` when configured. Value is a high-entropy random; the DB stores HMAC(pepper, value).

**Theory.** Cookies are **host-scoped**. `appa.com` cannot read `auth.company.com`’s cookie. Cross-domain SSO therefore works by **redirecting the browser to the IdP**. If that cookie is valid, `/authorize` issues a code with no form. That is Google’s “already signed in” behavior, not a shared session cookie across products.

`SameSite=Lax` is sent on top-level GET navigations (the `/authorize` redirect). `SameSite=None` is for iframes; this IdP does not do iframe silent SSO (third-party cookie death, clickjacking).

Idle expiry (`SESSION_IDLE_TTL`) and absolute expiry (`SESSION_ABSOLUTE_TTL`) are both stored. Idle is refreshed when the session is loaded. Absolute caps a stolen cookie’s lifetime.

**Session fixation:** a new session token is issued on password login and on MFA success; the old row is revoked. Otherwise an attacker who planted a cookie before login would inherit the session.

`amr` (Authentication Methods References, OIDC) is stored on the session: `pwd`, and `otp` after TOTP. `/authorize` requires `otp` in `amr` if the user has TOTP enabled — step-up, not a second product prompt.

The session is **not** a product API credential. Products never send this cookie to their own APIs (wrong host anyway).

---

## CSRF on IdP forms

Login, register, consent, MFA, password reset are HTML POSTs on the IdP origin. A signed **double-submit** token (`itsdangerous`) is set as an HttpOnly `csrf` cookie and as a hidden field. Both must match and unsign.

**Theory.** Cross-site POSTs from `evil.test` would send Lax cookies on some navigations but cannot read the CSRF cookie to fill the field. OAuth `state` is a related idea for the redirect, not a replacement for login-form CSRF.

The authorize query is carried across login as a signed `next` blob so `/login` cannot be used as an open redirector.

---

## OAuth clients

Table `oauth_clients`: `client_id`, HMAC’d `client_secret`, exact `redirect_uris[]`, `post_logout_redirect_uris[]`, `allowed_scopes[]`, `is_first_party`, `is_active`.

**Theory.** A **confidential** client can keep a secret (a server). A **public** client cannot (SPA, native app without a backend). This IdP only has confidential clients. The SPA in front of a product is **not** the client; the product API is.

Exact redirect URI matching is the main open-redirect control. “Allow the whole origin” or “strip trailing slashes” is how authorization codes get sent to attacker pages.

`is_first_party` skips the consent screen. Google skips consent for Gmail talking to accounts.google.com; it does not skip it for a random developer app. Third-party / partner apps set this false.

Client auth at `/token`: HTTP Basic (`client_secret_basic`) or form body (`client_secret_post`). Comparison is HMAC then `compare_digest`. Lookup is by `client_id`, not by hashing the secret as a primary key.

Created via `POST /admin/clients`. The plaintext secret is returned once.

---

## `/authorize`

Order is the security. Unknown `client_id` or a `redirect_uri` not in the list → **HTML error on the IdP**, never a 302. Only after that may `error=` go to the redirect URI. That is how you avoid turning `/authorize` into an open redirect (`?redirect_uri=https://evil`).

Then: `response_type=code`, PKCE S256 required (`plain` rejected), `scope` must include `openid` and be a subset of the client’s `allowed_scopes`.

Session:

- none + `prompt=none` → `login_required` on the redirect URI
- none → 302 to `/login?next=…`
- `prompt=login` or `max_age` exceeded → re-authenticate
- TOTP enabled and `amr` lacks `otp` → `/login/mfa`
- not first-party or `prompt=consent` → consent HTML
- else issue code, 302 to `redirect_uri?code=&state=`

`state` is echoed, not validated by the IdP (the **client** checks it). `nonce` is stored on the code and copied into the ID token.

---

## Authorization codes and PKCE

Table `authorization_codes`. The row is keyed by HMAC of the code. TTL default 60s. **The row is not deleted on use**; `consumed_at` is set and `issued_family_id` records the refresh family minted from it.

**Theory.** Codes travel in browser URLs (Referer, logs, history). They must be short-lived and one-time. RFC 7636 PKCE: the client generates a `code_verifier`, sends `code_challenge = S256(verifier)` at `/authorize`, and proves possession of the verifier at `/token`. An attacker who steals only the code cannot redeem it.

**Replay.** If a consumed code is presented again, this IdP revokes `issued_family_id`. Otherwise the thief who raced or replayed from logs would keep a live refresh family. Codes are `SELECT … FOR UPDATE` so two parallel redemptions serialize.

---

## `/token`

Rate-limited. Client must authenticate.

**`grant_type=authorization_code`:** look up code, reject expired / wrong client / wrong `redirect_uri` / bad PKCE / inactive user; consume; mint access JWT, ID token, refresh.

**`grant_type=refresh_token`:** look up refresh `FOR UPDATE`. If `used_at` or `revoked_at` is set, revoke the **entire family** and return `invalid_grant` (reuse detection). If only expired, `invalid_grant` without burning the family. Else mark used, insert a child with the same `family_id` and `family_expires_at`.

Rotation is what Okta, Auth0, and Google do for refresh tokens: each use issues a new one; presenting the old one means theft (or a buggy double-submit). Burning the family is the blast radius.

---

## IdP JWTs

Minted only through `mint_idp_jwt`. Allowlist: `iss sub aud exp iat jti auth_time nonce at_hash amr scope client_id typ email email_verified`. Anything else raises. That is the mechanical enforcement of “identity only.”

**Access token.** Header `typ: at+jwt` (RFC 9068). Claims include `typ: at+jwt`, `aud` = `client_id`, `scope`, `client_id`, `auth_time`, `amr`. Held by the **product backend**. Default 15 minutes. Not sent to browsers by design.

**ID token.** Header `typ: JWT`. `aud` = `client_id`, `auth_time`, `amr`, `at_hash`, optional `nonce`, and `email` / `email_verified` if `email` was in scope. `at_hash` is the left half of SHA-256 of the access token, base64url — OIDC’s binding of ID token to access token.

**`iss`** is `IDP_ISSUER` with trailing slash stripped. Products must verify `iss` and `aud` or they will accept another client’s tokens (mix-up).

**RS256** (asymmetric): the IdP signs with a private RSA key; products verify with JWKS. Symmetric HS256 would force every product to hold the IdP’s signing secret.

**`jti`** is a unique id (not a revoke list here). Short TTL is the practical revoke for access/ID tokens. Real-world instant logout of JWTs needs a denylist or token version; this IdP does not ship one for access tokens.

---

## Refresh families

Table `refresh_tokens`: `token_hash`, `family_id`, `parent_id`, sliding `expires_at`, absolute `family_expires_at`, `used_at`, `revoked_at`, `revoked_reason`.

A **family** is one login’s chain of rotated refresh tokens. Absolute cap (`IDP_REFRESH_ABSOLUTE_TTL`, default 90 days) stops an infinitely rotated token from living forever — a compliance and theft-window control.

Hashed with HMAC(pepper), not Argon2: high-entropy randoms are indexable; Argon2’s random salt is not.

These refresh tokens belong to the **product backend**, one family per client. Stolen refresh in App A does not kill App B.

---

## Signing keys and JWKS

Table `signing_keys`: `kid`, encrypted private JWK, public JWK JSON, `status` (`active` / `next` / `retiring`), `retire_after`.

RSA-2048, RS256. Private material is Fernet-encrypted with a key derived (HKDF) from `KEY_ENCRYPTION_KEY`. A stolen DB without that env var is not enough to mint tokens or read TOTP secrets.

`GET /jwks.json` serves public halves of `active`, `next`, and `retiring` keys that have not passed `retire_after`. Products must cache JWKS but still honor new `kid`s.

`POST /admin/keys/rotate`: current `active` → `retiring` until now + `KEY_RETIRE_SECONDS` (keep this ≥ access-token TTL); a new `active` key signs. Overlap is how you rotate without invalidating in-flight JWTs. Google and Auth0 keep old keys in JWKS for the same reason.

In-process cache TTL `KEY_CACHE_SECONDS`. Multiple IdP processes can lag that long after rotate; bounce or shorten the cache if that matters.

Boot: if no `active` row, one is generated.

---

## `/userinfo`

OIDC UserInfo endpoint. `Authorization: Bearer` IdP access token, verified against local JWKS. Returns `sub`, and `email` / `email_verified` if scoped. Used by backends that want current profile without parsing the ID token again. Not a product API.

---

## Logout

`GET /logout` (OIDC RP-Initiated Logout / `end_session_endpoint`). Revokes the **session row**, clears the cookie.

If `post_logout_redirect_uri` and a verifiable `id_token_hint` are sent, and the URI is in that client’s `post_logout_redirect_uris`, the browser is redirected there. Otherwise the user sees the IdP “signed out” page. Unvalidated URIs are **not** followed (open redirect).

This does not revoke product JWTs or IdP access tokens already issued. Real-world “sign out everywhere” is a product-side refresh revoke plus optional IdP logout so **future** SSO stops. Access JWTs die at `exp`.

---

## Consent

First-party clients skip it. Others get an Allow/Deny form; deny returns `access_denied` to the redirect URI. Consent is not persisted (YAGNI): third-party clients see it every authorize. Production consent stores are an upgrade if partners should be remembered.

---

## MFA (TOTP)

RFC 6238 TOTP (`pyotp`), 30-second windows, `valid_window=1` for clock skew. Secret is generated at setup, encrypted at rest, shown as an `otpauth://` URI for authenticator apps. Enable requires a valid code so a mistyped secret cannot lock the account on.

**Recovery codes:** 10 hashed (HMAC) single-use codes shown once. Without them, a lost phone is a permanent lockout — a real-world support incident every IdP hits.

Disable requires a current TOTP or unused recovery code, then wipes secret and codes, and rotates the session back to `amr=['pwd']`.

---

## Email verification and password reset

Table `email_tokens`, `purpose` = `verify_email` | `reset_password`. HMAC’d token in the link, TTL, single use.

Register always creates the user; verification is optional for login (email claim tracks `email_verified`). Reset sets a new Argon2 hash and clears lockout.

Forgot-password response is the same whether the email exists (user enumeration).

**Mail.** `MAIL_BACKEND=console` prints the link (local). `smtp` uses stdlib `smtplib`. No vendor mail SDK.

---

## Rate limits

Table `rate_limits`: `(key, window_start)` → count. Fixed window, Postgres `INSERT … ON CONFLICT DO UPDATE`. Keys like `login:<ip>`. Limits on login, register, `/token`.

**Theory.** Stops online password spraying and token-endpoint hammering. Fixed windows are simple and bursty at boundaries. Redis `INCR`+TTL is the usual next step for many instances; this table is one extra write on the primary (see the `ponytail` comment in code).

---

## Audit

Table `audit_events`: `event_type`, optional `user_id` / `client_id` / `ip` / `detail` JSON. No secrets in `detail`. Events include register, login success/failure, email verify, password reset, token issue, refresh reuse, code replay, MFA, logout, admin client create, key rotate.

This is the trail SOC2/ISO reviewers ask for: who authenticated, who minted tokens, who reused a refresh.

---

## Admin

`Authorization: Bearer` compared with `IDP_ADMIN_API_KEY` in constant time. Empty key → 503.

v1 is a static secret. Real-world staff access is SSO + roles (this IdP eating its own dogfood, or a VPN + identity-aware proxy). Treat `/admin` as internal until then.

---

## Crypto summary

| Secret class | Algorithm | Why |
| --- | --- | --- |
| User password | Argon2id | Low entropy; slow hash |
| Auth code, refresh, session, client secret, recovery, email token | HMAC-SHA256(pepper) | High entropy; must be lookup-keyed |
| TOTP secret, private JWK | Fernet (AES) via HKDF(`KEY_ENCRYPTION_KEY`) | Steal-the-DB should not steal signing or MFA |
| CSRF / `next` / demo-style blobs | `itsdangerous` + `SECRET_KEY` | Tamper-evident |
| IdP JWT | RS256 | Products verify without the private key |
| Dummy login | Argon2 against a fake hash | Timing |

---

## Schema (ten tables)

`users`, `oauth_clients`, `authorization_codes`, `refresh_tokens`, `auth_sessions`, `signing_keys`, `email_tokens`, `audit_events`, `rate_limits`, `mfa_recovery_codes`.

No `organizations` / memberships. Adding B2B later is a new module keyed off `user_id`, not a rewrite of tokens. Do not put `org_id` on IdP JWTs when that day comes; keep it in the product or a dedicated membership service.

Migrations: Alembic only. Lifespan ensures a signing key; it does not `create_all`.

---

## What this IdP is not

- Not a product session store or API gateway.
- Not SAML, not WS-Fed, not LDAP.
- Not social login (Google-as-IdP). This **is** the IdP.
- Not dynamic client registration (RFC 7591) beyond staff `POST /admin/clients`.
- Not DPoP / mTLS sender-constraining of access tokens.
- Not a global logout bus for product JWTs.

Those are real-world extras. They are omitted until a product actually needs them.
