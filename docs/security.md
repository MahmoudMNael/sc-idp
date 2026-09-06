# Security

## Non-negotiables

- PKCE S256 on every code. Discovery does not list `plain`.
- Exact `redirect_uri` / `post_logout_redirect_uri` match. Validate the client and URI before any redirect (open-redirect hole otherwise).
- IdP refresh tokens hashed, rotated, family-revoked on reuse. Codes survive consumption so a replay can revoke the family they minted.
- Passwords Argon2id. High-entropy tokens HMAC-SHA256(pepper). TOTP secret encrypted at rest.
- Identity-only JWT allowlist: `iss sub aud exp iat jti auth_time nonce at_hash amr scope client_id typ email email_verified`. Anything else raises.
- Browser holds product tokens only.
- Same login error for unknown user and wrong password. Dummy Argon2 verify so timing does not leak existence. Locked accounts also get that error.
- Session cookie `HttpOnly` + `SameSite=Lax` + `Secure` in production. New token on login and MFA (session fixation).
- CSRF on every HTML form (signed double-submit).
- Rate limits on login, register, token. Account lockout after repeated password failures.
- First-party clients skip consent; everyone else sees it.

## Why HMAC, not Argon2, for tokens

Argon2 is salted. `hash(token)` is different every call, so a lookup by hash is a full table scan plus a verify per row. Auth codes and refresh tokens are 256-bit random; a dictionary attack does not exist. HMAC with a server-held pepper is deterministic (indexable) and still useless to anyone who only stole the table.

Argon2 stays on **user passwords**, which are low entropy. `check_needs_rehash` upgrades cost parameters on successful login.

Client secrets are also high-entropy randoms we generate; they are HMAC'd and looked up by `client_id`, then compared in constant time.

## Threat notes

| Issue | Handling |
| --- | --- |
| Stolen authorization code | 60s, single use, PKCE binds it to the client that started the flow. Replay revokes issued refresh family. |
| Stolen IdP refresh | One use. Second use burns the family. Concurrent use is serialized with `FOR UPDATE`. |
| Stolen product refresh | Product's problem, same pattern. Other products untouched. |
| Stolen IdP session cookie | Valid until idle/absolute expiry or logout. MFA step-up required if TOTP is on. Rotate on login. |
| XSS on a product | Gets that product's JWT/refresh, not the IdP session (different host, HttpOnly). |
| Mix-up / wrong `aud` | Access and ID tokens set `aud` to `client_id`. Products must verify. |
| `role` smuggled onto IdP JWT | `mint_idp_jwt` refuses to encode. |
| Open redirect via `/authorize` | Unknown client or URI never 302s. |
| Login CSRF | Signed cookie must match signed field. |
| Admin endpoint | Bearer API key, constant-time compare. Replace with staff SSO before production internet exposure. |
| Key leak from DB | Private JWK is encrypted; need `KEY_ENCRYPTION_KEY` too. |

## Rate limit ceiling

Postgres fixed-window counters. Fine for a single primary. Under many IdP instances the extra row lock is the ceiling. Upgrade: Redis `INCR` + TTL.

## What we do not claim

Logout is not a distributed revoke. Short access-token TTLs are the practical bound. A product that needs instant kill must keep a server-side session version or denylist for **its** tokens.
