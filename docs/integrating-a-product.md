# Integrating a product with sc-idp

This IdP is a confidential-client OpenID Connect provider. Your **backend** is the OAuth client. Your **browser** never sees IdP tokens.

After the code exchange, mint **your own** short-lived access JWT and a rotating refresh token. That pair is what the browser holds.

## Register the client

```http
POST /admin/clients
Authorization: Bearer <IDP_ADMIN_API_KEY>
Content-Type: application/json

{
  "name": "App A",
  "redirect_uris": ["https://appa.example/callback"],
  "post_logout_redirect_uris": ["https://appa.example/"],
  "allowed_scopes": ["openid", "email"],
  "is_first_party": true
}
```

The response includes `client_secret` **once**. Store it in the product backend. First-party clients skip the consent screen.

Redirect URIs are matched as exact strings. No trailing-slash normalization, no origin-only match.

## Discovery

```http
GET {issuer}/.well-known/openid-configuration
GET {issuer}/.well-known/jwks.json
```

Metadata only advertises `response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]`, `id_token_signing_alg_values_supported: ["RS256"]`, and the two grants `authorization_code` and `refresh_token`. If a library tries implicit or PKCE `plain`, it is wrong for this IdP.

## Authorization code + PKCE

Redirect the **browser** to `/authorize`:

| Param | Required |
| --- | --- |
| `client_id` | yes |
| `redirect_uri` | yes, exact match |
| `response_type` | `code` |
| `scope` | must include `openid`; `email` is optional |
| `code_challenge` | yes, S256 of a 43–128 char verifier |
| `code_challenge_method` | `S256` |
| `state` | strongly recommended |
| `nonce` | recommended; echoed in the ID token |
| `prompt` | `none` / `login` / `consent` |
| `max_age` | seconds; forces re-auth if the IdP session is older |

PKCE S256:

```python
import base64, hashlib, secrets
verifier = secrets.token_urlsafe(64)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
```

If the user already has an IdP session cookie on the IdP host, `/authorize` returns a code with no login form (silent SSO). `prompt=none` returns `error=login_required` instead of a form when interaction would be needed.

Any OIDC client library that speaks authorization-code + PKCE S256 works. The in-repo demo uses Authlib's `AsyncOAuth2Client`.

## Token exchange (product backend only)

```http
POST /token
Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...
```

`redirect_uri` must be the same string used at `/authorize`. `client_secret_post` is also accepted.

Response:

```json
{
  "access_token": "<IdP JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<IdP refresh, backend only>",
  "id_token": "<IdP JWT>",
  "scope": "openid email"
}
```

Keep all three IdP tokens on the **product server**. Put none of them in a browser cookie or localStorage.

## Verify the ID token

1. Fetch JWKS (cache it; respect key rotation — old `kid` values stay in JWKS while retiring).
2. Verify RS256, `iss` = IdP issuer (no trailing slash mismatch), `aud` = your `client_id`, `exp`.
3. If you sent `nonce`, it must match.
4. Read `sub`. That is the stable user id. Upsert your user row on `sub`.

Do not put IdP `roles` in your mental model. There are none. If you see a role claim, reject the token — it did not come from this IdP.

Access token `typ` is `at+jwt` (RFC 9068). `GET /userinfo` with `Authorization: Bearer <access>` returns `sub` and, if scoped, `email` / `email_verified`.

## Mint product tokens

```text
IdP ID token  -->  product backend reads sub
               -->  product signs its own JWT (different iss, different keys)
               -->  product stores a hashed rotating refresh in the product DB
               -->  browser receives product JWT + product refresh only
```

Product JWT may include roles. The product still has to enforce anything that must be immediate.

When the product JWT expires, the client calls **your** `/refresh`. That endpoint must not talk to the IdP. Restart `/authorize` only when **your** refresh is dead (or reuse was detected). If the IdP session cookie is still valid, that restart is silent.

See `demo/product.py` for a complete relying party: Authlib PKCE, JWKS verification, product HS256 JWT, rotating product refresh, `/api/me`, `/refresh` that never calls the IdP.

## Refreshing IdP tokens

The product backend may call `/token` with `grant_type=refresh_token` when **it** still needs a fresh IdP access token (for `/userinfo`, or to learn `email_verified`). Rotation is mandatory: the returned refresh replaces the old one. Reuse of a spent IdP refresh revokes that client's family.

This is independent of the product refresh clock.

## Logout is not global

`GET /logout` revokes the **IdP browser session**. That stops silent SSO on the next `/authorize`.

It cannot revoke:

- product access JWTs already in browsers (wait for `exp`, or the product must track a denylist / version)
- product refresh tokens (the product must delete/revoke its own family)
- IdP access JWTs already issued to product backends (short TTL)

A product logout handler should: (1) revoke the product refresh family, (2) clear product cookies, (3) optionally redirect the browser to `{issuer}/logout?id_token_hint=...&post_logout_redirect_uri=...` so the central session dies too. Skipping step 3 means the next product the user opens will silently sign them in again. That is often what you want (SSO). It is not “log out of everything.”

`post_logout_redirect_uri` must be an exact registered URI, and `id_token_hint` must verify so the IdP knows which client is asking. Unvalidated redirects are ignored; the session is still cleared.

## Common mistakes

- Putting roles, permissions, plan, or tenant on the IdP token. The mint allowlist will refuse to sign it; do not work around that.
- Shipping the IdP refresh token to a browser or mobile app.
- Redirecting to `auth.company.com` because the product access JWT expired. Call product `/refresh`.
- Treating IdP logout as a kill switch for product sessions.
- Fuzzy `redirect_uri` matching (http vs https, trailing slash, registered path vs runtime query).
- PKCE `plain`, or skipping PKCE because the client is confidential. This IdP requires S256 every time.
- Storing refresh tokens with Argon2 and then wondering why lookup is a table scan.

## MFA

If the user has TOTP enabled, `/authorize` requires `amr` to include `otp`. A password-only IdP session is stepped up at `/login/mfa`. The ID token `amr` reflects that. Recovery codes are single-use.

Products do not implement a second TOTP prompt unless they want step-up for *their* sensitive actions — that is product AuthZ, not this IdP.
