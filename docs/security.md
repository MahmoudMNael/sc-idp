# Security Architecture & Threat Model

---

## 1. Non-Negotiables

- **Mandatory PKCE S256**: Enforced on every authorization code request. `plain` challenge method is rejected.
- **Exact Redirect URI Matching**: Strict string equality check on `redirect_uri` and `post_logout_redirect_uri`. Authorization requests with unknown clients or unregistered URIs render an IdP error page immediately and **never** issue a 302 redirect.
- **Token Claims Whitelist**: Tokens are minted through `mint_idp_jwt` enforcing an immutable allowlist:
  ```text
  iss sub aud exp iat jti auth_time nonce at_hash amr scope client_id typ email email_verified given_name family_name name idp_roles
  ```
  Any attempt to smuggle arbitrary claims raises a runtime exception.
- **Argon2id for Passwords**: Salted, memory-hard hashing (`time_cost=3`, `memory_cost=65536`, `parallelism=1`). Unknown usernames and locked accounts trigger a dummy Argon2 computation to prevent timing attacks.
- **HMAC-SHA256 for Tokens**: Authorization codes, refresh tokens, session tokens, client secrets, recovery codes, and 6-digit OTPs are hashed using HMAC-SHA256 with a server-side pepper (`TOKEN_HASH_PEPPER`).
- **Cryptographic Encryption at Rest**: RSA private signing keys and TOTP secrets are Fernet-encrypted with an encryption key derived via HKDF from `KEY_ENCRYPTION_KEY`.
- **Session Security**: `idp_session` cookie is marked `HttpOnly`, `SameSite=Lax`, and `Secure` (in production). Session fixation protection rotates the session token on password verification and MFA elevation.
- **Rate Limiting & Lockout**: Network-level rate limiting on login, registration, token exchange, and OTP operations. User account lockout is triggered after `LOGIN_MAX_FAILURES` wrong password attempts.
- **Admin Access Isolation**:
  - Web Admin Dashboard: strictly requires an active browser session with the `admin` role in `user_idp_roles` and double-submit CSRF validation.
  - Admin REST API: strictly requires `Authorization: Bearer <IDP_ADMIN_API_KEY>` validated with constant-time comparison.

---

## 2. Why HMAC, Not Argon2, for Tokens & OTPs

Argon2 is intentionally slow and salted. Verifying an Argon2 hash requires a full table scan and an expensive cryptographic verification per candidate row, making it unusable for index lookups.

High-entropy values (auth codes, refresh tokens, session cookies, client secrets) cannot be brute-forced via offline dictionary attacks. Hashing them with HMAC-SHA256 using a server-held pepper produces deterministic outputs that can be indexed cleanly with unique database constraints. A database leak without `TOKEN_HASH_PEPPER` provides no usable credentials to an attacker.

For 6-digit email OTPs, entropy is naturally low (1,000,000 possibilities). `sc-idp` binds the HMAC to the pepper, user ID, purpose, and code:
```python
hash_otp(pepper, user_id, purpose, code) = HMAC_SHA256(pepper, f"{user_id}:{purpose}:{code}")
```
Combined with a 10-minute expiration, 5-attempt rate limits per user (`otp_attempt:{user_id}`), and 3-resend limits (`otp_resend:{user_id}`), brute-force attacks against OTPs are mathematically neutralized.

---

## 3. Threat Assessment Matrix

| Threat Vector | Countermeasure in sc-idp |
| --- | --- |
| **Stolen authorization code** | Short 60s TTL, single-use consumption. PKCE S256 binds redemption to the caller possessing the secret verifier. Code replay revokes the issued refresh family. |
| **Stolen IdP refresh token** | Token rotation on every use. Replay of an already-used token triggers immediate revocation of the entire refresh family (`refresh_reuse`). |
| **Stolen product refresh token** | Isolated to that specific product. The product revokes its own local family; the IdP and other products remain unaffected. |
| **Stolen browser session cookie** | Bound by idle (`SESSION_IDLE_TTL`) and absolute (`SESSION_ABSOLUTE_TTL`) timeouts. MFA step-up required if TOTP is enabled. Rotated on login and privilege change. |
| **Cross-Site Scripting (XSS) on Product** | Attackers can steal product access tokens but cannot access the IdP session cookie due to browser host-scoping and `HttpOnly` flags. |
| **Open redirect via `/authorize`** | Unregistered `redirect_uri` never triggers a redirect; renders an IdP error page. |
| **Timing attack on login** | Constant-time dummy Argon2 hash computation runs on unknown emails and locked accounts. Generic `Invalid email or password` message used universally. |
| **CSRF on HTML forms** | Double-submit signed cookie (`itsdangerous`) validated against form field on all POST requests. |
| **Admin Dashboard privilege escalation** | Explicit database check against `user_idp_roles` for `RoleName.ADMIN` on every dashboard route. Unauthorized requests yield HTTP 403 Forbidden. |
| **Database compromise** | Private RSA signing keys and TOTP secrets are encrypted at rest using Fernet keys derived from `KEY_ENCRYPTION_KEY`. Stolen database dumps cannot decrypt private keys without the environment secret. |

---

## 4. Rate Limiting Limits & Boundaries

Postgres-backed fixed-window counters (`rate_limits` table) handle throttling:
- `login:<ip>`: default 10 requests per minute.
- `register:<ip>`: default 5 requests per minute.
- `token:<ip>`: default 30 requests per minute.
- `otp_attempt:<user_id>`: 5 attempts per 10-minute window.
- `otp_resend:<user_id>`: 3 resends per 10-minute window.
