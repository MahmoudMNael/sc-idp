# Integrating a Product with sc-idp

`sc-idp` is a **confidential-client** OpenID Connect (OIDC) provider. Your **product backend** is the OAuth client. The product **frontend never talks directly to the IdP as an API** and **never handles IdP tokens**.

You do **not** build login, registration, password reset, or MFA forms. Those interactions live exclusively on the IdP. Your UI only triggers "Sign in" / "Sign out" navigations and then calls **your** APIs using **your own** product tokens.

---

## 1. Responsibilities by Layer

| Actor | Owns |
| --- | --- |
| **IdP** | Login, registration, 6-digit email OTP verification, password reset, MFA, consent, IdP session cookie, `/authorize`, `/cancel`, `/token`, `/userinfo`, `/logout` |
| **Product backend** | OAuth client credentials (`client_id` + `client_secret`), PKCE verifier, code exchange, ID-token validation via JWKS, user upsert on `sub`, product JWT + product refresh token minting, all API authorization |
| **Product frontend** | "Sign in" navigation hitting your backend, following HTTP redirects, passing product access JWTs on API calls, calling your backend `/refresh`, "Sign out" navigation |

### Boundary Security

| Never in the Browser | Handled by Browser |
| --- | --- |
| `client_secret` | Product access JWT (in memory or authorization header) |
| IdP access token, ID token, IdP refresh token | Product refresh token (HttpOnly cookie recommended) |
| PKCE `code_verifier`, OAuth `state`, `nonce` | Browser redirects between product and IdP |

The frontend never calls `{issuer}/token`, never fetches JWKS to verify IdP tokens, and never sends `Authorization` headers to the IdP.

---

## 2. Authentication Flow

```mermaid
sequenceDiagram
  autonumber
  participant FE as Product Frontend
  participant BE as Product Backend
  participant IdP as sc-idp
  participant User as Browser

  FE->>BE: GET /login
  Note over BE: Generate state, nonce, and PKCE verifier/challenge (S256).<br/>Persist state/nonce/verifier in server session or signed cookie.
  BE-->>FE: 302 Redirect to IdP /authorize
  FE->>IdP: GET /authorize (with client_id, redirect_uri, scope, code_challenge, state, nonce)
  alt No valid IdP session
    IdP-->>User: Render IdP login / register / OTP form
    User->>IdP: Authenticate & verify OTP
  end
  alt User cancels flow
    User->>IdP: Click Cancel (/cancel?next=...)
    IdP-->>FE: 302 to redirect_uri?error=access_denied&state=...
  else Flow approved
    IdP-->>FE: 302 to redirect_uri?code=...&state=...
  end
  FE->>BE: GET /callback?code=...&state=...
  Note over BE: 1. Validate state.<br/>2. POST /token to IdP with code, client_id, client_secret, code_verifier.<br/>3. Verify ID token signature via JWKS.<br/>4. Match nonce.<br/>5. Upsert user by sub.<br/>6. Mint product access JWT and product refresh token.
  BE-->>FE: Set product cookies / return product tokens and redirect to app
  FE->>BE: API requests with product Bearer token
```

---

## 3. Scopes & Identity Claims

Request scopes space-delimited in `scope`:

| Scope | Required | Claims Returned in ID Token & UserInfo | Purpose |
| --- | --- | --- | --- |
| `openid` | **Yes** | `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `amr`, `at_hash`, `nonce` | Standard OpenID Connect identity |
| `email` | Optional | `email`, `email_verified` | Verified user email address |
| `profile` | Optional | `given_name`, `family_name`, `name` | User name collected during registration |
| `idp_roles` | Optional | `idp_roles` (list of strings, e.g. `["admin", "sc_member"]`) | Global company/platform roles |

### Two-Tier Role Architecture
- **IdP Roles (`idp_roles`)**: Represent high-level identity tier and platform membership claims (e.g. `admin`, `sc_member`).
- **Product Permissions**: Fine-grained resources, workspace permissions (e.g., `workspace:write`, `editor`, `billing_admin`), and tenant associations must remain strictly inside the product backend. Products can map `idp_roles` to internal permission presets upon user upsert.

---

## 4. Endpoints Implemented by Your Product Backend

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/login` | Generate PKCE `code_verifier` (43–128 characters) and `code_challenge = BASE64URL(SHA256(verifier))`. Save `code_verifier`, `state`, and `nonce` in an encrypted or signed HttpOnly session cookie. 302 redirect browser to IdP `/authorize`. |
| `GET` | `/callback` | Must be the **exact** registered `redirect_uri`. Handle errors (`error=access_denied`). Verify `state`. Make a server-to-server POST to IdP `/token`. Validate the ID token with JWKS. Upsert user on `sub`. Mint product tokens. |
| `POST` | `/refresh` | Rotate the **product** refresh token. Mint a fresh product access JWT. **Do not** call the IdP. |
| `GET` | `/logout` | Invalidate product refresh token, clear product cookies. Optionally 302 redirect browser to IdP `/logout`. |

---

## 5. Protocol Wire Contracts

### 1. Authorize (`GET /authorize`)

Redirect the browser from your backend `/login` to:

```http
GET {issuer}/authorize?
  client_id=your_client_id
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
  &response_type=code
  &scope=openid+email+profile+idp_roles
  &code_challenge=E9Melhoa2OwvFrGMTJguCH5rtx64ZWqiJ61Z35NYF88
  &code_challenge_method=S256
  &state=c2VjdXJlX3JhbmRvbV9zdGF0ZQ
  &nonce=c2VjdXJlX25vbmNl
```

#### Query Parameters
- `client_id` (string, required): Registered client identifier.
- `redirect_uri` (string, required): Must match a registered URI exactly (scheme, host, port, path).
- `response_type` (string, required): Must be `code`.
- `scope` (string, required): Must include `openid`.
- `code_challenge` (string, required): S256 digest of PKCE verifier (`plain` is rejected).
- `code_challenge_method` (string, required): Must be `S256`.
- `state` (string, required in practice): CSRF token validated by your callback handler.
- `nonce` (string, recommended): Cryptographic binding echoed in the ID token.
- `prompt` (string, optional): `none`, `login`, or `consent`.
- `max_age` (integer, optional): Forces re-authentication if the IdP session is older than `max_age` seconds.

#### Error Redirection & Cancellation
If the user cancels or authorization fails, the browser is redirected to:
```http
GET https://app.example.com/callback?error=access_denied&state=c2VjdXJlX3JhbmRvbV9zdGF0ZQ
```

---

### 2. Code Exchange (`POST /token`)

Performed **server-to-server** from your product backend:

```http
POST {issuer}/token
Authorization: Basic <BASE64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

*(Alternatively, send `client_id` and `client_secret` in the URL-encoded body).*

#### Response (200 OK)
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "random_idp_refresh_token_string",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "scope": "openid email profile idp_roles"
}
```

#### Verifying the ID Token
Using keys cached from `GET {issuer}/.well-known/jwks.json`:
1. Signature algorithm must be `RS256`.
2. `iss` must exactly match `{issuer}` (no trailing slash).
3. `aud` must match your `client_id`.
4. `exp` must be in the future.
5. `nonce` must match the value you provided at `/authorize`.
6. Read `sub` as the unique user identifier.

---

### 3. UserInfo (`GET /userinfo`)

Optional server-to-server call using the IdP access token:

```http
GET {issuer}/userinfo
Authorization: Bearer <IdP_access_token>
```

#### Response (200 OK)
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@shortcircuitcompany.com",
  "email_verified": true,
  "given_name": "Jane",
  "family_name": "Doe",
  "name": "Jane Doe",
  "idp_roles": ["sc_member"]
}
```

---

### 4. RP-Initiated Logout (`GET /logout`)

To terminate the IdP browser session when logging out of the product:

```http
GET {issuer}/logout?
  id_token_hint=<id_token>
  &post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F
```

- `id_token_hint`: The ID token previously issued to the client.
- `post_logout_redirect_uri`: Must match a registered `post_logout_redirect_uris` entry for that client.
- If validated, the IdP revokes the session cookie and 302 redirects back to `post_logout_redirect_uri`.

---

## 6. Refresh Token Mechanics

There are two distinct refresh clocks:

| Refresh Token | Who Handles It | Destination | Purpose |
| --- | --- | --- | --- |
| **Product Refresh** | Product Frontend → Product Backend | Your `/refresh` | Obtains new product access JWT without bothering the IdP. |
| **IdP Refresh** | Product Backend → IdP | IdP `/token` (`grant_type=refresh_token`) | Rotates IdP access token if the backend needs to call `/userinfo`. |

Products must **never** send IdP refresh tokens to the browser.

---

## 7. Common Integration Mistakes

1. **SPA directly calling `/token`**: Public clients cannot protect `client_secret`. The backend must exchange the code.
2. **Leaking IdP tokens to the browser**: The browser only receives product tokens.
3. **Misconfigured redirect URIs**: Missing port, wrong scheme (http vs https), or mismatched trailing slashes cause immediate rejection at `/authorize`.
4. **Skipping PKCE**: `sc-idp` strictly requires PKCE `S256` for confidential clients.
5. **Calling IdP on product token expiration**: When a product access JWT expires, call your product's `/refresh` endpoint, not the IdP.
