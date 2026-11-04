# Admin Guide & Dashboard

`sc-idp` provides two administration interfaces:
1. **Web Admin Dashboard (`/admin/dashboard`)**: An interactive browser UI for administrators authenticated with an active session and the `admin` IdP role.
2. **Admin REST API (`/admin/*`)**: Scriptable, headless endpoints authenticated via `Authorization: Bearer <IDP_ADMIN_API_KEY>`.

---

## 1. Web Admin Dashboard (`/admin/dashboard`)

The dashboard enables management of OAuth 2.0 / OpenID Connect relying party clients without requiring direct database access or cURL scripts.

### Access Control & Authentication
- **Session-authenticated**: Requires an active `idp_session` cookie. Unauthenticated requests are 303 redirected to `/login?next=/admin/dashboard`.
- **Role check**: Requires the `admin` role in `user_idp_roles`. Users without the `admin` role receive an HTTP 403 Forbidden error page.
- **CSRF protected**: Every action (client registration, secret rotation, status toggle) requires a valid signed double-submit CSRF token.

### Features
- **Client Overview**: Lists all clients with their names, client IDs, registered redirect URIs, allowed scopes, first-party status, and active state.
- **Client Registration**:
  - Name: human-readable product name.
  - Redirect URIs: exact URI whitelist (separated by newlines or commas).
  - Post-Logout Redirect URIs: exact URIs permitted for RP-initiated logout redirection.
  - Scopes: selectable checkboxes (`email`, `profile`, `idp_roles`). `openid` is always required and automatically enforced.
  - First-Party Toggle: when enabled, skips the user consent screen during `/authorize`.
- **One-Time Secret Display**: Newly generated client secrets are displayed in a secure flash banner once. They are stored as HMAC-SHA256 hashes and cannot be retrieved in plaintext afterward.
- **Secret Rotation**: Instantly generates a new high-entropy secret, invalidating the previous secret for that client.
- **Status Toggle**: Deactivate a client to immediately block `/authorize` and `/token` requests without deleting history.

---

## 2. Admin REST API

Automated deployments and CI/CD pipelines use the REST API authenticated with the static server key.

### Authentication
All REST calls require:
```http
Authorization: Bearer <IDP_ADMIN_API_KEY>
```
If `IDP_ADMIN_API_KEY` is empty or unset in the environment, all admin REST endpoints return HTTP 503 Service Unavailable.

### Client Management

#### Register Client
```http
POST /admin/clients
Content-Type: application/json
Authorization: Bearer <IDP_ADMIN_API_KEY>

{
  "name": "Billing Service",
  "redirect_uris": ["https://billing.example.com/callback"],
  "post_logout_redirect_uris": ["https://billing.example.com/"],
  "allowed_scopes": ["openid", "email", "profile", "idp_roles"],
  "is_first_party": true,
  "client_id": "optional-custom-id"
}
```
**Response (200 OK)**:
```json
{
  "client_id": "optional-custom-id",
  "client_secret": "generated-plaintext-secret"
}
```

---

### Key Rotation

Rotate active RSA signing keys without invalidating existing in-flight tokens:

```http
POST /admin/keys/rotate
Authorization: Bearer <IDP_ADMIN_API_KEY>
```
**Response (200 OK)**:
```json
{
  "kid": "new-rsa-key-id",
  "status": "active"
}
```
The previous active key is set to `retiring` and remains in `/.well-known/jwks.json` for `KEY_RETIRE_SECONDS` (default: 3600 seconds), ensuring currently issued JWTs verify until expiration.

---

### IdP Role Management

IdP roles define global platform roles (such as `admin` and `sc_member`).

#### Create Role
```http
POST /admin/roles
Content-Type: application/json
Authorization: Bearer <IDP_ADMIN_API_KEY>

{
  "name": "support",
  "description": "Customer support staff"
}
```

#### List Roles
```http
GET /admin/roles
Authorization: Bearer <IDP_ADMIN_API_KEY>
```
**Response (200 OK)**:
```json
[
  {"name": "admin", "description": "Platform administrator with dashboard access"},
  {"name": "sc_member", "description": "Short Circuit internal team member"}
]
```

#### Assign or Preassign Role by Email
Assigns a role to an active user, or preassigns it so it attaches as soon as the email registers or verifies:
```http
POST /admin/roles/assign
Content-Type: application/json
Authorization: Bearer <IDP_ADMIN_API_KEY>

{
  "email": "lead@shortcircuitcompany.com",
  "role": "admin"
}
```
**Response (200 OK)**:
```json
{
  "email": "lead@shortcircuitcompany.com",
  "role": "admin",
  "preassigned": true,
  "assigned_to_active_user": true
}
```

#### Unassign Role
Removes both preassignment and active user role:
```http
POST /admin/roles/unassign
Content-Type: application/json
Authorization: Bearer <IDP_ADMIN_API_KEY>

{
  "email": "lead@shortcircuitcompany.com",
  "role": "admin"
}
```

#### Inspect Role Assignments
```http
GET /admin/roles/assignments?email=lead@shortcircuitcompany.com
Authorization: Bearer <IDP_ADMIN_API_KEY>
```
**Response (200 OK)**:
```json
{
  "email": "lead@shortcircuitcompany.com",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_roles": ["admin", "sc_member"],
  "preassigned_roles": ["admin"]
}
```

---

## 3. Automatic Company Domain Role

When a user registers or verifies with an email address matching the configured company domain, `sc-idp` automatically assigns the company role:

- `COMPANY_DOMAIN`: Domain to match (default: `shortcircuitcompany.com`).
- `COMPANY_ROLE`: Role name to grant (default: `sc_member`).

This rule triggers automatically on registration, OTP verification, and login.

---

## 4. Bootstrapping the Initial Admin User

To gain initial access to the Web Admin Dashboard (`/admin/dashboard`):

1. **Via Admin REST API**:
   ```bash
   curl -X POST http://127.0.0.1:8000/admin/roles/assign \
     -H "Authorization: Bearer $IDP_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"email": "your-email@example.com", "role": "admin"}'
   ```
2. **Register or Sign in**:
   - Navigate to `/login` or `/register`.
   - Once verified, visit `/admin/dashboard`.
