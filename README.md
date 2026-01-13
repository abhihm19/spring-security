# Spring Security JWT Auth (RS256 + JWKS) — Reference Project

This project implements a **production-style authentication module** using:

- **Access tokens**: JWT (RS256) with short TTL
- **Refresh tokens**: JWT (RS256) with DB-backed **rotation + revocation**
- **JWKS**: public keys published at `/.well-known/jwks.json` for verification and key rotation
- **Immediate access-token invalidation** after logout/password change via a per-user **`tokenVersion`**

---

## Key concepts

### Access token (JWT)
- Used to access protected APIs via `Authorization: Bearer <accessToken>`.
- Includes:
  - `type=access`
  - `ver` (token version) → used to invalidate old tokens immediately
  - standard claims like `sub`, `iat`, `exp`, optional `iss`, `aud`
- Signed with **private RSA key**; verified with **public RSA key**.

### Refresh token (JWT)
- Used only to obtain a new access token (and a new refresh token).
- Sent to `/api/v1/auth/refresh-token` via request header: `Refresh-Token: <refreshToken>`.
- Includes:
  - `type=refresh`
  - `jti`
  - standard claims like `sub`, `iat`, `exp`, optional `iss`, `aud`

### Refresh token storage
Refresh tokens are **not stored in plaintext**. We store:
- `tokenHash` (HMAC-SHA256 with a server-side pepper)
- `jti`
- `expiryDate`
- `revoked`, `revokedAt`

### Rotation + reuse detection
On refresh:
1. Validate refresh JWT (signature/type/exp/iss/aud).
2. Look up its **hash** in DB.
3. If DB record is **revoked** → treat as **reuse/theft** and revoke all sessions.
4. Otherwise revoke it and issue **new access + new refresh**.

### Absolute session lifetime
When rotating refresh tokens, the new refresh token is issued with the **same expiry** as the current one.
This prevents infinite “sliding” refresh sessions.

### `kid` and JWKS
- JWT header contains `kid` (key id), which equals the active keystore alias.
- Verifiers select the correct public key using `kid`.
- Public keys are published as a **JWKS** document:
  - `GET /.well-known/jwks.json`

---

## Endpoints

### Public
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/signup`
- `POST /api/v1/auth/refresh-token`
- `GET /.well-known/jwks.json`
- `GET /api/v1/public_route`

### Authenticated
- `POST /api/v1/auth/change-password`
- `POST /api/v1/auth/logout`
- Any other endpoint not explicitly permitted in `SecurityConfig`

---

## Request/response examples (curl)

### 1) Login

```bash
curl -s -X POST "http://localhost:8080/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"usernameOrEmail":"user","password":"password"}'
```

Response includes:
- `accessToken`
- `refreshToken`

### 2) Call protected API

```bash
curl -s "http://localhost:8080/api/v1/protected" \
  -H "Authorization: Bearer <accessToken>"
```

### 3) Refresh tokens (rotation)

```bash
curl -s -X POST "http://localhost:8080/api/v1/auth/refresh-token" \
  -H "Refresh-Token: <refreshToken>"
```

Response includes a **new**:
- `accessToken`
- `refreshToken`

### 4) Change password (invalidates existing access/refresh sessions)

```bash
curl -s -X POST "http://localhost:8080/api/v1/auth/change-password" \
  -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" \
  -d '{"currentPassword":"old","newPassword":"newPassword123"}'
```

### 5) Logout (invalidates existing access/refresh sessions)

```bash
curl -s -X POST "http://localhost:8080/api/v1/auth/logout" \
  -H "Authorization: Bearer <accessToken>"
```

### 6) JWKS (public keys)

```bash
curl -s "http://localhost:8080/.well-known/jwks.json"
```

---

## Configuration

### JWT signing keys (RS256)
Configured via keystore (recommended for prod):
- `app.jwt.keystore.path` (e.g. `classpath:jwt-keys.p12` or `file:/etc/secrets/jwt-keys.p12`)
- `app.jwt.keystore.password`
- `app.jwt.keystore.key-password` (optional; defaults to keystore password)
- `app.jwt.keystore.active-alias` (this becomes the JWT header `kid`)

Dev fallback:
- If `app.jwt.keystore.path` is not set, the app generates an **ephemeral RSA keypair**.
- Tokens will **stop validating after restart** (dev-only behavior).

### Issuer/Audience (recommended)
- `app.jwt.issuer`
- `app.jwt.audience`

If set, they are included in tokens and enforced during validation.

### Refresh token hashing pepper
- `app.refresh.token.pepper`

This must be stable in an environment; changing it will prevent matching existing refresh token hashes (effectively logs out refresh sessions).

### CORS
- `app.cors.allowed-origin-patterns` (comma-separated)

Example:
`http://localhost:3000,http://localhost:5173`

---

## Key rotation (high level)
1. Generate a new keypair and add it to the keystore with a **new alias** (new `kid`).
2. Switch `app.jwt.keystore.active-alias` to the new alias.
3. Keep old public keys in the keystore (and thus in JWKS) until all tokens signed with them expire.

### Example (local) PKCS12 keystore creation

```bash
# Create a keystore with one RSA keypair alias "key-1"
keytool -genkeypair -alias key-1 -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore jwt-keys.p12 \
  -storepass changeit -keypass changeit \
  -dname "CN=jwt-key-1"

# Add a second keypair alias "key-2" for rotation
keytool -genkeypair -alias key-2 -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore jwt-keys.p12 \
  -storepass changeit -keypass changeit \
  -dname "CN=jwt-key-2"
```

Then set:
- `app.jwt.keystore.path=classpath:jwt-keys.p12` (or `file:...`)
- `app.jwt.keystore.active-alias=key-1` (later switch to `key-2`)

---

## Build

Skip tests:

```bash
mvn clean install -DskipTests
```

---

## Notes / recommended next hardening steps
- Add **rate limiting** on `login` and `refresh-token` (AWS WAF preferred).
- Add account lockout/backoff on repeated failed logins.
- Add security headers at reverse proxy (or in-app if needed).
