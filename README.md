# 🪪 IDPlease

**A tiny OIDC Identity Provider for development and pilot deployments.**

[![CI](https://github.com/jclement/idplease/actions/workflows/ci.yml/badge.svg)](https://github.com/jclement/idplease/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jclement/idplease)](https://goreportcard.com/report/github.com/jclement/idplease)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What is this?

IDPlease is a **drop-in replacement for Microsoft Entra ID** (formerly Azure AD) designed for local development, testing, and small pilot deployments. Instead of configuring a real Entra tenant with app registrations, redirect URIs, and user assignments, just run IDPlease and get a fully functional OIDC provider in seconds.

**Why use it?**

- 🏗️ **Local development** — No internet, no Azure subscription, no app registration dance
- 🧪 **Integration testing** — Spin up a predictable auth server in CI
- 🚀 **Pilot deployments** — Lightweight auth for internal tools before committing to Entra
- 🔌 **Entra-compatible claims** — `oid`, `upn`, `roles`, `groups`, `tid` — your app won't know the difference
- 📦 **Single binary** — No external dependencies, just one executable with embedded SQLite

**Features:**

- OpenID Connect Authorization Code flow with PKCE (S256)
- Client Credentials flow (machine-to-machine)
- Refresh token support with rotation
- Client registry with public and confidential clients
- UserInfo endpoint
- Token revocation (RFC 7009)
- End session / logout endpoint
- Standard discovery (`/.well-known/openid-configuration`) and JWKS endpoints
- RS256-signed JWTs with auto-generated keys
- User and role management via CLI and web-based Admin UI
- Client management via CLI and Admin UI
- Rate limiting on login attempts (per-user and per-IP)
- CORS support with configurable origins
- Health check endpoint
- First-run bootstrap user
- Structured logging (slog)
- SQLite-backed storage (no external database needed)
- Works behind reverse proxies with configurable base path

---

## Quick Start

### 1. Get the binary

Download from [Releases](https://github.com/jclement/idplease/releases), or build from source:

```bash
go install github.com/jclement/idplease@latest
```

Or use Docker:

```bash
docker run -p 8080:8080 -v $(pwd)/data:/data ghcr.io/jclement/idplease:latest
```

### 2. Start the server

```bash
./idplease server
```

On first start, IDPlease will:
- Create an `idplease.db` SQLite database
- Generate an RSA signing key (`idplease-key.json`)
- **Create a bootstrap `admin` user** with a random password (printed to stdout)

Override bootstrap credentials with environment variables:
```bash
IDPLEASE_ADMIN_USER=myadmin IDPLEASE_ADMIN_PASSWORD=mypassword ./idplease server
```

### 3. Open the Admin UI

Navigate to `http://localhost:8080/admin` and sign in with the bootstrap admin credentials printed to the console (or any user that has the `IDPlease.Admin` role).

From the admin UI you can:
- **Manage users** — add, edit, delete users; reset passwords
- **Manage roles** for each user
- **Manage OAuth clients** — add, edit, delete clients (public or confidential)
- **Configure settings** — issuer, token lifetimes, redirect URIs, CORS origins, group mappings, etc.

### 4. Or use the CLI

```bash
# Add a user
./idplease user add bob

# Add some roles
./idplease role add bob Admin
./idplease role add bob Reader

# Add an OAuth client
./idplease client add my-spa

# List clients
./idplease client list
```

### 5. Point your app at it

Discovery URL: `http://localhost:8080/.well-known/openid-configuration`

That's it. Your app can now authenticate users against IDPlease.

---

## OIDC Endpoints

All endpoints are relative to the configured base path (default `/`).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery document |
| `/.well-known/openid-configuration/keys` | GET | JWKS with the RSA public key |
| `/authorize` | GET/POST | Authorization endpoint (shows login form, processes login) |
| `/token` | POST | Token endpoint (authorization_code, refresh_token, client_credentials) |
| `/userinfo` | GET/POST | UserInfo endpoint (returns claims for Bearer token) |
| `/revoke` | POST | Token revocation (RFC 7009) |
| `/end-session` | GET | End session / logout |
| `/health` | GET | Health check (`{"status":"ok","version":"..."}`) |
| `/admin` | GET | Admin UI (requires `IDPlease.Admin` role) |

> Tip: When the base path is `/`, the discovery, authorize, token, userinfo, revoke, and end-session endpoints are also available under Azure-style prefixes (`/v2.0/` and `/oauth2/v2.0/`) for compatibility with Microsoft identity clients.

### Token Endpoint Grant Types

- **`authorization_code`** — Standard OIDC auth code exchange, optionally with PKCE
- **`refresh_token`** — Refresh token rotation (issues new access + refresh token, revokes old)
- **`client_credentials`** — Machine-to-machine (confidential clients only, no id_token/refresh_token)

### CORS

CORS headers are applied to `/token`, `/userinfo`, `/revoke`, and JWKS endpoints. Configure allowed origins via Admin UI or config (default: `["*"]`).

### Rate Limiting

Login attempts are rate-limited:
- **Per username:** 5 attempts per minute
- **Per IP:** 5 attempts per minute

Exceeding the limit shows a "too many attempts" error on the login form.

---

## Admin UI

IDPlease includes a built-in web admin interface at `{basePath}/admin`.

### Admin Access

Any user with the `IDPlease.Admin` role can sign in to the admin UI using their normal username and password. On first run a bootstrap `admin` account is created with this role so you can log in immediately.

### Admin Pages

- **Dashboard** — Overview: user count, client count, configured issuer
- **Settings** — Edit: display name, issuer URL, tenant ID, access/refresh token lifetimes, redirect URIs, CORS origins, group mappings, session secret
- **Users** — List, add, edit, delete users; reset passwords
- **Roles** — Per-user role management: add/remove roles
- **Clients** — List, add, delete OAuth clients (public or confidential)

---

## CLI Reference

All commands support `--config <path>` to specify an alternate config file (default: `idplease.json`).

### Server

```bash
./idplease server
./idplease server --config /etc/idplease/config.json
```

### User Management

```bash
./idplease user add alice       # Interactive: prompts for email, display name, password
./idplease user list
./idplease user delete alice
./idplease user reset bob       # Prompts for new password
```

### Role Management

```bash
./idplease role add bob Admin
./idplease role list bob
./idplease role remove bob Admin
```

### Client Management

```bash
./idplease client add my-app    # Interactive: prompts for name, type, redirect URIs
./idplease client list
./idplease client delete my-app
```

### Configuration

```bash
./idplease config set issuer https://idp.example.com
./idplease config get issuer
./idplease config list
```

---

## Configuration

IDPlease uses a JSON config file (`idplease.json`) for server-level settings and SQLite for OIDC/user configuration.

### Config File (idplease.json)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | `int` | `8080` | HTTP listen port |
| `keyFile` | `string` | `idplease-key.json` | Path to the RSA signing key file |
| `dbFile` | `string` | `idplease.db` | Path to the SQLite database |

### OIDC Settings (in SQLite, managed via Admin UI or CLI)

| Key | Description |
|-----|-------------|
| `issuer` | The OIDC issuer URL |
| `display_name` | Display name for the IDP |
| `base_path` | Base path for all routes |
| `tenant_id` | Tenant ID for the `tid` claim |
| `access_token_lifetime` | Access token lifetime in seconds (default: 300) |
| `refresh_token_lifetime` | Refresh token lifetime in seconds (default: 86400) |
| `redirect_uris` | Allowed redirect URIs (JSON array) |
| `cors_origins` | Allowed CORS origins (JSON array, default: `["*"]`) |
| `group_mappings` | Maps group GUIDs to role names (JSON object) |
| `session_secret` | Secret for session signing |

### Example: idplease.json

```json
{
  "port": 8080,
  "dbFile": "/data/idplease.db",
  "keyFile": "/data/idplease-key.json"
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `IDPLEASE_ADMIN_USER` | Bootstrap admin username (default: `admin`) |
| `IDPLEASE_ADMIN_PASSWORD` | Bootstrap admin password (default: random) |

---

## Token Claims

IDPlease tokens include the following claims, designed for compatibility with Microsoft Entra ID:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | `string` | Issuer URL |
| `sub` | `string` | User ID (UUID) or Client ID (for client_credentials) |
| `aud` | `string` | Client ID |
| `exp` | `number` | Expiration time |
| `iat` | `number` | Issued at |
| `oid` | `string` | Object ID (same as `sub`) |
| `preferred_username` | `string` | Username |
| `upn` | `string` | User Principal Name |
| `name` | `string` | Display name |
| `email` | `string` | Email address |
| `roles` | `string[]` | Application roles |
| `groups` | `string[]` | Group GUIDs (via group mappings) |
| `tid` | `string` | Tenant ID (if configured) |
| `nonce` | `string` | Nonce (if provided in auth request) |

---

## First-Run Bootstrap

On first startup with an empty database, IDPlease automatically creates an `admin` user with:
- A randomly generated 16-character password
- The `IDPlease.Admin` role

Credentials are printed prominently to stdout. Override with `IDPLEASE_ADMIN_USER` and `IDPLEASE_ADMIN_PASSWORD` environment variables.

---

## Docker

```bash
docker run -p 8080:8080 -v $(pwd)/data:/data ghcr.io/jclement/idplease:latest
```

The SQLite database, key file, and config are all stored in `/data`.

### Docker Compose with Cloudflare Tunnel

See `docker-compose.yml` for a complete example pairing IDPlease with a Cloudflare Tunnel.

```bash
docker compose up -d
docker compose exec idplease idplease user add bob
docker compose exec idplease idplease role add bob Admin
```

---

## Data Files

| File | Description |
|------|-------------|
| `idplease.json` | Server config (port, key file path, db path) |
| `idplease.db` | SQLite database (users, roles, clients, tokens, OIDC config) |
| `idplease-key.json` | RSA signing key (auto-generated) |

> ⚠️ **Backup `idplease-key.json`** if token continuity matters. Regenerating the key invalidates all previously issued tokens.

---

## Building from Source

```bash
git clone https://github.com/jclement/idplease.git
cd idplease
go build -o idplease .

# With version info
go build -ldflags "-X github.com/jclement/idplease/internal/config.Version=1.0.0" -o idplease .
```

### Running Tests

```bash
go test ./...
```

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Jeff Clement
