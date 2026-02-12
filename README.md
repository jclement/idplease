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

**What it supports:**

- OpenID Connect Authorization Code flow with PKCE (S256)
- Standard discovery (`/.well-known/openid-configuration`) and JWKS endpoints
- RS256-signed JWTs with auto-generated keys
- User and role management via CLI and web-based Admin UI
- SQLite-backed storage (no external database needed)
- Works behind reverse proxies with configurable base path

**What it doesn't:**

- Client Credentials flow (machine-to-machine)
- Refresh tokens
- Multi-tenant federation
- Production-grade security (it's a dev tool!)

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
- Generate a one-time admin key and print it to the console

### 3. Open the Admin UI

Navigate to `http://localhost:8080/admin` and enter the admin key shown in the console output.

From the admin UI you can:
- **Add users** with username, email, display name, and password
- **Manage roles** for each user
- **Configure OIDC settings** — issuer, client IDs, redirect URIs, group mappings, etc.

### 4. Or use the CLI

```bash
# Add a user
./idplease user add bob

# Add some roles
./idplease role add bob Admin
./idplease role add bob Reader
```

### 5. Point your app at it

Discovery URL: `http://localhost:8080/.well-known/openid-configuration`

That's it. Your app can now authenticate users against IDPlease.

---

## Admin UI

IDPlease includes a built-in web admin interface at `{basePath}/admin`.

### Admin Key

The admin UI is protected by an admin key. You can set it in several ways (in order of priority):

1. **CLI flag:** `./idplease server --admin-key=mysecret`
2. **Environment variable:** `IDPLEASE_ADMIN_KEY=mysecret`
3. **Config file:** `"adminKey": "mysecret"` in `idplease.json`
4. **Auto-generated:** If none of the above are set, a random key is generated and printed to stdout on startup

### Admin Pages

- **Dashboard** — Overview: user count, configured issuer, client IDs
- **Settings** — Edit: display name, issuer URL, client IDs, tenant ID, token lifetime, redirect URIs, group mappings, session secret
- **Users** — List, add, edit, delete users; reset passwords
- **Roles** — Per-user role management: add/remove roles

---

## CLI Reference

All commands support `--config <path>` to specify an alternate config file (default: `idplease.json`).

### Server

```bash
# Start the OIDC server
./idplease server

# Start with a custom admin key
./idplease server --admin-key=mysecretkey

# Start with a custom config
./idplease server --config /etc/idplease/config.json
```

### User Management

```bash
# Add a new user (interactive — prompts for email, display name, password)
./idplease user add alice

# List all users
./idplease user list

# Delete a user
./idplease user delete alice

# Reset a user's password (prompts for new password)
./idplease user reset bob
```

### Role Management

```bash
# Add a role to a user
./idplease role add bob Barreleye.Admin

# List roles for a user
./idplease role list bob

# Remove a role
./idplease role remove bob Barreleye.Update
```

### Configuration

```bash
# Set a config value
./idplease config set issuer https://idp.example.com

# Get a config value
./idplease config get issuer

# List all config values
./idplease config list
```

---

## Configuration

IDPlease uses a JSON config file (`idplease.json`) for server-level settings and SQLite for OIDC/user configuration.

### Config File (idplease.json)

The config file contains server-level settings:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | `int` | `8080` | HTTP listen port |
| `keyFile` | `string` | `idplease-key.json` | Path to the RSA signing key file |
| `dbFile` | `string` | `idplease.db` | Path to the SQLite database |
| `adminKey` | `string` | *(auto-generated)* | Admin key for the admin UI |

### OIDC Settings (in SQLite, managed via Admin UI or CLI)

These settings are stored in the SQLite database and can be edited via the Admin UI or `./idplease config set`:

| Key | Description |
|-----|-------------|
| `issuer` | The OIDC issuer URL |
| `display_name` | Display name for the IDP |
| `base_path` | Base path for all routes |
| `client_ids` | Allowed OIDC client IDs (JSON array) |
| `tenant_id` | Tenant ID for the `tid` claim |
| `token_lifetime` | Token lifetime in seconds |
| `redirect_uris` | Allowed redirect URIs (JSON array) |
| `group_mappings` | Maps group GUIDs to role names (JSON object) |
| `session_secret` | Secret for session signing |

### Legacy Config File Support

For backward compatibility, IDPlease will read OIDC settings from the JSON config file if they haven't been set in SQLite yet. Fields like `issuer`, `clientID`, `basePath`, etc. in the JSON file serve as defaults that can be overridden via the Admin UI or CLI.

### Example: idplease.json

```json
{
  "port": 8080,
  "adminKey": "my-secret-admin-key",
  "dbFile": "/data/idplease.db",
  "keyFile": "/data/idplease-key.json"
}
```

---

## OIDC Endpoints

All endpoints are relative to the configured base path (default `/`).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery document |
| `/.well-known/openid-configuration/keys` | GET | JWKS with the RSA public key |
| `/authorize` | GET | Shows the login form |
| `/authorize` | POST | Processes login, returns auth code via redirect |
| `/token` | POST | Exchanges authorization code for tokens |
| `/admin` | GET | Admin UI (requires admin key) |

---

## Token Claims

IDPlease tokens include the following claims, designed for compatibility with Microsoft Entra ID:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | `string` | Issuer URL |
| `sub` | `string` | User ID (UUID) |
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

---

## Docker

```bash
# Run
docker run -p 8080:8080 -v $(pwd)/data:/data ghcr.io/jclement/idplease:latest
```

The SQLite database, key file, and config are all stored in `/data`.

### Docker Compose with Cloudflare Tunnel

See `docker-compose.yml` for a complete example pairing IDPlease with a Cloudflare Tunnel.

```bash
docker compose up -d

# Manage users
docker compose exec idplease idplease user add bob
docker compose exec idplease idplease role add bob Admin
```

---

## Data Files

| File | Description |
|------|-------------|
| `idplease.json` | Server config (port, key file path, db path, admin key) |
| `idplease.db` | SQLite database (users, roles, OIDC config) |
| `idplease-key.json` | RSA signing key (auto-generated) |

> ⚠️ **Backup `idplease-key.json`** if token continuity matters. Regenerating the key invalidates all previously issued tokens.

---

## Building from Source

```bash
git clone https://github.com/jclement/idplease.git
cd idplease
go build -o idplease .
```

### Running Tests

```bash
go test ./...
```

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Jeff Clement
