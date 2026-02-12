# 🪪 IDPlease

A tiny OIDC Identity Provider for development and pilot deployments. Drop-in replacement for Microsoft Entra ID when you need a lightweight auth server.

## Features

- **Authorization Code + PKCE** flow (S256)
- **OpenID Connect Discovery** (`/.well-known/openid-configuration`)
- **JWKS endpoint** with auto-generated RSA keys
- **Entra ID-compatible claims** (`oid`, `sub`, `upn`, `roles`, `groups`, `tid`)
- **CLI user & role management** — no database required
- **Single binary** — runs anywhere
- **Base path support** — works behind reverse proxies
- **Clean login UI** with Tailwind CSS

## Quick Start

```bash
# Add a user
./idplease user add bob

# Start the server
./idplease server
```

That's it. Discovery at `http://localhost:8080/.well-known/openid-configuration`.

## Installation

### From Release

Download from [Releases](https://github.com/jclement/idplease/releases).

### From Source

```bash
go install github.com/jclement/idplease@latest
```

### Docker

```bash
docker run -p 8080:8080 -v $(pwd):/data ghcr.io/jclement/idplease:latest
```

## CLI Usage

```bash
# User management
./idplease user add <username>       # Add user (prompts for password, email, display name)
./idplease user list                 # List all users
./idplease user delete <username>    # Delete a user
./idplease user reset <username>     # Reset password

# Role management
./idplease role add <user> <role>    # Add role to user
./idplease role remove <user> <role> # Remove role from user
./idplease role list <user>          # List user's roles

# Server
./idplease server                    # Start the OIDC server
./idplease server --config alt.json  # Use alternate config
```

## Configuration

Create `idplease.json`:

```json
{
  "issuer": "http://localhost:8080",
  "port": 8080,
  "basePath": "/",
  "clientID": "my-app",
  "tenantID": "00000000-0000-0000-0000-000000000000",
  "tokenLifetime": 3600,
  "redirectURIs": ["http://localhost:3000/callback", "http://localhost:5000/signin-oidc"],
  "groupMapping": {
    "group-guid-1": "AdminRole",
    "group-guid-2": "ReaderRole"
  }
}
```

### Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | string | `http://localhost:8080` | OIDC issuer URL |
| `port` | int | `8080` | Listen port |
| `basePath` | string | `/` | Base path for all routes (e.g. `/idp`) |
| `clientID` | string/array | `idplease` | Allowed client ID(s) |
| `tenantID` | string | — | Included as `tid` claim |
| `tokenLifetime` | int | `3600` | Token lifetime in seconds |
| `redirectURIs` | array | `["*"]` | Allowed redirect URIs (`*` = allow all) |
| `sessionSecret` | string | auto | Session signing secret |
| `groupMapping` | object | — | Map group GUIDs → role names |
| `usersFile` | string | `users.json` | Path to users file |
| `keyFile` | string | `idplease-key.json` | Path to RSA key file |

## Token Claims

Tokens include these claims (Entra ID compatible):

| Claim | Description |
|-------|-------------|
| `iss` | Issuer URL |
| `sub` | User ID (UUID) |
| `oid` | Same as sub |
| `preferred_username` | Username |
| `upn` | Same as preferred_username |
| `name` | Display name |
| `email` | Email address |
| `roles` | Array of role names |
| `groups` | Array of group GUIDs (via groupMapping) |
| `tid` | Tenant ID (if configured) |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` | URN-style roles |

## Behind a Reverse Proxy

Set `basePath` to mount IDPlease at a sub-path:

```json
{
  "issuer": "https://example.com/idp",
  "basePath": "/idp"
}
```

## Login Screen

<!-- Screenshot placeholder -->
![Login Screen](docs/login-screenshot.png)

## License

MIT
