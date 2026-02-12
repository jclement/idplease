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
- 📦 **Single binary** — No database, no dependencies, just one executable and a couple of JSON files

**What it supports:**

- OpenID Connect Authorization Code flow with PKCE (S256)
- Standard discovery (`/.well-known/openid-configuration`) and JWKS endpoints
- RS256-signed JWTs with auto-generated keys
- User and role management via CLI
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

### 2. Add a user

```bash
./idplease user add bob
# Email: bob@example.com
# Display Name: Bob Smith
# Password: ********
```

### 3. Add some roles (optional)

```bash
./idplease role add bob Admin
./idplease role add bob Reader
```

### 4. Start the server

```bash
./idplease server
```

### 5. Point your app at it

Discovery URL: `http://localhost:8080/.well-known/openid-configuration`

That's it. Your app can now authenticate users against IDPlease.

---

## CLI Reference

All commands support `--config <path>` to specify an alternate config file (default: `idplease.json`).

### Server

```bash
# Start the OIDC server
./idplease server

# Start with a custom config
./idplease server --config /etc/idplease/config.json
```

### User Management

```bash
# Add a new user (interactive — prompts for email, display name, password)
./idplease user add alice

# List all users
./idplease user list
# Output:
# alice                alice@example.com              Alice Johnson
# bob                  bob@example.com                Bob Smith

# Delete a user
./idplease user delete alice

# Reset a user's password (prompts for new password)
./idplease user reset bob
```

### Role Management

```bash
# Add a role to a user
./idplease role add bob Barreleye.Admin

# Add multiple roles
./idplease role add bob Barreleye.Update
./idplease role add bob Barreleye.Read

# List roles for a user
./idplease role list bob
# Output:
# Barreleye.Admin
# Barreleye.Update
# Barreleye.Read

# Remove a role
./idplease role remove bob Barreleye.Update
```

---

## Configuration

IDPlease uses a JSON config file (default: `idplease.json`). If the file doesn't exist, sensible defaults are used.

### Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | `string` | `http://localhost:8080` | The OIDC issuer URL. Must match what your app expects. |
| `port` | `int` | `8080` | HTTP listen port. |
| `basePath` | `string` | `/` | Base path for all routes. Set this when running behind a reverse proxy at a sub-path (e.g., `/idp`). |
| `clientID` | `string` or `string[]` | `idplease` | Allowed OIDC client ID(s). Can be a single string or an array of strings. |
| `tenantID` | `string` | *(none)* | Optional tenant ID, included as the `tid` claim in tokens. |
| `tokenLifetime` | `int` | `3600` | Token lifetime in seconds. |
| `redirectURIs` | `string[]` | `["*"]` | Allowed redirect URIs. Use `["*"]` to allow any (convenient for development). |
| `sessionSecret` | `string` | *(auto-generated)* | Secret for session signing. Auto-generated on first run if not set. |
| `groupMapping` | `object` | *(none)* | Maps group GUIDs to role names. Users with the role get the corresponding group GUID in their `groups` claim. |
| `usersFile` | `string` | `users.json` | Path to the users data file. |
| `keyFile` | `string` | `idplease-key.json` | Path to the RSA signing key file. Auto-generated on first run. |

### Example: Standalone Development

```json
{
  "issuer": "http://localhost:8080",
  "port": 8080,
  "clientID": "my-spa",
  "redirectURIs": ["http://localhost:3000/callback", "http://localhost:5173/callback"]
}
```

### Example: Behind a Reverse Proxy

If your reverse proxy forwards `/idp/` to IDPlease:

```json
{
  "issuer": "https://myapp.example.com/idp",
  "port": 8080,
  "basePath": "/idp",
  "clientID": "my-app",
  "tenantID": "00000000-0000-0000-0000-000000000000",
  "redirectURIs": ["https://myapp.example.com/signin-oidc"]
}
```

Nginx config:

```nginx
location /idp/ {
    proxy_pass http://127.0.0.1:8080/idp/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Example: Entra ID Drop-in with Roles and Groups

```json
{
  "issuer": "http://localhost:8080",
  "port": 8080,
  "clientID": ["frontend-spa", "backend-api"],
  "tenantID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "tokenLifetime": 7200,
  "redirectURIs": [
    "http://localhost:3000/callback",
    "http://localhost:5000/signin-oidc"
  ],
  "groupMapping": {
    "11111111-1111-1111-1111-111111111111": "Barreleye.Admin",
    "22222222-2222-2222-2222-222222222222": "Barreleye.Update"
  }
}
```

With this config, if user `bob` has the role `Barreleye.Admin`, his token will include:
- `"roles": ["Barreleye.Admin"]`
- `"groups": ["11111111-1111-1111-1111-111111111111"]`

---

## OIDC Endpoints

All endpoints are relative to the configured `basePath` (default `/`).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery document |
| `/.well-known/openid-configuration/keys` | GET | JWKS (JSON Web Key Set) with the RSA public key |
| `/authorize` | GET | Shows the login form |
| `/authorize` | POST | Processes login, returns auth code via redirect |
| `/token` | POST | Exchanges authorization code for tokens |

### Discovery Document

```
GET /.well-known/openid-configuration
```

Returns the standard OIDC discovery document with endpoints, supported scopes, signing algorithms, and PKCE support.

### Token Exchange

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<auth_code>
&redirect_uri=<redirect_uri>
&code_verifier=<pkce_verifier>
```

Returns:

```json
{
  "access_token": "eyJhbGciOi...",
  "id_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

## Token Claims

IDPlease tokens include the following claims, designed for compatibility with Microsoft Entra ID:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | `string` | Issuer URL (from config) |
| `sub` | `string` | User ID (UUID) |
| `aud` | `string` | Client ID |
| `exp` | `number` | Expiration time (Unix timestamp) |
| `iat` | `number` | Issued at (Unix timestamp) |
| `nbf` | `number` | Not before (Unix timestamp) |
| `oid` | `string` | Object ID — same as `sub` (Entra compatibility) |
| `preferred_username` | `string` | Username or email |
| `upn` | `string` | User Principal Name — same as `preferred_username` |
| `name` | `string` | Display name |
| `email` | `string` | Email address |
| `roles` | `string[]` | Application roles assigned to the user |
| `groups` | `string[]` | Group GUIDs (populated via `groupMapping` config) |
| `tid` | `string` | Tenant ID (if configured) |
| `nonce` | `string` | Nonce (if provided in auth request) |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` | `string[]` | URN-style roles claim (Entra/WS-Fed compatibility) |

---

## How to Use with MSAL

IDPlease works with [MSAL](https://learn.microsoft.com/en-us/entra/msal/) (Microsoft Authentication Library) and any OIDC-compliant client.

### ASP.NET Core

```csharp
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(options =>
    {
        options.Instance = ""; // Not used — override Authority
        options.TenantId = "not-used";
        options.ClientId = "my-app";
        options.Authority = "http://localhost:8080";
        options.ResponseType = "code";
        options.UsePkce = true;
        // For development, disable HTTPS requirement
        options.RequireHttpsMetadata = false;
    });
```

Or with generic OIDC:

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    options.Authority = "http://localhost:8080";
    options.ClientId = "my-app";
    options.ResponseType = "code";
    options.UsePkce = true;
    options.RequireHttpsMetadata = false;
    options.GetClaimsFromUserInfoEndpoint = false;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.TokenValidationParameters.NameClaimType = "name";
    options.TokenValidationParameters.RoleClaimType = "roles";
});
```

### MSAL.js (SPA)

```javascript
const msalConfig = {
  auth: {
    clientId: "my-spa",
    authority: "http://localhost:8080",
    knownAuthorities: ["localhost"],
    redirectUri: "http://localhost:3000/callback",
  },
};

const pca = new msal.PublicClientApplication(msalConfig);
```

> **Note:** MSAL libraries may enforce HTTPS in some configurations. For local development, you may need to disable strict validation or use a simpler OIDC client library.

### JWT Validation (API Backend)

For backend services that only need to validate tokens (not initiate login), configure JWT Bearer authentication to use IDPlease's JWKS:

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "http://localhost:8080";
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "http://localhost:8080",
            ValidateAudience = true,
            ValidAudience = "my-app",
            RoleClaimType = "roles",
        };
    });
```

---

## Data Files

IDPlease stores all data in JSON files (no database required):

| File | Description |
|------|-------------|
| `idplease.json` | Configuration (you create this) |
| `users.json` | Users and roles (managed via CLI, passwords bcrypt-hashed) |
| `idplease-key.json` | RSA signing key (auto-generated, **keep this safe**) |

All files are created in the working directory by default. Paths are configurable in `idplease.json`.

> ⚠️ **Backup `idplease-key.json`** if token continuity matters. Regenerating the key invalidates all previously issued tokens.

---

## Docker

```bash
# Build
docker build -t idplease .

# Run
docker run -p 8080:8080 \
  -v $(pwd)/data:/data \
  -w /data \
  ghcr.io/jclement/idplease:latest
```

### Docker Compose with Cloudflare Tunnel

The included `docker-compose.yml` pairs IDPlease with a [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) for instant TLS and public accessibility — no port forwarding or certs to manage.

**Setup:**

1. Create a tunnel in the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com/) and copy the tunnel token
2. Configure the tunnel's public hostname (e.g. `idp.example.com`) to point to `http://idplease:8080`
3. Create a `.env` file:
   ```bash
   cp .env.example .env
   # Edit .env and set your TUNNEL_TOKEN
   ```
4. Update your `idplease.json` issuer to match the tunnel hostname:
   ```json
   {
     "issuer": "https://idp.example.com",
     "port": 8080,
     "clientID": "my-app",
     "redirectURIs": ["*"]
   }
   ```
5. Start it:
   ```bash
   docker compose up -d
   ```
6. Manage users:
   ```bash
   docker compose exec idplease idplease user add bob
   docker compose exec idplease idplease role add bob Barreleye.Admin
   ```

Your IDP is now live at `https://idp.example.com` with full TLS. 🎉

### Simple Docker Compose (no tunnel)

```yaml
services:
  idplease:
    image: ghcr.io/jclement/idplease:latest
    ports:
      - "8080:8080"
    volumes:
      - ./idplease-data:/data
    working_dir: /data
    command: ["server", "--config", "/data/idplease.json"]
```

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

### Building Releases

```bash
goreleaser release --snapshot --clean
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure `go test ./...` and `go vet ./...` pass
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/jclement/idplease.git
cd idplease
go mod tidy
go test ./...
```

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Jeff Clement
