# OAuth 2.1 — Architecture & Flow

## Overview

This server implements **OAuth 2.1 Authorization Code flow** with **Dynamic Client Registration (RFC 7591)**.

```
Claude.ai custom connector
        │
        ▼
POST /oauth/register          ← DCR: get client_id + client_secret
        │
        ▼
GET  /oauth/authorize          ← Redirect user to consent screen
        │
        ▼
 ┌─────────────┐
 │ Consent UI  │  ← User enters CONSENT_PASSWORD
 └─────────────┘
        │ user approves
        ▼
Redirect → redirect_uri?code=<authorization_code>&state=<state>
        │
        ▼
POST /oauth/token              ← Exchange code for access token
        │
        ▼
{ "access_token": "<JWT>", "token_type": "Bearer" }
        │
        ▼
GET/POST /mcp                  ← All MCP calls use Bearer token
  Authorization: Bearer <JWT>
        │
        ▼
  ✅ Vault access
```

---

## Step-by-step

### 1. Dynamic Client Registration

`POST /oauth/register`

```json
// Request
{
  "client_name": "Claude.ai",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
}

// Response
{
  "client_id": "abc123",
  "client_secret": "xyz789",
  "client_name": "Claude.ai",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": ["authorization_code"]
}
```

Store `client_id` and `client_secret` — needed for every step.

### 2. Authorization request

Redirect the user to:

```
GET /oauth/authorize
  ?client_id=abc123
  &redirect_uri=https://claude.ai/api/mcp/auth_callback
  &state=<random-csrf-token>
  &response_type=code
```

The server renders the consent screen. The user enters `CONSENT_PASSWORD`.

### 3. Authorization response

On success, the server redirects to:

```
https://claude.ai/api/mcp/auth_callback?code=<auth_code>&state=<state>
```

The `state` parameter must match the value sent in step 2 (CSRF protection).

### 4. Token exchange

`POST /oauth/token`

```json
// Request (JSON or form-encoded)
{
  "grant_type": "authorization_code",
  "code": "<auth_code>",
  "client_id": "abc123",
  "client_secret": "xyz789"
}

// Response
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "obsidian:read obsidian:write"
}
```

Authorization codes are **single-use** and expire in 10 minutes.

### 5. Authenticated MCP calls

```
Authorization: Bearer <JWT>
```

Every call to `/mcp/*` must include this header. The server validates:
- JWT signature (HMAC-SHA256 with `JWT_SECRET_KEY`)
- Token expiry (`exp` claim)
- Token is in the active store (not revoked)

---

## JWT structure

```json
// Header
{ "alg": "HS256", "typ": "JWT" }

// Payload
{
  "sub": "<client_id>",
  "jti": "<unique token id>",
  "exp": 1735000000,
  "iat": 1734996400,
  "scope": "obsidian:read obsidian:write"
}
```

---

## Security considerations

| Concern | Mitigation |
|---|---|
| CSRF on authorize | `state` parameter must match |
| Token theft | Short expiry (1h), HTTPS required in prod |
| Replay attacks | `jti` stored in memory, single-use codes |
| Path traversal | All vault paths resolved and checked against vault root |
| Brute force on consent | Rate limiting via WAF (Cloudflare) recommended |
| Secrets in env | `.env` never committed, `.gitignore` enforced |

**Tokens are stored in memory** — they are lost on server restart. Clients must re-authenticate after a restart.

---

## OAuth metadata

The server exposes RFC 8414 metadata at:

```
GET /.well-known/oauth-authorization-server
```

Claude.ai auto-discovers endpoints from this URL.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Unknown client_id` | DCR not done or server restarted | Re-register via `/oauth/register` |
| `Invalid or expired code` | Code used twice or >10min elapsed | Restart auth flow |
| `Token expired` | JWT past `exp` | Re-authenticate |
| `redirect_uri not registered` | URI mismatch | Register exact URI via DCR |
| 401 on `/mcp` | Missing or invalid Bearer | Check token, re-auth if needed |
