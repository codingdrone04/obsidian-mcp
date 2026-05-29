# OAuth 2.1 — Architecture & Flow

## Overview

This server implements **OAuth 2.1 Authorization Code flow** with **Dynamic Client Registration (RFC 7591)** and **mandatory PKCE (S256)**.

```
Claude.ai custom connector
        │
        ▼
POST /oauth/register          ← DCR: get client_id + client_secret
        │
        ▼
GET  /oauth/authorize          ← Redirect user to consent screen
   (+ code_challenge, S256)       PKCE challenge required
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
POST /oauth/token              ← Exchange code (+ code_verifier) for access token
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

> If `REGISTRATION_SECRET` is set on the server, `/oauth/register` requires an
> `Authorization: Bearer <REGISTRATION_SECRET>` header — otherwise it returns `401`.

### 2. Authorization request

Redirect the user to:

```
GET /oauth/authorize
  ?client_id=abc123
  &redirect_uri=https://claude.ai/api/mcp/auth_callback
  &state=<random-csrf-token>
  &response_type=code
  &code_challenge=<base64url(SHA256(verifier))>
  &code_challenge_method=S256
```

The server renders the consent screen. The user enters `CONSENT_PASSWORD`.

> **PKCE is mandatory.** A request without `code_challenge`, or with a
> `code_challenge_method` other than `S256`, is rejected with `400`. Claude.ai
> sends these automatically.

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
  "client_secret": "xyz789",
  "code_verifier": "<original PKCE verifier>"
}

// Response
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "obsidian:read obsidian:write"
}
```

Authorization codes are **single-use** and expire in 10 minutes. The
`code_verifier` is **required** — the server checks `SHA256(verifier) ==
code_challenge` (base64url) before issuing a token.

### 5. Authenticated MCP calls

```
Authorization: Bearer <JWT>
```

Every call to `/mcp/*` must include this header. The server validates:
- JWT signature (HMAC-SHA256 with `JWT_SECRET_KEY`)
- Token expiry (`exp` claim)
- Token is in the active store (not revoked)

### 6. Token revocation (RFC 7009)

`POST /oauth/revoke`

```json
{
  "token": "<JWT to revoke>",
  "client_id": "abc123",
  "client_secret": "xyz789"
}
```

Client authentication is required, and a client may only revoke its own tokens.
The `jti` is deleted from the active store, so the token fails immediately on the
next `/mcp` call. Per RFC 7009, revoking an already-invalid token still returns
`200`. The endpoint is advertised as `revocation_endpoint` in the OAuth metadata.

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
  "aud": "<OAUTH_DOMAIN>",
  "scope": "obsidian:read obsidian:write"
}
```

The `aud` claim binds the token to this server (`OAUTH_DOMAIN`) and is verified at
every `/mcp` call. Tokens issued before this claim existed remain valid until they
expire (backward-compatible migration).

---

## Security considerations

| Concern | Mitigation |
|---|---|
| CSRF on authorize | `state` parameter must match |
| Auth-code interception | Mandatory PKCE (S256) — `code_verifier` checked at token exchange |
| Open redirect / code leak | `redirect_uri` validated against registered URIs at both `GET` and `POST /oauth/authorize` |
| Token theft | Short expiry (1h), HTTPS required in prod |
| Replay attacks | `jti` persisted in SQLite, single-use codes |
| Path traversal | All vault paths resolved and checked against vault root (`is_relative_to`) |
| Brute force on consent | Built-in per-IP rate limiting (`RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW`); real IP read from `CF-Connecting-IP` behind Cloudflare |
| Timing attacks on secrets | Constant-time comparison (`secrets.compare_digest`) for password / client_secret / registration secret |
| Secrets in env | `.env` never committed, `.gitignore` enforced |

**Tokens are persisted in SQLite** (`DB_PATH`, default `/data/auth.db`, mounted on the `mcp-data` volume). Clients, auth codes and tokens survive a server restart; expired rows are purged on startup.

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
| `Unknown client_id` | DCR never done for this client | Re-register via `/oauth/register` (state now persists across restarts) |
| `Invalid or expired code` | Code used twice or >10min elapsed | Restart auth flow |
| `Token expired` | JWT past `exp` | Re-authenticate |
| `redirect_uri not registered` | URI mismatch | Register exact URI via DCR |
| `code_challenge required (PKCE)` | Authorize request missing `code_challenge` | Send `code_challenge` + `code_challenge_method=S256` |
| `code_verifier required` / `PKCE verification failed` | Missing/mismatched verifier at token exchange | Send the original `code_verifier` |
| 401 on `/mcp` | Missing or invalid Bearer | Check token, re-auth if needed |
