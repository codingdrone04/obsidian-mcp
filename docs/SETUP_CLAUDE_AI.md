# Setup — Claude.ai Custom Connector

Step-by-step guide to connect Claude.ai to your Obsidian MCP server.

---

## Prerequisites

- Server deployed at `https://your-domain.example.com` (HTTPS required)
- `CONSENT_PASSWORD` and `JWT_SECRET_KEY` set in `.env`
- Server running and healthy: `curl https://your-domain.example.com/health`

---

## Step 1 — Register a client via DCR

Run once to get your credentials:

```bash
curl -s -X POST https://your-domain.example.com/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Claude.ai",
    "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
  }' | jq
```

Response:

```json
{
  "client_id": "abc123xyz",
  "client_secret": "supersecretvalue",
  "client_name": "Claude.ai",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
}
```

**Save these values** — you'll need them in Claude.ai settings.

> Note: Tokens are in-memory. If the server restarts, re-run this step.

---

## Step 2 — Add the connector in Claude.ai

1. Go to **Claude.ai → Settings → Integrations** (or Connectors)
2. Click **Add custom connector** / **Add MCP server**
3. Fill in:
   - **Server URL**: `https://your-domain.example.com/mcp`
   - **Auth type**: OAuth 2.0
   - **Client ID**: `abc123xyz` (from step 1)
   - **Client Secret**: `supersecretvalue` (from step 1)
   - **Authorization URL**: `https://your-domain.example.com/oauth/authorize`
   - **Token URL**: `https://your-domain.example.com/oauth/token`
   - **Scopes**: `obsidian:read obsidian:write`

4. Click **Save / Connect**

> Alternatively, Claude.ai may auto-discover endpoints via:
> `https://your-domain.example.com/.well-known/oauth-authorization-server`
> In that case you only need to enter the base URL.

---

## Step 3 — Authorize the connection

Claude.ai will open a popup or redirect you to the consent screen at:

```
https://your-domain.example.com/oauth/authorize?client_id=...&redirect_uri=...&state=...
```

Enter your `CONSENT_PASSWORD` and click **Authorize**.

You'll be redirected back to Claude.ai, which exchanges the code for a Bearer token automatically.

---

## Step 4 — Test the connection

In Claude.ai, try asking:

> "List all my Obsidian notes"
> "Read the note 'Projects/todo'"
> "Search my vault for 'meeting'"

Claude should call the MCP tools and return real data from your vault.

---

## Troubleshooting

### "Unknown client_id"

The server was restarted and lost in-memory state. Re-run Step 1 and update the credentials in Claude.ai settings.

### Consent screen shows error after password

Double-check `CONSENT_PASSWORD` in your `.env`. The value must match exactly (no trailing spaces).

### 401 Unauthorized on MCP calls

Bearer token expired (1h by default). Re-authenticate in Claude.ai settings by clicking "Reconnect" or "Re-authorize".

### SSL certificate error

Ensure the server is behind a valid HTTPS reverse proxy (Caddy, Nginx + Certbot, or Cloudflare proxy).

### Rate limit / WAF block on consent

If a WAF blocks the consent form POST, temporarily disable IP rules during initial setup. Once OAuth is working, IP-based rules are no longer needed — Bearer tokens handle auth.

---

## Security notes

- The `CONSENT_PASSWORD` is the only human-facing credential. Keep it strong.
- Bearer tokens auto-expire after `TOKEN_EXPIRY_SECONDS` (default 3600).
- Rotating `JWT_SECRET_KEY` invalidates all active tokens — all clients must re-auth.
- The server never stores passwords or client secrets in logs.
