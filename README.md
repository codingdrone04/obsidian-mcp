# Obsidian MCP Server

FastMCP 2.0 server exposing your Obsidian vault over HTTP, secured by **OAuth 2.1** with Dynamic Client Registration.

## Quick start

```bash
cp .env.example .env
# Edit .env: set CONSENT_PASSWORD, JWT_SECRET_KEY, VAULT_PATH
docker compose up -d
```

Server runs on port **8008** (host) → **8000** (container).

---

## OAuth 2.1 Authentication

This server implements the full [OAuth 2.1 Authorization Code flow](docs/OAUTH.md) so it works with Claude.ai custom connectors.

### Endpoints

| Endpoint | Description |
|---|---|
| `POST /oauth/register` | Dynamic Client Registration |
| `GET /oauth/authorize` | Consent screen |
| `POST /oauth/token` | Exchange code → Bearer token |
| `GET /.well-known/oauth-authorization-server` | OAuth metadata |
| `/mcp/*` | MCP tools (Bearer required) |
| `GET /health` | Healthcheck |

### ⚠️ Security checklist before going live

1. Change `CONSENT_PASSWORD` — **never leave `changeme123`**
2. Generate a strong `JWT_SECRET_KEY`:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
3. Set `OAUTH_DOMAIN` to your public HTTPS domain
4. WAF IP-allowlist can be **removed** once OAuth is deployed — tokens replace it

---

## MCP Tools

| Tool | Description |
|---|---|
| `list_folders` | List all vault folders |
| `list_notes` | List notes in a folder |
| `read_note` | Read note content |
| `write_note` | Create / overwrite a note |
| `append_to_note` | Append to a note |
| `delete_note` | Move note to `.trash` |
| `search_notes` | Full-text search |
| `get_note_info` | Note metadata (size, dates, word count) |

---

## Setup with Claude.ai

See [docs/SETUP_CLAUDE_AI.md](docs/SETUP_CLAUDE_AI.md) for step-by-step instructions.

---

## Local development

```bash
pip install -r requirements.txt
cp .env.example .env
# Point VAULT_PATH to a local folder
python server.py
```

Run tests:

```bash
# 1. Register a client
curl -s -X POST http://localhost:8000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"client_name":"test","redirect_uris":["http://localhost:8000/oauth/callback"]}' | jq

# 2. Open consent screen in browser
#    http://localhost:8000/oauth/authorize?client_id=<id>&redirect_uri=http://localhost:8000/oauth/callback&state=abc&response_type=code

# 3. Exchange code for token
curl -s -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"<code>","client_id":"<id>","client_secret":"<secret>"}' | jq

# 4. Call MCP
curl -H "Authorization: Bearer <token>" http://localhost:8000/mcp
```
