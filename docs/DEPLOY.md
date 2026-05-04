# Deploy — Self-hosted server

Guide to deploy the Obsidian MCP server on a remote Linux host via Docker + Cloudflare Tunnel.

---

## Prerequisites

- Linux server with Docker + Docker Compose installed
- Cloudflare Tunnel configured (or any HTTPS reverse proxy: Caddy, Nginx + Certbot, etc.)
- SSH access to the server

---

## Step 1 — Clone the repo on the server

```bash
ssh your-server
git clone https://github.com/YOUR_USERNAME/obsidian-mcp.git ~/apps/obsidian-mcp
cd ~/apps/obsidian-mcp
```

Or copy files from your local machine:

```bash
rsync -av --exclude='venv' --exclude='__pycache__' ~/apps/obsidian-mcp/ your-server:~/apps/obsidian-mcp/
```

---

## Step 2 — Configure .env

```bash
ssh your-server
cd ~/apps/obsidian-mcp
cp .env.example .env
nano .env
```

Fill in the values:

```env
CONSENT_PASSWORD=your_secure_password_here
OAUTH_DOMAIN=https://your-domain.example.com
TOKEN_EXPIRY_SECONDS=3600
JWT_SECRET_KEY=your_secret_key_here   # python3 -c "import secrets; print(secrets.token_hex(32))"
HOST_VAULT_PATH=/home/YOUR_USER/YourVault
MCP_HOST=0.0.0.0
MCP_PORT=8000
LOG_LEVEL=info
```

> `HOST_VAULT_PATH` is the absolute path to your Obsidian vault **on the host**. It gets mounted at `/vault` inside the container.

---

## Step 3 — Build and start Docker

```bash
cd ~/apps/obsidian-mcp
docker compose up -d --build
docker logs -f obsidian-mcp
# Expected: INFO: Uvicorn running on http://0.0.0.0:8000
```

---

## Step 4 — Test the OAuth flow

```bash
# Test 1: DCR
curl -s -X POST https://your-domain.example.com/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"client_name":"test","redirect_uris":["https://your-domain.example.com/oauth/callback"]}' | jq
# → note client_id and client_secret

# Test 2: Consent screen (open in browser)
# https://your-domain.example.com/oauth/authorize?client_id=XXX&redirect_uri=https://your-domain.example.com/oauth/callback&state=test&response_type=code

# Test 3: Token exchange
curl -s -X POST https://your-domain.example.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"CODE","client_id":"XXX","client_secret":"YYY"}' | jq

# Test 4: MCP call
curl -s -H "Authorization: Bearer TOKEN" https://your-domain.example.com/mcp
```

---

## Step 5 — Cloudflare Tunnel (optional)

If using Cloudflare Tunnel to expose the server:

```bash
# /etc/cloudflared/config.yml
ingress:
  - hostname: your-domain.example.com
    service: http://localhost:8008
  - service: http_status:404

sudo systemctl restart cloudflared
sudo systemctl status cloudflared
```

Port mapping: `8008` (host) → `8000` (container), as defined in `docker-compose.yml`.

---

## Step 6 — Connect Claude.ai

See [SETUP_CLAUDE_AI.md](SETUP_CLAUDE_AI.md) for step-by-step instructions.

---

## Checklist

- [ ] `.env` filled in with real values
- [ ] `docker compose up -d --build` succeeded
- [ ] Logs clean, server healthy
- [ ] DCR test OK
- [ ] OAuth authorize test OK
- [ ] Token exchange test OK
- [ ] HTTPS / Cloudflare Tunnel configured
- [ ] Claude.ai custom connector connected
- [ ] End-to-end vault access verified
