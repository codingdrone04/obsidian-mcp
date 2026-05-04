"""
Obsidian MCP Server — OAuth 2.1 + DCR
FastMCP 2.0 mounted on FastAPI with full Authorization Code flow.
"""
import base64
import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
import uvicorn
from fastmcp import FastMCP

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
VAULT_PATH = Path(os.getenv("VAULT_PATH", "/vault"))
OAUTH_DOMAIN = os.getenv("OAUTH_DOMAIN", "http://localhost:8000")
CONSENT_PASSWORD = os.getenv("CONSENT_PASSWORD", "changeme123")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
TOKEN_EXPIRY = int(os.getenv("TOKEN_EXPIRY_SECONDS", "3600"))
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8000"))
DB_PATH = os.getenv("DB_PATH", "/data/auth.db")

# ── Rate limit (in-memory, ephemeral by design) ────────────────────────────────
_failed_attempts: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "300"))

# ── SQLite helpers ─────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _init_db() -> None:
    with _db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS clients (
                client_id   TEXT PRIMARY KEY,
                client_secret TEXT NOT NULL,
                client_name   TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                grant_types   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_codes (
                code                  TEXT PRIMARY KEY,
                client_id             TEXT NOT NULL,
                redirect_uri          TEXT NOT NULL,
                expires_at            REAL NOT NULL,
                code_challenge        TEXT DEFAULT '',
                code_challenge_method TEXT DEFAULT 'S256'
            );
            CREATE TABLE IF NOT EXISTS access_tokens (
                jti        TEXT PRIMARY KEY,
                client_id  TEXT NOT NULL,
                expires_at REAL NOT NULL
            );
        """)
        # Purge expired rows on startup
        now = time.time()
        conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM access_tokens WHERE expires_at < ?", (now,))


def _client_save(client_id: str, data: dict) -> None:
    with _db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO clients VALUES (?, ?, ?, ?, ?)",
            (
                client_id,
                data["client_secret"],
                data["client_name"],
                json.dumps(data["redirect_uris"]),
                json.dumps(data["grant_types"]),
            ),
        )


def _client_get(client_id: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM clients WHERE client_id = ?", (client_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "client_secret": row["client_secret"],
        "client_name": row["client_name"],
        "redirect_uris": json.loads(row["redirect_uris"]),
        "grant_types": json.loads(row["grant_types"]),
    }


def _code_save(code: str, data: dict) -> None:
    with _db() as conn:
        conn.execute(
            "INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?)",
            (
                code,
                data["client_id"],
                data["redirect_uri"],
                data["expires_at"],
                data.get("code_challenge", ""),
                data.get("code_challenge_method", "S256"),
            ),
        )


def _code_pop(code: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM auth_codes WHERE code = ?", (code,)
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
    return {
        "client_id": row["client_id"],
        "redirect_uri": row["redirect_uri"],
        "expires_at": row["expires_at"],
        "code_challenge": row["code_challenge"],
        "code_challenge_method": row["code_challenge_method"],
    }


def _token_save(jti: str, client_id: str, expires_at: int) -> None:
    with _db() as conn:
        conn.execute(
            "INSERT INTO access_tokens VALUES (?, ?, ?)",
            (jti, client_id, expires_at),
        )


def _token_exists(jti: str) -> bool:
    with _db() as conn:
        row = conn.execute(
            "SELECT 1 FROM access_tokens WHERE jti = ?", (jti,)
        ).fetchone()
    return row is not None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _token_id() -> str:
    return secrets.token_urlsafe(32)


def _issue_jwt(client_id: str) -> tuple[str, int]:
    jti = _token_id()
    exp = int(time.time()) + TOKEN_EXPIRY
    payload = {
        "sub": client_id,
        "jti": jti,
        "exp": exp,
        "iat": int(time.time()),
        "scope": "obsidian:read obsidian:write",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    _token_save(jti, client_id, exp)
    return token, TOKEN_EXPIRY


def _validate_bearer(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    jti = payload.get("jti")
    if not _token_exists(jti):
        raise HTTPException(status_code=401, detail="Token revoked or unknown")
    return payload


def _verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return computed == challenge


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    return len(_failed_attempts[ip]) >= RATE_LIMIT_MAX


def _record_failed(ip: str) -> None:
    _failed_attempts[ip].append(time.time())


# ── FastMCP app (created early so lifespan is available for FastAPI) ──────────
_init_db()
mcp = FastMCP("obsidian")
_mcp_http_app = mcp.http_app(path="/")

# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(title="Obsidian MCP", version="2.0.0", lifespan=_mcp_http_app.lifespan)
bearer_scheme = HTTPBearer(auto_error=False)


# ── OAuth: Dynamic Client Registration ────────────────────────────────────────
class DCRRequest(BaseModel):
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str] = ["authorization_code"]
    response_types: list[str] = ["code"]
    token_endpoint_auth_method: str = "client_secret_post"


@app.post("/oauth/register")
async def oauth_register(body: DCRRequest):
    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    _client_save(client_id, {
        "client_secret": client_secret,
        "client_name": body.client_name,
        "redirect_uris": body.redirect_uris,
        "grant_types": body.grant_types,
    })
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.client_name,
        "redirect_uris": body.redirect_uris,
        "grant_types": body.grant_types,
        "response_types": body.response_types,
        "token_endpoint_auth_method": body.token_endpoint_auth_method,
        "registration_access_token": secrets.token_urlsafe(16),
        "registration_client_uri": f"{OAUTH_DOMAIN}/oauth/clients/{client_id}",
    }


# ── OAuth: Authorization endpoint ─────────────────────────────────────────────
_CONSENT_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Obsidian MCP — Autorisation</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #1a1a2e; color: #e0e0e0;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh;
  }}
  .card {{
    background: #16213e; border: 1px solid #0f3460;
    border-radius: 12px; padding: 2rem; width: 100%; max-width: 420px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.5rem; color: #a78bfa; }}
  p {{ font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem; }}
  .app-name {{ color: #c4b5fd; font-weight: 600; }}
  label {{ display: block; font-size: 0.85rem; margin-bottom: 0.4rem; color: #d1d5db; }}
  input[type=password] {{
    width: 100%; padding: 0.6rem 0.8rem; border-radius: 8px;
    border: 1px solid #374151; background: #111827; color: #f9fafb;
    font-size: 1rem; outline: none;
  }}
  input[type=password]:focus {{ border-color: #7c3aed; }}
  .error {{ color: #f87171; font-size: 0.85rem; margin-top: 0.5rem; }}
  button {{
    margin-top: 1.2rem; width: 100%; padding: 0.75rem;
    background: #7c3aed; color: white; border: none;
    border-radius: 8px; font-size: 1rem; cursor: pointer;
    transition: background 0.2s;
  }}
  button:hover {{ background: #6d28d9; }}
  .scopes {{
    background: #0f172a; border-radius: 8px; padding: 0.8rem 1rem;
    margin-bottom: 1.2rem; font-size: 0.85rem;
  }}
  .scopes ul {{ list-style: none; padding: 0; margin-top: 0.4rem; }}
  .scopes li::before {{ content: "✓ "; color: #34d399; }}
</style>
</head>
<body>
<div class="card">
  <h1>🔐 Obsidian MCP</h1>
  <p><span class="app-name">{client_name}</span> souhaite accéder à votre vault Obsidian.</p>
  <div class="scopes">
    <strong>Permissions demandées :</strong>
    <ul><li>Lire les notes (obsidian:read)</li><li>Écrire les notes (obsidian:write)</li></ul>
  </div>
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <label for="password">Mot de passe de consentement</label>
    <input type="password" id="password" name="password" placeholder="••••••••" autofocus>
    {error}
    <button type="submit">Autoriser l'accès</button>
  </form>
</div>
</body>
</html>"""


@app.get("/oauth/authorize", response_class=HTMLResponse)
async def oauth_authorize_get(
    client_id: str,
    redirect_uri: str,
    state: str = "",
    response_type: str = "code",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
):
    client = _client_get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Unknown client_id")
    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="redirect_uri not registered")
    html = _CONSENT_HTML.format(
        client_name=client["client_name"],
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        error="",
    )
    return HTMLResponse(html)


@app.post("/oauth/authorize", response_class=HTMLResponse)
async def oauth_authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    response_type: str = Form("code"),
    password: str = Form(...),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
):
    ip = request.client.host if request.client else "unknown"

    if _is_rate_limited(ip):
        return HTMLResponse("Too many failed attempts. Try again in 5 minutes.", status_code=429)

    client = _client_get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if password != CONSENT_PASSWORD:
        _record_failed(ip)
        html = _CONSENT_HTML.format(
            client_name=client["client_name"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            error='<p class="error">Mot de passe incorrect.</p>',
        )
        return HTMLResponse(html, status_code=200)

    code = secrets.token_urlsafe(32)
    _code_save(code, {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + 600,  # 10 min
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    })
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}&state={state}"
    return RedirectResponse(location, status_code=302)


# ── OAuth: Token endpoint ──────────────────────────────────────────────────────
@app.post("/oauth/token")
async def oauth_token(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type")
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

    code = body.get("code")
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")

    code_data = _code_pop(code)
    if not code_data:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    if time.time() > code_data["expires_at"]:
        raise HTTPException(status_code=400, detail="Code expired")
    if code_data["client_id"] != client_id:
        raise HTTPException(status_code=400, detail="client_id mismatch")

    stored_challenge = code_data.get("code_challenge", "")
    if stored_challenge:
        code_verifier = body.get("code_verifier", "")
        if not code_verifier:
            raise HTTPException(status_code=400, detail="code_verifier required")
        if not _verify_pkce(code_verifier, stored_challenge):
            raise HTTPException(status_code=400, detail="PKCE verification failed")

    client = _client_get(client_id)
    if not client:
        raise HTTPException(status_code=401, detail="Unknown client")
    if client["client_secret"] != client_secret:
        raise HTTPException(status_code=401, detail="Invalid client_secret")

    token, expires_in = _issue_jwt(client_id)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": "obsidian:read obsidian:write",
    }


# ── OAuth metadata (RFC 8414) ─────────────────────────────────────────────────
@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/{path:path}")
async def oauth_protected_resource(path: str = ""):
    return {
        "resource": OAUTH_DOMAIN,
        "authorization_servers": [OAUTH_DOMAIN],
        "scopes_supported": ["obsidian:read", "obsidian:write"],
        "bearer_methods_supported": ["header"],
    }


@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {
        "issuer": OAUTH_DOMAIN,
        "authorization_endpoint": f"{OAUTH_DOMAIN}/oauth/authorize",
        "token_endpoint": f"{OAUTH_DOMAIN}/oauth/token",
        "registration_endpoint": f"{OAUTH_DOMAIN}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "scopes_supported": ["obsidian:read", "obsidian:write"],
        "code_challenge_methods_supported": ["S256"],
    }


# ── Auth dependency for MCP tools ─────────────────────────────────────────────
async def require_auth(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    if not creds:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return _validate_bearer(creds.credentials)


# ── MCP tools ─────────────────────────────────────────────────────────────────


def _note_path(folder: str, note: str) -> Path:
    p = VAULT_PATH / folder / f"{note}.md" if folder else VAULT_PATH / f"{note}.md"
    p = p.resolve()
    if not str(p).startswith(str(VAULT_PATH.resolve())):
        raise ValueError("Path traversal detected")
    return p


@mcp.tool()
def list_folders() -> list[str]:
    """List all folders in the vault."""
    if not VAULT_PATH.exists():
        return []
    return sorted(
        str(p.relative_to(VAULT_PATH))
        for p in VAULT_PATH.rglob("*")
        if p.is_dir()
    )


@mcp.tool()
def list_notes(folder: str = "") -> list[str]:
    """List all Markdown notes in a folder (empty = root)."""
    base = VAULT_PATH / folder if folder else VAULT_PATH
    if not base.exists():
        return []
    return sorted(
        str(p.relative_to(base).with_suffix(""))
        for p in base.rglob("*.md")
    )


@mcp.tool()
def read_note(note: str, folder: str = "") -> str:
    """Read the content of a note."""
    path = _note_path(folder, note)
    if not path.exists():
        return f"Note not found: {note}"
    return path.read_text(encoding="utf-8")


@mcp.tool()
def write_note(note: str, content: str, folder: str = "") -> str:
    """Create or overwrite a note."""
    path = _note_path(folder, note)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"Written: {path.relative_to(VAULT_PATH)}"


@mcp.tool()
def append_to_note(note: str, content: str, folder: str = "") -> str:
    """Append content to an existing note (creates if absent)."""
    path = _note_path(folder, note)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(("\n" if path.exists() else "") + content)
    return f"Appended to: {path.relative_to(VAULT_PATH)}"


@mcp.tool()
def delete_note(note: str, folder: str = "") -> str:
    """Delete a note (moves to .trash inside vault)."""
    path = _note_path(folder, note)
    if not path.exists():
        return f"Note not found: {note}"
    trash = VAULT_PATH / ".trash"
    trash.mkdir(exist_ok=True)
    dest = trash / path.name
    path.rename(dest)
    return f"Moved to trash: {dest.relative_to(VAULT_PATH)}"


@mcp.tool()
def search_notes(query: str, folder: str = "") -> list[dict]:
    """Full-text search across notes. Returns [{note, folder, snippet}]."""
    base = VAULT_PATH / folder if folder else VAULT_PATH
    results = []
    q = query.lower()
    for p in base.rglob("*.md"):
        text = p.read_text(encoding="utf-8", errors="ignore")
        if q in text.lower():
            idx = text.lower().find(q)
            snippet = text[max(0, idx - 60) : idx + 120].strip()
            results.append(
                {
                    "note": p.stem,
                    "folder": str(p.parent.relative_to(VAULT_PATH)),
                    "snippet": snippet,
                }
            )
    return results


@mcp.tool()
def get_note_info(note: str, folder: str = "") -> dict:
    """Return metadata about a note (size, dates, word count)."""
    path = _note_path(folder, note)
    if not path.exists():
        return {"error": f"Note not found: {note}"}
    stat = path.stat()
    text = path.read_text(encoding="utf-8", errors="ignore")
    return {
        "name": note,
        "folder": folder,
        "size_bytes": stat.st_size,
        "word_count": len(text.split()),
        "line_count": text.count("\n") + 1,
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }


# ── MCP ASGI + auth ───────────────────────────────────────────────────────────
_mcp_asgi = _mcp_http_app


class _AuthedMCP:
    """Bearer-auth guard + /mcp prefix stripping for the MCP ASGI app."""

    def __init__(self, mcp_app):
        self._mcp = mcp_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"").decode()
            if not auth.startswith("Bearer "):
                body = b'{"detail":"Missing Bearer token"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [[b"content-type", b"application/json"]]})
                await send({"type": "http.response.body", "body": body})
                return
            try:
                _validate_bearer(auth[7:])
            except HTTPException as e:
                body = f'{{"detail":"{e.detail}"}}'.encode()
                await send({"type": "http.response.start", "status": e.status_code,
                            "headers": [[b"content-type", b"application/json"]]})
                await send({"type": "http.response.body", "body": body})
                return
            # Strip /mcp prefix so MCP app sees / or /foo
            scope = dict(scope)
            path = scope["path"]
            stripped = path[4:] or "/"   # /mcp → /  ;  /mcp/sse → /sse
            scope["path"] = stripped
            scope["raw_path"] = stripped.encode()
        await self._mcp(scope, receive, send)


_mcp_handler = _AuthedMCP(_mcp_asgi)


class _Router:
    """Top-level ASGI router — intercepts /mcp before FastAPI's redirect logic."""

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            if path == "/mcp" or path.startswith("/mcp/"):
                await _mcp_handler(scope, receive, send)
                return
        await app(scope, receive, send)


main_app = _Router()


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "vault": str(VAULT_PATH), "vault_exists": VAULT_PATH.exists()}


# ── Entrypoint ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(main_app, host=MCP_HOST, port=MCP_PORT, log_level=os.getenv("LOG_LEVEL", "info"))
