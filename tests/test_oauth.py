"""OAuth 2.1 flow + security regression tests."""
import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import server

client = TestClient(server.app)

REDIRECT_URI = "http://testserver/cb"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _register() -> tuple[str, str]:
    r = client.post(
        "/oauth/register",
        json={"client_name": "test", "redirect_uris": [REDIRECT_URI]},
    )
    assert r.status_code == 200, r.text
    d = r.json()
    return d["client_id"], d["client_secret"]


def _get_code(client_id: str, challenge: str) -> str:
    r = client.post(
        "/oauth/authorize",
        data={
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "state": "xyz",
            "password": "testpass",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    qs = parse_qs(urlparse(r.headers["location"]).query)
    assert qs["state"][0] == "xyz"
    return qs["code"][0]


# ── Metadata & health ──────────────────────────────────────────────────────────

def test_metadata_advertises_pkce_and_revocation():
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["revocation_endpoint"].endswith("/oauth/revoke")


def test_health_has_no_vault_path():
    assert client.get("/health").json() == {"status": "ok"}


# ── PKCE is mandatory ────────────────────────────────────────────────────────────

def test_authorize_rejects_missing_pkce():
    cid, _ = _register()
    r = client.get(
        "/oauth/authorize",
        params={"client_id": cid, "redirect_uri": REDIRECT_URI},
    )
    assert r.status_code == 400


def test_authorize_rejects_non_s256():
    cid, _ = _register()
    _, ch = _pkce()
    r = client.get(
        "/oauth/authorize",
        params={
            "client_id": cid,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": ch,
            "code_challenge_method": "plain",
        },
    )
    assert r.status_code == 400


def test_token_requires_verifier():
    cid, secret = _register()
    _, ch = _pkce()
    code = _get_code(cid, ch)
    r = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": cid,
            "client_secret": secret,
        },
    )
    assert r.status_code == 400


def test_token_rejects_wrong_verifier():
    cid, secret = _register()
    _, ch = _pkce()
    code = _get_code(cid, ch)
    r = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": cid,
            "client_secret": secret,
            "code_verifier": "not-the-verifier",
        },
    )
    assert r.status_code == 400


# ── redirect_uri validation ──────────────────────────────────────────────────────

def test_authorize_rejects_unregistered_redirect_uri():
    cid, _ = _register()
    _, ch = _pkce()
    r = client.get(
        "/oauth/authorize",
        params={
            "client_id": cid,
            "redirect_uri": "http://evil.example.com/cb",
            "code_challenge": ch,
        },
    )
    assert r.status_code == 400


def test_authorize_post_rejects_unregistered_redirect_uri():
    cid, _ = _register()
    _, ch = _pkce()
    r = client.post(
        "/oauth/authorize",
        data={
            "client_id": cid,
            "redirect_uri": "http://evil.example.com/cb",
            "password": "testpass",
            "code_challenge": ch,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_wrong_password_shows_error():
    cid, _ = _register()
    _, ch = _pkce()
    r = client.post(
        "/oauth/authorize",
        data={
            "client_id": cid,
            "redirect_uri": REDIRECT_URI,
            "password": "wrong",
            "code_challenge": ch,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "incorrect" in r.text.lower()


# ── Happy path + revocation ──────────────────────────────────────────────────────

def test_full_flow_issues_valid_token():
    cid, secret = _register()
    verifier, ch = _pkce()
    code = _get_code(cid, ch)
    r = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": cid,
            "client_secret": secret,
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    payload = server._validate_bearer(token)  # does not raise
    assert payload["aud"] == "http://testserver"


def test_revocation_invalidates_token():
    cid, secret = _register()
    verifier, ch = _pkce()
    code = _get_code(cid, ch)
    token = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": cid,
            "client_secret": secret,
            "code_verifier": verifier,
        },
    ).json()["access_token"]

    server._validate_bearer(token)  # valid before revoke

    r = client.post(
        "/oauth/revoke",
        json={"token": token, "client_id": cid, "client_secret": secret},
    )
    assert r.status_code == 200

    with pytest.raises(HTTPException):
        server._validate_bearer(token)


def test_revocation_requires_client_auth():
    r = client.post("/oauth/revoke", json={"token": "x", "client_id": "nope"})
    assert r.status_code == 401


# ── Hardened endpoints / helpers ─────────────────────────────────────────────────

def test_admin_backup_disabled_without_secret():
    assert client.post("/admin/backup").status_code == 503


@pytest.mark.parametrize("folder", ["../", "../../etc", "../outside"])
def test_safe_dir_blocks_traversal(folder):
    with pytest.raises(ValueError):
        server._safe_dir(folder)


def test_safe_dir_allows_subfolder():
    # Resolves inside the vault without raising.
    assert server._safe_dir("sub").name == "sub"


def test_consent_page_escapes_query_params():
    cid, _ = _register()
    payload = '"><script>alert(1)</script>'
    r = client.get(
        "/oauth/authorize",
        params={
            "client_id": cid,
            "redirect_uri": REDIRECT_URI,
            "state": payload,
            "code_challenge": payload,
            "code_challenge_method": "S256",
        },
    )
    assert r.status_code == 200
    assert "<script>" not in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_state_is_encoded_in_redirect():
    cid, _ = _register()
    _, challenge = _pkce()
    r = client.post(
        "/oauth/authorize",
        data={
            "client_id": cid,
            "redirect_uri": REDIRECT_URI,
            "state": "a&code=evil",
            "password": "testpass",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    query = parse_qs(urlparse(r.headers["location"]).query)
    assert query["state"] == ["a&code=evil"]
    assert len(query["code"]) == 1


def test_api_docs_are_disabled():
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
